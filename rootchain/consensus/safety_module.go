package consensus

import (
	"bytes"
	gocrypto "crypto"
	"errors"
	"fmt"
	"math"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	ErrTimestampNotIncreasing     = errors.New("proposal timestamp does not exceed parent timestamp")
	ErrTimestampTooFarAhead       = errors.New("proposal timestamp exceeds voter clock skew")
	ErrTimestampOverflow          = errors.New("parent timestamp cannot be incremented")
	ErrTimestampParentUnavailable = errors.New("parent timestamp unavailable")
	ErrAlreadyVotedForRound       = errors.New("already voted for round")
	// ErrNotSafeToVote and ErrNotSafeToTimeout classify a refusal by the voting and timeout rules (as opposed to a storage or
	// signing failure); ErrBlockNotExtendingQC and ErrHighQcRoundTooLow name the two rules the decision tests isolate.
	ErrNotSafeToVote       = errors.New("not safe to vote")
	ErrNotSafeToTimeout    = errors.New("not safe to time-out")
	ErrBlockNotExtendingQC = errors.New("block does not extend its QC")
	ErrHighQcRoundTooLow   = errors.New("timeout high QC round is smaller than the highest QC round seen")
	// ErrNoDecisionStore is returned when an epoch signs with scheme 2 but the safety storage cannot persist a decision.
	ErrNoDecisionStore = errors.New("safety storage cannot persist signing decisions")
	// ErrCommittedBlock is returned when the committed block of a committing scheme 2 vote is not the locally executed one.
	ErrCommittedBlock = errors.New("committed block does not match the executed block")
	// ErrStoredMessage is returned when the signed message recorded with a decision cannot be decoded or is not the node's own
	// message for that (epoch, round).
	ErrStoredMessage = errors.New("recorded signed message does not match its decision")
	// ErrNoSigningHistory is returned by a module with an activation gate but no signing resolver: without the authenticated
	// history an epoch's scheme is unknown, and unknown is never scheme 1.
	ErrNoSigningHistory = errors.New("no authenticated signing history for the epoch")
)

type (
	SafetyModule struct {
		network  types.NetworkID
		peerID   string
		signer   crypto.Signer
		verifier crypto.Verifier
		storage  SafetyStorage
		// signing selects the scheme per epoch; nil keeps every vote and timeout legacy.
		signing SigningResolver
		// committed gives the executed block behind a committed round: scheme 2 votes sign no timestamp, so the native seal
		// timestamp comes from the locally executed block, never from the (timestamp-less) QC.
		committed CommittedLookup
		// gate admits signing in an epoch; nil admits every epoch the signing resolver knows (the legacy behaviour).
		gate       ActivationGate
		parentTime func(uint64) (uint64, error)
		now        func() uint64
	}

	// ActivationGate is the verified history's signer admission (q3active.Runtime). It refuses an epoch the history does not hold
	// and an activated epoch whose installation is not complete, so the module signs nothing under a half-installed activation.
	ActivationGate interface {
		Admit(epoch uint64) error
	}

	// SigningResolver is the authenticated per-epoch signing configuration (trustbase.TrustBaseStore).
	SigningResolver interface {
		SigningConfig(epoch uint64) (votesig.Config, error)
	}

	// CommittedBlockInfo is what a committing scheme 2 vote takes from the executed block of the committed round.
	CommittedBlockInfo struct {
		Epoch     uint64
		RootHash  []byte
		Timestamp uint64
	}
	CommittedLookup func(round uint64) (CommittedBlockInfo, error)

	// DecisionStorage persists the one signing decision per (kind, epoch, round) together with the complete signed message
	// (vote or timeout, with its HighQC and signatures) in one transaction. RecordSignedDecision is idempotent for the same
	// statement and returns storage.ErrDecisionConflict for a different one.
	DecisionStorage interface {
		SignedDecision(kind storage.DecisionKind, epoch, round uint64) (statement, message []byte, err error)
		RecordSignedDecision(kind storage.DecisionKind, epoch, round uint64, statement, message []byte) error
	}

	SafetyOption func(*SafetyModule)

	Signable interface {
		Sign(s crypto.Signer) error
	}

	// Persistent storage for SafetyModule state
	SafetyStorage = interface {
		GetHighestVotedRound() uint64
		SetHighestVotedRound(uint64) error
		GetHighestQcRound() uint64
		SetHighestQcRound(qcRound, votedRound uint64) error
	}
)

// ruleError is a refusal by one of the voting or timeout rules: its text is the rule's own message and it matches the
// rule's sentinel with errors.Is.
type ruleError struct {
	msg  string
	rule error
}

func (e *ruleError) Error() string        { return e.msg }
func (e *ruleError) Is(target error) bool { return target == e.rule }

func isConsecutive(blockRound, round uint64) bool {
	return round+1 == blockRound
}

// WithDomainBoundSigning lets the module sign the scheme 2 statements in epochs whose authenticated configuration says so.
func WithDomainBoundSigning(r SigningResolver, committed CommittedLookup) SafetyOption {
	return func(s *SafetyModule) { s.signing, s.committed = r, committed }
}

// WithActivationGate makes every signing decision of the module wait for the verified history's admission of its epoch. With a gate
// the module also refuses to fall back to a legacy configuration when it has no signing resolver: absent history is an error.
func WithActivationGate(g ActivationGate) SafetyOption {
	return func(s *SafetyModule) { s.gate = g }
}

// BoundTo reports whether the module's activation gate is the given authority (a q3active.Runtime), which is how the install
// journal knows the module cannot sign outside the verified history.
func (s *SafetyModule) BoundTo(authority any) bool {
	g, ok := authority.(ActivationGate)
	return ok && s.gate == g
}

func NewSafetyModule(network types.NetworkID, id string, signer crypto.Signer, db SafetyStorage, opts ...SafetyOption) (*SafetyModule, error) {
	ver, err := signer.Verifier()
	if err != nil {
		return nil, fmt.Errorf("invalid root validator signing key: %w", err)
	}

	m := &SafetyModule{network: network, peerID: id, signer: signer, verifier: ver, storage: db, now: types.NewTimestamp}
	for _, o := range opts {
		o(m)
	}
	return m, nil
}

// config is the signing configuration of the epoch; without a resolver everything is legacy.
func (s *SafetyModule) config(epoch uint64) (votesig.Config, error) {
	if s.gate != nil {
		if err := s.gate.Admit(epoch); err != nil {
			return votesig.Config{}, fmt.Errorf("epoch %d is not admitted for signing: %w", epoch, err)
		}
		if s.signing == nil {
			return votesig.Config{}, fmt.Errorf("%w: epoch %d", ErrNoSigningHistory, epoch)
		}
	}
	if s.signing == nil {
		return votesig.Config{Scheme: votesig.SchemeLegacy}, nil
	}
	return s.signing.SigningConfig(epoch)
}

func (s *SafetyModule) decisions() (DecisionStorage, error) {
	d, ok := s.storage.(DecisionStorage)
	if !ok {
		return nil, ErrNoDecisionStore
	}
	return d, nil
}

func (s *SafetyModule) isSafeToVote(block *drctypes.BlockData, lastRoundTC *drctypes.TimeoutCert) error {
	if block == nil {
		return fmt.Errorf("block is nil")
	}
	blockRound := block.Round
	// never vote for the same round twice
	if hvr := s.storage.GetHighestVotedRound(); blockRound <= hvr {
		return fmt.Errorf("%w %d, last voted round %d", ErrAlreadyVotedForRound, blockRound, hvr)
	}
	qcRound := block.GetParentRound()
	// normal case, block is extended from last QC
	if lastRoundTC == nil {
		if !isConsecutive(blockRound, qcRound) {
			return &ruleError{fmt.Sprintf("block round %d does not extend from block qc round %d", blockRound, qcRound), ErrBlockNotExtendingQC}
		}
		// all is fine
		return nil
	}
	// previous round was timeout, block is extended from TC
	tcRound := lastRoundTC.GetRound()
	tcHqcRound := lastRoundTC.GetHqcRound()
	if !isConsecutive(blockRound, tcRound) {
		return fmt.Errorf("block round %d does not extend timeout certificate round %d",
			blockRound, tcRound)
	}
	if qcRound < tcHqcRound {
		return fmt.Errorf("block qc round %d is smaller than timeout certificate highest qc round %d",
			qcRound, tcHqcRound)
	}
	return nil
}

func (s *SafetyModule) constructCommitInfo(block *drctypes.BlockData, voteInfoHash []byte) *types.UnicitySeal {
	committedRound := s.isCommitCandidate(block)
	if committedRound == nil {
		return &types.UnicitySeal{Version: 1, PreviousHash: voteInfoHash}
	}
	return &types.UnicitySeal{
		Version:              1,
		NetworkID:            s.network,
		PreviousHash:         voteInfoHash,
		RootChainRoundNumber: committedRound.RoundNumber,
		Epoch:                committedRound.Epoch,
		Timestamp:            committedRound.Timestamp,
		Hash:                 committedRound.CurrentRootHash,
	}
}

// WithParentTimestamp binds live voting to the locally executed parent, including
// scheme 2 QCs which carry no timestamp. The lookup must follow store replacement.
func WithParentTimestamp(lookup func(uint64) (uint64, error)) SafetyOption {
	return func(s *SafetyModule) { s.parentTime = lookup }
}

// proposalTimestamp fails closed at uint64 overflow instead of wrapping to zero.
func proposalTimestamp(now, parent uint64) (uint64, error) {
	if parent == math.MaxUint64 {
		return 0, ErrTimestampOverflow
	}
	return max(now, parent+1), nil
}

// validateVoteTimestamp is only for live voting, never certified history verification.
func (s *SafetyModule) validateVoteTimestamp(block *drctypes.BlockData) error {
	var parent uint64
	if s.parentTime != nil {
		var err error
		parent, err = s.parentTime(block.GetParentRound())
		if err != nil {
			return fmt.Errorf("%w: %w", ErrTimestampParentUnavailable, err)
		}
	} else if block.Qc != nil && block.Qc.VoteInfo != nil && block.Qc.Scheme != votesig.SchemeDomainBound {
		parent = block.Qc.VoteInfo.Timestamp
	} else {
		return ErrTimestampParentUnavailable
	}
	if block.Timestamp <= parent {
		return ErrTimestampNotIncreasing
	}
	now := s.now()
	// Subtract only after comparison, avoiding overflow at either end of uint64.
	if block.Timestamp > now && block.Timestamp-now > uint64(MaxClockSkew.Seconds()) {
		return ErrTimestampTooFarAhead
	}
	return nil
}

func (s *SafetyModule) MakeVote(block *drctypes.BlockData, execStateID []byte, highQC *drctypes.QuorumCert, lastRoundTC *drctypes.TimeoutCert) (*abdrc.VoteMsg, error) {
	if block == nil {
		return nil, fmt.Errorf("block is nil")
	}
	// The overall validity of the block must be checked prior to calling this method
	// However since we are de-referencing QC make sure it is not nil
	if block.Qc == nil && block.Anchor == nil {
		return nil, fmt.Errorf("make vote error, block is missing quorum certificate")
	}
	if err := s.validateVoteTimestamp(block); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotSafeToVote, err)
	}
	qcRound := block.GetParentRound()
	votingRound := block.Round
	cfg, err := s.config(block.Epoch)
	if err != nil {
		return nil, fmt.Errorf("signing configuration of epoch %d: %w", block.Epoch, err)
	}
	if cfg.Scheme == votesig.SchemeDomainBound {
		return s.makeVoteDomainBound(cfg, block, execStateID, highQC, lastRoundTC)
	}
	if err := s.isSafeToVote(block, lastRoundTC); err != nil {
		return nil, fmt.Errorf("%w, %w", ErrNotSafeToVote, err)
	}
	if err := s.storage.SetHighestQcRound(qcRound, votingRound); err != nil {
		return nil, fmt.Errorf("persisting voting rounds: %w", err)
	}

	// create vote info
	voteInfo := &drctypes.RoundInfo{
		RoundNumber:       block.Round,
		Epoch:             block.Epoch,
		Timestamp:         block.Timestamp,
		ParentRoundNumber: qcRound,
		CurrentRootHash:   execStateID,
	}
	h, err := voteInfo.Hash(gocrypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to hash vote info: %w", err)
	}
	// Create ledger commit info, the signed part of vote
	ledgerCommitInfo := s.constructCommitInfo(block, h)
	voteMsg := &abdrc.VoteMsg{
		VoteInfo:         voteInfo,
		LedgerCommitInfo: ledgerCommitInfo,
		HighQc:           highQC,
		Anchor:           block.Anchor,
		Author:           s.peerID,
	}
	// signs commit info hash
	if err := voteMsg.Sign(s.signer); err != nil {
		return nil, err
	}
	return voteMsg, nil
}

func (s *SafetyModule) SignTimeout(tmoVote *abdrc.TimeoutMsg, lastRoundTC *drctypes.TimeoutCert) error {
	if err := tmoVote.IsValid(); err != nil {
		return fmt.Errorf("timeout message not valid, %w", err)
	}
	cfg, err := s.config(tmoVote.Timeout.Epoch)
	if err != nil {
		return fmt.Errorf("signing configuration of epoch %d: %w", tmoVote.Timeout.Epoch, err)
	}
	if cfg.Scheme == votesig.SchemeDomainBound {
		return s.signTimeoutDomainBound(cfg, tmoVote, lastRoundTC)
	}
	qcRound := tmoVote.Timeout.GetHqcRound()
	round := tmoVote.GetRound()
	if err := s.isSafeToTimeout(round, qcRound, lastRoundTC); err != nil {
		return fmt.Errorf("%w, %w", ErrNotSafeToTimeout, err)
	}
	// stop voting for this round, all other request to sign a normal vote for this round will be rejected
	if err := s.storage.SetHighestVotedRound(round); err != nil {
		return fmt.Errorf("storing voted round: %w", err)
	}
	// Sign timeout
	return tmoVote.Sign(s.signer)
}

// Sign signs a message that carries no voting rule (a proposal, an IR change request) as a member of the given epoch. With an
// activation gate the epoch must be admitted, exactly as for a vote or timeout: a leader whose installed epoch is not completely
// activated signs and broadcasts nothing.
func (s *SafetyModule) Sign(epoch uint64, msg Signable) error {
	if s.gate != nil {
		if err := s.gate.Admit(epoch); err != nil {
			return fmt.Errorf("epoch %d is not admitted for signing: %w", epoch, err)
		}
	}
	return msg.Sign(s.signer)
}

func (s *SafetyModule) isSafeToTimeout(round, tmoHighQCRound uint64, lastRoundTC *drctypes.TimeoutCert) error {
	if hqc := s.storage.GetHighestQcRound(); tmoHighQCRound < hqc {
		// respect highest qc round
		return &ruleError{fmt.Sprintf("timeout high qc round %d is smaller than highest qc round %d seen", tmoHighQCRound, hqc), ErrHighQcRoundTooLow}
	}
	if round <= tmoHighQCRound {
		return fmt.Errorf("timeout round %v is in the past, timeout msg high qc is for round %v",
			round, tmoHighQCRound)
	}
	if hvr := s.storage.GetHighestVotedRound(); round < hvr {
		// don’t time out in a past round
		return fmt.Errorf("timeout round %d is in the past, already signed vote for round %d", round, hvr)
	}
	var tcRound uint64 = 0
	if lastRoundTC != nil {
		tcRound = lastRoundTC.GetRound()
	}
	// timeout round must follow either last qc or tc
	if !isConsecutive(round, tmoHighQCRound) && !isConsecutive(round, tcRound) {
		return fmt.Errorf("round %v does not follow last qc round %v or tc round %v",
			round, tmoHighQCRound, tcRound)
	}
	return nil
}

// isCommitCandidate - returns committed round info if commit criteria is valid
func (s *SafetyModule) isCommitCandidate(block *drctypes.BlockData) *drctypes.RoundInfo {
	if block.Qc == nil || block.Anchor != nil {
		return nil
	}
	// consecutive successful round commits previous round
	if isConsecutive(block.Round, block.Qc.VoteInfo.RoundNumber) {
		return block.Qc.VoteInfo
	}
	return nil
}

// makeVoteDomainBound makes a scheme 2 vote the way Diem/Aptos SafetyRules do. Both signatures are made first, in memory, and
// the statement (PV and, for a committing vote, the native seal bytes) is recorded durably together with the COMPLETE signed
// vote, HighQC and anchor included, in one transaction before the vote is returned. Nothing signed leaves the node before it is
// on disk, so a crash earlier leaves no decision and a retry is free; a crash later, or a restart, finds the decision and
// returns the recorded message itself, never a re-signed one. A different statement for the same (epoch, round) is refused
// with ErrDecisionConflict.
func (s *SafetyModule) makeVoteDomainBound(cfg votesig.Config, block *drctypes.BlockData, execStateID []byte, highQC *drctypes.QuorumCert, lastRoundTC *drctypes.TimeoutCert) (*abdrc.VoteMsg, error) {
	decisions, err := s.decisions()
	if err != nil {
		return nil, err
	}
	qcRound := block.GetParentRound()
	info := &drctypes.RoundInfo{Version: 1, RoundNumber: block.Round, Epoch: block.Epoch, ParentRoundNumber: qcRound, CurrentRootHash: execStateID}
	vi := votesig.VoteInfo{Epoch: info.Epoch, Round: info.RoundNumber, Parent: qcRound}
	copy(vi.Exec[:], execStateID)
	vh, err := cfg.VoteInfoHash(vi)
	if err != nil {
		return nil, err
	}
	seal, err := s.constructCommitInfoDomainBound(block, vh[:])
	if err != nil {
		return nil, err
	}
	pv, sealBytes, _, err := drctypes.DomainBoundStatement(cfg, info, seal, false)
	if err != nil {
		return nil, fmt.Errorf("vote statement: %w", err)
	}
	statement, err := types.Cbor.Marshal([][]byte{pv, sealBytes})
	if err != nil {
		return nil, fmt.Errorf("encoding vote statement: %w", err)
	}
	existing, stored, err := decisions.SignedDecision(storage.DecisionVote, block.Epoch, block.Round)
	if err != nil {
		return nil, fmt.Errorf("reading signing decision: %w", err)
	}
	if existing != nil {
		// a retry after a restart or a crash before the vote was sent: only the recorded statement, as the recorded message
		if !bytes.Equal(existing, statement) {
			return nil, fmt.Errorf("not safe to vote, %w: epoch %d round %d", storage.ErrDecisionConflict, block.Epoch, block.Round)
		}
		var voteMsg abdrc.VoteMsg
		if err := types.Cbor.Unmarshal(stored, &voteMsg); err != nil {
			return nil, fmt.Errorf("%w: vote epoch %d round %d: %w", ErrStoredMessage, block.Epoch, block.Round, err)
		}
		if voteMsg.VoteInfo == nil || voteMsg.VoteInfo.Epoch != block.Epoch || voteMsg.VoteInfo.RoundNumber != block.Round || voteMsg.Author != s.peerID {
			return nil, fmt.Errorf("%w: vote epoch %d round %d", ErrStoredMessage, block.Epoch, block.Round)
		}
		if err := s.storage.SetHighestQcRound(qcRound, block.Round); err != nil {
			return nil, fmt.Errorf("persisting voting rounds: %w", err)
		}
		return &voteMsg, nil
	}
	if err := s.isSafeToVote(block, lastRoundTC); err != nil {
		return nil, fmt.Errorf("%w, %w", ErrNotSafeToVote, err)
	}
	voteMsg := &abdrc.VoteMsg{VoteInfo: info, LedgerCommitInfo: seal, HighQc: highQC, Anchor: block.Anchor, Author: s.peerID}
	if err := voteMsg.SignDomainBound(s.signer, cfg); err != nil {
		return nil, err
	}
	message, err := types.Cbor.Marshal(voteMsg)
	if err != nil {
		return nil, fmt.Errorf("encoding signed vote: %w", err)
	}
	if err := decisions.RecordSignedDecision(storage.DecisionVote, block.Epoch, block.Round, statement, message); err != nil {
		return nil, fmt.Errorf("persisting signing decision: %w", err)
	}
	if err := s.storage.SetHighestQcRound(qcRound, block.Round); err != nil {
		return nil, fmt.Errorf("persisting voting rounds: %w", err)
	}
	return voteMsg, nil
}

// constructCommitInfoDomainBound is constructCommitInfo for scheme 2: the committed block is the locally executed one, whose
// epoch and state must be those of the committed round, and the seal timestamp is its timestamp.
func (s *SafetyModule) constructCommitInfoDomainBound(block *drctypes.BlockData, voteInfoHash []byte) (*types.UnicitySeal, error) {
	committedRound := s.isCommitCandidate(block)
	if committedRound == nil {
		return &types.UnicitySeal{Version: 1, PreviousHash: voteInfoHash}, nil
	}
	if s.committed == nil {
		return nil, fmt.Errorf("%w: no executed block source", ErrCommittedBlock)
	}
	executed, err := s.committed(committedRound.RoundNumber)
	if err != nil {
		return nil, fmt.Errorf("%w: round %d: %w", ErrCommittedBlock, committedRound.RoundNumber, err)
	}
	if executed.Epoch != committedRound.Epoch || !bytes.Equal(executed.RootHash, committedRound.CurrentRootHash) {
		return nil, fmt.Errorf("%w: round %d", ErrCommittedBlock, committedRound.RoundNumber)
	}
	return &types.UnicitySeal{
		Version:              1,
		NetworkID:            s.network,
		PreviousHash:         voteInfoHash,
		RootChainRoundNumber: committedRound.RoundNumber,
		Epoch:                committedRound.Epoch,
		Timestamp:            executed.Timestamp,
		Hash:                 committedRound.CurrentRootHash,
	}, nil
}

// signTimeoutDomainBound signs PT with the same rule as the vote: the signature is made in memory, then PT and the complete
// signed timeout (HighQC and last TC included) are recorded in one transaction, and only then is the message returned. A
// recorded decision for the same statement hands back the recorded message; a different statement is refused.
func (s *SafetyModule) signTimeoutDomainBound(cfg votesig.Config, tmoVote *abdrc.TimeoutMsg, lastRoundTC *drctypes.TimeoutCert) error {
	decisions, err := s.decisions()
	if err != nil {
		return err
	}
	statement, err := tmoVote.Preimage(cfg)
	if err != nil {
		return fmt.Errorf("timeout statement: %w", err)
	}
	epoch, round := tmoVote.Timeout.Epoch, tmoVote.GetRound()
	existing, stored, err := decisions.SignedDecision(storage.DecisionTimeout, epoch, round)
	if err != nil {
		return fmt.Errorf("reading signing decision: %w", err)
	}
	if existing != nil {
		if !bytes.Equal(existing, statement) {
			return fmt.Errorf("not safe to time-out, %w: epoch %d round %d", storage.ErrDecisionConflict, epoch, round)
		}
		recorded, err := s.decodeStoredTimeout(stored, epoch, round)
		if err != nil {
			return err
		}
		if err := s.storage.SetHighestVotedRound(round); err != nil {
			return fmt.Errorf("storing voted round: %w", err)
		}
		*tmoVote = *recorded
		return nil
	}
	if err := s.isSafeToTimeout(round, tmoVote.Timeout.GetHqcRound(), lastRoundTC); err != nil {
		return fmt.Errorf("%w, %w", ErrNotSafeToTimeout, err)
	}
	if err := tmoVote.SignDomainBound(s.signer, cfg); err != nil {
		return err
	}
	message, err := types.Cbor.Marshal(tmoVote)
	if err != nil {
		tmoVote.Signature = nil
		return fmt.Errorf("encoding signed timeout: %w", err)
	}
	if err := decisions.RecordSignedDecision(storage.DecisionTimeout, epoch, round, statement, message); err != nil {
		tmoVote.Signature = nil // nothing signed is returned that is not on disk
		return fmt.Errorf("persisting signing decision: %w", err)
	}
	if err := s.storage.SetHighestVotedRound(round); err != nil {
		return fmt.Errorf("storing voted round: %w", err)
	}
	return nil
}

// RecordedTimeout is the complete signed timeout this node recorded for (epoch, round), or nil when it recorded none. A node
// that restarted after signing a timeout sends this message again instead of building a new one from its (possibly advanced)
// HighQC, which the recorded decision would refuse. It is nil, without touching the store, for an epoch that signs legacy.
func (s *SafetyModule) RecordedTimeout(epoch, round uint64) (*abdrc.TimeoutMsg, error) {
	cfg, err := s.config(epoch)
	if err != nil {
		return nil, fmt.Errorf("signing configuration of epoch %d: %w", epoch, err)
	}
	if cfg.Scheme != votesig.SchemeDomainBound {
		return nil, nil // only scheme 2 records decisions; a legacy epoch never touches the decision store
	}
	decisions, err := s.decisions()
	if err != nil {
		if errors.Is(err, ErrNoDecisionStore) {
			return nil, nil // a store without decisions has recorded none
		}
		return nil, err
	}
	statement, stored, err := decisions.SignedDecision(storage.DecisionTimeout, epoch, round)
	if err != nil {
		return nil, fmt.Errorf("reading signing decision: %w", err)
	}
	if statement == nil {
		return nil, nil
	}
	recorded, err := s.decodeStoredTimeout(stored, epoch, round)
	if err != nil {
		return nil, err
	}
	if err := s.storage.SetHighestVotedRound(round); err != nil {
		return nil, fmt.Errorf("storing voted round: %w", err)
	}
	return recorded, nil
}

func (s *SafetyModule) decodeStoredTimeout(stored []byte, epoch, round uint64) (*abdrc.TimeoutMsg, error) {
	var msg abdrc.TimeoutMsg
	if err := types.Cbor.Unmarshal(stored, &msg); err != nil {
		return nil, fmt.Errorf("%w: timeout epoch %d round %d: %w", ErrStoredMessage, epoch, round, err)
	}
	if msg.Timeout == nil || msg.Timeout.Epoch != epoch || msg.Timeout.Round != round || msg.Author != s.peerID {
		return nil, fmt.Errorf("%w: timeout epoch %d round %d", ErrStoredMessage, epoch, round)
	}
	return &msg, nil
}
