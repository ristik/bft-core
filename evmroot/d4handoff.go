package evmroot

import (
	"errors"
	"fmt"
)

// D4 epoch-handoff state machine. Executable model of the ordered root
// transition prepare -> freeze -> endorse -> commit -> activate ->
// acknowledge, plus committed-abort, from governance.tex §"root handoff".
//
// The model's job is to make two safety properties checkable by
// exploration:
//
//   - no two effective successors for one epoch, and
//   - no root round at which both the old and the new assignment may
//     authorise a governance block (no overlap, no gap),
//
// while never requiring a signed message to commit to state that is not
// yet known at the moment it is signed.
//
// Normative source: docs/design/d4-epoch-handoff-state-machine.md,
// docs/adr/0006-epoch-handoff-state-machine.md. Issue:
// https://github.com/ristik/bft-core/issues/6

// Phase is the handoff state. Progress is strictly Prepared -> Frozen ->
// Endorsed -> Committed -> Activated -> Acknowledged; Aborted is reachable
// only from a pre-Committed phase.
type Phase uint8

const (
	PhaseIdle Phase = iota
	PhasePrepared
	PhaseFrozen
	PhaseEndorsed
	PhaseCommitted
	PhaseActivated
	PhaseAcknowledged
	PhaseAborted
)

func (p Phase) String() string {
	return [...]string{"idle", "prepared", "frozen", "endorsed", "committed", "activated", "acknowledged", "aborted"}[p]
}

// AssignmentID names which validator set may authorise a governance block.
type AssignmentID string

const (
	OldAssignment AssignmentID = "old"
	NewAssignment AssignmentID = "new"
)

// Candidate is the committed election candidate (appendix-evm.tex
// §"Candidate Record"), reduced to what the handoff state machine needs.
type Candidate struct {
	Network         uint64
	NextEpoch       uint64
	Attempt         uint64 // j — attempt number; a new attempt after an abort is j+1
	PredecessorHash []byte // h_e — the current trust-base body identity
	MinActivation   uint64 // A_min — earliest activation bound, NOT the actual round
	CandidateHash   []byte // H(c) — the committed candidate body hash (fixed slot at the epoch manager)
}

// PipelineDepth is the minimum root-round gap the committed activation
// round must leave after the commit round. It is NOT what establishes
// finality — finality of the commit comes from the root QC/ancestry rule,
// modelled by FinalizeCommit / CommitFinalized. The gap only keeps A* from
// being scheduled inside the window where the commit could still be
// reorged.
const PipelineDepth uint64 = 3

// Handoff is the durable state of one in-progress handoff.
type Handoff struct {
	Phase       Phase
	Candidate   Candidate
	ProtocolVer uint64

	// Set at Freeze:
	FrozenSummary []byte // frozen root state summary — determined by the handoff, not a local clock
	LastEVMParent []byte // last certified EVM block hash the new assignment resumes from
	BodyIdentity  []byte // identity of the constructed next trust-base body (D3 v2, witness-free)
	FrozenID      []byte // H(bodyIdentity, frozenSummary, lastEVMParent, candidateHash, attempt, predecessor) — what the endorsement signs

	// Set at Endorse:
	EndorsementWeight uint64 // old-epoch unique signer weight on the endorsement
	EndorsementDomain SigDomain

	// Set at Commit:
	CommitRound             uint64             // root round at which the endorsed handoff was committed
	ActivationRound         uint64             // A* — the actual boundary, fixed here, >= MinActivation and >= CommitRound+PipelineDepth
	SuccessorTRHash         []byte             // successor technical record — names the leader of the first successor proposal
	CommitRecordID          []byte             // identity of the old-quorum commit statement (see CommitRecordID)
	SelfCommitQC            CommitQC           // the old-quorum QC that certified THIS commit
	ActivationRecord        ActivatedTrustBase // D3 record fixing A*; what a joining node reads for the active epoch
	CommitFinalized         bool               // a descendant commit QC extends this one (root 2-chain, not a round count)
	FinalityEvidence        CommitQC           // the descendant commit QC that finalised this one
	FinalityDescendantRound uint64             // its round (== CommitRound + 1)

	// Set at Acknowledge:
	AckEVMRound uint64 // EVM block round whose system op acknowledged the handoff

	AbortReason string
}

// SigDomain is the set of fields a phase's signed message binds. The model
// asserts that no field names state unknown at signing time (see
// FieldsAreKnown).
type SigDomain struct {
	Phase           string
	Network         uint64
	ProtocolVer     uint64
	PredecessorHash []byte
	Attempt         uint64
	FrozenID        []byte // known from Freeze onward — binds body + frozen summary + parent + candidate
	MinActivation   uint64 // known from the candidate
	ActivationRound uint64 // 0 until Commit — MUST be 0 in the endorsement domain
	SuccessorTRHash []byte // nil until Commit
}

var (
	errPhase          = errors.New("d4: transition not allowed from this phase")
	errActivationRoot = errors.New("d4: activation round below MinActivation or inside the reorg window")
	errNoCommit       = errors.New("d4: cannot activate without a committed handoff record")
	errCommitNotFinal = errors.New("d4: commit is not yet final under the root 2-chain rule")
	errEndorseWeight  = errors.New("d4: endorsement weight below the old root threshold")
	errFutureState    = errors.New("d4: signed domain binds state not known at signing time")
	errFinalityLink   = errors.New("d4: finality QC does not extend this commit (ParentCommitID mismatch)")
	errFinalityGap    = errors.New("d4: finality QC is not the consecutive next commit (timeout gap)")
	errFinalityQuorum = errors.New("d4: finality QC weight below the old root threshold")
	errFinalityRoot   = errors.New("d4: finality QC binds no committed root hash")
	errFinalityShape  = errors.New("d4: finality QC is malformed")
)

// CommitQC is an old-quorum quorum certificate over a root commit — the
// executable stand-in for the root's SafetyModule.isCommitCandidate
// relation plus the signed LedgerCommitInfo. Finality of a handoff commit
// is a DESCENDANT CommitQC that (a) names this commit as its parent, (b)
// sits at the consecutive next round, (c) carries its own old-quorum weight
// and (d) binds a committed root hash. A larger round number alone is not
// finality.
type CommitQC struct {
	CommitRecordID    []byte // the commit statement this QC certifies
	Round             uint64 // root round of this commit
	ParentCommitID    []byte // the commit this one extends (the 2-chain link)
	CommittedRootHash []byte // root block hash bound by the signed LedgerCommitInfo
	QuorumWeight      uint64 // distinct old-assignment signer weight on this QC
}

// preHandoffHeadCommitID is a deterministic stand-in for the last committed
// root state the handoff extends — the parent of the handoff commit.
func preHandoffHeadCommitID(predecessor []byte, attempt uint64) []byte {
	return sha256Bytes(marshalCBOR(cArray{cText("UNICITY_HANDOFF_HEAD"), cBytes(predecessor), cUint(attempt)}))
}

// committedRootHashFor is the deterministic committed root hash a CommitQC
// binds in the model (the signed LedgerCommitInfo's committed-state field).
func committedRootHashFor(commitRecordID []byte, round uint64) []byte {
	return sha256Bytes(marshalCBOR(cArray{cText("UNICITY_ROOT_COMMIT"), cBytes(commitRecordID), cUint(round)}))
}

// NewHandoff starts an Idle handoff for a candidate.
func NewHandoff(c Candidate, protocolVer uint64) *Handoff {
	return &Handoff{Phase: PhaseIdle, Candidate: c, ProtocolVer: protocolVer}
}

// Prepare commits the prepare record under the old root quorum: admission
// of new old-assignment governance proposals is closed and in-flight work
// is drained or cancelled. Only from Idle.
func (h *Handoff) Prepare() error {
	if h.Phase != PhaseIdle {
		return errPhase
	}
	h.Phase = PhasePrepared
	return nil
}

// Freeze records the last certified EVM block/state and the frozen root
// state summary, constructs the next trust-base body, and computes the
// FrozenID that the endorsement will sign. The body it accepts must:
//
//   - be a valid D3 v2 body (Validate passes);
//   - carry EpochStart == the candidate's A_min (NOT A*, which is not known
//     until Commit — this is what removes the circularity: the body
//     identity is stable from Freeze, and A* lives only in the commit
//     record);
//   - carry PredecessorHash == the candidate's predecessor.
//
// Two handoffs that freeze the same body with different frozen summaries or
// EVM parents get DIFFERENT FrozenIDs, so one endorsement cannot authorise
// divergent handoff states.
func (h *Handoff) Freeze(frozenSummary, lastEVMParent []byte, body TrustBaseBodyV2) error {
	if h.Phase != PhasePrepared {
		return errPhase
	}
	if err := body.Validate(); err != nil {
		return fmt.Errorf("d4: frozen trust-base body invalid: %w", err)
	}
	// The body binds EarliestActivation (A_min) — a lower bound, known now.
	// The actual boundary A* is fixed at Commit and lives ONLY in the
	// ActivatedTrustBase record (D3), never in the body.
	if body.EarliestActivation != h.Candidate.MinActivation {
		return fmt.Errorf("d4: body EarliestActivation %d != candidate A_min %d", body.EarliestActivation, h.Candidate.MinActivation)
	}
	if !bytesEqual(body.PredecessorHash, h.Candidate.PredecessorHash) {
		return errors.New("d4: body predecessor hash does not match the candidate")
	}
	if len(frozenSummary) == 0 || len(lastEVMParent) == 0 {
		return errors.New("d4: frozen summary and last EVM parent are required")
	}
	h.FrozenSummary = bytesClone(frozenSummary)
	h.LastEVMParent = bytesClone(lastEVMParent)
	id := body.Identity()
	h.BodyIdentity = id[:]
	h.FrozenID = frozenID(id[:], frozenSummary, lastEVMParent, h.Candidate.CandidateHash, h.Candidate.Attempt, h.Candidate.PredecessorHash)
	h.Phase = PhaseFrozen
	return nil
}

// frozenID binds every component of the handoff state the endorsement
// commits to, so a signer that endorsed one cannot silently be counted for
// another.
func frozenID(bodyIdentity, frozenSummary, lastEVMParent, candidateHash []byte, attempt uint64, predecessor []byte) []byte {
	enc := marshalCBOR(cArray{
		cText("UNICITY_HANDOFF_FROZEN"),
		cBytes(bodyIdentity), cBytes(frozenSummary), cBytes(lastEVMParent),
		cBytes(candidateHash), cUint(attempt), cBytes(predecessor),
	})
	return sha256Slice(enc)
}

// EndorsementDomainFor returns the exact field set the endorsement
// signature binds. It binds the FrozenID (body + frozen summary + parent +
// candidate + attempt), never ActivationRound or SuccessorTRHash — those
// are unknown until Commit.
func (h *Handoff) EndorsementDomainFor() SigDomain {
	return SigDomain{
		Phase:           "endorse",
		Network:         h.Candidate.Network,
		ProtocolVer:     h.ProtocolVer,
		PredecessorHash: h.Candidate.PredecessorHash,
		Attempt:         h.Candidate.Attempt,
		FrozenID:        h.FrozenID,
		MinActivation:   h.Candidate.MinActivation,
		ActivationRound: 0,
		SuccessorTRHash: nil,
	}
}

func bytesEqual(a, b []byte) bool { return string(a) == string(b) }

func bytesClone(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// Endorse records old-validator endorsement of the agreed body. weight is
// the old-epoch unique signer weight; oldThreshold is D3's ⌊2W/3⌋+1 for the
// outgoing assignment. Only from Frozen.
func (h *Handoff) Endorse(weight, oldThreshold uint64) error {
	if h.Phase != PhaseFrozen {
		return errPhase
	}
	dom := h.EndorsementDomainFor()
	if !FieldsAreKnown(dom) {
		return errFutureState
	}
	if weight < oldThreshold {
		return errEndorseWeight
	}
	h.EndorsementWeight = weight
	h.EndorsementDomain = dom
	h.Phase = PhaseEndorsed
	return nil
}

// CommitRecordID is the identity of the old-quorum commit statement:
// H( "UNICITY_HANDOFF_COMMIT", frozenID, A*, successorTRHash, attempt,
// predecessor ). An honest old-quorum member signs at most one of these per
// (frozenID, attempt); a second commit with a different A* or successor TR
// is a distinct CommitRecordID and needs a second, conflicting old-quorum
// QC — impossible by quorum intersection (see d4multireplica.go G2/G6).
func CommitRecordID(frozenID []byte, aStar uint64, successorTRHash []byte, attempt uint64, predecessor []byte) []byte {
	return sha256Bytes(marshalCBOR(cArray{
		cText("UNICITY_HANDOFF_COMMIT"),
		cBytes(frozenID), cUint(aStar), cBytes(successorTRHash), cUint(attempt), cBytes(predecessor),
	}))
}

// Commit commits the endorsed handoff under the old consensus rules,
// binding the new body, the actual activation boundary and the successor
// technical record. It produces the ActivatedTrustBase record (D3) that
// fixes A*. Only from Endorsed.
func (h *Handoff) Commit(commitRound, activationRound uint64, successorTRHash []byte) error {
	if h.Phase != PhaseEndorsed {
		return errPhase
	}
	if activationRound < h.Candidate.MinActivation || activationRound < commitRound+PipelineDepth {
		return errActivationRoot
	}
	if len(successorTRHash) == 0 {
		return errors.New("d4: commit requires a successor technical record")
	}
	h.CommitRound = commitRound
	h.ActivationRound = activationRound
	h.SuccessorTRHash = successorTRHash
	h.CommitRecordID = CommitRecordID(h.FrozenID, activationRound, successorTRHash, h.Candidate.Attempt, h.Candidate.PredecessorHash)
	h.SelfCommitQC = CommitQC{
		CommitRecordID:    append([]byte(nil), h.CommitRecordID...),
		Round:             commitRound,
		ParentCommitID:    preHandoffHeadCommitID(h.Candidate.PredecessorHash, h.Candidate.Attempt),
		CommittedRootHash: committedRootHashFor(h.CommitRecordID, commitRound),
		QuorumWeight:      h.EndorsementWeight, // the commit is under the same old quorum that endorsed
	}
	h.ActivationRecord = ActivatedTrustBase{
		BodyIdentity:       append([]byte(nil), h.BodyIdentity...),
		EpochStart:         activationRound,
		ActivationCommitID: append([]byte(nil), h.CommitRecordID...),
	}
	h.Phase = PhaseCommitted
	return nil
}

// DescendantCommitQC builds the CommitQC that would finalise this handoff
// commit under the root 2-chain: a commit at the consecutive next round,
// naming this commit as its parent, carrying quorumWeight. Test/scenario
// helper — real code receives this object from the root consensus, it does
// not fabricate it.
func (h *Handoff) DescendantCommitQC(quorumWeight uint64) CommitQC {
	childID := sha256Bytes(marshalCBOR(cArray{cText("UNICITY_ROOT_COMMIT_CHILD"), cBytes(h.CommitRecordID)}))
	round := h.CommitRound + 1
	return CommitQC{
		CommitRecordID:    childID,
		Round:             round,
		ParentCommitID:    append([]byte(nil), h.CommitRecordID...),
		CommittedRootHash: committedRootHashFor(childID, round),
		QuorumWeight:      quorumWeight,
	}
}

// FinalizeCommit records finality under the ROOT 2-CHAIN RULE. It takes a
// DESCENDANT CommitQC (produced by the root consensus, never fabricated
// here) and oldThreshold, and checks the real relation:
//
//   - the descendant's ParentCommitID is THIS commit's CommitRecordID
//     (it extends this commit, not some unrelated higher-round commit);
//   - the descendant sits at the consecutive next round (CommitRound + 1) —
//     a timeout gap is not a 2-chain;
//   - the descendant carries its own old-quorum weight ≥ oldThreshold;
//   - the descendant binds a 32-byte committed root hash (the signed
//     LedgerCommitInfo's committed-state field).
//
// A larger round number on its own no longer finalises anything.
// PipelineDepth still only keeps A* outside the reorg window. Idempotent;
// only from Committed onward.
func (h *Handoff) FinalizeCommit(descendant CommitQC, oldThreshold uint64) error {
	if h.Phase < PhaseCommitted || h.Phase == PhaseAborted {
		return errPhase
	}
	if len(descendant.CommitRecordID) != 32 || len(descendant.ParentCommitID) != 32 {
		return errFinalityShape
	}
	if !bytesEqual(descendant.ParentCommitID, h.CommitRecordID) {
		return errFinalityLink
	}
	if descendant.Round != h.CommitRound+1 {
		return errFinalityGap
	}
	if len(descendant.CommittedRootHash) != 32 {
		return errFinalityRoot
	}
	if descendant.QuorumWeight < oldThreshold {
		return errFinalityQuorum
	}
	h.CommitFinalized = true
	h.FinalityEvidence = descendant
	h.FinalityDescendantRound = descendant.Round
	return nil
}

// FirstSuccessorProposal is the bootstrap step the re-review asked to make
// explicit: BEFORE any new-assignment certified root round ≥ A* exists,
// who produces the first proposal and what authorises it.
//
//   - Leader: the identity named by the committed successor technical
//     record (SuccessorTRHash). It is fixed at Commit, under the old quorum.
//   - BuildsOn: the last old-set finalised committed root — this handoff's
//     own finalised commit (SelfCommitQC + FinalityEvidence), NOT a
//     new-set round (none exists yet).
//   - Authorisation: the finalised commit chain (CommitRecordID +
//     SelfCommitQC + the descendant FinalityEvidence). The new set carries
//     this proof; it does not need the old set online.
//   - ProposedRound: A*. Once THIS proposal is certified it becomes the
//     first certified round ≥ A* — the activation round.
//
// Available only from a FINALISED commit; a bare commit cannot bootstrap.
type SuccessorProposal struct {
	Leader        []byte
	BuildsOnRoot  []byte // committed root hash the new set extends
	CommitRecord  []byte
	CommitQC      CommitQC
	FinalityQC    CommitQC
	ProposedRound uint64 // A*
}

func (h *Handoff) FirstSuccessorProposal() (SuccessorProposal, bool) {
	if h.Phase != PhaseCommitted && h.Phase != PhaseActivated && h.Phase != PhaseAcknowledged {
		return SuccessorProposal{}, false
	}
	if !h.CommitFinalized {
		return SuccessorProposal{}, false
	}
	return SuccessorProposal{
		Leader:        append([]byte(nil), h.SuccessorTRHash...),
		BuildsOnRoot:  append([]byte(nil), h.FinalityEvidence.CommittedRootHash...),
		CommitRecord:  append([]byte(nil), h.CommitRecordID...),
		CommitQC:      h.SelfCommitQC,
		FinalityQC:    h.FinalityEvidence,
		ProposedRound: h.ActivationRound,
	}, true
}

// FirstSuccessorProposalLeader is the leader identity alone (kept for
// callers that only need the name).
func (h *Handoff) FirstSuccessorProposalLeader() ([]byte, bool) {
	if h.Phase < PhaseCommitted || h.Phase == PhaseAborted {
		return nil, false
	}
	return h.SuccessorTRHash, true
}

// Activate lets the new root set resume from the certified handoff state.
// observedRootRound is the certified root round the new set has imported.
// Allowed only from Committed, only once the commit is FINAL under the root
// rule (not merely once a round counter elapsed), and only once
// observedRootRound has reached the committed A*. A timeout or repeat
// certificate between the commit and A* installs nobody; the first
// certified round >= A* under the new assignment is the activation.
func (h *Handoff) Activate(observedRootRound uint64) error {
	if h.Phase != PhaseCommitted {
		if h.Phase == PhasePrepared || h.Phase == PhaseFrozen || h.Phase == PhaseEndorsed {
			return errNoCommit // an incomplete prepare cannot activate
		}
		return errPhase
	}
	if !h.CommitFinalized {
		return errCommitNotFinal
	}
	if observedRootRound < h.ActivationRound {
		return fmt.Errorf("d4: observed root round %d has not reached committed activation round %d", observedRootRound, h.ActivationRound)
	}
	h.Phase = PhaseActivated
	return nil
}

// Acknowledge records that the first new-assignment governance block's
// system operation acknowledged the handoff, closing the old assignment's
// liabilities. Only from Activated.
func (h *Handoff) Acknowledge(evmRound uint64) error {
	if h.Phase != PhaseActivated {
		return errPhase
	}
	h.AckEVMRound = evmRound
	h.Phase = PhaseAcknowledged
	return nil
}

// Abort is the old-quorum committed abort of an incomplete prepare. Allowed
// only before Commit. After it, this attempt (j) is dead; a replacement
// needs attempt j+1 and the same predecessor.
func (h *Handoff) Abort(reason string) error {
	switch h.Phase {
	case PhasePrepared, PhaseFrozen, PhaseEndorsed:
		h.Phase = PhaseAborted
		h.AbortReason = reason
		return nil
	default:
		return errPhase
	}
}

// Authorized reports which assignment may authorise a governance block
// whose imported root round is observedRootRound. This is the function the
// safety exploration checks for overlap and gaps.
//
//   - Before a committed handoff (or after an abort): always the old set.
//   - From Committed onward: old for rounds strictly below A*, new for
//     rounds at or above A*. There is no round assigned to both and none
//     assigned to neither.
func (h *Handoff) Authorized(observedRootRound uint64) AssignmentID {
	switch h.Phase {
	case PhaseCommitted, PhaseActivated, PhaseAcknowledged:
		if observedRootRound >= h.ActivationRound {
			return NewAssignment
		}
		return OldAssignment
	default:
		return OldAssignment
	}
}

// FieldsAreKnown reports whether every field in a signed domain is known at
// the time that phase signs. For the endorsement phase, ActivationRound and
// SuccessorTRHash must be zero/nil — binding them there would be a
// signature over state fixed only at Commit.
func FieldsAreKnown(d SigDomain) bool {
	if d.Phase == "endorse" {
		return d.ActivationRound == 0 && d.SuccessorTRHash == nil && len(d.FrozenID) == 32
	}
	if d.Phase == "commit" {
		// At commit, A* is known and bounded by pipelining; the successor
		// TR is constructed now. Nothing here is future EVM state.
		return d.ActivationRound != 0 && len(d.SuccessorTRHash) > 0 && len(d.FrozenID) == 32
	}
	return true
}

// CommitDomainFor returns the field set the commit signature binds — an
// old-quorum QC over this domain is the authorisation the first successor
// proposal carries.
func (h *Handoff) CommitDomainFor() SigDomain {
	return SigDomain{
		Phase:           "commit",
		Network:         h.Candidate.Network,
		ProtocolVer:     h.ProtocolVer,
		PredecessorHash: h.Candidate.PredecessorHash,
		Attempt:         h.Candidate.Attempt,
		FrozenID:        h.FrozenID,
		MinActivation:   h.Candidate.MinActivation,
		ActivationRound: h.ActivationRound,
		SuccessorTRHash: h.SuccessorTRHash,
	}
}

// sampleHandoffBody builds a representative next trust-base body for the
// model. EarliestActivation is the candidate's A_min (known at Freeze); the
// actual boundary A* is never in the body — it lives only in the
// ActivatedTrustBase record.
func sampleHandoffBody(predecessor []byte, minActivation uint64) TrustBaseBodyV2 {
	ws := d3Assignment()
	w, _ := ws.TotalWeight()
	return TrustBaseBodyV2{
		Version: TrustBaseVersion, NetworkID: 3, Epoch: 8, EarliestActivation: minActivation,
		Members: ws, RootThreshold: RootQuorumThreshold(w),
		StateSummary: rep(0x5A, 32), ChangeRecordHash: sha256Slice([]byte("candidate-8-attempt-0")),
		PredecessorHash: predecessor,
	}
}
