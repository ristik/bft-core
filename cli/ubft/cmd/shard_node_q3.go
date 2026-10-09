package cmd

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
	basehex "github.com/unicitynetwork/bft-go-base/types/hex"
)

// shardEpochTrust is what the shard node asks of its root-epoch trust: certificate verification per epoch, which epoch is current, and the
// body identity a restore pin is checked against. The historical store and the Q3 store both are one.
type shardEpochTrust interface {
	shardnode.TrustBaseStore
	CurrentRootEpoch() (uint64, bool)
	BodyID(uint64) ([32]byte, error)
}

// ErrQ3ShardEpoch is returned by the shard's V3 root sink for an activation it cannot install or that is not installed.
var ErrQ3ShardEpoch = errors.New("shard node: V3 activation is not installed")

// ErrQ3Candidate is returned when the candidate delivered with an activation is not the one the activated body binds, or is not a coupled
// assignment of that body's own committee.
var ErrQ3Candidate = errors.New("shard node: the delivered candidate is not the one the activated V3 body binds")

// authenticateQ3Candidate checks the delivered candidate preimage against the verified entry before anything is installed from it: its digest
// is the one the body's change record binds (for this network, predecessor, attempt and earliest activation), it is the candidate of THIS
// handoff, its coupled assignment is valid, and its root members are exactly the body's committee, entity for entity and weight for weight.
// An absent preimage must be the operator candidate the body's own members derive (a root-only change), so a candidate cannot be dropped.
func authenticateQ3Candidate(entry q3format.Entry, r evmroot.OrderedHandoffRecord, candidate []byte) error {
	body, err := q3format.DecodeBody(entry.BodyEncoding())
	if err != nil {
		return errors.Join(ErrQ3Candidate, err)
	}
	var digest [32]byte
	if len(candidate) != 0 {
		digest = sha256.Sum256(candidate)
	} else if digest, err = evmroot.D4OperatorCandidateDigest(body.Members); err != nil {
		return errors.Join(ErrQ3Candidate, err)
	}
	if !bytes.Equal(body.ChangeRecordHash, evmroot.D4CandidateContextHash(r.Network, r.PredecessorBodyID, r.Attempt, digest[:], body.EarliestActivation)) {
		return fmt.Errorf("%w: its digest is not the body's change record", ErrQ3Candidate)
	}
	if len(candidate) == 0 {
		return nil
	}
	c, err := evmassign.DecodeCandidate(candidate)
	if err != nil {
		return errors.Join(ErrQ3Candidate, err)
	}
	if c.Network != r.Network || !bytes.Equal(c.Predecessor, r.PredecessorBodyID) || c.Attempt != r.Attempt {
		return fmt.Errorf("%w: it is the candidate of another handoff", ErrQ3Candidate)
	}
	if _, err := c.Successor(); err != nil { // the assignment's own validity, proofs of possession and coupling
		return errors.Join(ErrQ3Candidate, err)
	}
	if len(c.RootMembers) != len(body.Members) {
		return fmt.Errorf("%w: %d root members for a committee of %d", ErrQ3Candidate, len(c.RootMembers), len(body.Members))
	}
	committee := make(map[string]evmroot.Member, len(body.Members))
	for _, m := range body.Members {
		committee[m.NodeID] = m
	}
	for _, m := range c.RootMembers {
		b, ok := committee[m.NodeID]
		if !ok || b.Weight != m.Weight || !bytes.Equal(b.ConsensusKey, m.Key) {
			return fmt.Errorf("%w: root member %q is not the body's", ErrQ3Candidate, m.NodeID)
		}
	}
	return nil
}

// shardQ3Sink is the shard node's root participant of the install journal: the shard node has no consensus manager, so "installing a root
// epoch" is installing everything the shard needs from it (the shard configuration of the activated assignment, the execution transition,
// the terminal certificate, the current root epoch), each derived only from what this node's runtime has verified. Its state is volatile,
// so it is also the journal's restorer: after a restart every finished activation is applied again, in epoch order, before it is checked.
type shardQ3Sink struct {
	verify func(ctx context.Context, entry q3format.Entry, proof handoff.OldCommitProof, head *abdrc.CommittedBlock, candidate []byte) error
	holds  func(epoch uint64) bool
}

var (
	_ q3active.RootSink     = (*shardQ3Sink)(nil)
	_ q3active.RootRestorer = (*shardQ3Sink)(nil)
)

func (s *shardQ3Sink) InstallVerifiedEpoch(entry q3format.Entry, proof handoff.OldCommitProof, head *abdrc.CommittedBlock, candidate []byte) (*rctypes.EpochAnchor, error) {
	if err := s.verify(context.Background(), entry, proof, head, candidate); err != nil {
		return nil, err
	}
	_, g, ok := entry.Handoff()
	if !ok {
		return nil, ErrQ3ShardEpoch
	}
	return &rctypes.EpochAnchor{GenesisID: g.ID(), Epoch: g.Epoch, Slot: g.Start - 1, StateRoot: bytes.Clone(g.Root)}, nil
}

func (s *shardQ3Sink) RestoreVerifiedEpoch(entry q3format.Entry, proof handoff.OldCommitProof, head *abdrc.CommittedBlock, candidate []byte) error {
	return s.verify(context.Background(), entry, proof, head, candidate)
}

func (s *shardQ3Sink) HoldsVerifiedEpoch(entry q3format.Entry) error {
	if !s.holds(entry.Epoch()) {
		return fmt.Errorf("%w: epoch %d", ErrQ3ShardEpoch, entry.Epoch())
	}
	return nil
}

// q3NextConf is the full shard configuration hash the root certifies once the activation takes effect: the candidate's activated assignment
// for a coupled change, the unchanged one otherwise (the same rule handoffdelivery.Verify applies to a V2 bundle).
func q3NextConf(active []byte, record handoff.OldCommitProof, candidate []byte) ([]byte, error) {
	if len(candidate) == 0 {
		return bytes.Clone(active), nil
	}
	_, activated, err := evmassign.ActivatedFromPreimage(candidate, record.Record.ActivationRound)
	if err != nil {
		return nil, fmt.Errorf("candidate: %w", err)
	}
	h, err := activated.Hash(crypto.SHA256)
	if err != nil || len(h) != 32 {
		return nil, errors.New("activated configuration hash")
	}
	return h, nil
}

// shardCatchUp is the restore's catch-up through the root handoffs: the V2 follower's or the V3 follower's. The restore has exactly one call
// site, so the order of replay, catch-up and release the startup tests pin holds for either.
type shardCatchUp interface {
	CatchUp(ctx context.Context, target uint64) error
}

// v2CatchUp adapts the V2 follower, whose catch-up also returns the bundles it installed (only the archive restore of V2 consumes them).
type v2CatchUp struct{ f *shardnode.HandoffFollower }

func (c v2CatchUp) CatchUp(ctx context.Context, target uint64) error {
	_, err := c.f.CatchUp(ctx, target)
	return err
}

// shardQ3Installer is everything the shard node installs for one verified V3 activation, in the order it must: the old committee's commit and
// the checkpoint are verified once more, the terminal certificate of the epoch that ends is authenticated and kept, the execution client
// is given its acknowledgement transition, the assignment's shard configuration and validator set are installed, and only then does the
// current root epoch advance. Each step is supplied by the node wiring (it needs the node's own stores) and runs only if the one before
// it succeeded, so a failure never leaves the epoch active with a part of it missing. Apply is idempotent: a restart applies every
// finished activation again, and an epoch re-applied with another configuration is refused.
type shardQ3Installer struct {
	Partition   types.PartitionID
	Shard       types.ShardID
	AnchorEpoch uint64
	AnchorConf  []byte // the full shard configuration hash active at the anchor epoch

	// Trust is the verified history's trust base of an epoch; Signing the signing configuration it ran under.
	Trust   func(ctx context.Context, epoch uint64) (*types.RootTrustBaseV1, error)
	Signing func(epoch uint64) (votesig.Config, error)

	Terminal             func(ctx context.Context, verified handoffdelivery.Verified) error
	Transition           func(view handoffdelivery.Bundle, verified handoffdelivery.Verified, newEpoch uint64) error
	InstallAssignment    func(view handoffdelivery.Bundle, step handoff.AssignmentStep) error
	NoteJoiner           func(view handoffdelivery.Bundle, step handoff.AssignmentStep) error
	InstallEVMTransition func(raw []byte) error
	Activate             func(epoch uint64) error
	Log                  func(epoch uint64)

	confByEpoch map[uint64][]byte
}

// Apply installs one verified activation.
func (i *shardQ3Installer) Apply(ctx context.Context, entry q3format.Entry, proof handoff.OldCommitProof, head *abdrc.CommittedBlock, candidate []byte) error {
	verifiedRecord, g, ok := entry.Handoff()
	if !ok || entry.Epoch() == 0 {
		return ErrQ3ShardEpoch
	}
	if i.confByEpoch == nil {
		i.confByEpoch = map[uint64][]byte{i.AnchorEpoch: bytes.Clone(i.AnchorConf)}
	}
	newEpoch, oldEpoch := entry.Epoch(), entry.Epoch()-1
	activeConf, ok := i.confByEpoch[oldEpoch]
	if !ok {
		return fmt.Errorf("%w: no configuration is known for epoch %d", ErrQ3ShardEpoch, oldEpoch)
	}
	// the old committee's commit is verified once more under its own epoch's keys, weights and scheme, and the checkpoint against it: the
	// installer depends on nothing another component checked
	old, err := i.Trust(ctx, oldEpoch)
	if err != nil {
		return err
	}
	oldSigning, err := i.Signing(oldEpoch)
	if err != nil {
		return err
	}
	rec, err := handoff.VerifyOldCommitProofSigning(proof, old, oldSigning)
	if err != nil || !bytes.Equal(rec.RecordID[:], verifiedRecord.RecordID) {
		return fmt.Errorf("%w: the proof is not the one that activated epoch %d", ErrQ3ShardEpoch, newEpoch)
	}
	target, err := handoffdelivery.VerifySnapshot(proof, rec, head, i.Partition, i.Shard, activeConf)
	if err != nil {
		return err
	}
	if err := authenticateQ3Candidate(entry, proof.Record, candidate); err != nil {
		return err
	}
	nextConf, err := q3NextConf(activeConf, proof, candidate)
	if err != nil {
		return err
	}
	if have, seen := i.confByEpoch[newEpoch]; seen && !bytes.Equal(have, nextConf) {
		return fmt.Errorf("%w: epoch %d was installed with another configuration", ErrQ3ShardEpoch, newEpoch)
	}
	verified := handoffdelivery.Verified{Genesis: g, Record: rec, Shard: target, NextConfHash: nextConf}
	view := handoffdelivery.Bundle{Proof: proof, Snapshot: head, Candidate: candidate}
	if err := checkTerminalCertificate(view, verified); err != nil {
		return err
	}
	if err := i.Terminal(ctx, verified); err != nil {
		return err
	}
	if err := i.Transition(view, verified, newEpoch); err != nil {
		return err
	}
	step, err := handoffdelivery.AssignmentStepOf(view, verified)
	if err != nil {
		return err
	}
	if err := i.InstallAssignment(view, step); err != nil {
		return err
	}
	if err := i.NoteJoiner(view, step); err != nil {
		return err
	}
	transition, err := handoff.BuildTransition(proof.Record, proof.Control.FrozenParent, g.Epoch, g.ID(), verified.Shard.IRTR, step)
	if err != nil {
		return err
	}
	raw, err := transition.Encode()
	if err != nil {
		return err
	}
	if err := i.InstallEVMTransition(raw); err != nil {
		return err
	}
	i.confByEpoch[newEpoch] = nextConf
	if err := i.Activate(newEpoch); err != nil {
		return err
	}
	if i.Log != nil {
		i.Log(newEpoch)
	}
	return nil
}

// ErrQ3Pair is returned when a lane shard node cannot bind its execution client to the pair: the Q3 runtime needs the engine-api executor and
// the checked genesis origin the binding is anchored in.
var ErrQ3Pair = errors.New("shard node: --q3-lane needs the engine-api executor and a checked genesis origin for the pair binding")

// headAdmitter is the node's restart admission of its execution client's head (engineapi.Adapter.AdmitHead).
type headAdmitter interface {
	AdmitHead(ctx context.Context) error
}

// admitRestartedHead has the node re-authenticate its execution client's canonical head from its own verified trust before anything is built
// or imported on it. A client whose head cannot be admitted resolves no cached accounting, so a node that proceeded would only answer
// SYNCING to every round: it refuses to start instead, with the cause.
func admitRestartedHead(ctx context.Context, a headAdmitter) error {
	if err := a.AdmitHead(ctx); err != nil {
		return fmt.Errorf("restart admission of the execution client's head: %w", err)
	}
	return nil
}

// q3PairConfig is the paired-execution binding configuration of a lane shard node: the network and root genesis its execution client is
// pinned to (the history's own), the execution genesis it was configured with, and the verified activation of a root epoch for an input
// that carries no transition.
func q3PairConfig(rt *q3active.Runtime, network uint64, executionGenesis [32]byte) *engineapi.PairConfig {
	return &engineapi.PairConfig{
		Pins:             engineapi.PairPins{NetworkID: network, RootGenesisID: rt.History().Genesis()},
		ExecutionGenesis: executionGenesis,
		ActivationID: func(epoch uint64) ([32]byte, bool) {
			e, ok := rt.Activated(epoch)
			if !ok {
				return [32]byte{}, false
			}
			return e.ActivationCommitID(), true
		},
	}
}

// pairEnabler is what a lane shard node's executor must offer to carry the pair binding.
type pairEnabler interface {
	EnablePair(*engineapi.PairConfig)
	PairEnabled() bool
	headAdmitter
}

// wireQ3Pair turns the pair binding on in the node's executor, from the node's own verified runtime, and returns the executor's restart
// admission. Without it every build and import would leave the execution client without the binding it requires.
func wireQ3Pair(executor any, rt *q3active.Runtime, network uint64, originChecked bool, executionGenesis [32]byte) (headAdmitter, error) {
	adapter, ok := executor.(pairEnabler)
	if !ok || !originChecked {
		return nil, ErrQ3Pair
	}
	adapter.EnablePair(q3PairConfig(rt, network, executionGenesis))
	return adapter, nil
}

var (
	// ErrQ3StageDigest, ErrQ3StageBody and ErrQ3StageChain are the shard node's own refusals to stage a candidate: a digest that is not one, a
	// body that is not a valid V3 body, a body of another network, genesis or protocol tuple than the node's verified history.
	ErrQ3StageDigest = errors.New("shard node: staged candidate digest")
	ErrQ3StageBody   = errors.New("shard node: staged body")
	ErrQ3StageChain  = errors.New("shard node: staged body is of another chain")
)

// shardQ3StageRequest hands the shard node the V3 candidate its entity's operator is about to attest readiness for.
type shardQ3StageRequest struct {
	Body      basehex.Bytes `json:"body"`
	Candidate basehex.Bytes `json:"candidate"`
	Attempt   uint64        `json:"attempt"`
	Preimage  basehex.Bytes `json:"preimage,omitempty"` // the coupled candidate's canonical preimage; empty for a root-only change
}

// shardQ3Staging is the shard node's side of the readiness check: it reports the chain its own verified history is rooted in and the
// candidate it has been handed, which it accepts only for that chain. It is a report by a co-hosted service, not an attestation.
type shardQ3Staging struct {
	cfg func() (q3format.ProtocolConfig, error)
	// tip is the installed tip of this node's verified history (its epoch, body version and body identity) and self this node's EVM node
	// identity. Both are set in production; staging then checks the body against the node's own history and the candidate against its own
	// binding, and a staging-only joiner (no installed step names it yet) is held to exactly the same checks as a validator.
	tip  func() (epoch, version uint64, id [32]byte, err error)
	self string
	// onStaged is told the EVM node IDs of the staged successor assignment after a stage is accepted (production: the archive and records
	// authorization of the active peers, so a joiner that is behind can catch up before it gives its own readiness).
	onStaged func(evmNodeIDs []string) error
	mu       sync.Mutex
	staged   *[32]byte
	body     [32]byte
	config   [32]byte
	attempt  uint64
}

// Stage records the candidate if its body is a valid V3 body of this node's chain.
func (s *shardQ3Staging) Stage(req shardQ3StageRequest) error {
	if len(req.Candidate) != 32 {
		return fmt.Errorf("%w: the candidate digest is not 32 bytes", ErrQ3StageDigest)
	}
	body, err := q3format.DecodeBody(req.Body)
	if err != nil {
		return errors.Join(ErrQ3StageBody, err)
	}
	cfg, err := s.cfg()
	if err != nil {
		return err
	}
	if body.Config != cfg {
		return fmt.Errorf("%w: the candidate is for another network, genesis or protocol tuple than this node's verified history", ErrQ3StageChain)
	}
	var digest [32]byte
	copy(digest[:], req.Candidate)
	if err := s.checkStaged(body, digest, req); err != nil {
		return err
	}
	// announced and recorded under one lock, so two concurrent stages cannot leave the grant of one and the status of the other
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.announceStaged(req); err != nil {
		return err
	}
	s.staged, s.body, s.config, s.attempt = &digest, body.Identity(), body.Config.Identity(), req.Attempt
	return nil
}

// announceStaged tells onStaged the members of the candidate's successor assignment. A root-only change (no preimage) names no EVM node.
func (s *shardQ3Staging) announceStaged(req shardQ3StageRequest) error {
	if s.onStaged == nil || len(req.Preimage) == 0 {
		return nil
	}
	c, err := evmassign.DecodeCandidate(req.Preimage)
	if err != nil {
		return errors.Join(ErrQ3StageBody, err)
	}
	ids := make([]string, 0, len(c.Identities))
	for _, id := range c.Identities {
		ids = append(ids, id.EVMNodeID)
	}
	return s.onStaged(ids)
}

// checkStaged is everything about a candidate this node can verify without the root's signatures or any EVM state: that the candidate
// digest is the preimage's (or the root-only operator digest of the body's members), that the body is the next epoch of the tip of this
// node's own verified history with the change record that digest and attempt determine, and, for a coupled change, that the successor
// assignment names this node.
func (s *shardQ3Staging) checkStaged(body q3format.BodyV3, digest [32]byte, req shardQ3StageRequest) error {
	if len(req.Preimage) == 0 {
		operator, err := evmroot.D4OperatorCandidateDigest(body.Members)
		if err != nil || operator != digest {
			return fmt.Errorf("%w: without a preimage the candidate is the operator digest of the body's members", ErrQ3StageDigest)
		}
	} else if sum := sha256.Sum256(req.Preimage); sum != digest {
		return fmt.Errorf("%w: the preimage is not the candidate", ErrQ3StageDigest)
	}
	if s.tip != nil {
		epoch, version, id, err := s.tip()
		if err != nil {
			return err
		}
		prior, err := q3format.Prior{Network: body.Network, Epoch: epoch, BodyVersion: version, Identity: id[:]}.Hash()
		if err != nil || body.Epoch != epoch+1 || !bytes.Equal(body.PredecessorHash, prior) {
			return fmt.Errorf("%w: the body is not the successor of this node's verified tip", ErrQ3StageChain)
		}
		if !bytes.Equal(body.ChangeRecordHash, evmroot.D4CandidateContextHash(body.Network, id[:], req.Attempt, digest[:], body.EarliestActivation)) {
			return fmt.Errorf("%w: the body's change record is not the one the candidate and attempt determine", ErrQ3StageBody)
		}
	}
	if len(req.Preimage) != 0 && s.self != "" {
		c, err := evmassign.DecodeCandidate(req.Preimage)
		if err != nil {
			return errors.Join(ErrQ3StageBody, err)
		}
		named := false
		for _, id := range c.Identities {
			named = named || id.EVMNodeID == s.self
		}
		if !named {
			return fmt.Errorf("%w: the successor assignment does not name this node (%s)", ErrQ3StageBody, s.self)
		}
	}
	return nil
}

func (s *shardQ3Staging) status() (q3StatusResponse, error) {
	cfg, err := s.cfg()
	if err != nil {
		return q3StatusResponse{}, err
	}
	out := q3StatusResponse{Network: cfg.Network, Genesis: hex.EncodeToString(cfg.Genesis[:])}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.staged != nil {
		attempt := s.attempt // a copy: the response is encoded after the lock is released
		out.Staged = &q3StagedResponse{CandidateDigest: hex.EncodeToString(s.staged[:]), BodyID: hex.EncodeToString(s.body[:]), Attempt: &attempt, Config: hex.EncodeToString(s.config[:])}
	}
	return out, nil
}

// register adds the shard node's lane endpoints to its operator mux.
func (s *shardQ3Staging) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/q3/status", q3Endpoint(func(context.Context, json.RawMessage) (any, error) { return s.status() }))
	mux.HandleFunc("POST /api/v1/q3/stage", q3Endpoint(func(_ context.Context, raw json.RawMessage) (any, error) {
		var req shardQ3StageRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if err := s.Stage(req); err != nil {
			return nil, err
		}
		return struct{}{}, nil
	}))
}
