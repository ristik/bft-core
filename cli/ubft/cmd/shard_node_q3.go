package cmd

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
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
func wireQ3Pair(executor any, rt *q3active.Runtime, network uint64, origin registrygenesis.GenesisOrigin) (headAdmitter, error) {
	adapter, ok := executor.(pairEnabler)
	if !ok || !origin.Valid() {
		return nil, ErrQ3Pair
	}
	adapter.EnablePair(q3PairConfig(rt, network, [32]byte(origin.BlockHash())))
	return adapter, nil
}
