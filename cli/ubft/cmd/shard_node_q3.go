package cmd

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
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
