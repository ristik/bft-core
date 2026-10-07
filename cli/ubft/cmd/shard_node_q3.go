package cmd

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/shardnode"
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
