package archivewiring

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/handoffbundle"
	"github.com/unicitynetwork/bft-go-base/types"
)

type recordingBundleHistory struct{ requested []uint64 }

func (h *recordingBundleHistory) GetByEpoch(_ context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	h.requested = append(h.requested, epoch)
	return nil, errors.New("unavailable predecessor")
}

func TestBundleVerificationSelectsPredecessorTrustEpoch(t *testing.T) {
	history := &recordingBundleHistory{}
	q := archive.BundleRequest{Context: transportBundleContext(), Epoch: 2}
	bundle := handoffdelivery.Bundle{Proof: handoff.OldCommitProof{Record: evmroot.OrderedHandoffRecord{Epoch: 1}}, Body: evmroot.TrustBaseBodyV2{Epoch: 2}}
	raw, err := handoffdelivery.EncodeBundle(bundle)
	require.NoError(t, err)
	require.ErrorContains(t, VerifyBundle(context.Background(), q, raw, history, nil), "unavailable predecessor")
	require.Equal(t, []uint64{1}, history.requested)
	q.Epoch = 3
	require.ErrorIs(t, VerifyBundle(context.Background(), q, raw, history, nil), archive.ErrInvalid)
	require.Equal(t, []uint64{1}, history.requested, "wrong successor epoch never selects a trust base")
	bundle.Proof.Record.Epoch, bundle.Body.Epoch = 2, 3
	raw, err = handoffdelivery.EncodeBundle(bundle)
	require.NoError(t, err)
	require.ErrorContains(t, VerifyBundle(context.Background(), q, raw, history, nil), "unavailable predecessor")
	require.Equal(t, []uint64{1, 2}, history.requested)
}

func transportBundleContext() archive.Context {
	q, _ := transportFixture()
	return q.Context
}

type fixedBundleHistory struct{ old *types.RootTrustBaseV1 }

func (h fixedBundleHistory) GetByEpoch(_ context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	if epoch != h.old.Epoch {
		return nil, errors.New("unavailable predecessor")
	}
	return h.old, nil
}

// After an assignment activates, the next handoff's bundle snapshot carries the successor configuration. Publication and replica
// admission expect the configuration installed for the shard epoch the snapshot names, never the genesis one.
func TestBundleSnapshotIsVerifiedUnderItsShardEpochsInstalledConfiguration(t *testing.T) {
	ctx := context.Background()
	genesis := handoffbundle.New(t) // shard epoch 0: the genesis configuration
	f := handoffbundle.NewBoundAtShardEpoch(t, nil, 1)
	require.NotEqual(t, genesis.ConfHash, f.ConfHash, "a successor assignment's configuration differs from genesis")
	raw, err := handoffdelivery.EncodeBundle(handoffdelivery.Bundle{Proof: f.Proof, Body: f.Body, Snapshot: f.Snapshot})
	require.NoError(t, err)
	history := fixedBundleHistory{old: f.Old}
	var genesisHash [32]byte
	copy(genesisHash[:], genesis.ConfHash)
	q := archive.BundleRequest{Epoch: f.Body.Epoch, Context: archive.Context{PartitionID: f.Partition, ShardID: f.Shard, FullShardConfHash: genesisHash}}
	installed := func(set map[uint64][]byte) func(uint64) ([]byte, bool) {
		return func(epoch uint64) ([]byte, bool) { h, ok := set[epoch]; return h, ok }
	}

	t.Run("a post-activation bundle is accepted under its epoch's installed configuration", func(t *testing.T) {
		require.NoError(t, VerifyBundle(ctx, q, raw, history, installed(map[uint64][]byte{0: genesis.ConfHash, 1: f.ConfHash})))
	})
	t.Run("the genesis configuration at that shard epoch is refused", func(t *testing.T) {
		err := VerifyBundle(ctx, q, raw, history, installed(map[uint64][]byte{0: genesis.ConfHash, 1: genesis.ConfHash}))
		require.ErrorIs(t, err, handoffdelivery.ErrBundle, "a wrong epoch/hash pair")
	})
	t.Run("a shard epoch with no installed configuration is refused, retryably, with no fallback", func(t *testing.T) {
		err := VerifyBundle(ctx, q, raw, history, installed(map[uint64][]byte{0: genesis.ConfHash}))
		require.ErrorIs(t, err, ErrBundleConfEpochUnknown)
		require.NotErrorIs(t, err, handoffdelivery.ErrBundle)
	})
	t.Run("without a resolver the genesis-only expectation refuses a successor bundle", func(t *testing.T) {
		require.ErrorIs(t, VerifyBundle(ctx, q, raw, history, nil), handoffdelivery.ErrBundle)
	})
	t.Run("a genesis-epoch bundle still verifies under the genesis configuration", func(t *testing.T) {
		rawGenesis, err := handoffdelivery.EncodeBundle(handoffdelivery.Bundle{Proof: genesis.Proof, Body: genesis.Body, Snapshot: genesis.Snapshot})
		require.NoError(t, err)
		qg := archive.BundleRequest{Epoch: genesis.Body.Epoch, Context: q.Context}
		require.NoError(t, VerifyBundle(ctx, qg, rawGenesis, fixedBundleHistory{old: genesis.Old}, installed(map[uint64][]byte{0: genesis.ConfHash, 1: f.ConfHash})))
	})
}
