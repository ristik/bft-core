package storage

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// aggregatorWith is a type-1 (aggregator) configuration of epoch/start whose first validator has the given stake.
func aggregatorWith(f *viewFixture, epoch, start uint64, firstStake uint64) *types.PartitionDescriptionRecord {
	pdr, _ := f.pdr(epoch, start, 3, fxBody0, f.member(0, 0, firstStake), f.member(1, 1, 1), f.member(2, 2, 1))
	pdr.PartitionTypeID = 1
	return pdr
}

// Regression: production stays unit-weighted, so an aggregator is never given a root-stake vote. A configuration with a
// non-unit validator is refused (not normalised) at genesis, at restore and at an aggregator replacement, with the weight-cap
// sentinel, whether the stake is above one or zero; the unit configuration of the same shard is still accepted, and a refused
// replacement leaves the installed state untouched.
func TestAggregatorWeightTwoIsStillRefused(t *testing.T) {
	f := newViewFixture(t)
	for _, stake := range []uint64{2, 0, 1 << 40} {
		t.Run("genesis", func(t *testing.T) {
			_, err := NewShardInfo(aggregatorWith(f, 0, 1, stake), crypto.SHA256)
			require.ErrorIs(t, err, quorumweight.ErrWeightCap)
		})
		t.Run("restore", func(t *testing.T) {
			// restore installs the stored configuration through the same resetTrustBase the genesis uses
			good, err := NewShardInfo(aggregatorWith(f, 0, 1, 1), crypto.SHA256)
			require.NoError(t, err)
			bad := aggregatorWith(f, 0, 1, stake)
			h, err := bad.Hash(crypto.SHA256)
			require.NoError(t, err)
			require.ErrorIs(t, good.resetTrustBase(bad, crypto.SHA256, h), quorumweight.ErrWeightCap)
		})
	}

	// replacement: the derived aggregator configuration that activates at the boundary
	installedConf := aggregatorWith(f, 0, 1, 1)
	si := f.shardAt(installedConf, certification.TechnicalRecord{Round: 5, Epoch: 0, Leader: f.id(0)})
	si.LastCR.UC.UnicityTreeCertificate = &types.UnicityTreeCertificate{Version: 1, Partition: installedConf.PartitionID}
	trHash, err := si.LastCR.Technical.Hash()
	require.NoError(t, err)
	si.LastCR.UC.TRHash = trHash
	key := types.PartitionShardID{PartitionID: installedConf.PartitionID, ShardID: installedConf.ShardID.Key()}
	states := map[types.PartitionShardID]*ShardInfo{key: si}
	derived := map[types.PartitionShardID]struct{}{key: {}}
	const epochStart = 20
	var record evmroot.OrderedHandoffRecord // the derived aggregator branch reads no field of it

	good := aggregatorWith(f, 1, epochStart, 1)
	out, err := activateEVMAssignment(states, map[types.PartitionShardID]*types.PartitionDescriptionRecord{key: good}, record, epochStart, crypto.SHA256, derived)
	require.NoError(t, err, "the unit replacement activates")
	require.EqualValues(t, 1, out[key].TR.Epoch)

	for _, stake := range []uint64{2, 0} {
		heavy := aggregatorWith(f, 1, epochStart, stake)
		before := *states[key]
		out, err = activateEVMAssignment(states, map[types.PartitionShardID]*types.PartitionDescriptionRecord{key: heavy}, record, epochStart, crypto.SHA256, derived)
		require.ErrorIs(t, err, quorumweight.ErrWeightCap, "stake %d", stake)
		require.Nil(t, out)
		require.Equal(t, before.TR, states[key].TR, "the installed state is untouched")
		require.Same(t, si, states[key])
	}
}
