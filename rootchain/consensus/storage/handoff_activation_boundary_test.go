package storage

import (
	"crypto"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// The epoch starts at the committed activation round, not at the first block the new committee manages to propose: rounds that time
// out before it (a restarting committee, a faulty leader) move that block past the start. Every root derives the same activation from
// the committed record, so the EVM and the aggregator replacement activate whatever the first block's round is.
func TestActivationHoldsWhenTheFirstNewEpochRoundsTimeOut(t *testing.T) {
	for _, first := range []uint64{7, 8, 10} { // the epoch starts at 7: no timeout, one timed-out round, three
		t.Run(fmt.Sprintf("first block at round %d (start 7)", first), func(t *testing.T) {
			f := newAssignmentFixture(t)
			f.useRealOrchestration(t)
			f.seedFees(t)
			a := f.addAggregator(t)
			f.changes = []evmassign.Change{f.replace(t, a, a.conf, nil)}
			h := f.commitAssignment(t)
			anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
			require.NoError(t, err)
			require.EqualValues(t, 6, anchor.Slot, "the anchor is the round before the epoch start")
			confs, err := f.orch.ShardConfigs(first)
			require.NoError(t, err)
			require.EqualValues(t, 7, confs[f.shard].EpochStart)

			s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
			require.NoError(t, err)
			block := f.addSuccessorBlock(t, s, first, anchor) // its parent is the anchor: nothing was certified in the timed-out rounds
			evmHash, err := evmassign.PDRHash(h.activated)
			require.NoError(t, err)
			evm := block.ShardState.States[f.shard]
			require.Equal(t, evmHash[:], []byte(evm.ShardConfHash), "the EVM assignment is installed")
			require.EqualValues(t, 1, evm.TR.Epoch)
			aggHash, err := evmassign.PDRHash(confs[a.key])
			require.NoError(t, err)
			agg := block.ShardState.States[a.key]
			require.Equal(t, aggHash[:], []byte(agg.ShardConfHash), "and so is the aggregator key replacement")
			require.ErrorContains(t, agg.Verify(a.oldKey.id, func(abcrypto.Verifier) error { return nil }), "not in the trustbase")
			// the epoch goes on
			next := f.addSuccessorBlock(t, s, first+1, nil)
			require.Equal(t, evmHash[:], []byte(next.ShardState.States[f.shard].ShardConfHash))
		})
	}
}

// A configuration that does not start at the committed activation round is still refused, on both branches, with the sentinel.
func TestActivationRefusesAConfigurationThatDoesNotStartAtTheCommittedActivation(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	a := f.addAggregator(t)
	f.changes = []evmassign.Change{f.replace(t, a, a.conf, nil)}
	h := f.commitAssignment(t)
	_, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	root := f.store.blockTree.Root()
	configs, err := f.orch.ShardConfigs(7)
	require.NoError(t, err)
	record := h.commit
	_, err = activateEVMAssignment(root.ShardState.States, configs, record, record.ActivationRound, crypto.SHA256, nil)
	require.NoError(t, err, "the committed activation round is the start")
	derived := map[types.PartitionShardID]struct{}{a.key: {}}
	for _, other := range []uint64{record.ActivationRound - 1, record.ActivationRound + 1, record.ActivationRound + 3} {
		_, err = activateEVMAssignment(root.ShardState.States, configs, record, other, crypto.SHA256, nil)
		require.ErrorIs(t, err, ErrActivationBoundary, "EVM branch, activation %d", other)
		require.ErrorIs(t, err, ErrControlCheckpoint)
		// the aggregator replacement alone (its own branch), so the EVM branch cannot be the one that refuses
		onlyAggregator := map[types.PartitionShardID]*types.PartitionDescriptionRecord{a.key: configs[a.key]}
		_, err = activateEVMAssignment(root.ShardState.States, onlyAggregator, record, other, crypto.SHA256, derived)
		require.ErrorIs(t, err, ErrActivationBoundary, "aggregator replacement branch, activation %d", other)
	}
}

// The block executor itself binds the boundary to the committed record: an epoch anchor that is not the round before the committed
// activation round (a corrupt or foreign anchor) is refused with the sentinel, whatever round the first block carries.
func TestFirstBlockOfAnEpochWithAnAnchorOffTheCommittedActivationIsRefused(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	h := f.commitAssignment(t)
	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	root := f.store.blockTree.Root()
	require.EqualValues(t, 6, root.GetRound())

	shifted := *root
	data := *root.BlockData
	shiftedAnchor := *anchor
	shiftedAnchor.Slot = anchor.Slot + 1 // an anchor one round late: its first child would start at 8, the record says 7
	data.Round, data.Anchor = shiftedAnchor.Slot, &shiftedAnchor
	shifted.BlockData = &data
	require.True(t, isEpochAnchorRoot(&shifted))
	child := &rctypes.BlockData{Version: 2, Round: shiftedAnchor.Slot + 1, Epoch: data.Epoch, Anchor: &shiftedAnchor, Payload: &rctypes.Payload{Version: 2}}
	_, err = shifted.Extend(child, nil, f.orch, crypto.SHA256, logger.New(t))
	require.ErrorIs(t, err, ErrActivationBoundary)
	require.ErrorIs(t, err, ErrControlCheckpoint)

	// the real anchor, with the first block anywhere from the start on, is accepted by the same call
	for _, round := range []uint64{7, 9} {
		ok := &rctypes.BlockData{Version: 2, Round: round, Epoch: root.BlockData.Epoch, Anchor: anchor, Payload: &rctypes.Payload{Version: 2}}
		_, err = root.Extend(ok, nil, f.orch, crypto.SHA256, logger.New(t))
		require.NoError(t, err, "first block at round %d", round)
	}
}
