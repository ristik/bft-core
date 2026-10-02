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
			require.ErrorIs(t, agg.Verify(a.oldKey.id, func(abcrypto.Verifier) error { return nil }), ErrNodeNotInTrustBase)
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

// Two competing first blocks of the epoch, both children of the epoch anchor (the epoch starts at 7: one at 7, one at 8 after a timed-out
// round, as a fork), activate exactly the same state: the activation derives from the committed record and the anchor, never from the
// round the proposer happened to reach, so honest roots that voted for different forks still agree on what the epoch installs.
func TestTwoChildrenOfTheAnchorActivateIdentically(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	a := f.addAggregator(t)
	f.changes = []evmassign.Change{f.replace(t, a, a.conf, nil)}
	h := f.commitAssignment(t)
	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	require.EqualValues(t, 6, anchor.Slot)

	s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	atStart := f.addSuccessorBlock(t, s, 7, anchor)
	afterTimeout := f.addSuccessorBlock(t, s, 8, anchor)
	require.NotEqual(t, atStart.BlockData.Round, afterTimeout.BlockData.Round, "two distinct blocks of a fork")
	require.Equal(t, atStart.RootHash, afterTimeout.RootHash, "the root hash is the activated shard states' hash, so it does not depend on the round")

	for _, shard := range []types.PartitionShardID{f.shard, a.key} {
		x, y := atStart.ShardState.States[shard], afterTimeout.ShardState.States[shard]
		require.Equal(t, []byte(x.ShardConfHash), []byte(y.ShardConfHash), "installed configuration, shard %v", shard)
		xt, err := x.TR.Hash()
		require.NoError(t, err)
		yt, err := y.TR.Hash()
		require.NoError(t, err)
		require.Equal(t, xt, yt, "installed technical record, shard %v", shard)
		require.Equal(t, x.IR, y.IR, "input record, shard %v", shard)
		require.Equal(t, x.nodeIDs, y.nodeIDs, "trust base, shard %v", shard)
		require.Equal(t, x.Fees, y.Fees, "fees, shard %v", shard)
		require.Equal(t, []byte(x.PrevEpochFees), []byte(y.PrevEpochFees), "rolled fees, shard %v", shard)
	}
	require.Equal(t, atStart.ShardState.Control, afterTimeout.ShardState.Control, "the control state after the activation")
	xTree, _, err := atStart.ShardState.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	yTree, _, err := afterTimeout.ShardState.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, xTree.RootHash(), yTree.RootHash(), "the shard states' unicity tree root hash")
}

// A restart between the anchor and the first block of the epoch reloads the anchor from the database: the first block, at a round past
// the start, is accepted by a store that never saw the anchor installed in this process and activates what a store that did see it
// would, and a store that lost the anchor refuses it with the sentinel instead of guessing.
func TestFirstBlockOfAnEpochAfterARestartReloadsTheAnchorFromTheDatabase(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	h := f.commitAssignment(t)
	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)

	// Reference: the store that installed the anchor.
	live, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	want := f.addSuccessorBlock(t, live, 8, anchor)

	// A restart: a fresh store over the same database. The anchor is the persisted root, loaded rather than passed in memory.
	restarted, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	root := restarted.blockTree.Root()
	require.EqualValues(t, anchor.Slot, root.GetRound(), "the anchor is reloaded as the root")
	require.True(t, isEpochAnchorRoot(root), "and it is still recognized as an epoch anchor")
	got := f.addSuccessorBlock(t, restarted, 8, root.BlockData.Anchor)
	evmHash, err := evmassign.PDRHash(h.activated)
	require.NoError(t, err)
	require.Equal(t, evmHash[:], []byte(got.ShardState.States[f.shard].ShardConfHash), "the reloaded anchor activates the committed assignment")
	require.Equal(t, want.ShardState.States[f.shard].ShardConfHash, got.ShardState.States[f.shard].ShardConfHash)
	wantTree, _, err := want.ShardState.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	gotTree, _, err := got.ShardState.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, wantTree.RootHash(), gotTree.RootHash(), "the same shard-state root as before the restart")
}
