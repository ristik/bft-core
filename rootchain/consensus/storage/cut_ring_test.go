package storage

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

func cutBlock(round uint64, pos []byte) *ExecutedBlock {
	return &ExecutedBlock{
		BlockData:  &rctypes.BlockData{Round: round},
		ShardState: ShardStates{Control: &evmroot.ControlState{Network: 5, Epoch: 1, Phase: "idle", PreviousDigest: make([]byte, 32), Pos: pos}},
	}
}

func TestACommittedBlockWithASourceStateKeepsItsCutAndNothingElseDoes(t *testing.T) {
	var bt BlockTree
	pos := rootrecords.NewState(1, 1).Bytes()
	b := cutBlock(7, pos)
	bt.captureCut(b)
	cut, err := bt.ControlCut(7)
	require.NoError(t, err)
	require.True(t, bytes.Equal(cut.Control.Pos, pos))
	// the path leads from the control leaf to the block's tree root
	tree, _, err := b.ShardState.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	root, err := handoff.ControlRoot(cut.Control, cut.Path)
	require.NoError(t, err)
	require.Equal(t, tree.RootHash(), root, "the retained path leads to the block's own tree root")

	bt.captureCut(cutBlock(8, nil))
	_, err = bt.ControlCut(8)
	require.ErrorIs(t, err, ErrCutUnavailable, "a block without a source state has no cut")
	bt.captureCut(&ExecutedBlock{BlockData: &rctypes.BlockData{Round: 9}})
	_, err = bt.ControlCut(9)
	require.ErrorIs(t, err, ErrCutUnavailable, "a chain without a control state has no cut")
	_, err = bt.ControlCut(6)
	require.ErrorIs(t, err, ErrCutUnavailable, "a round never committed here")
}

func TestTheCutRingKeepsTheLatestAndEvictsTheOldest(t *testing.T) {
	var r cutRing
	for i := uint64(1); i <= MaxRetainedCuts+3; i++ {
		r.put(i, ControlCut{Control: &evmroot.ControlState{Epoch: i}})
	}
	for i := uint64(1); i <= 3; i++ {
		_, ok := r.get(i)
		require.False(t, ok, "round %d is evicted", i)
	}
	for i := uint64(4); i <= MaxRetainedCuts+3; i++ {
		cut, ok := r.get(i)
		require.True(t, ok)
		require.Equal(t, i, cut.Control.Epoch)
	}
	// a repeat of a round replaces it without growing the ring
	r.put(10, ControlCut{Control: &evmroot.ControlState{Epoch: 99}})
	cut, _ := r.get(10)
	require.EqualValues(t, 99, cut.Control.Epoch)
	require.Len(t, r.order, MaxRetainedCuts)
}

func TestCommittingABlockRetainsItsCutBeforeItBecomesTheRoot(t *testing.T) {
	rootBlock, childBlock := mockExecutedBlock(1, 0), mockExecutedBlock(2, 1)
	rootBlock.ShardState.Changed, childBlock.ShardState.Changed = ShardSet{}, ShardSet{}
	pos := rootrecords.NewState(1, 1).Bytes()
	childBlock.ShardState.Control = &evmroot.ControlState{Network: 5, Epoch: 1, Phase: "idle", PreviousDigest: make([]byte, 32), Pos: pos}
	root, child := newNode(&rootBlock), newNode(&childBlock)
	root.addChild(child)
	bt := &BlockTree{root: root, roundToNode: map[uint64]*node{1: root, 2: child}}
	ut, _, err := child.data.ShardState.UnicityTree(child.data.HashAlgo)
	require.NoError(t, err)
	child.data.RootHash = ut.RootHash()
	bt.blocksDB = mockPersistentStore{writeBlock: func(*ExecutedBlock, bool) error { return nil }}
	qc := &rctypes.QuorumCert{
		VoteInfo:         &rctypes.RoundInfo{RoundNumber: 3, ParentRoundNumber: 2},
		LedgerCommitInfo: &types.UnicitySeal{RootChainRoundNumber: 2, Hash: ut.RootHash()},
	}
	_, err = bt.Commit(qc)
	require.NoError(t, err)
	cut, err := bt.ControlCut(2)
	require.NoError(t, err)
	got, err := handoff.ControlRoot(cut.Control, cut.Path)
	require.NoError(t, err)
	require.Equal(t, ut.RootHash(), got, "the cut authenticates against the tree root the block was sealed with")
	_, err = bt.ControlCut(1)
	require.ErrorIs(t, err, ErrCutUnavailable)
}
