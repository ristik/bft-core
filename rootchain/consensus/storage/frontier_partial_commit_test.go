package storage

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// These fixtures exercise failure classification, not certificate authentication.
// The distinction matters to the sampler: missing history before mutation may
// recover, but a partially changed tree must close admission for the process.
func TestFrontierPartialCommitClassification(t *testing.T) {
	fixture := func(link bool) (*BlockTree, *node, *rctypes.QuorumCert) {
		rootBlock, childBlock := mockExecutedBlock(1, 0), mockExecutedBlock(2, 1)
		rootBlock.ShardState.Changed = ShardSet{}
		childBlock.ShardState.Changed = ShardSet{}
		root, child := newNode(&rootBlock), newNode(&childBlock)
		if link {
			root.addChild(child)
		}
		bt := &BlockTree{root: root, roundToNode: map[uint64]*node{1: root, 2: child}}
		qc := &rctypes.QuorumCert{
			VoteInfo:         &rctypes.RoundInfo{RoundNumber: 3, ParentRoundNumber: 2},
			LedgerCommitInfo: &types.UnicitySeal{RootChainRoundNumber: 2},
		}
		return bt, child, qc
	}

	t.Run("missing history is not partial mutation", func(t *testing.T) {
		bt, _, qc := fixture(true)
		qc.VoteInfo.ParentRoundNumber = 4
		_, err := bt.Commit(qc)
		require.ErrorIs(t, err, ErrCommitFailed)
		require.NotErrorIs(t, err, ErrPersistenceUncertain)
		require.Len(t, bt.roundToNode, 2)
		require.Equal(t, uint64(1), bt.root.data.GetRound())
	})

	t.Run("prune failure follows LastCR mutation", func(t *testing.T) {
		bt, child, qc := fixture(false)
		key := types.PartitionShardID{PartitionID: 1, ShardID: types.ShardID{}.Key()}
		previous := &certification.CertificationResponse{Message: "previous"}
		bt.root.data.ShardState.States[key] = &ShardInfo{LastCR: previous}
		child.data.ShardState.States[key] = &ShardInfo{LastCR: &certification.CertificationResponse{Message: "child"}}
		_, err := bt.Commit(qc)
		require.ErrorContains(t, err, "finding blocks to prune")
		require.ErrorIs(t, err, ErrPersistenceUncertain)
		require.Same(t, previous, child.data.ShardState.States[key].LastCR)
	})

	t.Run("certificate generation failure follows pruning", func(t *testing.T) {
		bt, child, qc := fixture(true)
		child.data.RootHash = []byte{1}
		_, err := bt.Commit(qc)
		require.ErrorContains(t, err, "generating certificates")
		require.ErrorIs(t, err, ErrPersistenceUncertain)
		require.NotContains(t, bt.roundToNode, uint64(1))
		require.Equal(t, uint64(1), bt.root.data.GetRound(), "root pointer has not advanced")
	})

	t.Run("write failure keeps original cause and marks uncertainty", func(t *testing.T) {
		bt, child, qc := fixture(true)
		ut, _, err := child.data.ShardState.UnicityTree(child.data.HashAlgo)
		require.NoError(t, err)
		child.data.RootHash = ut.RootHash()
		qc.LedgerCommitInfo.Hash = ut.RootHash()
		writeErr := errors.New("injected committed-root write failure")
		called := false
		bt.blocksDB = mockPersistentStore{writeBlock: func(block *ExecutedBlock, root bool) error {
			called = true
			require.True(t, root)
			require.Same(t, child.data, block)
			return writeErr
		}}
		_, err = bt.Commit(qc)
		require.True(t, called)
		require.ErrorIs(t, err, writeErr)
		require.Equal(t, writeErr.Error(), err.Error(), "existing error text remains unchanged")
		require.ErrorIs(t, err, ErrPersistenceUncertain)
		require.NotContains(t, bt.roundToNode, uint64(1))
		require.Equal(t, uint64(1), bt.root.data.GetRound())
	})
}
