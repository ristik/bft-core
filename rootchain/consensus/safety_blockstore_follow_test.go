package consensus

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// Recovery replaces the manager's block store (x.blockStore = blockStore). The committed-block lookup of the scheme 2 safety
// module must follow the current store: a committing vote after a recovery is built from a block that exists only in the store
// recovery installed.
func TestSafetyModuleCommittedLookupFollowsTheStoreRecoveryInstalls(t *testing.T) {
	c := newAnchorCluster(t)
	state := c.pastTheFirstSuccessor()
	round := state.CommittedHead.Block.Round
	root := restartedRoot(t, firstReplica(c.replicas))
	require.NotNil(t, root.safety.committed)

	before := root.blockStore
	_, err := before.Block(round)
	require.Error(t, err, "premise: the block is in no block of the store the manager was built with")
	_, err = root.safety.committed(round)
	require.Error(t, err)

	require.NoError(t, recoverTo(t, root, state))
	require.NotSame(t, before, root.blockStore, "premise: recovery replaced the block store")
	info, err := root.safety.committed(round)
	require.NoError(t, err, "the lookup resolves a block committed only in the new store")
	installed, err := root.blockStore.Block(round)
	require.NoError(t, err)
	require.True(t, bytes.Equal(installed.RootHash, info.RootHash))
	require.Equal(t, installed.BlockData.Epoch, info.Epoch)
	require.Equal(t, installed.BlockData.Timestamp, info.Timestamp)
}
