package storage

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

// A root built from a committed head (a peer's state message, or a handoff checkpoint) gets each shard's partition parameters from the local
// configuration the head's ShardConfHash was checked against: the head carries no parameters, and without them the request verifier of a root
// with no request history takes the shard for one without a proof and accepts any proof (#941).
func Test_RootFromCommittedHeadKeepsPartitionParams(t *testing.T) {
	rsmt := map[string]string{"proof_type": "aggregator_rsmt_v1"}
	c := newTestChain(t, chainShard{partition: 1, epochStarts: []uint64{1}, params: rsmt}, chainShard{partition: 2, epochStarts: []uint64{1}})
	c.next()
	c.next()
	c.next(1)
	c.next(1, 2)
	params := func(bs *BlockStore, p types.PartitionID) map[string]string {
		si := bs.ShardInfo(p, types.ShardID{})
		require.NotNil(t, si, "shard %d", p)
		return si.PartitionParams
	}
	// the control: the store that executed the blocks has them from the configuration
	require.Equal(t, rsmt, params(c.store, 1))
	require.Empty(t, params(c.store, 2))

	sm := received(t, c.state())
	t.Run("recovered from a peer's state", func(t *testing.T) {
		bs, db, err := c.recoverInto(sm)
		require.NoError(t, err)
		require.Equal(t, rsmt, params(bs, 1))
		require.Empty(t, params(bs, 2))
		// and what was written is what a restart loads
		restarted, err := New(crypto.SHA256, db, c.orch, c.log)
		require.NoError(t, err)
		require.Equal(t, rsmt, params(restarted, 1))
	})
	t.Run("handoff checkpoint", func(t *testing.T) {
		root, err := NewRootBlock(sm.CommittedHead, crypto.SHA256, c.orch)
		require.NoError(t, err)
		si := root.ShardState.States[types.PartitionShardID{PartitionID: 1, ShardID: types.ShardID{}.Key()}]
		require.NotNil(t, si)
		require.Equal(t, rsmt, si.PartitionParams)
	})
}
