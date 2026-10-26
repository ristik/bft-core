package consensus

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// #845: a commit stamped just before a stall window opens must not fall inside it at the checker's millisecond precision.
func TestQ4BWindowStartFollowsEveryEarlierStamp(t *testing.T) {
	for range 200 {
		stamp := time.Now()
		from := q4bWindowStart()
		require.Less(t, stamp.UnixMilli(), from.UnixMilli())
		require.False(t, time.Now().Before(from), "the window opens only once its start has passed")
	}
}

// #845: a recovery rewrites the epoch anchor root through the observed store; it is not recorded as a committed block or an ordinary
// commit, while the first block of the epoch above it is.
func TestQ4BObservedSkipsTheEpochAnchorRoot(t *testing.T) {
	db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "observed.db"), storage.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	live := &q4bLive{t: t, seen: map[int][]q4Commit{}, chains: map[int]map[uint64]q4Block{}, blocks: map[int]map[uint64]q4Block{}}
	s := &q4bStore{BoltDB: db, live: live, c: newQ4BCrash()}
	anchor := &rctypes.EpochAnchor{GenesisID: bytes.Repeat([]byte{1}, 32), Epoch: 2, Slot: 6, StateRoot: bytes.Repeat([]byte{2}, 32)}
	block := func(round uint64) *storage.ExecutedBlock {
		return &storage.ExecutedBlock{BlockData: &rctypes.BlockData{Version: rctypes.VersionHandoff, Epoch: 2, Round: round, Anchor: anchor}}
	}

	root := block(anchor.Slot)
	require.True(t, q4bAnchorRoot(root))
	require.Equal(t, root.GetRound(), root.GetParentRound(), "the anchor root's parent round is its own round")
	require.NoError(t, s.WriteBlock(root, true))
	require.Empty(t, live.blocks[0])
	require.Empty(t, live.chains[0])
	require.Empty(t, live.seen[0])

	first := block(anchor.Slot + 1)
	first.CommitQc = &rctypes.QuorumCert{}
	require.False(t, q4bAnchorRoot(first))
	require.NoError(t, s.WriteBlock(first, true))
	require.Contains(t, live.chains[0], first.GetRound())
	require.Equal(t, anchor.Slot, live.chains[0][first.GetRound()].Parent)
	require.Len(t, live.seen[0], 1)
}
