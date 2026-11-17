package consensus

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	testobservability "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestValidateTargetBlockInterval(t *testing.T) {
	lt := 10 * time.Second
	require.NoError(t, ValidateTargetBlockInterval(DefaultTargetBlockInterval, lt))
	require.NoError(t, ValidateTargetBlockInterval(100*time.Millisecond, lt))
	require.ErrorIs(t, ValidateTargetBlockInterval(99*time.Millisecond, lt), ErrTargetBlockInterval)
	require.NoError(t, ValidateTargetBlockInterval(5*time.Second-time.Millisecond, lt))
	require.ErrorIs(t, ValidateTargetBlockInterval(5*time.Second, lt), ErrTargetBlockInterval, "strictly below LocalTimeout/2")
	require.ErrorIs(t, ValidateTargetBlockInterval(0, lt), ErrTargetBlockInterval)
}

// TestTargetBlockIntervalIsRejectedBeforeThePacemaker: an invalid target never builds a manager, and touches no storage.
func TestTargetBlockIntervalIsRejectedBeforeThePacemaker(t *testing.T) {
	net := testnetwork.NewRootMockNetwork()
	root := testutils.NewTestNode(t)
	observe := testobservability.Default(t)
	store, err := tbstore.NewTrustBaseStore(memorydb.New(), observe.Logger())
	require.NoError(t, err)
	cm, err := NewConsensusManager(root.PeerConf.ID, store, nil, net, root.Signer, nil, observe, WithTargetBlockInterval(10*time.Millisecond))
	require.Nil(t, cm)
	require.ErrorIs(t, err, ErrTargetBlockInterval)
}

// TestMixedTargetBlockIntervalsAgree runs four roots with different local targets (two at the 100 ms floor, two at 300 ms): the
// target feeds only each node's own pacemaker, so every root commits the same blocks with the same root hashes and certificates.
func TestMixedTargetBlockIntervalsAgree(t *testing.T) {
	var n atomic.Int32
	targets := []time.Duration{100 * time.Millisecond, 300 * time.Millisecond, 100 * time.Millisecond, 300 * time.Millisecond}
	var mu sync.Mutex
	var recs []*committedRecorder
	cms, _ := createConsensusManagersWithOptions(t, 4, nil, func(*types.RootTrustBaseV1) []Option {
		return []Option{WithTargetBlockInterval(targets[int(n.Add(1)-1)%len(targets)])}
	}, func(s PersistentStore) PersistentStore {
		r := &committedRecorder{PersistentStore: s, mu: &mu, roots: map[uint64][]byte{}}
		recs = append(recs, r)
		return r
	})
	seen := map[time.Duration]bool{}
	for _, cm := range cms {
		seen[cm.pacemaker.minRoundLen] = true
	}
	require.Len(t, seen, 2, "the nodes run different targets")

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for _, cm := range cms {
		wg.Add(2)
		go func(cm *ConsensusManager) { defer wg.Done(); _ = cm.Run(ctx) }(cm)
		go func(cm *ConsensusManager) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-cm.certResultCh:
				}
			}
		}(cm)
	}
	const dest = 9
	require.Eventually(t, func() bool {
		for _, cm := range cms {
			if cm.pacemaker.GetCurrentRound() < dest {
				return false
			}
		}
		return true
	}, 60*time.Second, 50*time.Millisecond)
	cancel()
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	compared := 0
	for r, h := range recs[0].roots {
		for _, other := range recs[1:] {
			if oh, ok := other.roots[r]; ok {
				require.Equal(t, h, oh, "committed root of round %d", r)
				compared++
			}
		}
	}
	require.Positive(t, compared, "the nodes committed common rounds")
	t.Logf("compared %d block root hashes across mixed targets", compared)
}

// committedRecorder records the root hash of every block a node writes as its committed root.
type committedRecorder struct {
	PersistentStore
	mu    *sync.Mutex
	roots map[uint64][]byte
}

func (c *committedRecorder) WriteBlock(b *storage.ExecutedBlock, root bool) error {
	if root && b != nil && b.BlockData != nil {
		c.mu.Lock()
		c.roots[b.BlockData.Round] = append([]byte(nil), b.RootHash...)
		c.mu.Unlock()
	}
	return c.PersistentStore.WriteBlock(b, root)
}
