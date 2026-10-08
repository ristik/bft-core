package leader

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTableCacheKeysBoundsAndRebuild(t *testing.T) {
	a, b := committee(t, 6, 1, 1, 1), committee(t, 3, 3, 2, 1)
	_, err := NewTableCache(0)
	require.ErrorIs(t, err, ErrCacheSize)
	c, err := NewTableCache(2)
	require.NoError(t, err)

	k1 := TableKey{Network: 5, Epoch: 2, Start: 10}
	k2 := TableKey{Network: 5, Epoch: 3, Start: 10}                      // same start, another epoch
	k3 := TableKey{Network: 5, Epoch: 2, Start: 10, Config: [32]byte{1}} // same epoch and start, another body
	w1, err := c.Get(k1, a)
	require.NoError(t, err)
	again, err := c.Get(k1, a)
	require.NoError(t, err)
	require.Same(t, w1, again)
	w2, err := c.Get(k2, b)
	require.NoError(t, err)
	require.NotSame(t, w1, w2, "the epoch is part of the key: overlapping rounds never share a table")
	require.Equal(t, 2, c.Builds())

	// a third key evicts the least recently used (k1); asking for it rebuilds the identical schedule
	_, err = c.Get(k3, a)
	require.NoError(t, err)
	require.Equal(t, 2, c.Len(), "bounded")
	rebuilt, err := c.Get(k1, a)
	require.NoError(t, err)
	require.NotSame(t, w1, rebuilt)
	require.Equal(t, 4, c.Builds(), "the rebuild after eviction is a construction")
	for r := uint64(10); r < 40; r++ {
		x, _ := w1.GetLeaderForRound(r)
		y, _ := rebuilt.GetLeaderForRound(r)
		require.Equal(t, x, y)
	}

	// a failure is not cached
	bad := TableKey{Network: 5, Epoch: 9, Start: 0}
	_, err = c.Get(bad, a)
	require.ErrorIs(t, err, ErrInvalidStart)
	require.NotContains(t, c.byKey, bad)
}

func TestTableCacheCoalescesConcurrentColdCallers(t *testing.T) {
	nodes := committee(t, 40000, 25535, 1)
	c, err := NewTableCache(4)
	require.NoError(t, err)
	key := TableKey{Network: 1, Epoch: 2, Start: 1}
	var wg sync.WaitGroup
	got := make([]*Weighted, 8)
	start := make(chan struct{})
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			w, err := c.Get(key, nodes)
			if err != nil {
				t.Error(err)
			}
			got[i] = w
		}()
	}
	close(start)
	wg.Wait()
	require.Equal(t, 1, c.Builds(), "eight concurrent cold callers cost one construction")
	for _, w := range got {
		require.Same(t, got[0], w)
	}
}
