package q3format

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// A replay extends the history in place, amortised: a chain of a thousand epochs reallocates its entries a logarithmic number of times,
// never once per epoch.
func TestExtendingAHistoryAppendsWithoutCopyingItPerEpoch(t *testing.T) {
	cur := &History{entries: []Entry{{epoch: 1}}, tail: new(atomic.Bool)}
	moves := 0
	for e := uint64(2); e <= 1000; e++ {
		next := cur.extend(Entry{epoch: e})
		if &next.entries[0] != &cur.entries[0] {
			moves++
		}
		require.EqualValues(t, e-1, cur.Tip().Epoch(), "the extended history is unchanged")
		cur = next
	}
	require.EqualValues(t, 1000, cur.Tip().Epoch())
	for e := uint64(1); e <= 1000; e++ {
		got, err := cur.ForEpoch(e)
		require.NoError(t, err)
		require.Equal(t, e, got.Epoch())
	}
	require.LessOrEqual(t, moves, 11, "the entries move only when the array is full")
}

// Two extensions of the same history (two envelopes verified against it, a verify racing an adopt, the UTB copy of a history and the history
// itself) never write the same slot: each keeps its own tip, and the history they extend keeps its length.
func TestExtensionsOfOneHistoryNeverShareTheirNewSlot(t *testing.T) {
	base := &History{entries: make([]Entry, 1, 64), tail: new(atomic.Bool)}
	base.entries[0] = Entry{epoch: 1}
	const n = 32
	out := make([]*History, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = base.extend(Entry{epoch: 2, start: uint64(100 + i)})
		}()
	}
	wg.Wait()
	for i, h := range out {
		require.Len(t, h.entries, 2)
		require.EqualValues(t, 100+i, h.Tip().Start(), "extension %d keeps its own tip", i)
	}
	require.Len(t, base.entries, 1)

	plain := &History{entries: make([]Entry, 1, 8), tail: new(atomic.Bool)}
	plain.entries[0] = Entry{epoch: 1}
	utb := plain.WithUTBGenesis()
	a, b := plain.extend(Entry{epoch: 2, start: 7}), utb.extend(Entry{epoch: 2, start: 9})
	require.EqualValues(t, 7, a.Tip().Start())
	require.EqualValues(t, 9, b.Tip().Start())
	require.True(t, b.UTB())

	// a history without a tail (one built outside NewHistory) is always copied to extend
	loose := &History{entries: make([]Entry, 1, 8)}
	x, y := loose.extend(Entry{epoch: 2, start: 1}), loose.extend(Entry{epoch: 2, start: 2})
	require.EqualValues(t, 1, x.Tip().Start())
	require.EqualValues(t, 2, y.Tip().Start())
}
