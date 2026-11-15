package recordsfeed

import (
	"context"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

// slowRemote is a mirror over a WAN link: every cut costs one round trip (one exchange on its own stream), and it counts the cuts it
// served and the most it served at once. forge, when set, answers a cut with another one (a mirror that substitutes).
type slowRemote struct {
	cut      Cut
	records  []rootrecords.Record
	rtt      time.Duration
	cuts     atomic.Int64
	inFlight atomic.Int64
	peak     atomic.Int64
	forge    func(CutKey) (Cut, bool)
}

func (r *slowRemote) Cut(ctx context.Context, key CutKey) (Cut, error) {
	r.cuts.Add(1)
	n := r.inFlight.Add(1)
	defer r.inFlight.Add(-1)
	for {
		peak := r.peak.Load()
		if n <= peak || r.peak.CompareAndSwap(peak, n) {
			break
		}
	}
	select {
	case <-time.After(r.rtt):
	case <-ctx.Done():
		return Cut{}, ctx.Err()
	}
	if r.forge != nil {
		if cut, ok := r.forge(key); ok {
			return cut, nil
		}
	}
	return r.cut, nil
}

func (r *slowRemote) Records(_ context.Context, from uint64, max int) ([]rootrecords.Record, error) {
	end := min(from+uint64(max), uint64(len(r.records)))
	if from >= end {
		return nil, nil
	}
	return append([]rootrecords.Record(nil), r.records[from:end]...), nil
}

// origins are n consecutive committed root blocks of one log, one per shard block as a catch-up meets them.
func origins(t *testing.T, c chain, n int) (Cut, []evmroot.RootOriginV2, []CutKey) {
	t.Helper()
	var cut Cut
	var out []evmroot.RootOriginV2
	var keys []CutKey
	for i := range n {
		var o evmroot.RootOriginV2
		cut, o = c.cutOf(t, uint64(200+i), uint64(9_000+i))
		key, err := KeyOf(o)
		require.NoError(t, err)
		out, keys = append(out, o), append(keys, key)
	}
	return cut, out, keys
}

// TestEachOriginsCutIsFetchedOnce is bft-core#1071 in the records feed: a block's derivation asks for its origin's cursor twice, and each
// ask was a round trip to a mirror (at 50 ms RTT about 200 ms per block of a staging catch-up). A cut the source verified is now
// verified again against the origin and used without a remote.
func TestEachOriginsCutIsFetchedOnce(t *testing.T) {
	c := buildChain(t, 3)
	cut, obs, _ := origins(t, c, 8)
	remote := &slowRemote{cut: cut, records: c.records}
	src := NewSource(remote)
	for _, o := range obs {
		first, err := src.Cursor(context.Background(), o)
		require.NoError(t, err)
		second, err := src.Cursor(context.Background(), o)
		require.NoError(t, err)
		require.Equal(t, first, second)
	}
	require.EqualValues(t, len(obs), remote.cuts.Load(), "one fetch per origin, not per derivation")

	// a cached cut still answers only the origin it authenticates
	other := obs[0]
	other.UnicityTreeRoot = make([]byte, 32)
	_, err := src.Cursor(context.Background(), other)
	require.ErrorIs(t, err, ErrAuth, "another tree root under the same round is another key, and the remote's cut does not lead to it")
}

// Prefetched cuts arrive several at a time, so a page of blocks verified one by one waits about one round trip per prefetchStreams
// blocks, and a mirror is never asked for more than prefetchStreams cuts at once.
func TestPrefetchedCutsSpareARoundTripPerBlock(t *testing.T) {
	const n, rtt = 64, 50 * time.Millisecond
	c := buildChain(t, 3)
	cut, obs, keys := origins(t, c, n)
	remote := &slowRemote{cut: cut, records: c.records, rtt: rtt}
	src := NewSource(remote)
	started := time.Now()
	src.Prefetch(context.Background(), keys)
	for _, o := range obs {
		for range 2 { // as a derivation does
			_, err := src.Cursor(context.Background(), o)
			require.NoError(t, err)
		}
	}
	took := time.Since(started)
	t.Logf("%d origins at %s RTT in %s, %d cut fetches, at most %d at once", n, rtt, took, remote.cuts.Load(), remote.peak.Load())
	require.EqualValues(t, n, remote.cuts.Load(), "each cut fetched once")
	require.LessOrEqual(t, remote.peak.Load(), int64(prefetchStreams), "bounded fetches in flight")
	require.Less(t, took, time.Duration(n)*rtt/2, "one round trip per block was %s", time.Duration(n)*rtt)
	src.mu.Lock()
	require.Empty(t, src.prefetched, "every prefetched cut was used once and retained as verified")
	src.mu.Unlock()
}

// A prefetched cut is a locator, never evidence: a mirror that substitutes one is not believed, the cursor is asked again of the remotes,
// and the forged cut is neither used nor mirrored.
func TestAForgedPrefetchedCutIsRefusedAndAskedAgain(t *testing.T) {
	c := buildChain(t, 3)
	cut, obs, keys := origins(t, c, 4)
	other := buildChain(t, 7)
	forged, _ := other.cutOf(t, 999, 1)
	forged.Control.Network++ // a valid-looking cut of another network and tree
	var mu sync.Mutex
	forgedOnce := map[CutKey]bool{}
	remote := &slowRemote{cut: cut, records: c.records, forge: func(key CutKey) (Cut, bool) {
		mu.Lock()
		defer mu.Unlock()
		if forgedOnce[key] {
			return Cut{}, false
		}
		forgedOnce[key] = true // the prefetch gets the forgery, the cursor's own fetch the honest cut
		return forged, true
	}}
	src := NewSource(remote)
	src.Prefetch(context.Background(), keys)
	for i, o := range obs {
		cursor, err := src.Cursor(context.Background(), o)
		require.NoError(t, err, "origin %d", i)
		require.EqualValues(t, len(c.records), cursor.TargetCount)
		served, err := src.ControlCut(keys[i])
		require.NoError(t, err)
		require.Equal(t, cut, served, "only the verified cut is mirrored")
	}
	require.EqualValues(t, 2*len(obs), remote.cuts.Load(), "the forgery, then the honest cut")
}

// A prefetch that is canceled, or that no remote can serve, leaves nothing behind: the cursor asks the remotes at once.
func TestAFailedPrefetchLeavesTheCursorToTheRemotes(t *testing.T) {
	c := buildChain(t, 3)
	cut, obs, keys := origins(t, c, 4)
	remote := &slowRemote{cut: cut, records: c.records, rtt: time.Hour}
	src := NewSource(remote)
	ctx, cancel := context.WithCancel(context.Background())
	src.Prefetch(ctx, keys)
	cancel()
	require.Eventually(t, func() bool {
		src.mu.Lock()
		defer src.mu.Unlock()
		return len(src.prefetched) == 0
	}, 5*time.Second, 10*time.Millisecond, "canceled prefetches are dropped")
	remote.rtt = 0
	_, err := src.Cursor(context.Background(), obs[0])
	require.NoError(t, err)
}

// TestCursorRateProfile measures the root-record cursor a catch-up derives per block (two asks per block) at 0 and 50 ms RTT: two cut
// fetches per block (before bft-core#1071), the verified-cut reuse alone, and with the page's cuts prefetched. CURSOR_PROFILE_BLOCKS
// selects the number of blocks (unset: skipped).
func TestCursorRateProfile(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("CURSOR_PROFILE_BLOCKS"))
	if n == 0 {
		t.Skip("set CURSOR_PROFILE_BLOCKS")
	}
	c := buildChain(t, 3)
	cut, obs, keys := origins(t, c, n)
	for _, rtt := range []time.Duration{0, 50 * time.Millisecond} {
		remote := &slowRemote{cut: cut, records: c.records, rtt: rtt}
		started := time.Now()
		for _, o := range obs {
			for range 2 {
				key, _ := KeyOf(o)
				got, err := remote.Cut(context.Background(), key)
				require.NoError(t, err)
				_, _, err = VerifyCut(got, o)
				require.NoError(t, err)
			}
		}
		t.Logf("rtt %-5s two fetches per block   %7.1f blocks/s", rtt, float64(n)/time.Since(started).Seconds())
		for _, prefetch := range []bool{false, true} {
			src := NewSource(&slowRemote{cut: cut, records: c.records, rtt: rtt})
			started := time.Now()
			for page := 0; page < n; page += 64 {
				if prefetch {
					src.Prefetch(context.Background(), keys[page:min(page+64, n)])
				}
				for _, o := range obs[page:min(page+64, n)] {
					for range 2 {
						_, err := src.Cursor(context.Background(), o)
						require.NoError(t, err)
					}
				}
			}
			t.Logf("rtt %-5s reuse, prefetch %-5v %7.1f blocks/s", rtt, prefetch, float64(n)/time.Since(started).Seconds())
		}
	}
}
