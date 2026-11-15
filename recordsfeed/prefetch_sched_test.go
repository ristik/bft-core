package recordsfeed

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootrecords"
)

// peerFake is a RoleRemote stand-in: the mirrors it would ask, each with its own latency and health, and the requests each has in flight
// (speculative and foreground alike), so a test sees what a server's per-peer admission would see.
type peerFake struct {
	cut     Cut
	records []rootrecords.Record
	peers   []peer.ID
	rtt     map[peer.ID]time.Duration
	failing map[peer.ID]bool

	mu        sync.Mutex
	inFlight  map[peer.ID]int
	peak      map[peer.ID]int
	total     int
	peakTotal int
	served    map[peer.ID]int
}

func newPeerFake(cut Cut, records []rootrecords.Record, rtt time.Duration, n int) *peerFake {
	f := &peerFake{cut: cut, records: records, rtt: map[peer.ID]time.Duration{}, failing: map[peer.ID]bool{},
		inFlight: map[peer.ID]int{}, peak: map[peer.ID]int{}, served: map[peer.ID]int{}}
	for i := range n {
		id := peer.ID(fmt.Sprintf("mirror-%d", i))
		f.peers = append(f.peers, id)
		f.rtt[id] = rtt
	}
	return f
}

func (f *peerFake) Peers() []peer.ID { return f.peers }

func (f *peerFake) CutFrom(ctx context.Context, id peer.ID, key CutKey) (Cut, error) {
	f.mu.Lock()
	f.inFlight[id]++
	f.total++
	f.peak[id] = max(f.peak[id], f.inFlight[id])
	f.peakTotal = max(f.peakTotal, f.total)
	rtt, failing := f.rtt[id], f.failing[id]
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inFlight[id]--
		f.total--
		f.mu.Unlock()
	}()
	select {
	case <-time.After(rtt):
	case <-ctx.Done():
		return Cut{}, ctx.Err()
	}
	if failing {
		return Cut{}, errors.New("stream reset")
	}
	f.mu.Lock()
	f.served[id]++
	f.mu.Unlock()
	return f.cut, nil
}

// Cut is the foreground path: the peers in order, as P2PRemote asks them.
func (f *peerFake) Cut(ctx context.Context, key CutKey) (Cut, error) {
	for _, id := range f.peers {
		if cut, err := f.CutFrom(ctx, id, key); err == nil {
			return cut, nil
		}
	}
	return Cut{}, ErrUnavailable
}

func (f *peerFake) Records(_ context.Context, from uint64, max int) ([]rootrecords.Record, error) {
	end := min(from+uint64(max), uint64(len(f.records)))
	if from >= end {
		return nil, nil
	}
	return append([]rootrecords.Record(nil), f.records[from:end]...), nil
}

func (f *peerFake) peaks() (map[peer.ID]int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[peer.ID]int{}
	for k, v := range f.peak {
		out[k] = v
	}
	return out, f.peakTotal
}

// disabledRoots is a joiner's root remote: it names no peer for a non-active node.
type disabledRoots struct{ *peerFake }

func (*disabledRoots) Peers() []peer.ID { return nil }

func waitIdle(t *testing.T, src *Source) {
	t.Helper()
	require.Eventually(t, func() bool {
		st := src.prefetch.stats()
		return st.queued == 0 && st.running == 0
	}, 10*time.Second, 5*time.Millisecond)
}

// One scheduler bounds a Source's prefetches in all and per peer, on every fallback: overlapping batches, a joiner's root remotes that
// name no peer (listed first), one mirror that fails everything, uneven latency, and a foreground Cursor at the same time. Each mirror
// keeps half its stream slots for the foreground requests, and every cut is still had.
func TestPrefetchIsBoundedSourceWideAndPerPeer(t *testing.T) {
	c := buildChain(t, 3)
	cut, obs, keys := origins(t, c, 96)
	mirrors := newPeerFake(cut, c.records, 20*time.Millisecond, 4)
	mirrors.failing[mirrors.peers[0]] = true               // the first mirror resets every stream
	mirrors.rtt[mirrors.peers[3]] = 120 * time.Millisecond // and one is slow
	roots := &disabledRoots{peerFake: newPeerFake(cut, c.records, 0, 0)}
	src := NewSource(roots, roots, mirrors)

	endA := src.Prefetch(context.Background(), keys[:48])
	endB := src.Prefetch(context.Background(), keys[24:90]) // overlapping: shares 24 keys with the first batch
	defer endA()
	defer endB()
	// a foreground cursor for a key nobody prefetched, while the batches run
	_, err := src.Cursor(context.Background(), obs[95])
	require.NoError(t, err)
	waitIdle(t, src)
	for i, o := range obs {
		_, err := src.Cursor(context.Background(), o)
		require.NoError(t, err, "origin %d", i)
	}
	peaks, total := mirrors.peaks()
	t.Logf("peak in flight %d, per mirror %v, served %v", total, peaks, mirrors.served)
	for id, n := range peaks {
		require.LessOrEqual(t, n, prefetchPerPeer+1, "mirror %s: speculative requests plus the one foreground request", id)
	}
	require.LessOrEqual(t, total, prefetchStreams+1, "Source-wide bound, plus the foreground request")
	require.Zero(t, mirrors.served[mirrors.peers[0]], "the failing mirror served nothing")
	require.Positive(t, mirrors.served[mirrors.peers[3]], "the slow mirror took a share")
}

// A batch that ends (its suffix refused, or abandoned) leaves nothing behind: what it fetched and nothing used is dropped, at once on
// release and when its context ends after the fetches completed, but not the keys a newer batch asked for too.
func TestAnEndedBatchLeavesNoSpeculativeEntries(t *testing.T) {
	c := buildChain(t, 3)
	cut, _, keys := origins(t, c, 16)
	src := NewSource(newPeerFake(cut, c.records, 0, 3))

	// a refused page: released after its fetches completed, none used
	end := src.Prefetch(context.Background(), keys[:8])
	waitIdle(t, src)
	require.Equal(t, 8, src.prefetch.stats().entries)
	end()
	require.Equal(t, prefetchStats{}, src.prefetch.stats(), "dropped with its batch, bytes too")

	// an abandoned call: its context ends after the fetches completed
	ctx, cancel := context.WithCancel(context.Background())
	src.Prefetch(ctx, keys[:8])
	waitIdle(t, src)
	cancel()
	require.Eventually(t, func() bool { return src.prefetch.stats() == prefetchStats{} }, 5*time.Second, 5*time.Millisecond)

	// ownership: a key a newer batch asked for too survives the older batch's end
	older := src.Prefetch(context.Background(), keys[:8])
	newer := src.Prefetch(context.Background(), keys[4:12])
	waitIdle(t, src)
	older()
	require.Equal(t, 8, src.prefetch.stats().entries, "keys 4..11 belong to the newer batch")
	newer()
	require.Zero(t, src.prefetch.stats().entries)
}

// Locators are unauthenticated: a peer can name keys that are fetched and never used. Completed, unused entries are evicted for new
// keys (and expire), so prefetching keeps working without anyone asking for the abandoned keys.
func TestPrefetchCapacityRecoversWithoutUsingTheAbandonedKeys(t *testing.T) {
	c := buildChain(t, 3)
	cut, obs, keys := origins(t, c, maxPrefetched+8)
	mirrors := newPeerFake(cut, c.records, 0, 3)
	src := NewSource(mirrors)
	now := time.Unix(1000, 0)
	var clock sync.Mutex
	src.prefetch.now = func() time.Time { clock.Lock(); defer clock.Unlock(); return now }

	src.Prefetch(context.Background(), keys[:maxPrefetched]) // never ended, never used
	waitIdle(t, src)
	require.Equal(t, maxPrefetched, src.prefetch.stats().entries)

	fresh := keys[maxPrefetched:]
	src.Prefetch(context.Background(), fresh)
	waitIdle(t, src)
	require.Equal(t, maxPrefetched, src.prefetch.stats().entries, "full, by eviction of the oldest unused entries")
	for i, o := range obs[maxPrefetched:] {
		took, ok := src.prefetch.take(context.Background(), fresh[i])
		require.True(t, ok, "the new key %d was prefetched", i)
		_, _, err := VerifyCut(took, o)
		require.NoError(t, err)
	}

	clock.Lock()
	now = now.Add(prefetchTTL + time.Second)
	clock.Unlock()
	src.Prefetch(context.Background(), nil)
	src.Prefetch(context.Background(), keys[:1]) // any call sweeps what expired
	waitIdle(t, src)
	require.Equal(t, 1, src.prefetch.stats().entries, "expired entries are gone")
}
