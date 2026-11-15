package archivewiring

import (
	"context"
	"os"
	"sort"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/frontier"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// readBackFixture is a node whose journal holds n certified blocks, all executed and retained locally, and three archive replicas that
// hold every one of them, reached over libp2p through the production client path (the per-peer stream gate) with a WAN delay. public
// serves the node under the replicas' public read budget (a late joiner, not an active validator) instead of as an authorized peer;
// the replica with index lacking (when one of 0..2) holds nothing.
type readBackFixture struct {
	f         *wiringFixture
	host      *PeerGatedHost
	exchanges *atomic.Int64
	replicas  []peer.ID
	stores    []*archive.Store
	local     *archive.Store
	top       shardnode.BlockRef
}

func newReadBackFixture(t *testing.T, n int, rtt time.Duration, public bool, lacking int) *readBackFixture {
	t.Helper()
	f := newWiringFixtureWithLimits(t, n, configuredprogress.JournalLimits{Candidates: n + 16, Observations: 2*n + 32, Bytes: 128 << 20})
	sort.Slice(f.entries, func(i, j int) bool { return f.entries[i].Candidate.Number < f.entries[j].Candidate.Number })
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	x := &readBackFixture{f: f, local: local, exchanges: new(atomic.Int64)}
	authorized := []peer.ID{sender.ID()}
	if public {
		authorized = []peer.ID{"validator"}
	}
	for range 3 {
		remote := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
		store, err := archive.Open(t.TempDir())
		require.NoError(t, err)
		sender.Network().Peerstore().AddAddrs(remote.ID(), remote.MultiAddresses(), peerstore.PermanentAddrTTL)
		server, err := NewServer(store, f.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, authorized, DefaultLimits())
		require.NoError(t, err)
		if public {
			// the production public budget (shard_node_run: --archive-public-reads)
			require.NoError(t, server.SetPublicReads(Limits{Deadline: DefaultLimits().Deadline, Pending: 4, PerPeer: 2}))
		}
		server.Register(context.Background(), remote)
		x.replicas, x.stores = append(x.replicas, remote.ID()), append(x.stores, store)
	}
	for i, e := range f.entries {
		q, rec := f.record(t, i)
		require.NoError(t, local.Put(q, rec))
		for j, s := range x.stores {
			if j != lacking {
				require.NoError(t, s.Put(q, rec))
			}
		}
		x.top = shardnode.BlockRef{Number: e.Candidate.Number, Hash: e.Candidate.Hash, StateRoot: e.Candidate.StateRoot}
	}
	x.host, err = NewPeerGatedHost(latencyHost{EvidenceHost: sender, rtt: rtt, exchanges: x.exchanges}, DefaultLimits().PerPeer)
	require.NoError(t, err)
	return x
}

// worker enables the derived frontier policy over the three replicas and returns its worker; cache is what both share (nil: every block is
// read back singly, as before bft-core#1071).
func (x *readBackFixture) worker(t *testing.T, cache *ReadBackCache) *FrontierWorker {
	t.Helper()
	policy := frontier.Policy{Context: x.f.subject, Eligible: names(x.replicas), PolicyDigest: testPolicyDigest, Binding: CertifiedBinding{Context: x.f.context, Subject: x.f.subject},
		Availability: ReplicaAvailability{Context: context.Background(), Host: x.host, Replicas: x.replicas, Limits: DefaultLimits(), ReadBacks: cache}}
	require.NoError(t, x.f.store.EnableFrontier(context.Background(), x.f.context, x.f.limits, policy))
	return &FrontierWorker{Journal: x.f.store, Context: x.f.context, Limits: x.f.limits, Archive: x.local, Subject: x.f.subject, Replicas: x.replicas,
		PolicyDigest: testPolicyDigest, Host: x.host, TransportLimits: DefaultLimits(), ReadBacks: cache,
		Finalized: func(context.Context) (shardnode.BlockRef, error) { return x.top, nil }}
}

// cover advances the frontier as a long catch-up does (Advance of a page at a time) until it reaches the top, and returns blocks per second.
func (x *readBackFixture) cover(t *testing.T, w *FrontierWorker, page int) float64 {
	t.Helper()
	started := time.Now()
	for calls := 0; anchorHeight(t, x.f) < x.top.Number; calls++ {
		require.Less(t, calls, 4*int(x.top.Number), "the frontier does not advance")
		require.NoError(t, w.Advance(context.Background(), page))
	}
	return float64(x.top.Number) / time.Since(started).Seconds()
}

// TestFrontierAdvanceReadsBackInChainReads is bft-core#1071 at the frontier: a late joiner's catch-up runs at most a journal ahead of its
// frontier, and the frontier read every block back singly from each acknowledging replica twice (the worker's choice of holders, then
// the journal's plan): at 50 ms RTT about 4 blocks/s, which held the staging joiner at 2 blocks/s in 40 s stalls after every few pages.
// An advance now reads its run back in chain reads: a constant number of exchanges per page and replica, asserted exactly enough to
// catch a return to single reads, and the page's time at 50 ms RTT bounded well below one block per round trip.
func TestFrontierAdvanceReadsBackInChainReads(t *testing.T) {
	t.Parallel()
	const blocks, page = 2 * MaxChainRecords, MaxChainRecords
	x := newReadBackFixture(t, blocks, 50*time.Millisecond, true, -1)
	cache := new(ReadBackCache)
	w := x.worker(t, cache)
	started := time.Now()
	x.cover(t, w, page)
	took := time.Since(started)
	advances := blocks / page
	// per advance: one chain read from each of the two acknowledging replicas, and the journal's check of the anchor's two copies
	require.LessOrEqual(t, x.exchanges.Load(), int64(advances*(2+2)), "chain reads, not one exchange per block and replica")
	t.Logf("%d blocks covered at 50 ms RTT in %s, %d exchanges", blocks, took, x.exchanges.Load())
	require.Less(t, took, 5*time.Second, "single reads took four exchanges per block: over 50 s")
	cache.mu.Lock()
	require.Empty(t, cache.seen, "an advance's read-backs do not outlive it")
	cache.mu.Unlock()
}

// A read-back is a verdict only for exactly what was read: another representation, another replica, a stale entry or a cleared cache is
// read singly again, and a replica that lost the copy after the advance is not covered by an old read-back.
func TestReadBackCacheStandsOnlyForWhatWasRead(t *testing.T) {
	t.Parallel()
	subject := newWiringFixture(t, 1).subject
	q := archive.Request{Context: subject, BlockHash: [32]byte{1}}
	now := time.Unix(1000, 0)
	c := &ReadBackCache{now: func() time.Time { return now }}
	var nilCache *ReadBackCache
	require.False(t, nilCache.holds("a", q, [32]byte{9}), "a nil cache holds nothing")
	nilCache.note("a", q, [32]byte{9})
	c.note("a", q, [32]byte{9})
	require.True(t, c.holds("a", q, [32]byte{9}))
	require.False(t, c.holds("a", q, [32]byte{8}), "another manifest")
	require.False(t, c.holds("b", q, [32]byte{9}), "another replica")
	require.False(t, c.holds("a", archive.Request{Context: subject, BlockHash: [32]byte{2}}, [32]byte{9}), "another block")
	now = now.Add(readBackFresh + time.Second)
	require.False(t, c.holds("a", q, [32]byte{9}), "too old")
	c.note("a", q, [32]byte{9})
	c.clear()
	require.False(t, c.holds("a", q, [32]byte{9}), "cleared with its advance")
}

// A replica that serves another chain, or none, under the chain read does not acknowledge anything: the single read decides, and the
// frontier still names only replicas that hold the copy.
func TestFrontierReadBackFallsBackToSingleReadsForAReplicaWithoutTheCopy(t *testing.T) {
	t.Parallel()
	const blocks = 12
	// the first replica holds nothing: the chain read finds nothing there, the single reads find nothing either, the third replica is asked
	x := newReadBackFixture(t, blocks, 0, false, 0)
	w := x.worker(t, new(ReadBackCache))
	x.cover(t, w, blocks)
	snap, err := x.f.store.LoadFrontier(context.Background(), x.f.context, x.f.limits)
	require.NoError(t, err)
	got := []string{snap.Anchor.Acks[0].Replica, snap.Anchor.Acks[1].Replica}
	require.ElementsMatch(t, []string{x.replicas[1].String(), x.replicas[2].String()}, got, "acknowledged by the replicas that hold the copy")
}

// TestFrontierAdvanceRateProfile measures how fast the frontier covers a catch-up's pages at 0 and 50 ms RTT under the production limits
// and public read budget, with every block read back singly (before bft-core#1071) and in chain reads. FRONTIER_PROFILE_BLOCKS selects the
// chain length (unset: skipped).
func TestFrontierAdvanceRateProfile(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("FRONTIER_PROFILE_BLOCKS"))
	if n == 0 {
		t.Skip("set FRONTIER_PROFILE_BLOCKS")
	}
	for _, rtt := range []time.Duration{0, 50 * time.Millisecond} {
		for _, batched := range []bool{false, true} {
			x := newReadBackFixture(t, n, rtt, true, -1)
			var cache *ReadBackCache
			if batched {
				cache = new(ReadBackCache)
			}
			rate := x.cover(t, x.worker(t, cache), 64)
			t.Logf("rtt %-5s chain reads %-5v %d blocks at %7.1f blocks/s, %d exchanges", rtt, batched, n, rate, x.exchanges.Load())
		}
	}
}
