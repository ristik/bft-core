package archivewiring

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// latencyHost delays a client's archive exchanges in process, as a WAN link would: one round trip to open a stream (protocol negotiation)
// and one from the request to the first byte of its answer. Bandwidth is not limited. exchanges counts the archive streams opened.
type latencyHost struct {
	shardnode.EvidenceHost
	rtt       time.Duration
	exchanges *atomic.Int64
}

func (h latencyHost) CreateStream(ctx context.Context, id peer.ID, protocolID string) (libp2pnetwork.Stream, error) {
	if protocolID == ProtocolArchive && h.exchanges != nil {
		h.exchanges.Add(1)
	}
	if err := sleepCtx(ctx, h.rtt); err != nil {
		return nil, err
	}
	s, err := h.EvidenceHost.CreateStream(ctx, id, protocolID)
	if err != nil {
		return nil, err
	}
	return &latencyStream{Stream: s, rtt: h.rtt}, nil
}

type latencyStream struct {
	libp2pnetwork.Stream
	rtt      time.Duration
	mu       sync.Mutex
	written  bool
	deadline time.Time
}

func (s *latencyStream) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.deadline = t
	s.mu.Unlock()
	return s.Stream.SetDeadline(t)
}

func (s *latencyStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	s.written = true
	s.mu.Unlock()
	return s.Stream.Write(p)
}

func (s *latencyStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	wait, deadline := s.written, s.deadline
	s.written = false
	s.mu.Unlock()
	if wait && s.rtt > 0 {
		if !deadline.IsZero() && time.Until(deadline) < s.rtt {
			// the answer would arrive after the stream's deadline, as on a real link
			time.Sleep(time.Until(deadline))
			return 0, os.ErrDeadlineExceeded
		}
		time.Sleep(s.rtt)
	}
	return s.Stream.Read(p)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// latencyFixture is a late joiner's state: a certified chain of n blocks on one archive replica that serves this node only under the public
// read budget (it is not an active validator), an empty local archive, and the production client path (the per-peer stream gate).
type latencyFixture struct {
	f       *wiringFixture
	sender  *network.Peer
	replica peer.ID
	genesis shardnode.BlockRef
}

func newLatencyFixture(t *testing.T, n int) *latencyFixture {
	return newLatencyFixtureBudget(t, n, nil)
}

// newLatencyFixtureBudget serves under budget instead of DefaultPublicBudget when it is set.
func newLatencyFixtureBudget(t *testing.T, n int, budget *PublicBudget) *latencyFixture {
	t.Helper()
	f := newWiringFixtureWithLimits(t, n, configuredprogress.JournalLimits{Candidates: n + 16, Observations: 2*n + 32, Bytes: 128 << 20})
	sort.Slice(f.entries, func(i, j int) bool { return f.entries[i].Candidate.Number < f.entries[j].Candidate.Number })
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	host := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	sender.Network().Peerstore().AddAddrs(host.ID(), host.MultiAddresses(), peerstore.PermanentAddrTTL)
	store, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	for i := range f.entries {
		q, rec := f.record(t, i)
		require.NoError(t, store.Put(q, rec))
	}
	server, err := NewServer(store, f.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{"validator"}, DefaultLimits())
	require.NoError(t, err)
	// the production public budget (shard_node_run: --archive-public-reads)
	require.NoError(t, server.SetPublicReads(Limits{Deadline: DefaultLimits().Deadline, Pending: 4, PerPeer: 2}))
	if budget != nil {
		require.NoError(t, server.SetPublicBudget(*budget))
	}
	server.Register(context.Background(), host)
	first := f.entries[0].Candidate
	return &latencyFixture{f: f, sender: sender, replica: host.ID(),
		genesis: shardnode.BlockRef{Number: first.ParentNumber, Hash: first.ParentHash, StateRoot: first.ParentState}}
}

func (l *latencyFixture) source(t *testing.T, rtt time.Duration) *RecoverySource {
	source, _ := l.countedSource(t, rtt)
	return source
}

// countedSource is source with the count of its archive exchanges.
func (l *latencyFixture) countedSource(t *testing.T, rtt time.Duration) (*RecoverySource, *atomic.Int64) {
	t.Helper()
	exchanges := new(atomic.Int64)
	gated, err := NewPeerGatedHost(latencyHost{EvidenceHost: l.sender, rtt: rtt, exchanges: exchanges}, DefaultLimits().PerPeer)
	require.NoError(t, err)
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	return &RecoverySource{Context: l.f.context, Subject: l.f.subject, Local: local, Host: gated, Replicas: []peer.ID{l.replica},
		Limits: DefaultLimits(), MaxBlocks: 64}, exchanges
}

// catchUp runs the archive catch-up as the coordinator does: walks bounded by a time budget, resumed until the plan joins the anchor, then
// pages read back from the local archive. It returns the blocks per second over the whole catch-up and every error a walk returned.
func (l *latencyFixture) catchUp(t *testing.T, source *RecoverySource, budget, limit time.Duration) (float64, []error) {
	t.Helper()
	n := len(l.f.entries)
	top := l.f.entries[n-1].Candidate.Hash
	c := &CatchUp{Source: source}
	var errs []error
	started := time.Now()
	for {
		joined, _, err := c.Walk(context.Background(), l.genesis, top, time.Now().Add(budget))
		if err != nil {
			errs = append(errs, err)
		}
		if joined {
			break
		}
		if time.Since(started) > limit {
			t.Logf("the walk did not join within %s", limit)
			return 0, append(errs, errors.New("stalled"))
		}
	}
	from, admitted := l.genesis, 0
	for admitted < n {
		page, _, err := c.Page(context.Background(), from, 64)
		require.NoError(t, err)
		require.NotEmpty(t, page)
		last := page[len(page)-1].Block
		from = shardnode.BlockRef{Number: last.Number, Hash: last.Hash, StateRoot: last.StateRoot}
		admitted += len(page)
	}
	require.True(t, bytes.Equal(l.f.entries[n-1].Candidate.Hash, from.Hash), "the pages reach the top")
	return float64(n) / time.Since(started).Seconds(), errs
}

// TestArchiveCatchUpExchangesUnderLatency is bft-core#1066: a late joiner walked the archive one record per exchange (two round trips each),
// so at 50 ms RTT its catch-up was round-trip bound, and a walk whose time budget ran out mid-read reported a failure instead of its
// progress. With the chain read the walk takes one exchange per MaxChainRecords blocks, which is asserted exactly (the speed itself
// depends on the machine: TestArchiveCatchUpRateProfile measures it), and a walk cut by its budget is not a failure.
func TestArchiveCatchUpExchangesUnderLatency(t *testing.T) {
	const blocks = 3 * MaxChainRecords
	l := newLatencyFixture(t, blocks)

	// one walk with time to spare: exactly one exchange per MaxChainRecords blocks (one per block before the chain read)
	source, exchanges := l.countedSource(t, 50*time.Millisecond)
	_, errs := l.catchUp(t, source, time.Minute, time.Minute)
	require.Empty(t, errs)
	require.EqualValues(t, blocks/MaxChainRecords, exchanges.Load(), "round trips per block: one exchange per chain read of %d records", MaxChainRecords)

	// short walk budgets (production: a third of the recovery call) that run out mid-read: each costs at most the exchange it cut
	source, exchanges = l.countedSource(t, 50*time.Millisecond)
	walks := 0
	top := l.f.entries[blocks-1].Candidate.Hash
	c := &CatchUp{Source: source}
	for joined := false; !joined; walks++ {
		require.Less(t, walks, 200, "the walk stalls")
		var err error
		joined, _, err = c.Walk(context.Background(), l.genesis, top, time.Now().Add(120*time.Millisecond))
		require.NoError(t, err, "a spent walk budget is progress, not a failure")
	}
	t.Logf("%d walks of 120 ms at 50 ms RTT, %d exchanges for %d blocks", walks, exchanges.Load(), blocks)
	require.LessOrEqual(t, exchanges.Load(), int64(blocks/MaxChainRecords+walks))
}

// TestArchiveCatchUpRateProfile measures the catch-up's speed at 0 and 50 ms RTT and where a record's time goes (fetch, verification,
// retention, the page's read-back). CATCHUP_PROFILE_BLOCKS selects the chain length (unset: skipped).
func TestArchiveCatchUpRateProfile(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("CATCHUP_PROFILE_BLOCKS"))
	if n == 0 {
		t.Skip("set CATCHUP_PROFILE_BLOCKS")
	}
	unbounded := PublicBudget{Rate: 1e9, Burst: 1 << 30, GlobalRate: 1e9, GlobalBurst: 1 << 30, ByteRate: 1e12, ByteBurst: 1 << 40,
		GlobalByteRate: 1e12, GlobalByteBurst: 1 << 40, MaxTrackedPeers: 16}
	l := newLatencyFixtureBudget(t, n, &unbounded)
	for _, rtt := range []time.Duration{0, 50 * time.Millisecond} {
		source, exchanges := l.countedSource(t, rtt)
		rate, errs := l.catchUp(t, source, 10*time.Second, 10*time.Minute)
		require.Empty(t, errs)
		t.Logf("rtt %-5s %d blocks at %7.1f blocks/s, %d exchanges", rtt, n, rate, exchanges.Load())
	}
	// the parts, per record
	source := l.source(t, 0)
	ctx := context.Background()
	var qs []archive.Request
	var recs []*archive.Record
	start := time.Now()
	for next := 0; next < n; {
		top := l.f.entries[n-1-next].Candidate.Hash
		chain, err := FetchChain(ctx, source.Host, l.replica, archive.Request{Context: l.f.subject, BlockHash: [32]byte(top)}, [32]byte(l.genesis.Hash), MaxChainRecords, DefaultLimits())
		require.NoError(t, err)
		for _, c := range chain {
			qs, recs = append(qs, c.Request), append(recs, c.Record)
		}
		next += len(chain)
	}
	per := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 / float64(n) }
	t.Logf("  %-28s %7.3f ms per record", "chain fetch (loopback)", per(time.Since(start)))
	start = time.Now()
	for i := range qs {
		_, err := source.decodeEntry(ctx, qs[i], recs[i])
		require.NoError(t, err)
	}
	t.Logf("  %-28s %7.3f ms per record", "verification (decodeEntry)", per(time.Since(start)))
	start = time.Now()
	for i := 0; i < len(qs); i += planPutBatch {
		end := min(i+planPutBatch, len(qs))
		require.NoError(t, source.Local.PutBatch(qs[i:end], recs[i:end]))
	}
	t.Logf("  %-28s %7.3f ms per record", "retention (PutBatch of 16)", per(time.Since(start)))
	start = time.Now()
	for i := range qs {
		rec, err := source.Local.Get(qs[i])
		require.NoError(t, err)
		_, err = source.decodeEntry(ctx, qs[i], rec)
		require.NoError(t, err)
	}
	t.Logf("  %-28s %7.3f ms per record", "page read-back + verification", per(time.Since(start)))
}

// TestFetchSuffixRefusesALongGapInOneExchange: a gap longer than one recovery is refused for its length from the target's certified height,
// not after walking MaxBlocks records one round trip each.
func TestFetchSuffixRefusesALongGapInOneExchange(t *testing.T) {
	l := newLatencyFixture(t, 96)
	source := l.source(t, 50*time.Millisecond)
	source.MaxBlocks = 64
	top := l.f.entries[len(l.f.entries)-1].Candidate.Hash
	started := time.Now()
	_, err := source.FetchSuffix(context.Background(), l.genesis, top)
	took := time.Since(started)
	require.ErrorIs(t, err, ErrArchiveSuffixTooLong)
	require.ErrorIs(t, err, ErrArchiveRecoveryInvalid)
	t.Logf("a 96-block gap refused in %s at 50 ms RTT", took)
	require.Less(t, took, time.Second, "one exchange, not one per block")

	// a gap that fits is fetched whole, in a few exchanges
	short := l.f.entries[39].Candidate.Hash
	started = time.Now()
	entries, err := source.FetchSuffix(context.Background(), l.genesis, short)
	require.NoError(t, err)
	require.Len(t, entries, 40)
	require.True(t, bytes.Equal(l.genesis.StateRoot, entries[0].ParentState))
	t.Logf("a 40-block suffix fetched in %s at 50 ms RTT", time.Since(started))
	require.Less(t, time.Since(started), time.Second)
}

// TestFetchChainStopsAtTheAnchorTheCountAndAGap: the chain read follows parent hashes from the requested block and stops before the
// caller's anchor, after the requested count, and at the first block the replica does not hold.
func TestFetchChainStopsAtTheAnchorTheCountAndAGap(t *testing.T) {
	t.Parallel()
	p := newPlanFixture(t, 12)
	p.serve(t, 1, 5)
	p.serve(t, 8, 12)
	host, id := p.source.Host, p.source.Replicas[0]
	q := func(h int) archive.Request { return archive.Request{Context: p.f.subject, BlockHash: p.hash(h)} }
	hashes := func(c []ChainRecord) (out []int) {
		for _, r := range c {
			for h := 1; h <= 12; h++ {
				if r.Request.BlockHash == p.hash(h) {
					out = append(out, h)
				}
			}
		}
		return out
	}
	got, err := FetchChain(context.Background(), host, id, q(12), [32]byte{}, MaxChainRecords, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, []int{12, 11, 10, 9, 8}, hashes(got), "up to the first block the replica lacks")
	got, err = FetchChain(context.Background(), host, id, q(12), p.hash(9), MaxChainRecords, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, []int{12, 11, 10}, hashes(got), "not past the anchor")
	got, err = FetchChain(context.Background(), host, id, q(12), [32]byte{}, 2, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, []int{12, 11}, hashes(got), "the count")
	got, err = FetchChain(context.Background(), host, id, q(5), [32]byte(p.genesis.Hash), MaxChainRecords, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, []int{5, 4, 3, 2, 1}, hashes(got))
	for i, r := range got {
		_, rec := p.f.record(t, 4-i)
		require.True(t, equalRecord(r.Request, rec, r.Record))
	}
	_, err = FetchChain(context.Background(), host, id, q(7), [32]byte{}, MaxChainRecords, DefaultLimits())
	require.ErrorIs(t, err, ErrReplica, "a block the replica lacks")
	_, err = FetchChain(context.Background(), host, id, q(12), [32]byte{}, MaxChainRecords+1, DefaultLimits())
	require.NoError(t, err, "a larger count is the client's to cap")
}

// TestTheWalkFallsBackToSingleReadsOnAReplicaWithoutTheChainRead: a replica of an earlier build refuses the chain read as an unknown
// operation; the walk then reads it one record at a time and still joins.
func TestTheWalkFallsBackToSingleReadsOnAReplicaWithoutTheChainRead(t *testing.T) {
	t.Parallel()
	p := newPlanFixture(t, 10)
	p.serve(t, 1, 10)
	old := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	sender := p.source.Host.(*network.Peer)
	sender.Network().Peerstore().AddAddrs(old.ID(), old.MultiAddresses(), peerstore.PermanentAddrTTL)
	server, err := NewServer(p.replica, p.f.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{sender.ID()}, DefaultLimits())
	require.NoError(t, err)
	server.ctx = context.Background()
	var chainReads atomic.Int32
	old.RegisterProtocolHandler(ProtocolArchive, func(stream libp2pnetwork.Stream) {
		defer stream.Close()
		frame, err := readFrame(stream, maxArchiveFrameBytes)
		if err != nil {
			_ = stream.Reset()
			return
		}
		if frame[0] == opChain {
			chainReads.Add(1)
			_ = writeFrame(stream, resetFrame(fmt.Errorf("%w: %w", ErrHandler, archive.ErrInvalid))) // what an earlier build answers
			return
		}
		if err := server.serveFrame(context.Background(), stream, frame, nil); err != nil {
			_ = writeFrame(stream, resetFrame(typedHandlerError(err)))
		}
	})
	p.source.Replicas = []peer.ID{old.ID()}
	plan, err := NewArchivePlan(p.genesis, p.hash(10))
	require.NoError(t, err)
	require.NoError(t, p.source.Extend(context.Background(), plan, far()))
	require.True(t, plan.Joined())
	require.Equal(t, 10, plan.Walked())
	require.Positive(t, chainReads.Load(), "the chain read was tried")
}
