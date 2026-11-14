package archivewiring

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
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
// and one from the request to the first byte of its answer. Bandwidth is not limited.
type latencyHost struct {
	shardnode.EvidenceHost
	rtt time.Duration
}

func (h latencyHost) CreateStream(ctx context.Context, id peer.ID, protocolID string) (libp2pnetwork.Stream, error) {
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
	server.Register(context.Background(), host)
	first := f.entries[0].Candidate
	return &latencyFixture{f: f, sender: sender, replica: host.ID(),
		genesis: shardnode.BlockRef{Number: first.ParentNumber, Hash: first.ParentHash, StateRoot: first.ParentState}}
}

func (l *latencyFixture) source(t *testing.T, rtt time.Duration) *RecoverySource {
	t.Helper()
	gated, err := NewPeerGatedHost(latencyHost{EvidenceHost: l.sender, rtt: rtt}, DefaultLimits().PerPeer)
	require.NoError(t, err)
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	return &RecoverySource{Context: l.f.context, Subject: l.f.subject, Local: local, Host: gated, Replicas: []peer.ID{l.replica},
		Limits: DefaultLimits(), MaxBlocks: 64}
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

// TestArchiveCatchUpThroughputUnderLatency is bft-core#1066: a late joiner walked the archive one record per exchange, so at 50 ms RTT its
// catch-up was round-trip bound, and a walk whose time budget ran out mid-read reported a failure instead of its progress. With the chain
// read the walk takes one exchange per MaxChainRecords blocks: the rate at 50 ms stays close to the loopback rate, and no walk fails.
func TestArchiveCatchUpThroughputUnderLatency(t *testing.T) {
	const blocks = 192
	l := newLatencyFixture(t, blocks)
	rates := map[time.Duration]float64{}
	for _, rtt := range []time.Duration{0, 50 * time.Millisecond} {
		source := l.source(t, rtt)
		// a short walk budget (production: a third of the recovery call) so that budgets run out mid-read
		rate, errs := l.catchUp(t, source, 700*time.Millisecond, 60*time.Second)
		rates[rtt] = rate
		t.Logf("rtt %s: %d blocks caught up at %.1f blocks/s, %d walk errors", rtt, blocks, rate, len(errs))
		require.Empty(t, errs, "a spent walk budget is progress, not a failure (rtt %s)", rtt)
	}
	// one exchange per record costs two round trips (stream set-up, request): at most 10 blocks/s at 50 ms whatever the machine
	serialBound := 1 / (2 * 0.050)
	require.GreaterOrEqual(t, rates[50*time.Millisecond], 3*serialBound, "at 50 ms RTT the catch-up is not round-trip bound")
	require.GreaterOrEqual(t, rates[50*time.Millisecond], rates[0]/2, "50 ms RTT costs at most half the loopback rate")
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
		if err := server.serveFrame(context.Background(), stream, frame); err != nil {
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
