package gettrustbase

import (
	"bufio"
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/utbstore"
)

func req(from uint64) *Request {
	return &Request{Version: 1, Network: testNetwork, FromEpoch: from, MaxEntries: 64, MaxBytes: DefaultMaxResponse}
}

func epochs(r *Response) []uint64 {
	var out []uint64
	for _, e := range r.Entries {
		d, _ := types.DecodeRootTrustBaseV2(e)
		out = append(out, d.Epoch)
	}
	return out
}

func newServer(t *testing.T, s Source, cfg Config) *Server {
	srv, err := NewServer(s, cfg)
	require.NoError(t, err)
	return srv
}

func TestRespondClampsAheadRangesAndPages(t *testing.T) {
	es := chain(t, nodes(t, 4), 9) // epochs 1..10
	st := store(t, es, 9)
	srv := newServer(t, st, Config{MaxEntries: 4})
	tip := idOf(t, es[9])

	// the whole history from the genesis, capped at the server's 4 entries, with a cursor
	r := srv.Respond(req(1))
	require.Equal(t, StatusOK, r.Status)
	require.Equal(t, []uint64{1, 2, 3, 4}, epochs(r))
	require.Equal(t, uint64(10), r.EffectiveEnd)
	require.Equal(t, tip[:], r.EndEntryID)
	require.Equal(t, uint64(5), *r.NextEpoch)

	// a client cannot raise the server's cap, only lower it
	q := req(1)
	q.MaxEntries = 1000
	require.Len(t, srv.Respond(q).Entries, 4)
	q.MaxEntries = 2
	require.Equal(t, []uint64{1, 2}, epochs(srv.Respond(q)))

	// a requested end ahead of the tip is clamped, not rejected; the final page has no cursor
	q = req(9)
	q.ToEpoch = u64(500)
	r = srv.Respond(q)
	require.Equal(t, StatusOK, r.Status)
	require.Equal(t, []uint64{9, 10}, epochs(r))
	require.Equal(t, uint64(10), r.EffectiveEnd)
	require.Nil(t, r.NextEpoch)

	// an inner end is honored and names its own EntryID
	q = req(2)
	q.ToEpoch = u64(3)
	r = srv.Respond(q)
	id3 := idOf(t, es[2])
	require.Equal(t, []uint64{2, 3}, epochs(r))
	require.Equal(t, uint64(3), r.EffectiveEnd)
	require.Equal(t, id3[:], r.EndEntryID)
	require.Nil(t, r.NextEpoch)

	// from ahead of the tip: nothing, no fabricated entries
	r = srv.Respond(req(11))
	require.Equal(t, StatusNotYetAvailable, r.Status)
	require.Empty(t, r.Entries)
	require.Equal(t, uint64(10), r.EffectiveEnd)
}

func TestRespondRefusesInvalidRequestsAndBudgets(t *testing.T) {
	es := chain(t, nodes(t, 4), 3)
	srv := newServer(t, store(t, es, 3), Config{})
	id := idOf(t, es[3])
	cases := map[string]func(*Request){
		"from below the genesis": func(r *Request) { r.FromEpoch = 0 },
		"to below from":          func(r *Request) { r.FromEpoch = 3; r.ToEpoch = u64(2) },
		"zero entries":           func(r *Request) { r.MaxEntries = 0 },
		"zero bytes":             func(r *Request) { r.MaxBytes = 0 },
		"version":                func(r *Request) { r.Version = 9 },
		"snapshot id alone":      func(r *Request) { r.SnapshotEntryID = id[:] },
		"snapshot end alone":     func(r *Request) { r.SnapshotEnd = u64(3) },
		"from past the snapshot": func(r *Request) { r.FromEpoch = 4; r.SnapshotEnd = u64(3); r.SnapshotEntryID = id[:] },
		"to below the snapshot":  func(r *Request) { r.ToEpoch = u64(2); r.SnapshotEnd = u64(3); r.SnapshotEntryID = id[:] },
	}
	for name, m := range cases {
		q := req(1)
		m(q)
		require.Equal(t, StatusInvalidRequest, srv.Respond(q).Status, name)
	}
	q := req(1)
	q.Network = 99
	require.Equal(t, StatusWrongNetwork, srv.Respond(q).Status)

	// a budget that cannot carry one entry is LimitTooSmall, never an empty page with a cursor
	es1 := raw(t, es)
	q = req(2)
	q.MaxBytes = uint32(envelopeBound + len(es1[1]) - 1)
	r := srv.Respond(q)
	require.Equal(t, StatusLimitTooSmall, r.Status)
	require.Nil(t, r.NextEpoch)
	q.MaxBytes = 10 // below the envelope itself
	require.Equal(t, StatusLimitTooSmall, srv.Respond(q).Status)
	// exactly enough for one entry: progress, one at a time
	q.MaxBytes = uint32(envelopeBound + len(es1[1]))
	r = srv.Respond(q)
	require.Equal(t, StatusOK, r.Status)
	require.Len(t, r.Entries, 1)
	require.NotNil(t, r.NextEpoch)
}

func TestSnapshotFreezesPaginationWhileTheTipMoves(t *testing.T) {
	es := chain(t, nodes(t, 4), 9)
	st := store(t, es, 5) // tip 6
	srv := newServer(t, st, Config{MaxEntries: 3})
	first := srv.Respond(req(1))
	require.Equal(t, uint64(6), first.EffectiveEnd)
	snapID := first.EndEntryID

	// the history grows between pages; the snapshot still ends at 6
	for _, b := range raw(t, es)[6:] {
		_, err := st.Append(b)
		require.NoError(t, err)
	}
	q := req(*first.NextEpoch)
	q.SnapshotEnd, q.SnapshotEntryID = u64(6), snapID
	second := srv.Respond(q)
	require.Equal(t, StatusOK, second.Status)
	require.Equal(t, []uint64{4, 5, 6}, epochs(second))
	require.Equal(t, uint64(6), second.EffectiveEnd)
	require.Nil(t, second.NextEpoch)
	// a fresh request now sees the new tip
	require.Equal(t, uint64(10), srv.Respond(req(1)).EffectiveEnd)

	// another server that is behind the snapshot says so; one on another history refuses it
	behind := newServer(t, store(t, es, 3), Config{})
	q = req(5)
	q.SnapshotEnd, q.SnapshotEntryID = u64(6), snapID
	require.Equal(t, StatusNotYetAvailable, behind.Respond(q).Status)
	q.SnapshotEntryID = es1Wrong()
	require.Equal(t, StatusHistoryMismatch, srv.Respond(q).Status)
}

func es1Wrong() []byte { return append(make([]byte, 31), 1) }

// holey serves a store whose finalized history has a hole.
type holey struct {
	Source
	hole uint64
}

func (h holey) Range(from, to uint64, maxEntries, maxBytes int) ([][]byte, uint64, bool, error) {
	if from <= h.hole && h.hole <= to {
		return nil, 0, false, utbstore.ErrNotFound
	}
	return h.Source.Range(from, to, maxEntries, maxBytes)
}

func TestAMissingFinalizedEntryIsUnavailableNeverASkip(t *testing.T) {
	es := chain(t, nodes(t, 4), 5)
	srv := newServer(t, holey{store(t, es, 5), 3}, Config{})
	r := srv.Respond(req(1))
	require.Equal(t, StatusUnavailable, r.Status)
	require.Empty(t, r.Entries)
	require.Nil(t, r.NextEpoch)
}

func TestServerConfigMustCarryOneMaximumEntry(t *testing.T) {
	st := store(t, chain(t, nodes(t, 4), 1), 1)
	_, err := NewServer(st, Config{MaxResponseBytes: MaxEntryBytes})
	require.ErrorIs(t, err, ErrConfig)
	_, err = NewServer(st, Config{MaxResponseBytes: MaxEntryBytes + envelopeBound})
	require.NoError(t, err)
}

func connect(t *testing.T) (server, client *testPeer) {
	a, b := testutilsPeer(t), testutilsPeer(t)
	b.p.Network().Peerstore().AddAddrs(a.p.ID(), a.p.MultiAddresses(), 1<<62)
	return a, b
}

func TestOverLibp2pSyncCatchesUpAcrossPagesAndPeers(t *testing.T) {
	es := chain(t, nodes(t, 4), 150) // 3 pages of at most 64
	full := store(t, es, 150)
	a, b := connect(t)
	srv := newServer(t, full, Config{})
	srv.Register(a.p)
	c := &Client{Peer: b.p}

	sink := store(t, es, 10)
	n, err := Sync(context.Background(), c, sink, []peer.ID{a.p.ID()}, SyncOptions{Network: testNetwork})
	require.NoError(t, err)
	require.Equal(t, 140, n)
	require.Equal(t, full.Tip(), sink.Tip())
	for e := uint64(1); e <= 151; e++ {
		x, _ := full.Get(e)
		y, _ := sink.Get(e)
		require.Equal(t, x, y, e)
	}
	// already current: nothing newer, no error
	n, err = Sync(context.Background(), c, sink, []peer.ID{a.p.ID()}, SyncOptions{Network: testNetwork})
	require.NoError(t, err)
	require.Zero(t, n)
}

func TestSyncSkipsABehindPeerAndKeepsTheSnapshotCursor(t *testing.T) {
	es := chain(t, nodes(t, 4), 20)
	full, lagging := store(t, es, 20), store(t, es, 12)
	a, b := connect(t) // a: full, serves the first page then goes away
	l := testutilsPeer(t)
	b.p.Network().Peerstore().AddAddrs(l.p.ID(), l.p.MultiAddresses(), 1<<62)
	newServer(t, lagging, Config{}).Register(l.p)
	newServer(t, full, Config{}).Register(a.p)

	// the lagging peer is tried first and cannot satisfy the end: with a page size of 5 the snapshot (end 21) comes from the first page of
	// the full peer; the lagging peer is behind it and the full one finishes
	sink := store(t, es, 0)
	f := &flaky{inner: &Client{Peer: b.p}, failAfter: map[peer.ID]int{a.p.ID(): 1}}
	n, err := Sync(context.Background(), f, sink, []peer.ID{a.p.ID(), l.p.ID(), a.p.ID()}, SyncOptions{Network: testNetwork, MaxEntries: 5, Rounds: 1})
	require.NoError(t, err)
	require.Equal(t, 20, n)
	require.Equal(t, uint64(21), sink.Tip().Epoch)
}

// flaky fails a peer's requests after n successes.
type flaky struct {
	inner     Fetcher
	failAfter map[peer.ID]int
	seen      map[peer.ID]int
}

func (f *flaky) Page(ctx context.Context, id peer.ID, r *Request) (*Response, [][]byte, error) {
	if f.seen == nil {
		f.seen = map[peer.ID]int{}
	}
	if limit, ok := f.failAfter[id]; ok && f.seen[id] >= limit && r.FromEpoch > 1 && r.SnapshotEnd != nil && f.seen[id] == limit {
		f.seen[id]++
		return nil, nil, context.DeadlineExceeded
	}
	f.seen[id]++
	return f.inner.Page(ctx, id, r)
}

func TestOverLibp2pLimitsBusyOversizeAndSlowClients(t *testing.T) {
	es := chain(t, nodes(t, 4), 3)
	a, b := connect(t)
	srv := newServer(t, store(t, es, 3), Config{MaxPerPeer: 1, Timeout: 300 * time.Millisecond})
	srv.Register(a.p)
	c := &Client{Peer: b.p}

	// one in-flight request per peer: a second concurrent stream from the same peer is Busy
	held, err := b.p.CreateStream(context.Background(), a.p.ID(), ProtocolID) // opened, never written: occupies the slot until the deadline
	require.NoError(t, err)
	_, err = held.Write([]byte{0x05}) // a frame head with no body: the handler is reading and holds the slot
	require.NoError(t, err)
	require.Eventually(t, func() bool { // the handler must have taken the slot
		r, _, err := c.Page(context.Background(), a.p.ID(), req(1))
		return err == nil && r.Status == StatusBusy
	}, time.Second, 10*time.Millisecond)
	_ = held.Reset()
	// the slot is released at the deadline; then the request is served
	require.Eventually(t, func() bool {
		r, _, err := c.Page(context.Background(), a.p.ID(), req(1))
		return err == nil && r.Status == StatusOK
	}, 3*time.Second, 50*time.Millisecond)

	// an oversize frame is refused before allocation and never served
	s, err := b.p.CreateStream(context.Background(), a.p.ID(), ProtocolID)
	require.NoError(t, err)
	_, err = s.Write([]byte{0xff, 0xff, 0xff, 0x7f}) // declares ~268 MB
	require.NoError(t, err)
	_ = s.CloseWrite()
	buf := make([]byte, 1<<16)
	n, _ := s.Read(buf)
	got, _, derr := decodeFrame(buf[:n])
	require.NoError(t, derr)
	require.Equal(t, StatusInvalidRequest, got.Status)

	// a garbage request body is InvalidRequest, not a hang
	s2, err := b.p.CreateStream(context.Background(), a.p.ID(), ProtocolID)
	require.NoError(t, err)
	require.NoError(t, writeFrame(s2, []byte{0x01, 0x02, 0x03}))
	_ = s2.CloseWrite()
	n, _ = s2.Read(buf)
	got, _, derr = decodeFrame(buf[:n])
	require.NoError(t, derr)
	require.Equal(t, StatusInvalidRequest, got.Status)
}

func TestFrameLengthIsRefusedBeforeAllocation(t *testing.T) {
	_, err := readFrame(bufio.NewReader(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0x7f})), MaxRequestBytes)
	require.ErrorIs(t, err, errFrameLength)
	_, err = readFrame(bufio.NewReader(bytes.NewReader([]byte{0})), MaxRequestBytes)
	require.ErrorIs(t, err, errFrameLength)
}

// scripted answers each request with the next canned page.
type scripted struct {
	pages []func(*Request) (*Response, [][]byte)
	seen  []*Request
}

func (s *scripted) Page(_ context.Context, _ peer.ID, r *Request) (*Response, [][]byte, error) {
	s.seen = append(s.seen, r)
	if len(s.pages) == 0 {
		return nil, nil, context.DeadlineExceeded
	}
	f := s.pages[0]
	s.pages = s.pages[1:]
	resp, ents := f(r)
	return resp, ents, nil
}

func TestSyncRefusesPagesThatDoNotContinueTheRequest(t *testing.T) {
	es := chain(t, nodes(t, 4), 6)
	rs := raw(t, es)
	id := peer.ID("p")
	page := func(from, end int, next *uint64, mutate func(*Response)) func(*Request) (*Response, [][]byte) {
		return func(*Request) (*Response, [][]byte) {
			e := idOf(t, es[end-1])
			r := &Response{Version: 1, Network: testNetwork, Status: StatusOK, FromEpoch: uint64(from), EffectiveEnd: uint64(end), EndEntryID: e[:], NextEpoch: next}
			var ents [][]byte
			for i := from; i <= end && i < from+2; i++ {
				ents = append(ents, rs[i-1])
			}
			if mutate != nil {
				mutate(r)
			}
			return r, ents
		}
	}
	opt := SyncOptions{Network: testNetwork, Rounds: 1}
	for name, p := range map[string]func(*Request) (*Response, [][]byte){
		"other network": page(2, 3, nil, func(r *Response) { r.Network = 9 }),
		"another start": page(3, 3, nil, nil),
		"not even a page": func(*Request) (*Response, [][]byte) {
			return &Response{Version: 1, Network: testNetwork, Status: StatusBusy}, nil
		},
	} {
		sink := store(t, es, 0)
		n, err := Sync(context.Background(), &scripted{pages: []func(*Request) (*Response, [][]byte){p}}, sink, []peer.ID{id}, opt)
		require.ErrorIs(t, err, ErrNoPeer, name)
		require.Zero(t, n, name)
		require.Equal(t, uint64(1), sink.Tip().Epoch, name)
	}
	// a later page of another snapshot is refused, the authenticated first page is kept
	sink := store(t, es, 0)
	next := u64(4)
	s := &scripted{pages: []func(*Request) (*Response, [][]byte){
		page(2, 6, next, nil),
		page(4, 5, nil, nil), // a different end than the frozen snapshot (6)
	}}
	n, err := Sync(context.Background(), s, sink, []peer.ID{id}, opt)
	require.ErrorIs(t, err, ErrNoPeer)
	require.Equal(t, 2, n)
	require.Equal(t, uint64(3), sink.Tip().Epoch)
	require.NotNil(t, s.seen[1].SnapshotEnd)
	require.Equal(t, uint64(6), *s.seen[1].SnapshotEnd)
	require.Equal(t, uint64(4), s.seen[1].FromEpoch)
}
