package recordsfeed

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ask sends one request from `from` to srv over a pipe and returns the response body, or an error when the server hung up.
func ask(t *testing.T, srv *Server, from peer.ID, req request) ([]byte, error) {
	t.Helper()
	cl, sv := net.Pipe()
	done := make(chan struct{})
	go func() { srv.Serve(from, pipeStream{sv}); close(done) }()
	defer func() { _ = cl.Close(); <-done }()
	_ = cl.SetDeadline(time.Now().Add(3 * time.Second))
	raw, err := types.Cbor.Marshal(req)
	require.NoError(t, err)
	if err := writeFrame(cl, raw); err != nil {
		return nil, err
	}
	return readFrame(cl, MaxCutBytes)
}

func publicServer(t *testing.T, records int, limits PublicLimits) (*Server, chain, Cut, CutKey) {
	t.Helper()
	c := buildChain(t, records)
	cut, origin := c.cutOf(t, 200, 5_000)
	key := keyOf(t, origin)
	srv := NewServer(serverFake{cuts: map[CutKey]Cut{key: cut}, records: c.records}, func(id peer.ID) bool { return id == "member" })
	require.NoError(t, srv.SetPublicRecords(limits))
	return srv, c, cut, key
}

func cutRequest(key CutKey) request {
	return request{Kind: kindCut, Network: key.Network, Epoch: key.Epoch, Round: key.Round, TreeRoot: key.TreeRoot[:]}
}

// bft-core#1048: record reads are public, cuts are not. A peer the server does not authorize (a non-member root catching up) reads records
// under the public budget and never gets a cut; an authorized peer keeps both; without public reads a stranger gets nothing.
func TestRecordReadsArePublicAndCutsAreNot(t *testing.T) {
	srv, c, _, key := publicServer(t, 10, DefaultPublicLimits())
	body, err := ask(t, srv, "stranger", request{Kind: kindRecords, From: 0, Max: 5})
	require.NoError(t, err)
	var wire []wireRecord
	require.NoError(t, types.Cbor.Unmarshal(body, &wire))
	require.Len(t, wire, 5)
	require.Equal(t, c.records[0].ID[:], wire[0].ID)

	_, err = ask(t, srv, "stranger", cutRequest(key))
	require.Error(t, err, "a cut is never public: the stream is reset")
	_, err = ask(t, srv, "stranger", request{Kind: 9})
	require.Error(t, err, "nor any other operation")

	body, err = ask(t, srv, "member", cutRequest(key))
	require.NoError(t, err, "an authorized peer keeps its cuts")
	require.NotEmpty(t, body)

	closed := NewServer(serverFake{records: c.records}, func(id peer.ID) bool { return id == "member" })
	_, err = ask(t, closed, "stranger", request{Kind: kindRecords, From: 0, Max: 5})
	require.Error(t, err, "public reads are off unless enabled")
	_, err = ask(t, srv, "", request{Kind: kindRecords, From: 0, Max: 5})
	require.Error(t, err, "an unauthenticated stream is refused")
}

func TestPublicReadsAreBoundedByTheirOwnBudget(t *testing.T) {
	t.Run("batch", func(t *testing.T) {
		l := DefaultPublicLimits()
		l.MaxBatch = 7
		srv, _, _, _ := publicServer(t, 300, l)
		body, err := ask(t, srv, "stranger", request{Kind: kindRecords, From: 0, Max: 1 << 30})
		require.NoError(t, err)
		var wire []wireRecord
		require.NoError(t, types.Cbor.Unmarshal(body, &wire))
		require.Len(t, wire, 7, "a public read returns at most the public batch")
		body, err = ask(t, srv, "member", request{Kind: kindRecords, From: 0, Max: 1 << 30})
		require.NoError(t, err)
		require.NoError(t, types.Cbor.Unmarshal(body, &wire))
		require.Len(t, wire, MaxBatch, "an authorized read keeps the full batch")
	})

	t.Run("concurrency per peer and in all", func(t *testing.T) {
		l := DefaultPublicLimits()
		l.Pending, l.PerPeer = 2, 1
		b := newPublicBudget(l, time.Now)
		require.True(t, b.admit("a"))
		require.False(t, b.admit("a"), "one stream per peer")
		require.True(t, b.admit("b"))
		require.False(t, b.admit("c"), "the public slots are full")
		b.release("a")
		require.True(t, b.admit("c"))
		srv, _, _, _ := publicServer(t, 3, l)
		srv.public = b
		_, err := ask(t, srv, "d", request{Kind: kindRecords, Max: 1})
		require.Error(t, err, "a full public budget refuses before reading the request")
		require.True(t, srv.admit("member"), "the authorized peers' slots are separate")
	})

	t.Run("request rate per peer and in all", func(t *testing.T) {
		now := time.Unix(1_000, 0)
		l := DefaultPublicLimits()
		l.Rate, l.Burst, l.GlobalRate, l.GlobalBurst = 1, 2, 1, 3
		b := newPublicBudget(l, func() time.Time { return now })
		take := func(id peer.ID) bool {
			ok := b.admit(id)
			if ok {
				b.release(id)
			}
			return ok
		}
		require.True(t, take("a"))
		require.True(t, take("a"))
		require.False(t, take("a"), "the peer's burst is spent")
		require.True(t, take("b"))
		require.False(t, take("c"), "the global burst is spent")
		now = now.Add(time.Second)
		require.True(t, take("c"), "refilled at the global rate")
		require.False(t, take("a"))
	})

	t.Run("response bytes per peer and in all", func(t *testing.T) {
		now := time.Unix(1_000, 0)
		l := DefaultPublicLimits()
		l.ByteRate, l.ByteBurst, l.GlobalByteRate, l.GlobalByteBurst = 1000, MaxBatchBytes, 1000, MaxBatchBytes+MaxBatchBytes/2
		b := newPublicBudget(l, func() time.Time { return now })
		require.True(t, b.spend("a", MaxBatchBytes))
		require.False(t, b.spend("a", 10_000), "the peer's bytes are spent")
		require.True(t, b.spend("b", MaxBatchBytes/2))
		require.False(t, b.spend("b", MaxBatchBytes/4), "all public readers' bytes are spent")
		now = now.Add(20 * time.Second)
		require.True(t, b.spend("a", 10_000))

		srv, _, _, _ := publicServer(t, 300, DefaultPublicLimits())
		srv.public.limits.ByteBurst, srv.public.limits.ByteRate = 64, 1
		srv.public.bytes = map[peer.ID]*tokenBucket{}
		_, err := ask(t, srv, "greedy", request{Kind: kindRecords, From: 0, Max: 200})
		require.Error(t, err, "a response over the byte budget is not sent")
		require.Positive(t, srv.PublicStats().Rejected)
	})

	t.Run("a withheld request frees the slot at the header deadline", func(t *testing.T) {
		l := DefaultPublicLimits()
		l.HeaderDeadline, l.Deadline, l.Pending, l.PerPeer = 50*time.Millisecond, time.Second, 1, 1
		srv, _, _, _ := publicServer(t, 3, l)
		cl, sv := net.Pipe()
		done := make(chan struct{})
		go func() { srv.Serve("slow", pipeStream{sv}); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("the server waited past the header deadline")
		}
		_ = cl.Close()
		require.Zero(t, srv.PublicStats().Pending)
		_, err := ask(t, srv, "next", request{Kind: kindRecords, Max: 1})
		require.NoError(t, err)
	})

	t.Run("the tracked peers are bounded", func(t *testing.T) {
		l := DefaultPublicLimits()
		l.MaxTrackedPeers, l.Pending, l.PerPeer = 4, 4, 1
		b := newPublicBudget(l, time.Now)
		for i := 0; i < 50; i++ {
			id := peer.ID(rune('a' + i))
			if b.admit(id) {
				b.release(id)
			}
		}
		require.LessOrEqual(t, len(b.requests), 4)
	})

	// astra's review of #1056 (P2): with a small table, a depleted bucket must not be dropped and recreated full by other peers' churn.
	t.Run("a depleted request bucket is never reset by eviction", func(t *testing.T) {
		now := time.Unix(1_000, 0)
		l := DefaultPublicLimits()
		l.MaxTrackedPeers, l.Pending, l.PerPeer, l.GlobalBurst, l.GlobalRate = 2, 2, 1, 1_000, 1_000
		b := newPublicBudget(l, func() time.Time { return now })
		take := func(id peer.ID) bool {
			ok := b.admit(id)
			if ok {
				b.release(id)
			}
			return ok
		}
		for i := 0; i < l.Burst; i++ {
			require.True(t, take("A"), i)
		}
		require.False(t, take("A"), "A's burst is spent")
		require.True(t, take("B"))
		require.False(t, take("C"), "no entry has refilled: a new peer is refused, A's depleted bucket is kept")
		require.False(t, take("A"), "A is still depleted: no token without refill")
		now = now.Add(time.Duration(float64(l.Burst)/l.Rate*float64(time.Second)) + time.Second)
		require.True(t, take("C"), "B has refilled completely: dropping it gives nobody tokens")
		require.True(t, take("A"), "and A has earned its tokens back by the rate")
	})

	t.Run("a depleted byte bucket is never reset by eviction", func(t *testing.T) {
		now := time.Unix(1_000, 0)
		l := DefaultPublicLimits()
		l.MaxTrackedPeers, l.Pending, l.PerPeer = 2, 2, 1
		l.ByteRate, l.ByteBurst, l.GlobalByteRate, l.GlobalByteBurst = 1_000, MaxBatchBytes, 1e9, 100*MaxBatchBytes
		b := newPublicBudget(l, func() time.Time { return now })
		require.True(t, b.spend("A", MaxBatchBytes))
		require.False(t, b.spend("A", 10_000), "A's bytes are spent")
		require.True(t, b.spend("B", 1))
		require.False(t, b.spend("C", 1), "no entry has refilled: a new peer is refused")
		require.False(t, b.spend("A", 10_000), "A's depleted byte bucket was kept")
		now = now.Add(time.Duration(float64(MaxBatchBytes)/l.ByteRate*float64(time.Second)) + time.Second)
		require.True(t, b.spend("C", 1))
		require.LessOrEqual(t, len(b.bytes), 2)
	})

	t.Run("a table whose entries are all in flight takes no new peer", func(t *testing.T) {
		l := DefaultPublicLimits()
		l.MaxTrackedPeers, l.Pending, l.PerPeer = 2, 2, 1
		b := newPublicBudget(l, time.Now)
		require.True(t, b.admit("A"))
		require.True(t, b.admit("B"))
		b.limits.Pending = 3 // a third slot, but no room in the table
		require.False(t, b.admit("C"))
		require.Len(t, b.requests, 2)
	})
}

func TestPublicLimitsThatCannotWorkAreRefused(t *testing.T) {
	srv := NewServer(serverFake{}, nil)
	for name, mutate := range map[string]func(*PublicLimits){
		"no slots":                     func(l *PublicLimits) { l.Pending = 0 },
		"per peer above all":           func(l *PublicLimits) { l.PerPeer = l.Pending + 1 },
		"no rate":                      func(l *PublicLimits) { l.Rate = 0 },
		"byte burst below a response":  func(l *PublicLimits) { l.ByteBurst = MaxBatchBytes - 1 },
		"global bytes below a respons": func(l *PublicLimits) { l.GlobalByteBurst = MaxBatchBytes - 1 },
		"batch above the feed's":       func(l *PublicLimits) { l.MaxBatch = MaxBatch + 1 },
		"deadline below the header":    func(l *PublicLimits) { l.Deadline = l.HeaderDeadline / 2 },
		"no tracked peers":             func(l *PublicLimits) { l.MaxTrackedPeers = 0 },
		"a table below the slots":      func(l *PublicLimits) { l.MaxTrackedPeers = l.Pending - 1 },
	} {
		l := DefaultPublicLimits()
		mutate(&l)
		require.ErrorIs(t, srv.SetPublicRecords(l), ErrPublicLimits, name)
	}
	require.NoError(t, srv.SetPublicRecords(DefaultPublicLimits()))
}

// A reader whose old committee is offline is served the log by a newer root that does not authorize it (it is no member of its committee):
// the client side is unchanged, and the reader verifies every record itself (the storage prefix fetch; the consensus package's restart
// test drives a lying source and then an honest one through it).
func TestANonMemberIsServedTheLogByANewerRootThatDoesNotAuthorizeIt(t *testing.T) {
	c := buildChain(t, 40)
	newer := NewServer(serverFake{records: c.records}, func(peer.ID) bool { return false })
	require.NoError(t, newer.SetPublicRecords(DefaultPublicLimits()))
	remote := P2PRemote{Opener: pipeOpener{"newer": newer}, Roots: []peer.ID{"old-root-offline", "newer"}}
	_, err := remote.RecordsFromSource(context.Background(), 0, 0, 10)
	require.Error(t, err, "the old committee is offline")
	got, err := remote.RecordsFromSource(context.Background(), 1, 0, 41)
	require.NoError(t, err)
	require.Equal(t, c.records, got)
}
