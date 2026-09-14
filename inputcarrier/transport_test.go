package inputcarrier_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/inputcarrier"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// network.Peer is the production host type. Asserted so the Host interface cannot drift from it.
var _ inputcarrier.Host = (*network.Peer)(nil)

func frame(t *testing.T, e inputcarrier.Envelope) []byte {
	t.Helper()
	body, err := inputcarrier.Encode(e, inputcarrier.DefaultLimits)
	require.NoError(t, err)
	prefix := binary.AppendUvarint(nil, uint64(len(body)))
	return append(prefix, body...)
}

func newReceiver(t *testing.T, l inputcarrier.TransportLimits) *inputcarrier.Receiver {
	t.Helper()
	r, err := inputcarrier.NewReceiver(l, nil)
	require.NoError(t, err)
	t.Cleanup(r.Close)
	return r
}

// expectSample declares the sample envelope's round and block.
func expectSample(t *testing.T, r *inputcarrier.Receiver) {
	t.Helper()
	e := sampleEnvelope()
	require.NoError(t, r.Expect(e.ShardRound, inputcarrier.Expectation{BlockHash: e.BlockHash}))
}

// variant is a distinct, well-formed candidate for the sample round and block.
func variant(b byte) inputcarrier.Envelope {
	e := sampleEnvelope()
	e.Certificate = []byte{0x80, b}
	return e
}

func TestProtocolIsSeparateFromTheShardPayloadProtocol(t *testing.T) {
	require.Equal(t, "/unicity/shard-payload/1.0.0", shardnode.ProtocolShardPayload, "the production dissemination protocol is unchanged")
	require.NotEqual(t, shardnode.ProtocolShardPayload, inputcarrier.Protocol)
}

func TestTransport_TwoRealPeers(t *testing.T) {
	leader := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	follower := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	leader.Network().Peerstore().AddAddrs(follower.ID(), follower.MultiAddresses(), peerstore.PermanentAddrTTL)
	follower.Network().Peerstore().AddAddrs(leader.ID(), leader.MultiAddresses(), peerstore.PermanentAddrTTL)

	r := newReceiver(t, inputcarrier.DefaultTransportLimits)
	r.Register(follower)
	e := sampleEnvelope()
	require.NoError(t, r.Expect(e.ShardRound, inputcarrier.Expectation{BlockHash: e.BlockHash, Proposer: leader.ID().String()}))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, inputcarrier.Send(ctx, leader, follower.ID(), e, inputcarrier.DefaultTransportLimits))

	got, err := r.Await(ctx, e.ShardRound)
	require.NoError(t, err)
	require.Equal(t, e, got)
}

// TestReceiver_RejectedCandidateDoesNotExcludeTheHonestWitness runs receiver, verifier and retry end to
// end: an unauthenticated candidate arriving first is examined, verified, rejected and removed, and the
// genuine witness, arriving either before or after that rejection, is then examined and accepted.
func TestReceiver_RejectedCandidateDoesNotExcludeTheHonestWitness(t *testing.T) {
	for _, honestFirst := range []bool{false, true} {
		name := "honest witness arrives after the rejection"
		if honestFirst {
			name = "honest witness arrives before the rejection"
		}
		t.Run(name, func(t *testing.T) {
			s := newScenario(t)
			r := newReceiver(t, inputcarrier.DefaultTransportLimits)
			require.NoError(t, r.Expect(s.env.ShardRound, inputcarrier.Expectation{BlockHash: s.env.BlockHash}))

			bad := s.env
			bad.Certificate = []byte{0x80}
			require.NoError(t, r.Serve(bytes.NewReader(frame(t, bad)), "attacker"))
			if honestFirst {
				require.NoError(t, r.Serve(bytes.NewReader(frame(t, s.env)), "honest-proposer"))
			}

			// The caller examines the oldest candidate, verifies it and rejects it.
			got, err := r.Await(context.Background(), s.env.ShardRound)
			require.NoError(t, err)
			require.Equal(t, bad, got)
			_, err = inputcarrier.Verify(context.Background(), s.ctx, got, s.header)
			require.Error(t, err)
			require.NoError(t, r.Reject(s.env.ShardRound, got))

			// The same bytes cannot occupy the round again.
			require.ErrorIs(t, r.Serve(bytes.NewReader(frame(t, bad)), "another-attacker"), inputcarrier.ErrRejected)

			if !honestFirst {
				require.NoError(t, r.Serve(bytes.NewReader(frame(t, s.env)), "honest-proposer"))
			}
			got, err = r.Await(context.Background(), s.env.ShardRound)
			require.NoError(t, err)
			_, err = inputcarrier.Verify(context.Background(), s.ctx, got, s.header)
			require.NoError(t, err)
			require.NoError(t, r.Accept(s.env.ShardRound, got))

			// Bounded, so a round that fails to settle fails this test rather than hanging the package.
			settledCtx, cancelSettled := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancelSettled()
			settled, err := r.Await(settledCtx, s.env.ShardRound)
			require.NoError(t, err)
			require.Equal(t, s.env, settled)
			require.ErrorIs(t, r.Serve(bytes.NewReader(frame(t, variant(0x09))), "late"), inputcarrier.ErrRoundSettled)
		})
	}
}

// TestReceiver_UndeclaredRoundsCannotBeFilled: deliveries for rounds the caller did not declare occupy
// nothing, so a peer flooding future rounds cannot push out the round the caller is working on.
func TestReceiver_UndeclaredRoundsCannotBeFilled(t *testing.T) {
	l := inputcarrier.DefaultTransportLimits
	l.MaxPendingRounds = 2
	r := newReceiver(t, l)

	for round := uint64(100); round < 100+uint64(10*l.MaxPendingRounds); round++ {
		e := sampleEnvelope()
		e.ShardRound = round
		require.ErrorIs(t, r.Serve(bytes.NewReader(frame(t, e)), "attacker"), inputcarrier.ErrUnexpectedRound)
	}
	require.Zero(t, r.PendingRounds())

	expectSample(t, r)
	require.NoError(t, r.Serve(bytes.NewReader(frame(t, sampleEnvelope())), "honest-proposer"))
	require.Equal(t, 1, r.Candidates(sampleEnvelope().ShardRound))

	// Only the caller declares rounds, within its own bound.
	require.NoError(t, r.Expect(6, inputcarrier.Expectation{BlockHash: bytes.Repeat([]byte{6}, 32)}))
	require.ErrorIs(t, r.Expect(7, inputcarrier.Expectation{BlockHash: bytes.Repeat([]byte{7}, 32)}), inputcarrier.ErrTooManyRounds)
	r.Prune(6)
	require.Zero(t, r.PendingRounds())
	require.ErrorIs(t, r.Serve(bytes.NewReader(frame(t, sampleEnvelope())), "late"), inputcarrier.ErrPruned)
	require.ErrorIs(t, r.Expect(5, inputcarrier.Expectation{BlockHash: sampleEnvelope().BlockHash}), inputcarrier.ErrPruned)
	require.NoError(t, r.Expect(7, inputcarrier.Expectation{BlockHash: bytes.Repeat([]byte{7}, 32)}))
}

func TestReceiver_ExpectationNarrowsAdmission(t *testing.T) {
	r := newReceiver(t, inputcarrier.DefaultTransportLimits)
	e := sampleEnvelope()
	require.NoError(t, r.Expect(e.ShardRound, inputcarrier.Expectation{BlockHash: e.BlockHash, Proposer: "proposer"}))

	other := e
	other.BlockHash = bytes.Repeat([]byte{0xcc}, 32)
	require.ErrorIs(t, r.Serve(bytes.NewReader(frame(t, other)), "proposer"), inputcarrier.ErrUnexpectedBlock)
	require.ErrorIs(t, r.Serve(bytes.NewReader(frame(t, e)), "not-the-proposer"), inputcarrier.ErrUnexpectedSender)
	require.Zero(t, r.Candidates(e.ShardRound), "refused deliveries occupy nothing")
	require.NoError(t, r.Serve(bytes.NewReader(frame(t, e)), "proposer"))

	require.Error(t, r.Expect(e.ShardRound, inputcarrier.Expectation{BlockHash: other.BlockHash}), "a declared round cannot be redeclared differently")
	require.NoError(t, r.Expect(e.ShardRound, inputcarrier.Expectation{BlockHash: e.BlockHash, Proposer: "proposer"}), "the same declaration is a no-op")
	require.Error(t, r.Expect(9, inputcarrier.Expectation{BlockHash: e.BlockHash[:31]}))
}

func TestReceiver_CandidateBounds(t *testing.T) {
	l := inputcarrier.DefaultTransportLimits
	l.MaxCandidatesPerRound = 2
	l.MaxRejectsPerPeer = 2
	r := newReceiver(t, l)
	expectSample(t, r)
	round := sampleEnvelope().ShardRound

	t.Run("identical bytes are one candidate", func(t *testing.T) {
		require.NoError(t, r.Serve(bytes.NewReader(frame(t, variant(1))), "a"))
		require.ErrorIs(t, r.Serve(bytes.NewReader(frame(t, variant(1))), "b"), inputcarrier.ErrDuplicate)
	})
	t.Run("one pending candidate per sender", func(t *testing.T) {
		require.ErrorIs(t, r.Serve(bytes.NewReader(frame(t, variant(2))), "a"), inputcarrier.ErrPeerHasCandidate)
	})
	t.Run("the round's candidate bound, released by rejection", func(t *testing.T) {
		require.NoError(t, r.Serve(bytes.NewReader(frame(t, variant(3))), "b"))
		require.ErrorIs(t, r.Serve(bytes.NewReader(frame(t, variant(4))), "c"), inputcarrier.ErrCandidatesFull)
		require.NoError(t, r.Reject(round, variant(1)))
		require.NoError(t, r.Serve(bytes.NewReader(frame(t, variant(4))), "c"))
	})
	t.Run("a sender is refused after its rejection bound", func(t *testing.T) {
		require.NoError(t, r.Reject(round, variant(4)))
		require.NoError(t, r.Serve(bytes.NewReader(frame(t, variant(5))), "a"))
		require.NoError(t, r.Reject(round, variant(5)))
		require.ErrorIs(t, r.Serve(bytes.NewReader(frame(t, variant(6))), "a"), inputcarrier.ErrPeerExhausted)
	})
	t.Run("arrival order decides nothing: examination is oldest first, settlement is the caller's", func(t *testing.T) {
		got, err := r.Await(context.Background(), round)
		require.NoError(t, err)
		require.Equal(t, variant(3), got)
		require.ErrorIs(t, r.Accept(round, variant(9)), inputcarrier.ErrNoSuchCandidate)
		require.ErrorIs(t, r.Reject(round, variant(9)), inputcarrier.ErrNoSuchCandidate)
		require.NoError(t, r.Accept(round, variant(3)))
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		settled, err := r.Await(ctx, round)
		require.NoError(t, err, "a settled round answers Await with its envelope")
		require.Equal(t, variant(3), settled)
		require.ErrorIs(t, r.Reject(round, variant(3)), inputcarrier.ErrRoundSettled)
		require.ErrorIs(t, r.Accept(round, variant(3)), inputcarrier.ErrRoundSettled)
	})
}

func TestReceiver_AwaitWaitsForACandidateAndEndsOnPruneOrClose(t *testing.T) {
	r := newReceiver(t, inputcarrier.DefaultTransportLimits)
	expectSample(t, r)
	round := sampleEnvelope().ShardRound

	got := make(chan error, 1)
	go func() {
		_, err := r.Await(context.Background(), round)
		got <- err
	}()
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, r.Serve(bytes.NewReader(frame(t, sampleEnvelope())), "proposer"))
	require.NoError(t, <-got)

	require.NoError(t, r.Expect(6, inputcarrier.Expectation{BlockHash: bytes.Repeat([]byte{6}, 32)}))
	go func() {
		_, err := r.Await(context.Background(), 6)
		got <- err
	}()
	time.Sleep(50 * time.Millisecond)
	r.Prune(6)
	require.ErrorIs(t, <-got, inputcarrier.ErrPruned)

	_, err := r.Await(context.Background(), 99)
	require.ErrorIs(t, err, inputcarrier.ErrUnexpectedRound)

	require.NoError(t, r.Expect(7, inputcarrier.Expectation{BlockHash: bytes.Repeat([]byte{7}, 32)}))
	go func() {
		_, err := r.Await(context.Background(), 7)
		got <- err
	}()
	time.Sleep(50 * time.Millisecond)
	r.Close()
	require.ErrorIs(t, <-got, inputcarrier.ErrClosed)
}

// endless yields zero bytes forever. A receiver that read a declared body before checking its length
// would allocate the declared size and never finish reading.
type endless struct{}

func (endless) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestReceiver_FrameOverTheBoundIsRefusedBeforeItsBodyIsRead(t *testing.T) {
	r := newReceiver(t, inputcarrier.DefaultTransportLimits)
	expectSample(t, r)
	prefix := binary.AppendUvarint(nil, 1<<40)

	done := make(chan error, 1)
	go func() { done <- r.Serve(io.MultiReader(bytes.NewReader(prefix), endless{}), "peer-a") }()
	select {
	case err := <-done:
		require.ErrorIs(t, err, inputcarrier.ErrTransport)
	case <-time.After(5 * time.Second):
		t.Fatal("Serve kept reading a frame whose declared length is over the bound")
	}
	require.Zero(t, r.Candidates(sampleEnvelope().ShardRound))
	streams, _ := r.PendingStreams()
	require.Zero(t, streams, "the admission slot is released on the refusal path")
}

func TestReceiver_NonCanonicalFrameIsNotDelivered(t *testing.T) {
	r := newReceiver(t, inputcarrier.DefaultTransportLimits)
	expectSample(t, r)
	body, err := inputcarrier.Encode(sampleEnvelope(), inputcarrier.DefaultLimits)
	require.NoError(t, err)
	body = append(body, 0x00)
	f := append(binary.AppendUvarint(nil, uint64(len(body))), body...)

	require.ErrorIs(t, r.Serve(bytes.NewReader(f), "peer-a"), inputcarrier.ErrMalformedEnvelope)
	require.Zero(t, r.Candidates(sampleEnvelope().ShardRound))
}

func TestReceiver_StreamAdmissionIsBoundedPerPeerAndReleased(t *testing.T) {
	l := inputcarrier.DefaultTransportLimits
	l.MaxPendingStreams = 3
	l.MaxPendingStreamsPerPeer = 1
	r := newReceiver(t, l)
	expectSample(t, r)

	// hold opens a stream from a peer that has sent nothing yet, and returns its writer and result.
	hold := func(from string) (*io.PipeWriter, chan error) {
		rd, w := io.Pipe()
		done := make(chan error, 1)
		go func() { done <- r.Serve(rd, from) }()
		return w, done
	}
	pending := func(n int) {
		require.Eventually(t, func() bool { s, _ := r.PendingStreams(); return s == n }, 5*time.Second, 10*time.Millisecond)
	}

	// Two streams held, from two peers: under the total bound of three.
	aWrite, aDone := hold("peer-a")
	bWrite, bDone := hold("peer-b")
	pending(2)

	// The per-peer bound refuses peer-a's second stream while total capacity remains, so this
	// refusal can only come from the per-peer bound.
	require.ErrorIs(t, r.Serve(bytes.NewReader(frame(t, sampleEnvelope())), "peer-a"), inputcarrier.ErrNotAdmitted, "per-peer bound")
	s, _ := r.PendingStreams()
	require.Less(t, s, l.MaxPendingStreams, "premise: the total bound was not reached")

	// A third peer fills the total bound; a fourth is then refused by it.
	cWrite, cDone := hold("peer-c")
	pending(3)
	require.ErrorIs(t, r.Serve(bytes.NewReader(frame(t, sampleEnvelope())), "peer-d"), inputcarrier.ErrNotAdmitted, "total bound")

	// One stream completes, two are abandoned; all release their slots.
	go func() { _, _ = aWrite.Write(frame(t, sampleEnvelope())); _ = aWrite.Close() }()
	require.NoError(t, <-aDone)
	_ = bWrite.CloseWithError(errors.New("peer went away"))
	require.ErrorIs(t, <-bDone, inputcarrier.ErrTransport)
	_ = cWrite.CloseWithError(errors.New("peer went away"))
	require.ErrorIs(t, <-cDone, inputcarrier.ErrTransport)

	streams, peers := r.PendingStreams()
	require.Zero(t, streams)
	require.Zero(t, peers)
}

func TestTransport_StalledStreamCostsOneDeadline(t *testing.T) {
	leader := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	follower := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	leader.Network().Peerstore().AddAddrs(follower.ID(), follower.MultiAddresses(), peerstore.PermanentAddrTTL)

	l := inputcarrier.DefaultTransportLimits
	l.Deadline = 300 * time.Millisecond
	r := newReceiver(t, l)
	r.Register(follower)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := leader.CreateStream(ctx, follower.ID(), inputcarrier.Protocol)
	require.NoError(t, err)
	defer s.Reset()
	// Write one byte so the receiver's handler is certainly running, then stall.
	_, err = s.Write([]byte{0x05})
	require.NoError(t, err)

	require.Eventually(t, func() bool { n, _ := r.PendingStreams(); return n == 1 }, 5*time.Second, 5*time.Millisecond)
	start := time.Now()
	require.Eventually(t, func() bool { n, _ := r.PendingStreams(); return n == 0 }, 5*time.Second, 5*time.Millisecond)
	require.Less(t, time.Since(start), 3*time.Second, "a stalled stream is released after about one deadline")
}

// countingHost records whether a stream was opened.
type countingHost struct{ opened int }

func (h *countingHost) RegisterProtocolHandler(string, libp2pnetwork.StreamHandler) {}
func (h *countingHost) CreateStream(context.Context, peer.ID, string) (libp2pnetwork.Stream, error) {
	h.opened++
	return nil, errors.New("not a real host")
}

func TestSend_RefusesAnOversizedEnvelopeBeforeOpeningAStream(t *testing.T) {
	h := &countingHost{}
	e := sampleEnvelope()
	e.Certificate = make([]byte, inputcarrier.DefaultLimits.MaxCertificateBytes+1)
	err := inputcarrier.Send(context.Background(), h, peer.ID("x"), e, inputcarrier.DefaultTransportLimits)
	require.ErrorIs(t, err, inputcarrier.ErrMalformedEnvelope)
	require.Zero(t, h.opened)
}

// pipeStream is a stream over one end of a net.Pipe, whose other end nobody reads, so a write blocks
// until the deadline passes or the stream is reset.
type pipeStream struct {
	libp2pnetwork.Stream
	c      net.Conn
	resets atomic.Int32
}

func (s *pipeStream) Write(b []byte) (int, error)      { return s.c.Write(b) }
func (s *pipeStream) SetDeadline(d time.Time) error    { return s.c.SetDeadline(d) }
func (s *pipeStream) Reset() error                     { s.resets.Add(1); return s.c.Close() }
func (s *pipeStream) Close() error                     { return s.c.Close() }
func (s *pipeStream) CloseWrite() error                { return nil }
func (s *pipeStream) SetWriteDeadline(time.Time) error { return nil }

// resetIgnoringStream is a pipeStream whose Reset does nothing, so a blocked write can end only at the
// stream's own deadline. It separates that deadline from the cancellation watcher, which resets the
// stream at the same instant the budget runs out and would otherwise mask a wrong deadline.
type resetIgnoringStream struct{ *pipeStream }

func (s resetIgnoringStream) Reset() error { s.resets.Add(1); return nil }

// pipeHost opens a pipeStream after an optional dial delay, running onOpen once it has.
type pipeHost struct {
	stream      *pipeStream
	dial        time.Duration
	onOpen      func()
	ignoreReset bool
}

func (h *pipeHost) RegisterProtocolHandler(string, libp2pnetwork.StreamHandler) {}
func (h *pipeHost) CreateStream(ctx context.Context, _ peer.ID, _ string) (libp2pnetwork.Stream, error) {
	select {
	case <-time.After(h.dial):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if h.onOpen != nil {
		h.onOpen()
	}
	if h.ignoreReset {
		return resetIgnoringStream{h.stream}, nil
	}
	return h.stream, nil
}

func newPipeHost(t *testing.T) *pipeHost {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return &pipeHost{stream: &pipeStream{c: a}}
}

// sendSettles runs Send and requires it to return within within, and the watcher goroutine it started
// to be gone once it has.
func sendSettles(t *testing.T, ctx context.Context, h inputcarrier.Host, l inputcarrier.TransportLimits, within time.Duration) error {
	t.Helper()
	before := runtime.NumGoroutine()
	start := time.Now()
	err := inputcarrier.Send(ctx, h, peer.ID("peer"), sampleEnvelope(), l)
	require.Less(t, time.Since(start), within)
	// Polled by hand rather than with require.Eventually, which evaluates its condition on a goroutine
	// of its own and so can never observe the count fall back to the baseline.
	for deadline := time.Now().Add(2 * time.Second); runtime.NumGoroutine() > before; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("Send left %d goroutines behind", runtime.NumGoroutine()-before)
		}
	}
	return err
}

func TestSend_OneBudgetForTheWholeOperation(t *testing.T) {
	l := inputcarrier.DefaultTransportLimits
	l.Deadline = 600 * time.Millisecond

	t.Run("a short caller deadline bounds a blocked write", func(t *testing.T) {
		h := newPipeHost(t)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		err := sendSettles(t, ctx, h, l, 250*time.Millisecond)
		require.ErrorIs(t, err, inputcarrier.ErrTransport)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
	t.Run("cancellation after dialing unblocks the write", func(t *testing.T) {
		h := newPipeHost(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h.onOpen = func() { time.AfterFunc(40*time.Millisecond, cancel) }
		err := sendSettles(t, ctx, h, l, 250*time.Millisecond)
		require.ErrorIs(t, err, context.Canceled)
		require.Positive(t, h.stream.resets.Load(), "the blocked stream was reset")
	})
	t.Run("a slow dial spends the same budget as the write", func(t *testing.T) {
		h := newPipeHost(t)
		h.dial = 400 * time.Millisecond
		err := sendSettles(t, context.Background(), h, l, 900*time.Millisecond)
		require.ErrorIs(t, err, context.DeadlineExceeded, "the transport limit, not a fresh one after dialing")
	})
	t.Run("after a slow dial, the stream deadline alone still ends at the budget", func(t *testing.T) {
		h := newPipeHost(t)
		h.dial = 400 * time.Millisecond
		h.ignoreReset = true
		err := sendSettles(t, context.Background(), h, l, 900*time.Millisecond)
		require.ErrorIs(t, err, context.DeadlineExceeded, "the absolute deadline from Send's start, not a fresh one after dialing")
	})
	t.Run("a dial that outlasts the budget", func(t *testing.T) {
		h := newPipeHost(t)
		h.dial = 2 * time.Second
		err := sendSettles(t, context.Background(), h, l, 900*time.Millisecond)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
}
