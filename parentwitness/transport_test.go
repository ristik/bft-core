package parentwitness

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/registryproof"
)

func testLimits() TransportLimits {
	return TransportLimits{Deadline: 2 * time.Second, MaxEligiblePeers: 2, MaxPendingStreams: 2, MaxPendingStreamsPerPeer: 1, MaxConcurrentServes: 1, RequestsPerSecond: 1000, Burst: 2}
}

type pipeTransportStream struct {
	net.Conn
	mu    sync.Mutex
	reset bool
}

func (s *pipeTransportStream) CloseWrite() error { return nil }
func (s *pipeTransportStream) Reset() error {
	s.mu.Lock()
	s.reset = true
	s.mu.Unlock()
	return s.Conn.Close()
}

func TestTransportPipeVerifiedAndPredicateRefusal(t *testing.T) {
	c, target := fixtureTarget(t)
	reader := &providerReader{evidence: c.Blocks[1].Evidence, found: true}
	provider, err := NewProvider(target, reader)
	require.NoError(t, err)
	server, err := NewServer(context.Background(), provider, []peer.ID{"peer"}, testLimits())
	require.NoError(t, err)
	defer server.Close()
	clientConn, serverConn := net.Pipe()
	client, remote := &pipeTransportStream{Conn: clientConn}, &pipeTransportStream{Conn: serverConn}
	go server.handle(remote, "peer")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := exchangeVerified(ctx, client, target)
	require.NoError(t, err)
	require.True(t, got.Found())

	// A syntactically valid found response remains untrusted until the client predicate runs.
	bad := c.Blocks[1].Evidence
	bad.Header = append([]byte(nil), bad.Header...)
	bad.Header[10] ^= 1
	a, b := net.Pipe()
	defer b.Close()
	go func() {
		req, _ := ReadRequestFrame(b)
		_ = WriteResponseFrame(b, Response{Request: req, Outcome: OutcomeFound, Evidence: bad})
	}()
	_, err = exchangeVerified(ctx, &pipeTransportStream{Conn: a}, target)
	require.ErrorIs(t, err, registryproof.ErrHeaderHash)
}

type readTrackingStream struct {
	*pipeTransportStream
	mu    sync.Mutex
	reads int
}

func (s *readTrackingStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	s.reads++
	s.mu.Unlock()
	return s.pipeTransportStream.Read(p)
}

func TestTransportAdmissionBeforeReadAndReleases(t *testing.T) {
	_, target := fixtureTarget(t)
	p, _ := NewProvider(target, &providerReader{})
	server, err := NewServer(context.Background(), p, []peer.ID{"eligible"}, testLimits())
	require.NoError(t, err)
	defer server.Close()
	a, b := net.Pipe()
	defer a.Close()
	tracked := &readTrackingStream{pipeTransportStream: &pipeTransportStream{Conn: b}}
	done := make(chan struct{})
	go func() { server.handle(tracked, "stranger"); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ineligible stream did not reset")
	}
	tracked.mu.Lock()
	reads := tracked.reads
	tracked.mu.Unlock()
	require.Zero(t, reads)
	require.Eventually(t, func() bool { x, y := server.Pending(); return x == 0 && y == 0 }, time.Second, time.Millisecond)
}

func TestTransportPendingBoundsRefuseBeforeRead(t *testing.T) {
	_, target := fixtureTarget(t)
	p, _ := NewProvider(target, &providerReader{})
	limits := testLimits()
	limits.MaxPendingStreams = 2
	limits.MaxPendingStreamsPerPeer = 1
	server, err := NewServer(context.Background(), p, []peer.ID{"a", "b"}, limits)
	require.NoError(t, err)
	defer server.Close()

	firstClient, firstServer := net.Pipe()
	defer firstClient.Close()
	go server.handle(&pipeTransportStream{Conn: firstServer}, "a")
	_, err = firstClient.Write([]byte{0x18})
	require.NoError(t, err)
	require.Eventually(t, func() bool { n, _ := server.Pending(); return n == 1 }, time.Second, time.Millisecond)

	for _, id := range []peer.ID{"a", "a"} {
		a, b := net.Pipe()
		tracked := &readTrackingStream{pipeTransportStream: &pipeTransportStream{Conn: b}}
		done := make(chan struct{})
		go func() { server.handle(tracked, id); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("saturated stream was not reset")
		}
		tracked.mu.Lock()
		reads := tracked.reads
		tracked.mu.Unlock()
		require.Zero(t, reads)
		_ = a.Close()
	}
	positiveClient, positiveServer := net.Pipe()
	go server.handle(&pipeTransportStream{Conn: positiveServer}, "b")
	require.Eventually(t, func() bool { n, _ := server.Pending(); return n == 2 }, time.Second, time.Millisecond)
	_ = positiveClient.Close()
	_ = firstClient.Close()
	require.Eventually(t, func() bool { n, peers := server.Pending(); return n == 0 && peers == 0 }, time.Second, time.Millisecond)
}

func TestTransportGlobalPendingBoundRefusesBeforeRead(t *testing.T) {
	_, target := fixtureTarget(t)
	p, _ := NewProvider(target, &providerReader{})
	limits := testLimits()
	limits.MaxPendingStreams = 1
	limits.MaxPendingStreamsPerPeer = 1
	server, err := NewServer(context.Background(), p, []peer.ID{"a", "b"}, limits)
	require.NoError(t, err)
	defer server.Close()
	firstClient, firstServer := net.Pipe()
	defer firstClient.Close()
	go server.handle(&pipeTransportStream{Conn: firstServer}, "a")
	_, err = firstClient.Write([]byte{0x18})
	require.NoError(t, err)
	require.Eventually(t, func() bool { n, _ := server.Pending(); return n == 1 }, time.Second, time.Millisecond)
	a, b := net.Pipe()
	tracked := &readTrackingStream{pipeTransportStream: &pipeTransportStream{Conn: b}}
	done := make(chan struct{})
	go func() { server.handle(tracked, "b"); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("global saturation was not refused")
	}
	tracked.mu.Lock()
	reads := tracked.reads
	tracked.mu.Unlock()
	require.Zero(t, reads)
	_ = a.Close()
}

func TestTransportOversizePrefixReleasesAdmission(t *testing.T) {
	_, target := fixtureTarget(t)
	p, _ := NewProvider(target, &providerReader{})
	server, err := NewServer(context.Background(), p, []peer.ID{"peer"}, testLimits())
	require.NoError(t, err)
	defer server.Close()
	a, b := net.Pipe()
	defer a.Close()
	done := make(chan struct{})
	go func() { server.handle(&pipeTransportStream{Conn: b}, "peer"); close(done) }()
	_, err = a.Write(binary.AppendUvarint(nil, MaxRequestBytes+1))
	require.NoError(t, err)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("oversize prefix was not refused")
	}
	n, peers := server.Pending()
	require.Zero(t, n)
	require.Zero(t, peers)
}

func TestTransportPartialFrameCancellationAndClose(t *testing.T) {
	_, target := fixtureTarget(t)
	p, _ := NewProvider(target, &providerReader{})
	server, err := NewServer(context.Background(), p, []peer.ID{"peer"}, testLimits())
	require.NoError(t, err)
	a, b := net.Pipe()
	client, remote := &pipeTransportStream{Conn: a}, &pipeTransportStream{Conn: b}
	done := make(chan struct{})
	go func() { server.handle(remote, "peer"); close(done) }()
	_, err = a.Write([]byte{0x18}) // declared body length 24, body never arrives
	require.NoError(t, err)
	require.Eventually(t, func() bool { x, _ := server.Pending(); return x == 1 }, time.Second, time.Millisecond)
	closed := make(chan struct{})
	go func() { server.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not reset and join partial read")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not join")
	}
	_ = client.Close()
}

func TestTransportClientCancellationResetsAndJoins(t *testing.T) {
	_, target := fixtureTarget(t)
	a, b := net.Pipe()
	defer b.Close()
	client := &pipeTransportStream{Conn: a}
	read := make(chan struct{})
	go func() { _, _ = ReadRequestFrame(b); close(read); var one [1]byte; _, _ = b.Read(one[:]) }()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := exchangeVerified(ctx, client, target); done <- err }()
	<-read
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("cancel did not unblock client")
	}
	client.mu.Lock()
	reset := client.reset
	client.mu.Unlock()
	require.True(t, reset)
}

func TestTransportLimitsAndBusyRate(t *testing.T) {
	_, target := fixtureTarget(t)
	p, _ := NewProvider(target, &providerReader{})
	bad := testLimits()
	bad.RequestsPerSecond = 0
	_, err := NewServer(context.Background(), p, []peer.ID{"p"}, bad)
	require.Error(t, err)
	bad = testLimits()
	bad.MaxEligiblePeers = 1
	_, err = NewServer(context.Background(), p, []peer.ID{"p", "q"}, bad)
	require.Error(t, err)

	limits := testLimits()
	limits.Burst = 1
	limits.RequestsPerSecond = .001
	s, _ := NewServer(context.Background(), p, []peer.ID{"p"}, limits)
	defer s.Close()
	request := func() VerifiedResponse {
		a, b := net.Pipe()
		handled := make(chan struct{})
		go func() {
			defer close(handled)
			s.handle(&pipeTransportStream{Conn: b}, "p")
		}()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		r, e := exchangeVerified(ctx, &pipeTransportStream{Conn: a}, target)
		select {
		case <-handled:
		case <-time.After(time.Second):
			t.Fatal("server handler did not finish")
		}
		require.NoError(t, e)
		return r
	}
	require.Equal(t, OutcomeUnavailable, request().Outcome())
	require.Equal(t, OutcomeBusy, request().Outcome())
}

type slowOpener struct{ seen time.Time }

func (h *slowOpener) CreateStream(ctx context.Context, _ peer.ID, _ string) (libp2pnetwork.Stream, error) {
	<-ctx.Done()
	h.seen = time.Now()
	return nil, ctx.Err()
}

func TestTransportDialAndExchangeShareOneBudget(t *testing.T) {
	_, target := fixtureTarget(t)
	h := &slowOpener{}
	start := time.Now()
	_, err := RequestVerified(context.Background(), h, "peer", target, 40*time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), time.Second)
}

type delayedStream struct {
	libp2pnetwork.Stream
	conn     net.Conn
	deadline time.Time
}

func (s *delayedStream) Read(p []byte) (int, error)    { return s.conn.Read(p) }
func (s *delayedStream) Write(p []byte) (int, error)   { return s.conn.Write(p) }
func (s *delayedStream) Close() error                  { return s.conn.Close() }
func (s *delayedStream) CloseWrite() error             { return nil }
func (s *delayedStream) Reset() error                  { return s.conn.Close() }
func (s *delayedStream) SetDeadline(d time.Time) error { s.deadline = d; return s.conn.SetDeadline(d) }

var _ libp2pnetwork.Stream = (*delayedStream)(nil)

type delayedSuccessfulOpener struct {
	stream            *delayedStream
	requestedDeadline time.Time
}

func (o *delayedSuccessfulOpener) CreateStream(ctx context.Context, _ peer.ID, _ string) (libp2pnetwork.Stream, error) {
	o.requestedDeadline, _ = ctx.Deadline()
	if err := sleepContext(ctx, 50*time.Millisecond); err != nil {
		return nil, err
	}
	a, b := net.Pipe()
	o.stream = &delayedStream{conn: a}
	go func() { _, _ = ReadRequestFrame(b); <-ctx.Done(); _ = b.Close() }()
	return o.stream, nil
}
func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestTransportSuccessfulDialSharesRemainingBudget(t *testing.T) {
	_, target := fixtureTarget(t)
	opener := &delayedSuccessfulOpener{}
	_, err := RequestVerified(context.Background(), opener, "peer", target, 200*time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NotNil(t, opener.stream)
	require.Equal(t, opener.requestedDeadline, opener.stream.deadline, "dial and exchange retain the same absolute deadline")
}

type cannedResponseStream struct {
	bytes.Reader
	written bytes.Buffer
}

func (s *cannedResponseStream) Write(p []byte) (int, error) { return s.written.Write(p) }

func (s *cannedResponseStream) SetDeadline(time.Time) error { return nil }
func (s *cannedResponseStream) CloseWrite() error           { return nil }
func (s *cannedResponseStream) Close() error                { return nil }
func (s *cannedResponseStream) Reset() error                { return nil }

func TestTransportCompletedResponseAfterDeadlineIsRejected(t *testing.T) {
	_, target := fixtureTarget(t)
	var frame bytes.Buffer
	require.NoError(t, WriteResponseFrame(&frame, Response{Request: target.Request(), Outcome: OutcomeUnavailable}))
	st := &cannedResponseStream{Reader: *bytes.NewReader(frame.Bytes())}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := exchangeVerified(ctx, st, target)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

type blockingResponseProvider struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *blockingResponseProvider) Serve(ctx context.Context, req Request) (Response, error) {
	p.once.Do(func() { close(p.started) })
	select {
	case <-p.release:
		return Response{Request: req, Outcome: OutcomeUnavailable}, nil
	case <-ctx.Done():
		return Response{}, ctx.Err()
	}
}

func TestTransportServeSaturationAndOperationTimeout(t *testing.T) {
	_, target := fixtureTarget(t)
	provider := &blockingResponseProvider{started: make(chan struct{}), release: make(chan struct{})}
	limits := testLimits()
	limits.MaxPendingStreams = 2
	limits.MaxPendingStreamsPerPeer = 2
	limits.MaxConcurrentServes = 1
	server, err := NewServer(context.Background(), provider, []peer.ID{"peer"}, limits)
	require.NoError(t, err)
	defer server.Close()
	firstA, firstB := net.Pipe()
	firstDone := make(chan struct{})
	go func() { server.handle(&pipeTransportStream{Conn: firstB}, "peer"); close(firstDone) }()
	firstResult := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := exchangeVerified(ctx, &pipeTransportStream{Conn: firstA}, target)
		firstResult <- err
	}()
	<-provider.started
	secondA, secondB := net.Pipe()
	go server.handle(&pipeTransportStream{Conn: secondB}, "peer")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	second, err := exchangeVerified(ctx, &pipeTransportStream{Conn: secondA}, target)
	require.NoError(t, err)
	require.Equal(t, OutcomeBusy, second.Outcome())
	close(provider.release)
	require.NoError(t, <-firstResult)
	<-firstDone

	timedProvider := &blockingResponseProvider{started: make(chan struct{}), release: make(chan struct{})}
	short := testLimits()
	short.Deadline = 40 * time.Millisecond
	timed, err := NewServer(context.Background(), timedProvider, []peer.ID{"peer"}, short)
	require.NoError(t, err)
	defer timed.Close()
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { timed.handle(&pipeTransportStream{Conn: b}, "peer"); close(done) }()
	go func() { _ = WriteRequestFrame(a, target.Request()) }()
	<-timedProvider.started
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server operation exceeded deadline")
	}
	require.Eventually(t, func() bool { n, _ := timed.Pending(); return n == 0 }, time.Second, time.Millisecond)
	_ = a.Close()
}

type joinProvider struct {
	started     chan struct{}
	release     chan struct{}
	once        sync.Once
	releaseOnce sync.Once
}

func (p *joinProvider) Serve(_ context.Context, req Request) (Response, error) {
	p.once.Do(func() { close(p.started) })
	<-p.release
	return Response{Request: req, Outcome: OutcomeUnavailable}, nil
}

func (p *joinProvider) unblock() { p.releaseOnce.Do(func() { close(p.release) }) }

func TestTransportConcurrentCloseWaitsForSameJoin(t *testing.T) {
	_, target := fixtureTarget(t)
	provider := &joinProvider{started: make(chan struct{}), release: make(chan struct{})}
	server, err := NewServer(context.Background(), provider, []peer.ID{"peer"}, testLimits())
	require.NoError(t, err)
	t.Cleanup(func() { provider.unblock(); server.Close() })
	a, b := net.Pipe()
	defer a.Close()
	go server.handle(&pipeTransportStream{Conn: b}, "peer")
	go func() { _ = WriteRequestFrame(a, target.Request()) }()
	<-provider.started
	one, two := make(chan struct{}), make(chan struct{})
	go func() { server.Close(); close(one) }()
	go func() { server.Close(); close(two) }()
	select {
	case <-one:
		t.Fatal("first Close returned before handler joined")
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-two:
		t.Fatal("second Close returned before handler joined")
	case <-time.After(20 * time.Millisecond):
	}
	provider.unblock()
	select {
	case <-one:
	case <-time.After(time.Second):
		t.Fatal("first Close did not join")
	}
	select {
	case <-two:
	case <-time.After(time.Second):
		t.Fatal("second Close did not share join")
	}
}
