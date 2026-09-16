package frontiertransport

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/internal/frontiercodec"
)

type pipeStream struct{ net.Conn }

func (s *pipeStream) CloseWrite() error { return nil }
func (s *pipeStream) Reset() error      { return s.Close() }

type testOpener func(context.Context, peer.ID, string) (Stream, error)

func (o testOpener) CreateStream(ctx context.Context, to peer.ID, protocol string) (libp2pnetwork.Stream, error) {
	st, err := o(ctx, to, protocol)
	if err != nil || st == nil {
		return nil, err
	}
	return &networkStreamAdapter{stream: st}, nil
}

type networkStreamAdapter struct {
	libp2pnetwork.Stream
	stream Stream
}

func (s *networkStreamAdapter) Read(p []byte) (int, error)    { return s.stream.Read(p) }
func (s *networkStreamAdapter) Write(p []byte) (int, error)   { return s.stream.Write(p) }
func (s *networkStreamAdapter) SetDeadline(t time.Time) error { return s.stream.SetDeadline(t) }
func (s *networkStreamAdapter) CloseWrite() error             { return s.stream.CloseWrite() }
func (s *networkStreamAdapter) Close() error                  { return s.stream.Close() }
func (s *networkStreamAdapter) Reset() error                  { return s.stream.Reset() }

func testContext() frontiercodec.Context {
	return frontiercodec.Context{NetworkID: 5, PartitionID: 0xff0001, CanonicalShardBytes: []byte{0x80}, FullShardConfHash: bytes.Repeat([]byte{1}, 32), RootEpoch: 1, GenesisOriginIdentity: bytes.Repeat([]byte{2}, 32)}
}

func testFrontierRequest(t *testing.T) []byte {
	t.Helper()
	b, err := EncodeFrontierRequest(FrontierRequest{Version: 1, Context: testContext(), Nonce: bytes.Repeat([]byte{3}, 32)})
	require.NoError(t, err)
	return b
}

func testLimits() Limits {
	return Limits{Deadline: time.Second, MaxEligiblePeers: 2, MaxPendingStreams: 2, MaxPendingStreamsPerPeer: 1, RequestsPerSecond: 64, Burst: 2}
}

func TestExchangeReturnsCompleteRawAcrossCancellationRace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	body := []byte("complete signed response")
	var framed bytes.Buffer
	require.NoError(t, writeFrame(&framed, body, MaxResponseBytes))
	st := &cancelAfterReadStream{Reader: bytes.NewReader(framed.Bytes()), cancel: cancel}
	budget, err := NewReceiveBudget(1024)
	require.NoError(t, err)
	result := ExchangeFrontier(ctx, testOpener(func(context.Context, peer.ID, string) (Stream, error) { return st, nil }), "peer", FrontierRequest{Version: 1, Context: testContext(), Nonce: bytes.Repeat([]byte{3}, 32)}, budget, time.Second)
	require.True(t, result.Complete)
	require.Equal(t, body, result.Raw)
	require.ErrorIs(t, result.Err, context.Canceled)
	require.Equal(t, ExchangeCompleteAfterCancellation, result.Status)
	require.Empty(t, result.Partial)
}

func TestExchangePreservesCompleteBodyReturnedWithTerminalError(t *testing.T) {
	for _, terminal := range []error{io.EOF, context.Canceled} {
		t.Run(terminal.Error(), func(t *testing.T) {
			body := []byte("complete")
			var framed bytes.Buffer
			require.NoError(t, writeFrame(&framed, body, MaxResponseBytes))
			st := &terminalReadStream{data: framed.Bytes(), terminal: terminal}
			budget, err := NewReceiveBudget(1024)
			require.NoError(t, err)
			result := exchangeStream(context.Background(), st, testFrontierRequest(t), budget)
			require.True(t, result.Complete)
			require.Equal(t, body, result.Raw)
			require.Error(t, result.Err)
			require.Empty(t, result.Partial)
		})
	}
}

type terminalReadStream struct {
	data     []byte
	offset   int
	terminal error
	writes   bytes.Buffer
}

func (s *terminalReadStream) Read(p []byte) (int, error) {
	if s.offset >= len(s.data) {
		return 0, s.terminal
	}
	n := copy(p, s.data[s.offset:])
	s.offset += n
	if s.offset == len(s.data) {
		return n, s.terminal
	}
	return n, nil
}
func (s *terminalReadStream) Write(p []byte) (int, error) { return s.writes.Write(p) }
func (s *terminalReadStream) SetDeadline(time.Time) error { return nil }
func (s *terminalReadStream) CloseWrite() error           { return nil }
func (s *terminalReadStream) Close() error                { return nil }
func (s *terminalReadStream) Reset() error                { return nil }

type cancelAfterReadStream struct {
	io.Reader
	cancel context.CancelFunc
	writes bytes.Buffer
	once   sync.Once
}

func (s *cancelAfterReadStream) Read(p []byte) (int, error) {
	n, err := s.Reader.Read(p)
	if n > 0 {
		s.once.Do(s.cancel)
	}
	return n, err
}
func (s *cancelAfterReadStream) Write(p []byte) (int, error) { return s.writes.Write(p) }
func (s *cancelAfterReadStream) SetDeadline(time.Time) error { return nil }
func (s *cancelAfterReadStream) CloseWrite() error           { return nil }
func (s *cancelAfterReadStream) Close() error                { return nil }
func (s *cancelAfterReadStream) Reset() error                { return nil }

func TestReceiveBudgetCountsPartialAndMalformedFramesWithoutRefund(t *testing.T) {
	budget, err := NewReceiveBudget(32)
	require.NoError(t, err)
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], 10)
	input := append(prefix[:], []byte{1, 2, 3}...)
	body, partial, err := readBudgetedFrame(bytes.NewReader(input), budget)
	require.Error(t, err)
	require.Nil(t, body)
	require.Equal(t, []byte{1, 2, 3}, partial)
	s := budget.Snapshot()
	require.EqualValues(t, 14, s.Committed)
	require.EqualValues(t, 7, s.Consumed)

	binary.BigEndian.PutUint32(prefix[:], MaxResponseBytes+1)
	_, _, err = readBudgetedFrame(bytes.NewReader(prefix[:]), budget)
	require.ErrorIs(t, err, ErrBounds)
	s = budget.Snapshot()
	require.EqualValues(t, 18, s.Committed)
	require.EqualValues(t, 11, s.Consumed)
}

func TestSharedReceiveBudgetReservesBeforeBodyRead(t *testing.T) {
	budget, err := NewReceiveBudget(MaxReceiveBudget)
	require.NoError(t, err)
	first := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseReader := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseReader)
	var firstPrefix [4]byte
	binary.BigEndian.PutUint32(firstPrefix[:], 700<<10)
	reader := io.MultiReader(bytes.NewReader(firstPrefix[:]), &gatedBodyReader{entered: first, release: release})
	done := make(chan error, 1)
	go func() { _, _, err := readBudgetedFrame(reader, budget); done <- err }()
	select {
	case <-first:
	case <-time.After(time.Second):
		t.Fatal("first body reservation did not occur")
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], 400<<10)
	_, _, err = readBudgetedFrame(bytes.NewReader(prefix[:]), budget)
	require.ErrorIs(t, err, ErrBudget)
	releaseReader()
	select {
	case readErr := <-done:
		require.Error(t, readErr)
	case <-time.After(time.Second):
		t.Fatal("reserved reader did not finish")
	}
	s := budget.Snapshot()
	require.LessOrEqual(t, s.Committed, s.Limit)
}

type gatedBodyReader struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *gatedBodyReader) Read([]byte) (int, error) {
	r.once.Do(func() { close(r.entered) })
	<-r.release
	return 0, io.EOF
}

func TestServerAdmissionCloseAndDeadline(t *testing.T) {
	entered := make(chan struct{}, 1)
	handlers := Handlers{
		Frontier: func(ctx context.Context, _ FrontierRequest) ([]byte, error) {
			entered <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		},
		Cut: func(context.Context, CutRequest) ([]byte, error) { return []byte{1}, nil },
	}
	limits := testLimits()
	limits.Deadline = 5 * time.Second
	server, err := NewServer(context.Background(), []peer.ID{"peer-a"}, limits, handlers)
	require.NoError(t, err)
	a, b := net.Pipe()
	defer a.Close()
	go server.ServeFrontier("peer-a", &pipeStream{b})
	require.NoError(t, writeFrame(a, testFrontierRequest(t), MaxRequestBytes))
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	secondA, secondB := net.Pipe()
	go server.ServeFrontier("peer-a", &pipeStream{secondB})
	require.NoError(t, secondA.SetReadDeadline(time.Now().Add(time.Second)))
	var one [1]byte
	_, err = secondA.Read(one[:])
	require.Error(t, err)
	_ = secondA.Close()
	closed := make(chan struct{})
	go func() { server.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("server close did not cancel and join callback")
	}
}

func TestExchangeDialUsesSameDeadlineAndConcurrentCapIsNotLifetimeCap(t *testing.T) {
	budget, err := NewReceiveBudget(1024)
	require.NoError(t, err)
	for range 6 {
		result := ExchangeFrontier(context.Background(), testOpener(func(ctx context.Context, _ peer.ID, _ string) (Stream, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}), "peer", FrontierRequest{Version: 1, Context: testContext(), Nonce: bytes.Repeat([]byte{3}, 32)}, budget, 5*time.Millisecond)
		require.ErrorIs(t, result.Err, context.DeadlineExceeded)
	}
	s := budget.Snapshot()
	require.EqualValues(t, 6, s.Attempts)
	require.Zero(t, s.Active)
}

func TestServerGlobalPerPeerAndRateLimits(t *testing.T) {
	handlers := Handlers{Frontier: func(context.Context, FrontierRequest) ([]byte, error) { return []byte{1}, nil }, Cut: func(context.Context, CutRequest) ([]byte, error) { return []byte{1}, nil }}
	noop := func() Stream { return &cancelAfterReadStream{Reader: bytes.NewReader(nil), cancel: func() {}} }
	t.Run("global distinct peers", func(t *testing.T) {
		l := testLimits()
		l.MaxPendingStreams = 1
		s, err := NewServer(context.Background(), []peer.ID{"a", "b"}, l, handlers)
		require.NoError(t, err)
		one, two := noop(), noop()
		require.True(t, s.admit("a", one))
		require.False(t, s.admit("b", two))
		s.release("a", one)
		s.Close()
	})
	t.Run("per peer with global spare", func(t *testing.T) {
		s, err := NewServer(context.Background(), []peer.ID{"a", "b"}, testLimits(), handlers)
		require.NoError(t, err)
		one, two := noop(), noop()
		require.True(t, s.admit("a", one))
		require.False(t, s.admit("a", two))
		s.release("a", one)
		s.Close()
	})
	t.Run("sequential burst", func(t *testing.T) {
		l := testLimits()
		l.Burst, l.RequestsPerSecond = 1, 0.01
		s, err := NewServer(context.Background(), []peer.ID{"a"}, l, handlers)
		require.NoError(t, err)
		one, two := noop(), noop()
		require.True(t, s.admit("a", one))
		s.release("a", one)
		require.False(t, s.admit("a", two))
		s.Close()
	})
}
