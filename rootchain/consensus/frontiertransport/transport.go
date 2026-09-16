package frontiertransport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

const MaxExchangeDuration = 5 * time.Second

const (
	MaxEligiblePeers         = 1024
	MaxPendingStreams        = 32
	MaxPendingStreamsPerPeer = 4
	MaxRequestsPerSecond     = 64
	MaxBurst                 = 32
)

type Stream interface {
	io.ReadWriter
	SetDeadline(time.Time) error
	CloseWrite() error
	Close() error
	Reset() error
}

type StreamOpener interface {
	CreateStream(context.Context, peer.ID, string) (libp2pnetwork.Stream, error)
}

type ExchangeStatus uint8

const (
	ExchangeFailed ExchangeStatus = iota
	ExchangeComplete
	ExchangeCompleteAfterCancellation
	ExchangeBudgetExhausted
)

// ExchangeResult retains a complete response even when cancellation wins just
// after its final byte. Partial is diagnostic only and is never complete.
type ExchangeResult struct {
	Status   ExchangeStatus
	Raw      []byte
	Partial  []byte
	Complete bool
	Err      error
}

func ExchangeFrontier(ctx context.Context, opener StreamOpener, to peer.ID, request FrontierRequest, budget *ReceiveBudget, limit time.Duration) ExchangeResult {
	b, err := EncodeFrontierRequest(request)
	if err != nil {
		return ExchangeResult{Err: err}
	}
	return exchange(ctx, opener, to, FrontierProtocolID, b, budget, limit)
}

func ExchangeCut(ctx context.Context, opener StreamOpener, to peer.ID, request CutRequest, budget *ReceiveBudget, limit time.Duration) ExchangeResult {
	b, err := EncodeCutRequest(request)
	if err != nil {
		return ExchangeResult{Err: err}
	}
	return exchange(ctx, opener, to, CutProtocolID, b, budget, limit)
}

func exchange(ctx context.Context, opener StreamOpener, to peer.ID, protocol string, request []byte, budget *ReceiveBudget, limit time.Duration) ExchangeResult {
	if ctx == nil || opener == nil || to == "" || limit <= 0 || limit > MaxExchangeDuration {
		return ExchangeResult{Err: ErrBounds}
	}
	if err := budget.begin(); err != nil {
		status := ExchangeFailed
		if errors.Is(err, ErrBudget) {
			status = ExchangeBudgetExhausted
		}
		return ExchangeResult{Status: status, Err: err}
	}
	defer budget.end()
	opCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	st, err := opener.CreateStream(opCtx, to, protocol)
	if err != nil {
		return ExchangeResult{Err: preferContext(opCtx, err)}
	}
	if st == nil {
		return ExchangeResult{Err: ErrWire}
	}
	return exchangeStream(opCtx, st, request, budget)
}

func exchangeStream(ctx context.Context, st Stream, request []byte, budget *ReceiveBudget) ExchangeResult {
	if dl, ok := ctx.Deadline(); ok {
		if err := st.SetDeadline(dl); err != nil {
			_ = st.Reset()
			return ExchangeResult{Err: preferContext(ctx, err)}
		}
	}
	stop, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-ctx.Done():
			_ = st.Reset()
		case <-stop:
		}
	}()
	finishWatcher := func() { close(stop); <-joined }
	if err := writeFrame(st, request, MaxRequestBytes); err != nil {
		finishWatcher()
		_ = st.Reset()
		return ExchangeResult{Err: preferContext(ctx, err)}
	}
	_ = st.CloseWrite()
	body, partial, err := readBudgetedFrame(st, budget)
	finishWatcher()
	if body != nil {
		_ = st.Close()
		finalErr := err
		status := ExchangeComplete
		if cerr := contextResult(ctx); cerr != nil {
			finalErr = cerr
			status = ExchangeCompleteAfterCancellation
		}
		return ExchangeResult{Status: status, Raw: body, Complete: true, Err: finalErr}
	}
	if err != nil {
		_ = st.Reset()
		status := ExchangeFailed
		if errors.Is(err, ErrBudget) {
			status = ExchangeBudgetExhausted
		}
		return ExchangeResult{Status: status, Partial: partial, Err: preferContext(ctx, err)}
	}
	_ = st.Reset()
	return ExchangeResult{Err: ErrWire}
}

func readBudgetedFrame(r io.Reader, budget *ReceiveBudget) ([]byte, []byte, error) {
	var prefix [4]byte
	for i := range prefix {
		if err := budget.reserve(1); err != nil {
			return nil, nil, err
		}
		n, err := io.ReadFull(r, prefix[i:i+1])
		if n > 0 {
			budget.consume(uint64(n))
		}
		if err != nil {
			return nil, nil, fmt.Errorf("%w: response prefix: %v", ErrWire, err)
		}
	}
	n := uint64(binary.BigEndian.Uint32(prefix[:]))
	if n == 0 || n > MaxResponseBytes {
		return nil, nil, ErrBounds
	}
	if err := budget.reserveBody(n); err != nil {
		return nil, nil, err
	}
	body := make([]byte, int(n))
	offset := 0
	for offset < len(body) {
		read, err := r.Read(body[offset:])
		if read > 0 {
			budget.consume(uint64(read))
			offset += read
		}
		if err != nil {
			if offset == len(body) {
				return body, nil, fmt.Errorf("%w: response body: %v", ErrWire, err)
			}
			return nil, body[:offset], fmt.Errorf("%w: response body: %v", ErrWire, err)
		}
		if read == 0 {
			return nil, body[:offset], fmt.Errorf("%w: response body made no progress", ErrWire)
		}
	}
	return body, nil, nil
}

func writeFrame(w io.Writer, body []byte, max int) error {
	if len(body) == 0 || len(body) > max {
		return ErrBounds
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(body)))
	if err := writeExact(w, prefix[:]); err != nil {
		return err
	}
	return writeExact(w, body)
}

func readFrame(r io.Reader, max int) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 || uint64(n) > uint64(max) {
		return nil, ErrBounds
	}
	body := make([]byte, int(n))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

func writeExact(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func preferContext(ctx context.Context, fallback error) error {
	if err := contextResult(ctx); err != nil {
		return err
	}
	return fallback
}

func contextResult(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok && !time.Now().Before(dl) {
		return context.DeadlineExceeded
	}
	return nil
}

type Limits struct {
	Deadline                 time.Duration
	MaxEligiblePeers         int
	MaxPendingStreams        int
	MaxPendingStreamsPerPeer int
	RequestsPerSecond        float64
	Burst                    int
}

func (l Limits) validate() error {
	if l.Deadline <= 0 || l.Deadline > MaxExchangeDuration || l.MaxEligiblePeers <= 0 || l.MaxEligiblePeers > MaxEligiblePeers || l.MaxPendingStreams <= 0 || l.MaxPendingStreams > MaxPendingStreams || l.MaxPendingStreamsPerPeer <= 0 || l.MaxPendingStreamsPerPeer > MaxPendingStreamsPerPeer || l.MaxPendingStreamsPerPeer > l.MaxPendingStreams || l.RequestsPerSecond <= 0 || l.RequestsPerSecond > MaxRequestsPerSecond || math.IsNaN(l.RequestsPerSecond) || math.IsInf(l.RequestsPerSecond, 0) || l.Burst <= 0 || l.Burst > MaxBurst {
		return ErrBounds
	}
	return nil
}

type Handlers struct {
	Frontier func(context.Context, FrontierRequest) ([]byte, error)
	Cut      func(context.Context, CutRequest) ([]byte, error)
}

type peerState struct {
	pending int
	tokens  float64
	last    time.Time
}

// Server is inactive until a caller explicitly registers FrontierHandler and
// CutHandler on a host. Handler callbacks must honor their context.
type Server struct {
	limits   Limits
	handlers Handlers
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	peers    map[peer.ID]*peerState
	total    int
	streams  map[Stream]struct{}
	closed   bool
	wg       sync.WaitGroup
}

func NewServer(parent context.Context, eligible []peer.ID, limits Limits, handlers Handlers) (*Server, error) {
	if parent == nil || handlers.Frontier == nil || handlers.Cut == nil || limits.validate() != nil || len(eligible) == 0 || len(eligible) > limits.MaxEligiblePeers {
		return nil, ErrBounds
	}
	peers := make(map[peer.ID]*peerState, len(eligible))
	now := time.Now()
	for _, id := range eligible {
		if id == "" || peers[id] != nil {
			return nil, ErrBounds
		}
		peers[id] = &peerState{tokens: float64(limits.Burst), last: now}
	}
	ctx, cancel := context.WithCancel(parent)
	return &Server{limits: limits, handlers: handlers, ctx: ctx, cancel: cancel, peers: peers, streams: make(map[Stream]struct{}, limits.MaxPendingStreams)}, nil
}

func (s *Server) FrontierHandler(st libp2pnetwork.Stream) {
	s.ServeFrontier(st.Conn().RemotePeer(), st)
}
func (s *Server) CutHandler(st libp2pnetwork.Stream) { s.ServeCut(st.Conn().RemotePeer(), st) }

func (s *Server) ServeFrontier(from peer.ID, st Stream) {
	s.serve(from, st, func(ctx context.Context, raw []byte) ([]byte, error) {
		r, err := DecodeFrontierRequest(raw)
		if err != nil {
			return nil, err
		}
		return s.handlers.Frontier(ctx, r)
	})
}

func (s *Server) ServeCut(from peer.ID, st Stream) {
	s.serve(from, st, func(ctx context.Context, raw []byte) ([]byte, error) {
		r, err := DecodeCutRequest(raw)
		if err != nil {
			return nil, err
		}
		return s.handlers.Cut(ctx, r)
	})
}

func (s *Server) serve(from peer.ID, st Stream, handler func(context.Context, []byte) ([]byte, error)) {
	if st == nil || !s.admit(from, st) {
		if st != nil {
			_ = st.Reset()
		}
		return
	}
	defer s.release(from, st)
	ctx, cancel := context.WithTimeout(s.ctx, s.limits.Deadline)
	defer cancel()
	if dl, ok := ctx.Deadline(); ok {
		if err := st.SetDeadline(dl); err != nil {
			_ = st.Reset()
			return
		}
	}
	stop, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-ctx.Done():
			_ = st.Reset()
		case <-stop:
		}
	}()
	request, err := readFrame(st, MaxRequestBytes)
	if err == nil {
		var response []byte
		response, err = handler(ctx, request)
		if err == nil && contextResult(ctx) == nil {
			err = writeFrame(st, response, MaxResponseBytes)
		}
	}
	close(stop)
	<-joined
	if err != nil || contextResult(ctx) != nil {
		_ = st.Reset()
		return
	}
	_ = st.Close()
}

func (s *Server) admit(id peer.ID, st Stream) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.peers[id]
	if s.closed || p == nil || s.total >= s.limits.MaxPendingStreams || p.pending >= s.limits.MaxPendingStreamsPerPeer {
		return false
	}
	now := time.Now()
	p.tokens = math.Min(float64(s.limits.Burst), p.tokens+now.Sub(p.last).Seconds()*s.limits.RequestsPerSecond)
	p.last = now
	if p.tokens < 1 {
		return false
	}
	p.tokens--
	p.pending++
	s.total++
	s.streams[st] = struct{}{}
	s.wg.Add(1)
	return true
}

func (s *Server) release(id peer.ID, st Stream) {
	s.mu.Lock()
	delete(s.streams, st)
	p := s.peers[id]
	if p != nil {
		p.pending--
	}
	s.total--
	s.mu.Unlock()
	s.wg.Done()
}

func (s *Server) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.wg.Wait()
		return
	}
	s.closed = true
	s.cancel()
	streams := make([]Stream, 0, len(s.streams))
	for st := range s.streams {
		streams = append(streams, st)
	}
	s.mu.Unlock()
	for _, st := range streams {
		_ = st.Reset()
	}
	s.wg.Wait()
}
