package parentwitness

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

var (
	ErrTransport   = errors.New("parent witness: transport failure")
	ErrNotAdmitted = errors.New("parent witness: stream not admitted")
)

// TransportLimits are explicit deployment bounds. Wire byte limits are fixed by the
// versioned codec and are therefore not configurable here.
type TransportLimits struct {
	Deadline                 time.Duration
	MaxEligiblePeers         int
	MaxPendingStreams        int
	MaxPendingStreamsPerPeer int
	MaxConcurrentServes      int
	RequestsPerSecond        float64
	Burst                    int
}

func (l TransportLimits) validate() error {
	switch {
	case l.Deadline <= 0:
		return fmt.Errorf("%w: deadline must be positive", ErrTransport)
	case l.MaxEligiblePeers <= 0 || l.MaxPendingStreams <= 0 || l.MaxPendingStreamsPerPeer <= 0 || l.MaxConcurrentServes <= 0:
		return fmt.Errorf("%w: concurrency limits must be positive", ErrTransport)
	case l.MaxPendingStreamsPerPeer > l.MaxPendingStreams:
		return fmt.Errorf("%w: per-peer pending limit exceeds global limit", ErrTransport)
	case l.RequestsPerSecond <= 0 || math.IsNaN(l.RequestsPerSecond) || math.IsInf(l.RequestsPerSecond, 0):
		return fmt.Errorf("%w: request rate must be positive and finite", ErrTransport)
	case l.Burst <= 0:
		return fmt.Errorf("%w: burst must be positive", ErrTransport)
	}
	return nil
}

type StreamOpener interface {
	CreateStream(context.Context, peer.ID, string) (libp2pnetwork.Stream, error)
}

type transportStream interface {
	io.ReadWriter
	SetDeadline(time.Time) error
	CloseWrite() error
	Close() error
	Reset() error
}

// RequestVerified performs one dial and one exchange. It returns only a response verified
// against the caller-owned Target; provider selection and retries remain outside this package.
func RequestVerified(ctx context.Context, h StreamOpener, to peer.ID, target Target, deadline time.Duration) (VerifiedResponse, error) {
	if h == nil || !target.Valid() || to == "" || deadline <= 0 {
		return VerifiedResponse{}, fmt.Errorf("%w: invalid client configuration", ErrTransport)
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	st, err := h.CreateStream(ctx, to, ProtocolID)
	if err != nil {
		if cerr := contextResult(ctx); cerr != nil {
			return VerifiedResponse{}, fmt.Errorf("%w: %w", ErrTransport, cerr)
		}
		return VerifiedResponse{}, fmt.Errorf("%w: open stream: %w", ErrTransport, err)
	}
	return exchangeVerified(ctx, st, target)
}

func exchangeVerified(ctx context.Context, st transportStream, target Target) (VerifiedResponse, error) {
	dl, ok := ctx.Deadline()
	if ok {
		if err := st.SetDeadline(dl); err != nil {
			_ = st.Reset()
			if cerr := contextResult(ctx); cerr != nil {
				return VerifiedResponse{}, fmt.Errorf("%w: %w", ErrTransport, cerr)
			}
			return VerifiedResponse{}, fmt.Errorf("%w: set deadline: %v", ErrTransport, err)
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
	err := WriteRequestFrame(st, target.Request())
	if err == nil {
		_ = st.CloseWrite()
		var response VerifiedResponse
		response, err = ReadVerifiedResponseFrame(st, target)
		close(stop)
		<-joined
		if err == nil {
			if cerr := contextResult(ctx); cerr != nil {
				_ = st.Reset()
				return VerifiedResponse{}, fmt.Errorf("%w: %w", ErrTransport, cerr)
			}
			_ = st.Close()
			return response, nil
		}
	} else {
		close(stop)
		<-joined
	}
	_ = st.Reset()
	if cerr := contextResult(ctx); cerr != nil {
		return VerifiedResponse{}, fmt.Errorf("%w: %w", ErrTransport, cerr)
	}
	return VerifiedResponse{}, fmt.Errorf("%w: exchange: %w", ErrTransport, err)
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

type rateState struct {
	tokens float64
	last   time.Time
}

type admission struct {
	mu       sync.Mutex
	total    int
	perPeer  map[peer.ID]int
	rates    map[peer.ID]rateState
	eligible map[peer.ID]struct{}
	limits   TransportLimits
}

func newAdmission(eligible []peer.ID, limits TransportLimits) (*admission, error) {
	if len(eligible) == 0 || len(eligible) > limits.MaxEligiblePeers {
		return nil, fmt.Errorf("%w: eligible peer set must be nonempty and at most MaxEligiblePeers", ErrTransport)
	}
	a := &admission{perPeer: make(map[peer.ID]int), rates: make(map[peer.ID]rateState, len(eligible)), eligible: make(map[peer.ID]struct{}, len(eligible)), limits: limits}
	for _, id := range eligible {
		if id == "" {
			return nil, fmt.Errorf("%w: empty eligible peer", ErrTransport)
		}
		if _, exists := a.eligible[id]; exists {
			return nil, fmt.Errorf("%w: duplicate eligible peer", ErrTransport)
		}
		a.eligible[id] = struct{}{}
		a.rates[id] = rateState{tokens: float64(limits.Burst), last: time.Now()}
	}
	return a, nil
}

func (a *admission) acquire(id peer.ID) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.eligible[id]; !ok {
		return fmt.Errorf("%w: ineligible peer", ErrNotAdmitted)
	}
	if a.total >= a.limits.MaxPendingStreams || a.perPeer[id] >= a.limits.MaxPendingStreamsPerPeer {
		return ErrNotAdmitted
	}
	a.total++
	a.perPeer[id]++
	return nil
}
func (a *admission) release(id peer.ID) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.total--
	if a.perPeer[id]--; a.perPeer[id] == 0 {
		delete(a.perPeer, id)
	}
}
func (a *admission) allow(id peer.ID, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := a.rates[id]
	r.tokens = math.Min(float64(a.limits.Burst), r.tokens+now.Sub(r.last).Seconds()*a.limits.RequestsPerSecond)
	r.last = now
	if r.tokens < 1 {
		a.rates[id] = r
		return false
	}
	r.tokens--
	a.rates[id] = r
	return true
}
func (a *admission) pending() (int, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.total, len(a.perPeer)
}

// Server is inactive until a caller explicitly installs Handler on a libp2p host.
type Server struct {
	provider  ResponseProvider
	limits    TransportLimits
	admission *admission
	serves    chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	streams   map[transportStream]struct{}
	wg        sync.WaitGroup
	closed    bool
	closeOnce sync.Once
}

type ResponseProvider interface {
	Serve(context.Context, Request) (Response, error)
}

func NewServer(parent context.Context, provider ResponseProvider, eligible []peer.ID, limits TransportLimits) (*Server, error) {
	if parent == nil || provider == nil {
		return nil, fmt.Errorf("%w: server requires context and provider", ErrTransport)
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if len(eligible) == 0 || len(eligible) > limits.MaxEligiblePeers {
		return nil, fmt.Errorf("%w: eligible peer set must be nonempty and at most MaxEligiblePeers", ErrTransport)
	}
	a, err := newAdmission(append([]peer.ID(nil), eligible...), limits)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	return &Server{provider: provider, limits: limits, admission: a, serves: make(chan struct{}, limits.MaxConcurrentServes), ctx: ctx, cancel: cancel, streams: make(map[transportStream]struct{})}, nil
}

// Handler serves exactly one request and response. It is exposed for later explicit registration.
func (s *Server) Handler(st libp2pnetwork.Stream) { s.handle(st, st.Conn().RemotePeer()) }

func (s *Server) handle(st transportStream, from peer.ID) {
	if err := s.admission.acquire(from); err != nil {
		_ = st.Reset()
		return
	}
	if !s.track(st) {
		s.admission.release(from)
		_ = st.Reset()
		return
	}
	defer s.untrack(st)
	released := false
	defer func() {
		if !released {
			s.admission.release(from)
		}
	}()
	ctx, cancel := context.WithTimeout(s.ctx, s.limits.Deadline)
	defer cancel()
	dl, _ := ctx.Deadline()
	if err := st.SetDeadline(dl); err != nil {
		_ = st.Reset()
		return
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
	err := s.serve(ctx, st, from)
	close(stop)
	<-joined
	s.admission.release(from)
	released = true
	if err != nil {
		_ = st.Reset()
		return
	}
	_ = st.CloseWrite()
	_ = st.Close()
}

func (s *Server) serve(ctx context.Context, rw io.ReadWriter, from peer.ID) error {
	req, err := ReadRequestFrame(rw)
	if err != nil {
		return err
	}
	if !s.admission.allow(from, time.Now()) {
		return WriteResponseFrame(rw, Response{Request: req, Outcome: OutcomeBusy, Detail: "rate limit"})
	}
	select {
	case s.serves <- struct{}{}:
		defer func() { <-s.serves }()
	default:
		return WriteResponseFrame(rw, Response{Request: req, Outcome: OutcomeBusy, Detail: "serve limit"})
	}
	resp, err := s.provider.Serve(ctx, req)
	if err != nil {
		return err
	}
	return WriteResponseFrame(rw, resp)
}

func (s *Server) track(st transportStream) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.streams[st] = struct{}{}
	s.wg.Add(1)
	return true
}
func (s *Server) untrack(st transportStream) {
	s.mu.Lock()
	delete(s.streams, st)
	s.mu.Unlock()
	s.wg.Done()
}
func (s *Server) Pending() (int, int) { return s.admission.pending() }

// Close cancels and resets active streams, then joins handlers. Provider work must honor its
// context; a provider that ignores cancellation can delay Close and violates the Provider contract.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.cancel()
		streams := make([]transportStream, 0, len(s.streams))
		for st := range s.streams {
			streams = append(streams, st)
		}
		s.mu.Unlock()
		for _, st := range streams {
			_ = st.Reset()
		}
		s.wg.Wait()
	})
}
