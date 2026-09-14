package inputcarrier

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

/*
The shard-internal wire for envelopes: one frame on one stream, from a proposer to a validator.

It decides how an envelope is framed, what a receiver spends holding one, and when a delivery is
refused. It decides nothing about whether the evidence is true; that is Verify's job, against the
receiver's own configured trust. The shape follows shardnode/evidencetransport.go, and not the shared
network.deserializeMsg, which decodes whatever length a peer declares: here the declared length is
checked before a body byte is read.

WHAT AN UNTRUSTED PEER CAN DO THROUGH THIS FILE. Hold at most its per-peer share of the stream bound,
each stream for at most one deadline; send a frame that is discarded without being decoded; deliver at
most one envelope per round, which a later delivery for that round cannot replace; and occupy at most
MaxPendingRounds rounds until the caller prunes them. Availability, never finality.
*/

// Protocol is the carrier's protocol. It is separate from shardnode.ProtocolShardPayload, whose
// messages this unit does not change.
const Protocol = "/unicity/shard-input-witness/1.0.0"

var (
	// ErrTransport marks a failure of the exchange itself: framing, I/O, a frame over the bound.
	ErrTransport = errors.New("inputcarrier: transport")
	// ErrNotAdmitted is a stream turned away before anything was read.
	ErrNotAdmitted = errors.New("inputcarrier: stream not admitted")
	// ErrTooManyRounds is a delivery or Await for a new round when MaxPendingRounds rounds are held.
	ErrTooManyRounds = errors.New("inputcarrier: too many pending rounds")
	// ErrDuplicate is a second delivery for a round that already holds an envelope. The first stays.
	ErrDuplicate = errors.New("inputcarrier: round already holds an envelope")
	// ErrPruned is a delivery or Await for a round at or below the pruning watermark.
	ErrPruned = errors.New("inputcarrier: round already pruned")
	// ErrClosed is returned after Close.
	ErrClosed = errors.New("inputcarrier: receiver closed")
)

// Host is the part of a libp2p host the transport uses. *network.Peer satisfies it.
type Host interface {
	RegisterProtocolHandler(protocolID string, handler libp2pnetwork.StreamHandler)
	CreateStream(ctx context.Context, peerID peer.ID, protocolID string) (libp2pnetwork.Stream, error)
}

// TransportLimits bounds what the transport may cost a receiver.
type TransportLimits struct {
	Envelope Limits

	// Deadline bounds one exchange on both sides.
	Deadline time.Duration

	// MaxPendingStreams and MaxPendingStreamsPerPeer bound streams held at all, from before the first
	// byte is read to the handler's exit, in total and per peer.
	MaxPendingStreams        int
	MaxPendingStreamsPerPeer int

	// MaxPendingRounds bounds how many distinct rounds hold a slot (a delivered envelope, an unmet
	// Await, or both) until Prune releases them.
	MaxPendingRounds int
}

// DefaultTransportLimits are starting values.
var DefaultTransportLimits = TransportLimits{
	Envelope:                 DefaultLimits,
	Deadline:                 2 * time.Second,
	MaxPendingStreams:        32,
	MaxPendingStreamsPerPeer: 4,
	MaxPendingRounds:         8,
}

func (l TransportLimits) validate() error {
	if err := l.Envelope.validate(); err != nil {
		return err
	}
	switch {
	case l.Deadline <= 0:
		return fmt.Errorf("inputcarrier: deadline must be positive, got %s", l.Deadline)
	case l.MaxPendingStreams <= 0, l.MaxPendingStreamsPerPeer <= 0, l.MaxPendingRounds <= 0:
		return fmt.Errorf("inputcarrier: pending bounds must be positive, got %+v", l)
	case l.MaxPendingStreamsPerPeer > l.MaxPendingStreams:
		return fmt.Errorf("inputcarrier: MaxPendingStreamsPerPeer=%d exceeds MaxPendingStreams=%d", l.MaxPendingStreamsPerPeer, l.MaxPendingStreams)
	}
	return nil
}

// Send writes one envelope to one peer. An envelope outside the limits is refused before a stream is
// opened.
func Send(ctx context.Context, h Host, to peer.ID, e Envelope, l TransportLimits) error {
	if err := l.validate(); err != nil {
		return err
	}
	body, err := Encode(e, l.Envelope)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, l.Deadline)
	defer cancel()
	s, err := h.CreateStream(ctx, to, Protocol)
	if err != nil {
		return fmt.Errorf("%w: opening stream to %s: %w", ErrTransport, to, err)
	}
	if err := s.SetDeadline(time.Now().Add(l.Deadline)); err != nil {
		_ = s.Reset()
		return fmt.Errorf("%w: setting deadline: %w", ErrTransport, err)
	}
	if err := writeFrame(s, body); err != nil {
		_ = s.Reset()
		return err
	}
	_ = s.CloseWrite()
	return s.Close()
}

// slot is one round's delivery. env is set once, and ready is closed when it is.
type slot struct {
	env   *Envelope
	ready chan struct{}
}

// Receiver holds envelopes delivered for rounds until the caller prunes them.
type Receiver struct {
	limits TransportLimits
	log    *slog.Logger

	admMu      sync.Mutex
	admTotal   int
	admPerPeer map[string]int

	mu        sync.Mutex
	slots     map[uint64]*slot
	watermark uint64
	pruned    bool // whether watermark has been set
	closed    bool
	done      chan struct{}
}

func NewReceiver(l TransportLimits, log *slog.Logger) (*Receiver, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}
	return &Receiver{
		limits: l, log: log, admPerPeer: map[string]int{},
		slots: map[uint64]*slot{}, done: make(chan struct{}),
	}, nil
}

// Register installs the stream handler on h.
func (r *Receiver) Register(h Host) { h.RegisterProtocolHandler(Protocol, r.handleStream) }

func (r *Receiver) handleStream(s libp2pnetwork.Stream) {
	from := s.Conn().RemotePeer().String()
	if err := s.SetDeadline(time.Now().Add(r.limits.Deadline)); err != nil {
		_ = s.Reset()
		return
	}
	if err := r.Serve(s, from); err != nil {
		if r.log != nil {
			r.log.Debug("receiving input witness", "peer", from, "err", err.Error())
		}
		_ = s.Reset()
		return
	}
	_ = s.Close()
}

/*
Serve reads one frame from one stream, decodes it strictly and delivers it. Admission is taken before
the first byte is read, so a stream that never sends a frame still counts against the bounds; what
ends such a stream is the deadline its caller sets (handleStream does).
*/
func (r *Receiver) Serve(rd io.Reader, from string) error {
	if err := r.acquire(from); err != nil {
		return err
	}
	defer r.release(from)

	body, err := readFrame(bufio.NewReader(rd), r.limits.Envelope.FrameBytes())
	if err != nil {
		return err
	}
	e, err := Decode(body, r.limits.Envelope)
	if err != nil {
		return err
	}
	return r.deliver(e)
}

func (r *Receiver) acquire(from string) error {
	r.admMu.Lock()
	defer r.admMu.Unlock()
	if r.admTotal >= r.limits.MaxPendingStreams {
		return fmt.Errorf("%w: %d streams pending, the limit", ErrNotAdmitted, r.admTotal)
	}
	if r.admPerPeer[from] >= r.limits.MaxPendingStreamsPerPeer {
		return fmt.Errorf("%w: %s holds %d of its %d streams", ErrNotAdmitted, from, r.admPerPeer[from], r.limits.MaxPendingStreamsPerPeer)
	}
	r.admTotal++
	r.admPerPeer[from]++
	return nil
}

// release must run on every exit from Serve.
func (r *Receiver) release(from string) {
	r.admMu.Lock()
	defer r.admMu.Unlock()
	r.admTotal--
	if n := r.admPerPeer[from] - 1; n > 0 {
		r.admPerPeer[from] = n
	} else {
		delete(r.admPerPeer, from)
	}
}

// PendingStreams reports admitted streams and the distinct peers holding them.
func (r *Receiver) PendingStreams() (streams, peers int) {
	r.admMu.Lock()
	defer r.admMu.Unlock()
	return r.admTotal, len(r.admPerPeer)
}

// PendingRounds reports how many rounds hold a slot.
func (r *Receiver) PendingRounds() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.slots)
}

// slotLocked returns the round's slot, creating it within the bound. r.mu must be held.
func (r *Receiver) slotLocked(round uint64) (*slot, error) {
	if r.closed {
		return nil, ErrClosed
	}
	if r.pruned && round <= r.watermark {
		return nil, fmt.Errorf("%w: round %d, watermark %d", ErrPruned, round, r.watermark)
	}
	s, ok := r.slots[round]
	if !ok {
		if len(r.slots) >= r.limits.MaxPendingRounds {
			return nil, fmt.Errorf("%w: %d rounds held", ErrTooManyRounds, len(r.slots))
		}
		s = &slot{ready: make(chan struct{})}
		r.slots[round] = s
	}
	return s, nil
}

func (r *Receiver) deliver(e Envelope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, err := r.slotLocked(e.ShardRound)
	if err != nil {
		return err
	}
	if s.env != nil {
		return fmt.Errorf("%w: round %d", ErrDuplicate, e.ShardRound)
	}
	s.env = &e
	close(s.ready)
	return nil
}

// Await returns a copy of the envelope delivered for round, or an error. Every Await for a round sees
// the same first delivery. The slot stays until Prune, so the caller must prune rounds it has finished
// with, or new rounds are eventually refused with ErrTooManyRounds.
func (r *Receiver) Await(ctx context.Context, round uint64) (Envelope, error) {
	r.mu.Lock()
	s, err := r.slotLocked(round)
	r.mu.Unlock()
	if err != nil {
		return Envelope{}, err
	}
	select {
	case <-s.ready:
		r.mu.Lock()
		defer r.mu.Unlock()
		return s.env.clone(), nil
	case <-r.done:
		return Envelope{}, ErrClosed
	case <-ctx.Done():
		return Envelope{}, fmt.Errorf("inputcarrier: awaiting round %d: %w", round, ctx.Err())
	}
}

// Prune releases every slot at or below round, and refuses later deliveries and Awaits for them.
func (r *Receiver) Prune(round uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.pruned || round > r.watermark {
		r.watermark, r.pruned = round, true
	}
	for k := range r.slots {
		if k <= r.watermark {
			delete(r.slots, k)
		}
	}
}

// Close refuses further deliveries and ends pending Awaits.
func (r *Receiver) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	close(r.done)
}

// writeFrame writes one uvarint-length-prefixed frame, the repository's framing.
func writeFrame(w io.Writer, body []byte) error {
	prefix := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(prefix, uint64(len(body)))
	if _, err := w.Write(append(prefix[:n], body...)); err != nil {
		return fmt.Errorf("%w: writing frame: %w", ErrTransport, err)
	}
	return nil
}

// readFrame reads one frame, checking the declared length against max before reading the body.
func readFrame(r *bufio.Reader, max int) ([]byte, error) {
	length, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, fmt.Errorf("%w: reading frame length: %w", ErrTransport, err)
	}
	if length == 0 || length > uint64(max) {
		return nil, fmt.Errorf("%w: frame declares %d bytes, bound 1..%d", ErrTransport, length, max)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("%w: reading %d-byte frame: %w", ErrTransport, length, err)
	}
	return body, nil
}
