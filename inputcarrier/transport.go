package inputcarrier

import (
	"bufio"
	"context"
	"crypto/sha256"
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

It decides how an envelope is framed, what a receiver spends holding candidates, and when a delivery is
refused. It decides nothing about whether the evidence is true: that is Verify's job, run by the caller
against its own configured trust. The shape follows shardnode/evidencetransport.go, and not the shared
network.deserializeMsg, which decodes whatever length a peer declares: here the declared length is
checked before a body byte is read.

ADMISSION IS SCOPED BY THE CALLER, AND ARRIVAL ORDER DECIDES NOTHING (review 5196428126, P1). A receiver
accepts deliveries only for rounds the caller has declared with Expect, and only for the block that
declaration names (and, when given, from the expected proposer). Within a declared round it holds a
bounded set of distinct candidates, at most one pending per peer. The caller examines candidates with
Await, and answers each with Reject or Accept after verifying it. A rejected candidate is removed and
remembered, so it cannot occupy the round again, and its sender is charged for it; an honest witness
that arrives before or after the rejection still has room. Nothing here chooses between candidates by
arrival or replaces one with a later one: only the caller's verdict settles a round.

WHAT AN UNTRUSTED PEER CAN DO THROUGH THIS FILE. Hold at most its per-peer share of the stream bound,
each stream for at most one deadline; send a frame that is discarded without being decoded; place at
most one pending candidate in a round the caller declared, and at most MaxRejectsPerPeer rejected ones;
and cost the caller one verification per candidate. It cannot open a round, fill rounds the caller did
not declare, or keep an honest witness out of a declared round. Availability, never finality.
*/

// Protocol is the carrier's protocol. It is separate from shardnode.ProtocolShardPayload, whose
// messages this unit does not change.
const Protocol = "/unicity/shard-input-witness/1.0.0"

var (
	// ErrTransport marks a failure of the exchange itself: framing, I/O, a frame over the bound, or
	// the caller's budget running out.
	ErrTransport = errors.New("inputcarrier: transport")
	// ErrNotAdmitted is a stream turned away before anything was read.
	ErrNotAdmitted = errors.New("inputcarrier: stream not admitted")
	// ErrTooManyRounds is an Expect for a new round when MaxPendingRounds rounds are declared.
	ErrTooManyRounds = errors.New("inputcarrier: too many declared rounds")
	// ErrUnexpectedRound is a delivery, Await, Reject or Accept for a round the caller has not declared.
	ErrUnexpectedRound = errors.New("inputcarrier: round not declared")
	// ErrUnexpectedBlock is a delivery bound to another block than the declared one.
	ErrUnexpectedBlock = errors.New("inputcarrier: envelope for another block")
	// ErrUnexpectedSender is a delivery from another sender than the declared proposer.
	ErrUnexpectedSender = errors.New("inputcarrier: envelope from another sender")
	// ErrDuplicate is a delivery of bytes identical to a candidate already pending.
	ErrDuplicate = errors.New("inputcarrier: identical candidate already pending")
	// ErrRejected is a delivery of bytes identical to a candidate the caller rejected.
	ErrRejected = errors.New("inputcarrier: candidate already rejected")
	// ErrPeerHasCandidate is a delivery from a peer that already has a candidate pending in the round.
	ErrPeerHasCandidate = errors.New("inputcarrier: sender already has a pending candidate")
	// ErrPeerExhausted is a delivery from a peer whose candidates were rejected MaxRejectsPerPeer times.
	ErrPeerExhausted = errors.New("inputcarrier: sender exhausted its rejections for the round")
	// ErrCandidatesFull is a delivery when MaxCandidatesPerRound candidates are pending.
	ErrCandidatesFull = errors.New("inputcarrier: round holds its maximum candidates")
	// ErrRoundSettled is a delivery, Reject or Accept for a round the caller already settled.
	ErrRoundSettled = errors.New("inputcarrier: round already settled")
	// ErrNoSuchCandidate is a Reject or Accept for bytes that are not a pending candidate.
	ErrNoSuchCandidate = errors.New("inputcarrier: no such pending candidate")
	// ErrPruned is any operation for a round at or below the pruning watermark.
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

	// Deadline bounds one exchange. For Send it is an upper bound on the whole operation, dial
	// included; a caller's own earlier deadline or cancellation still applies.
	Deadline time.Duration

	// MaxPendingStreams and MaxPendingStreamsPerPeer bound streams held at all, from before the first
	// byte is read to the handler's exit, in total and per peer.
	MaxPendingStreams        int
	MaxPendingStreamsPerPeer int

	// MaxPendingRounds bounds how many rounds the caller may have declared and not yet pruned.
	MaxPendingRounds int

	// MaxCandidatesPerRound bounds pending candidates in one round.
	MaxCandidatesPerRound int

	// MaxRejectsPerPeer bounds how many of one sender's candidates may be rejected in one round before
	// that sender is refused for the round.
	MaxRejectsPerPeer int

	// MaxRejectedPerRound bounds how many rejected digests one round remembers. Past it, the oldest is
	// forgotten; the per-peer rejection bound still charges its sender.
	MaxRejectedPerRound int
}

// DefaultTransportLimits are starting values.
var DefaultTransportLimits = TransportLimits{
	Envelope:                 DefaultLimits,
	Deadline:                 2 * time.Second,
	MaxPendingStreams:        32,
	MaxPendingStreamsPerPeer: 4,
	MaxPendingRounds:         8,
	MaxCandidatesPerRound:    4,
	MaxRejectsPerPeer:        2,
	MaxRejectedPerRound:      16,
}

func (l TransportLimits) validate() error {
	if err := l.Envelope.validate(); err != nil {
		return err
	}
	switch {
	case l.Deadline <= 0:
		return fmt.Errorf("inputcarrier: deadline must be positive, got %s", l.Deadline)
	case l.MaxPendingStreams <= 0, l.MaxPendingStreamsPerPeer <= 0, l.MaxPendingRounds <= 0,
		l.MaxCandidatesPerRound <= 0, l.MaxRejectsPerPeer <= 0, l.MaxRejectedPerRound <= 0:
		return fmt.Errorf("inputcarrier: bounds must be positive, got %+v", l)
	case l.MaxPendingStreamsPerPeer > l.MaxPendingStreams:
		return fmt.Errorf("inputcarrier: MaxPendingStreamsPerPeer=%d exceeds MaxPendingStreams=%d", l.MaxPendingStreamsPerPeer, l.MaxPendingStreams)
	}
	return nil
}

/*
Send writes one envelope to one peer within one budget: the earlier of the caller's deadline and
l.Deadline from the moment Send is called. Dialing spends that budget; the stream gets the same
absolute deadline rather than a fresh one; and cancellation of the caller's context resets the stream
so a blocked write returns (review 5196428126, P2). The watcher that does so is stopped and joined
before Send returns. An error caused by the budget carries the context's cause, so
errors.Is(err, context.DeadlineExceeded) or context.Canceled holds.

An envelope outside the limits is refused before a stream is opened.
*/
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
	deadline, _ := ctx.Deadline() // always set: WithTimeout

	budgetErr := func(what string, err error) error {
		cause := context.Cause(ctx)
		// The stream's I/O deadline is the context's deadline, and the two timers are independent: an
		// I/O timeout can surface a moment before the context records its own expiry. An error at or
		// after the shared deadline is the budget running out either way.
		if cause == nil && !time.Now().Before(deadline) {
			cause = context.DeadlineExceeded
		}
		if cause != nil {
			return fmt.Errorf("%w: %s: %w (%w)", ErrTransport, what, cause, err)
		}
		return fmt.Errorf("%w: %s: %w", ErrTransport, what, err)
	}

	s, err := h.CreateStream(ctx, to, Protocol)
	if err != nil {
		return budgetErr("opening stream to "+to.String(), err)
	}
	if err := ctx.Err(); err != nil {
		_ = s.Reset()
		return budgetErr("after opening stream", err)
	}
	if err := s.SetDeadline(deadline); err != nil {
		_ = s.Reset()
		return budgetErr("setting deadline", err)
	}

	stop := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = s.Reset()
		case <-stop:
		}
	}()
	defer func() {
		close(stop)
		<-watcherDone
	}()

	if err := writeFrame(s, body); err != nil {
		_ = s.Reset()
		return budgetErr("writing", err)
	}
	if err := s.CloseWrite(); err != nil {
		_ = s.Reset()
		return budgetErr("closing write", err)
	}
	if err := s.Close(); err != nil {
		return budgetErr("closing", err)
	}
	return nil
}

// Expectation is what the caller declares for a round before it admits deliveries.
type Expectation struct {
	// BlockHash is the 32-byte hash of the block the caller holds for the round. Only envelopes bound
	// to it are admitted.
	BlockHash []byte
	// Proposer, when non-empty, is the only sender whose deliveries are admitted.
	Proposer string
}

type candidate struct {
	digest [32]byte
	env    Envelope
	from   string
}

type roundState struct {
	expect        Expectation
	pending       []candidate
	rejected      map[[32]byte]struct{}
	rejectedOrder [][32]byte
	rejectsByPeer map[string]int
	accepted      *Envelope
	changed       chan struct{} // closed and replaced whenever the round's state changes
}

func (rs *roundState) notify() {
	close(rs.changed)
	rs.changed = make(chan struct{})
}

func (rs *roundState) find(d [32]byte) int {
	for i, c := range rs.pending {
		if c.digest == d {
			return i
		}
	}
	return -1
}

// Receiver holds candidates for rounds the caller declared, until the caller settles or prunes them.
type Receiver struct {
	limits TransportLimits
	log    *slog.Logger

	admMu      sync.Mutex
	admTotal   int
	admPerPeer map[string]int

	mu        sync.Mutex
	rounds    map[uint64]*roundState
	watermark uint64
	pruned    bool
	closed    bool
	done      chan struct{}
}

func NewReceiver(l TransportLimits, log *slog.Logger) (*Receiver, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}
	return &Receiver{
		limits: l, log: log, admPerPeer: map[string]int{},
		rounds: map[uint64]*roundState{}, done: make(chan struct{}),
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
Serve reads one frame from one stream, decodes it strictly and offers it as a candidate. Admission is
taken before the first byte is read, so a stream that never sends a frame still counts against the
bounds; what ends such a stream is the deadline its caller sets (handleStream does).
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
	return r.offer(e, sha256.Sum256(body), from)
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

// PendingRounds reports how many rounds are declared and not pruned.
func (r *Receiver) PendingRounds() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.rounds)
}

// Candidates reports how many candidates are pending in round.
func (r *Receiver) Candidates(round uint64) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rs, ok := r.rounds[round]; ok {
		return len(rs.pending)
	}
	return 0
}

// roundLocked returns the declared round's state. r.mu must be held.
func (r *Receiver) roundLocked(round uint64) (*roundState, error) {
	if r.closed {
		return nil, ErrClosed
	}
	if r.pruned && round <= r.watermark {
		return nil, fmt.Errorf("%w: round %d, watermark %d", ErrPruned, round, r.watermark)
	}
	rs, ok := r.rounds[round]
	if !ok {
		return nil, fmt.Errorf("%w: round %d", ErrUnexpectedRound, round)
	}
	return rs, nil
}

// Expect declares a round, and the block and optionally the proposer its witness must be bound to.
// Declaring the same round again with the same expectation is a no-op; with a different one it is an
// error.
func (r *Receiver) Expect(round uint64, x Expectation) error {
	if len(x.BlockHash) != 32 {
		return fmt.Errorf("inputcarrier: expected block hash must be 32 bytes, got %d", len(x.BlockHash))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if r.pruned && round <= r.watermark {
		return fmt.Errorf("%w: round %d, watermark %d", ErrPruned, round, r.watermark)
	}
	if rs, ok := r.rounds[round]; ok {
		if string(rs.expect.BlockHash) != string(x.BlockHash) || rs.expect.Proposer != x.Proposer {
			return fmt.Errorf("inputcarrier: round %d is already declared with another expectation", round)
		}
		return nil
	}
	if len(r.rounds) >= r.limits.MaxPendingRounds {
		return fmt.Errorf("%w: %d rounds declared", ErrTooManyRounds, len(r.rounds))
	}
	r.rounds[round] = &roundState{
		expect:        Expectation{BlockHash: append([]byte(nil), x.BlockHash...), Proposer: x.Proposer},
		rejected:      map[[32]byte]struct{}{},
		rejectsByPeer: map[string]int{},
		changed:       make(chan struct{}),
	}
	return nil
}

func (r *Receiver) offer(e Envelope, digest [32]byte, from string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rs, err := r.roundLocked(e.ShardRound)
	if err != nil {
		return err
	}
	switch {
	case rs.accepted != nil:
		return fmt.Errorf("%w: round %d", ErrRoundSettled, e.ShardRound)
	case string(e.BlockHash) != string(rs.expect.BlockHash):
		return fmt.Errorf("%w: round %d", ErrUnexpectedBlock, e.ShardRound)
	case rs.expect.Proposer != "" && from != rs.expect.Proposer:
		return fmt.Errorf("%w: %s, expected %s", ErrUnexpectedSender, from, rs.expect.Proposer)
	}
	if _, bad := rs.rejected[digest]; bad {
		return fmt.Errorf("%w: round %d", ErrRejected, e.ShardRound)
	}
	if rs.find(digest) >= 0 {
		return fmt.Errorf("%w: round %d", ErrDuplicate, e.ShardRound)
	}
	if rs.rejectsByPeer[from] >= r.limits.MaxRejectsPerPeer {
		return fmt.Errorf("%w: %s in round %d", ErrPeerExhausted, from, e.ShardRound)
	}
	for _, c := range rs.pending {
		if c.from == from {
			return fmt.Errorf("%w: %s in round %d", ErrPeerHasCandidate, from, e.ShardRound)
		}
	}
	if len(rs.pending) >= r.limits.MaxCandidatesPerRound {
		return fmt.Errorf("%w: round %d", ErrCandidatesFull, e.ShardRound)
	}
	rs.pending = append(rs.pending, candidate{digest: digest, env: e, from: from})
	rs.notify()
	return nil
}

/*
Await returns the settled envelope of round if the caller accepted one, and otherwise the oldest pending
candidate, waiting until there is one. It does not consume the candidate: the caller verifies it and
answers with Reject or Accept, and until then every Await returns the same candidate.
*/
func (r *Receiver) Await(ctx context.Context, round uint64) (Envelope, error) {
	for {
		r.mu.Lock()
		rs, err := r.roundLocked(round)
		if err != nil {
			r.mu.Unlock()
			return Envelope{}, err
		}
		if rs.accepted != nil {
			e := rs.accepted.clone()
			r.mu.Unlock()
			return e, nil
		}
		if len(rs.pending) > 0 {
			e := rs.pending[0].env.clone()
			r.mu.Unlock()
			return e, nil
		}
		changed := rs.changed
		r.mu.Unlock()

		select {
		case <-changed:
		case <-r.done:
			return Envelope{}, ErrClosed
		case <-ctx.Done():
			return Envelope{}, fmt.Errorf("inputcarrier: awaiting round %d: %w", round, ctx.Err())
		}
	}
}

// digestOf returns the digest a candidate with e's canonical encoding is held under.
func (r *Receiver) digestOf(e Envelope) ([32]byte, error) {
	b, err := Encode(e, r.limits.Envelope)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// Reject removes a pending candidate the caller refused, remembers its bytes so they cannot occupy the
// round again, and charges its sender.
func (r *Receiver) Reject(round uint64, e Envelope) error {
	d, err := r.digestOf(e)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rs, err := r.roundLocked(round)
	if err != nil {
		return err
	}
	if rs.accepted != nil {
		return fmt.Errorf("%w: round %d", ErrRoundSettled, round)
	}
	i := rs.find(d)
	if i < 0 {
		return fmt.Errorf("%w: round %d", ErrNoSuchCandidate, round)
	}
	c := rs.pending[i]
	rs.pending = append(rs.pending[:i], rs.pending[i+1:]...)
	if len(rs.rejectedOrder) >= r.limits.MaxRejectedPerRound {
		delete(rs.rejected, rs.rejectedOrder[0])
		rs.rejectedOrder = rs.rejectedOrder[1:]
	}
	rs.rejected[d] = struct{}{}
	rs.rejectedOrder = append(rs.rejectedOrder, d)
	rs.rejectsByPeer[c.from]++
	rs.notify()
	return nil
}

// Accept settles round with a pending candidate the caller verified. Other candidates are dropped, and
// later deliveries for the round are refused.
func (r *Receiver) Accept(round uint64, e Envelope) error {
	d, err := r.digestOf(e)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rs, err := r.roundLocked(round)
	if err != nil {
		return err
	}
	if rs.accepted != nil {
		return fmt.Errorf("%w: round %d", ErrRoundSettled, round)
	}
	i := rs.find(d)
	if i < 0 {
		return fmt.Errorf("%w: round %d", ErrNoSuchCandidate, round)
	}
	accepted := rs.pending[i].env.clone()
	rs.accepted = &accepted
	rs.pending = nil
	rs.notify()
	return nil
}

// Prune forgets every round at or below round, and refuses later operations for them.
func (r *Receiver) Prune(round uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.pruned || round > r.watermark {
		r.watermark, r.pruned = round, true
	}
	for k, rs := range r.rounds {
		if k <= r.watermark {
			delete(r.rounds, k)
			rs.notify()
		}
	}
}

// Close refuses further operations and ends pending Awaits.
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
		return err
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
