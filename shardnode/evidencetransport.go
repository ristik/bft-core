package shardnode

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

	"github.com/unicitynetwork/bft-go-base/types"
)

/*
The wire between the two halves of authenticated anchor recovery: one request, one response, both
bounded, over a libp2p stream.

WHAT THIS FILE DECIDES, AND WHAT IT DOES NOT. It decides how a request and a response are framed,
what a provider is allowed to spend answering one, and how a refusal is named on the wire. It decides
NOTHING about whether the evidence is true. The response is decoded, never trusted: no signature is
checked here, no trust base is consulted, and the returned bundle is handed back to the caller
exactly as it arrived, for VerifyAnchorEvidence to accept or refuse against this node's own
configured trust (docs/design/f6b-quiet-tail-anchor-recovery.md §3). Which providers to ask, in what
order, how many attempts to spend and what to do with a refusal are the requester's decisions and are
deliberately not made here — a transport that also decided them would be a recovery mechanism whose
policy could not be reviewed separately from its framing.

WHY THE BOUNDS ARE THIS FILE'S OWN. §4 requires the transport to cap what it reads and decodes
INDEPENDENTLY of the predicate's bounds, and the reason is ordering: AnchorEvidenceLimits is checked
against a bundle this process already holds, so by the time it applies, a decoder has already
allocated whatever arrived. The caps here apply BEFORE that — to the declared frame length, before a
single byte of the body is read into memory. The repository's shared helper (network.deserializeMsg)
deliberately has no such cap, because for its protocols the message size is bounded by construction;
it is not reused here for exactly that reason.

WHAT AN UNTRUSTED PEER CAN DO THROUGH THIS FILE. Refuse, stall until the deadline, or send a large
frame that is discarded without being decoded. That is the whole of it: availability, never finality.
*/

// ProtocolAnchorEvidence is the shard's evidence-retrieval protocol — validator to validator, and
// never root-chain-facing. It shares a libp2p host with ProtocolShardPayload and the root-chain
// connection; libp2p multiplexes protocols over one connection.
const ProtocolAnchorEvidence = "/unicity/shard-anchor-evidence/1.0.0"

// ErrEvidenceTransport marks a failure of the exchange itself — framing, I/O, a frame over the cap,
// a response this side cannot make sense of. It is deliberately ONE error rather than a taxonomy: a
// provider that cannot hold up its end of the wire tells the requester nothing about the shard's
// history, and every one of these is "ask somebody else", the same as the named provider outcomes.
var ErrEvidenceTransport = errors.New("anchor evidence transport")

// errFrameTooLarge distinguishes "this message does not fit the frame bound" from every other write
// failure. The distinction is load-bearing: nothing has been written to the peer in that case, so a
// named refusal can still be sent on the same stream, whereas after a failed write the stream is in
// an unknown state and must not be written to again.
var errFrameTooLarge = errors.New("frame exceeds the bound")

// EvidenceTransportLimits bounds what one exchange may cost each side.
type EvidenceTransportLimits struct {
	// MaxRequestBytes caps the request frame a provider will read. A request is a round number and
	// one canonical input-record encoding; the cap is generous against that and still refuses
	// anything designed to be expensive.
	MaxRequestBytes int

	// MaxResponseBytes caps the response frame a requester will read. It is derived from the
	// predicate's own byte bound plus a small allowance for the response wrapper, because a frame
	// larger than that encodes a bundle the predicate would refuse anyway — decoding it would be
	// spending memory to reach a refusal already guaranteed.
	MaxResponseBytes int

	// MaxCertificates caps the certificate count in a decoded response, checked before the bundle
	// is handed onwards. It mirrors the predicate's bound so a requester never carries around a
	// chain it has already established it will not accept.
	MaxCertificates int

	// Deadline bounds one exchange end to end, on both sides. A peer that opens a stream and then
	// writes nothing costs the provider this much and no more.
	Deadline time.Duration

	// MaxConcurrentServes caps how many requests one provider ASSEMBLES at once — the second of two
	// tiers, applied once a request has been read and understood. Beyond it, requests are refused
	// immediately with a named busy outcome rather than queued: a queue is a place for an attacker
	// to accumulate work, and a fast refusal lets an honest requester ask elsewhere.
	MaxConcurrentServes int

	// MaxPendingStreams caps how many streams this server is willing to hold AT ALL — counted from
	// before the first byte is read, through the read, the assembly and the response write, to the
	// handler's exit. It is the tier MaxConcurrentServes cannot be: a peer that opens streams and
	// then sends nothing, or half a frame, never reaches the second tier, so without this one its
	// cost is bounded only per stream (by the deadline) and not in aggregate. libp2p multiplexes
	// arbitrarily many streams over one connection, so "one request per stream" bounds nothing by
	// itself.
	MaxPendingStreams int

	// MaxPendingStreamsPerPeer caps how many of those one peer may hold. Without it, one peer can
	// occupy the whole global budget and every other validator is refused — which is the same
	// availability loss this protocol exists to repair, arriving from the other direction.
	MaxPendingStreamsPerPeer int
}

// evidenceResponseOverhead is the allowance MaxResponseBytes adds over the predicate's byte bound:
// the outcome code, the detail string and the CBOR wrapper around the bundle. It is explicit so that
// a bundle just inside AnchorEvidenceLimits.MaxBytes is never refused by the transport that carries
// it — the two bounds must not disagree about the same bundle.
const evidenceResponseOverhead = 4 << 10

// evidenceMinResponseBytes is the smallest response bound a server may be configured with. A refusal
// has to fit inside the bound too: a bound so tight that the provider cannot even say "no" turns a
// configuration mistake into silence on the wire, which the requester cannot tell from a stall.
const evidenceMinResponseBytes = 1 << 10

// evidenceMaxDetail caps the diagnostic text in a response. Detail is never read by a decision on
// either side, so the only thing its length can affect is whether a refusal still fits in a frame —
// which it must, always.
const evidenceMaxDetail = 200

func detail(s string) string {
	if len(s) > evidenceMaxDetail {
		return s[:evidenceMaxDetail]
	}
	return s
}

// DefaultEvidenceTransportLimits are starting values, aligned with DefaultAnchorEvidenceLimits so
// that neither end refuses what the other would have accepted.
var DefaultEvidenceTransportLimits = EvidenceTransportLimits{
	MaxRequestBytes:     4 << 10,
	MaxResponseBytes:    DefaultAnchorEvidenceLimits.MaxBytes + evidenceResponseOverhead,
	MaxCertificates:     DefaultAnchorEvidenceLimits.MaxCertificates,
	Deadline:            5 * time.Second,
	MaxConcurrentServes: 4,

	// Room for several validators to be mid-request while a few peers stall, and no more. These are
	// THIS protocol's own bounds. A libp2p resource manager, where one is configured, may refuse
	// streams before the handler ever runs, but nothing here depends on that: an unconfigured or
	// permissive host must not remove this protocol's limits.
	MaxPendingStreams:        32,
	MaxPendingStreamsPerPeer: 4,
}

func (l EvidenceTransportLimits) validate() error {
	switch {
	case l.MaxRequestBytes <= 0, l.MaxResponseBytes <= 0, l.MaxCertificates <= 0:
		return fmt.Errorf("evidence transport: byte and certificate bounds must be positive, got %+v", l)
	case l.MaxResponseBytes < evidenceMinResponseBytes:
		return fmt.Errorf("evidence transport: MaxResponseBytes must leave room for a refusal (at least %d bytes), got %d",
			evidenceMinResponseBytes, l.MaxResponseBytes)
	case l.Deadline <= 0:
		return fmt.Errorf("evidence transport: deadline must be positive, got %s", l.Deadline)
	case l.MaxConcurrentServes <= 0:
		return fmt.Errorf("evidence transport: MaxConcurrentServes must be positive, got %d", l.MaxConcurrentServes)
	case l.MaxPendingStreams <= 0, l.MaxPendingStreamsPerPeer <= 0:
		return fmt.Errorf("evidence transport: stream admission bounds must be positive, got MaxPendingStreams=%d MaxPendingStreamsPerPeer=%d",
			l.MaxPendingStreams, l.MaxPendingStreamsPerPeer)
	case l.MaxPendingStreamsPerPeer > l.MaxPendingStreams:
		return fmt.Errorf("evidence transport: MaxPendingStreamsPerPeer=%d exceeds MaxPendingStreams=%d, so the per-peer bound could never apply",
			l.MaxPendingStreamsPerPeer, l.MaxPendingStreams)
	}
	return nil
}

// The wire messages. CBOR toarray, matching the convention the repository's own protocols use
// (network/protocol/certification, and ProtocolShardPayload's disseminatedBlock) rather than
// inventing a second wire style for shard-internal traffic.
type evidenceRequestMsg struct {
	_            struct{} `cbor:",toarray"`
	HeldRound    uint64
	HeldIdentity []byte
}

type evidenceResponseMsg struct {
	_ struct{} `cbor:",toarray"`

	// Outcome is the whole of the response's meaning. Detail is diagnostic text and is NEVER read
	// by any decision on this side: a provider that can write an error string could otherwise steer
	// a requester by writing a persuasive one.
	Outcome  uint64
	Detail   string
	Evidence *AnchorEvidence
}

// Outcome codes. The zero value carries evidence, so a truncated or empty response cannot be
// mistaken for a successful one — an empty CBOR array decodes to outcome 0 with a nil bundle, which
// is refused as malformed below rather than accepted as an answer.
const (
	outcomeEvidence uint64 = iota
	outcomeNotReady
	outcomeEvicted
	outcomeBehind
	outcomeMismatch
	outcomeTooLarge
	outcomeBusy
	outcomeMalformedRequest
)

// outcomeFor maps a provider-side refusal to its wire code. An error this side does not recognise
// becomes not-ready rather than anything more specific: saying less than is known is safe, saying
// more is not.
func outcomeFor(err error) uint64 {
	switch {
	case errors.Is(err, ErrProviderEvicted):
		return outcomeEvicted
	case errors.Is(err, ErrProviderBehind):
		return outcomeBehind
	case errors.Is(err, ErrProviderMismatch):
		return outcomeMismatch
	default:
		return outcomeNotReady
	}
}

// errorForOutcome maps a wire code back to a local error. An UNKNOWN code — a newer provider, a
// confused one, a hostile one — is a transport failure, never silently treated as any particular
// refusal and never as success.
func errorForOutcome(code uint64, detail string) error {
	switch code {
	case outcomeNotReady:
		return fmt.Errorf("%w (provider says: %q)", ErrProviderNotReady, detail)
	case outcomeEvicted:
		return fmt.Errorf("%w (provider says: %q)", ErrProviderEvicted, detail)
	case outcomeBehind:
		return fmt.Errorf("%w (provider says: %q)", ErrProviderBehind, detail)
	case outcomeMismatch:
		return fmt.Errorf("%w (provider says: %q)", ErrProviderMismatch, detail)
	case outcomeTooLarge:
		return fmt.Errorf("%w: the provider's answer exceeds what it may send (provider says: %q)", ErrEvidenceTransport, detail)
	case outcomeBusy:
		return fmt.Errorf("%w: the provider is already serving its maximum number of requests (provider says: %q)", ErrEvidenceTransport, detail)
	case outcomeMalformedRequest:
		return fmt.Errorf("%w: the provider refused this request as malformed (provider says: %q)", ErrEvidenceTransport, detail)
	default:
		return fmt.Errorf("%w: unrecognised outcome code %d", ErrEvidenceTransport, code)
	}
}

// EvidenceHost is the part of network.Peer this file uses: registering a stream handler and opening
// a stream. Narrowed to those two so the transport can be exercised without a libp2p host, and so
// that nothing here can reach for the rest of a Peer's surface.
type EvidenceHost interface {
	RegisterProtocolHandler(protocolID string, handler libp2pnetwork.StreamHandler)
	CreateStream(ctx context.Context, peerID peer.ID, protocolID string) (libp2pnetwork.Stream, error)
}

// EvidenceProvider is what a server serves from. *EvidenceBuffer is the implementation; the
// interface exists so the serving policy above can be tested against a provider that returns each
// named outcome deterministically.
type EvidenceProvider interface {
	Assemble(EvidenceRequest) (AnchorEvidence, error)
}

// ErrNotAdmitted is the refusal that reaches no peer. A stream turned away by admission is reset
// without a response, deliberately: writing a refusal means writing into a stream whose peer may
// still be writing its own request, which is the deadlock the read-first ordering exists to avoid,
// and a peer that opened more streams than it is allowed has already been told everything it needs
// to know by the reset.
var ErrNotAdmitted = errors.New("evidence transport: stream not admitted")

/*
streamAdmission is the FIRST of the server's two tiers, and the one that bounds work an attacker can
cause without ever completing a request.

It counts streams, not requests: a slot is taken before a single byte is read and released when the
handler exits, so a peer that opens a stream and sends nothing, or half a length prefix, or a body it
never finishes, occupies exactly one slot for at most one deadline. The second tier
(MaxConcurrentServes) counts assembly, which only a well-formed request reaches.

Per-peer as well as global, because a global bound alone is a bound on the whole shard's access to
one provider: one peer holding all of it refuses every honest validator, which is the availability
loss this protocol exists to repair, arriving from the other direction.
*/
type streamAdmission struct {
	mu         sync.Mutex
	total      int
	perPeer    map[string]int
	maxTotal   int
	maxPerPeer int
}

func newStreamAdmission(maxTotal, maxPerPeer int) *streamAdmission {
	return &streamAdmission{perPeer: make(map[string]int), maxTotal: maxTotal, maxPerPeer: maxPerPeer}
}

// acquire takes a slot for one stream, or reports that there is none. It never blocks: waiting for a
// slot IS the queue this bound exists to prevent.
func (a *streamAdmission) acquire(from string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.total >= a.maxTotal {
		return fmt.Errorf("%w: %d streams already pending, the limit", ErrNotAdmitted, a.total)
	}
	if a.perPeer[from] >= a.maxPerPeer {
		return fmt.Errorf("%w: %s already holds %d of its %d streams", ErrNotAdmitted, from, a.perPeer[from], a.maxPerPeer)
	}
	a.total++
	a.perPeer[from]++
	return nil
}

// release must run on EVERY exit from a handler — a slot leaked by a path that returns early is a
// bound that erodes to zero over the life of the process.
func (a *streamAdmission) release(from string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.total--
	if n := a.perPeer[from] - 1; n > 0 {
		a.perPeer[from] = n
	} else {
		// Removed rather than left at zero, so the map does not grow with every peer ever seen.
		delete(a.perPeer, from)
	}
}

func (a *streamAdmission) pending() (total int, peers int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.total, len(a.perPeer)
}

// EvidenceServer answers evidence requests from a provider, under its own bounds.
type EvidenceServer struct {
	provider  EvidenceProvider
	limits    EvidenceTransportLimits
	log       *slog.Logger
	admission *streamAdmission
	inFlight  chan struct{}
}

func NewEvidenceServer(provider EvidenceProvider, limits EvidenceTransportLimits, log *slog.Logger) (*EvidenceServer, error) {
	if provider == nil {
		return nil, errors.New("evidence transport: a server needs a provider")
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	return &EvidenceServer{
		provider:  provider,
		limits:    limits,
		log:       log,
		admission: newStreamAdmission(limits.MaxPendingStreams, limits.MaxPendingStreamsPerPeer),
		inFlight:  make(chan struct{}, limits.MaxConcurrentServes),
	}, nil
}

// Register installs the stream handler on a host. A node that has a serving buffer calls this once
// at startup; a node that does not simply never registers the protocol, and dialing it fails at the
// libp2p level — which is a correct "ask somebody else" answer without this file being involved.
func (s *EvidenceServer) Register(h EvidenceHost) {
	h.RegisterProtocolHandler(ProtocolAnchorEvidence, s.handleStream)
}

func (s *EvidenceServer) handleStream(stream libp2pnetwork.Stream) {
	from := stream.Conn().RemotePeer().String()

	// The deadline covers reading the request and writing the response together, so an admitted
	// peer that opens a stream and then stalls costs one slot for one deadline and nothing more.
	if err := stream.SetDeadline(time.Now().Add(s.limits.Deadline)); err != nil {
		_ = stream.Reset()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.limits.Deadline)
	defer cancel()

	if err := s.Serve(ctx, stream, from); err != nil {
		if s.log != nil {
			s.log.Debug("serving anchor evidence", "peer", from, "err", err.Error())
		}
		_ = stream.Reset()
		return
	}
	_ = stream.CloseWrite()
	_ = stream.Close()
}

/*
Serve reads one request from one stream and writes one response. One of each, then done: there is no
loop, so a stream cannot be held open feeding a provider work.

TWO TIERS, AND WHY. `from` identifies the peer on the other end (its libp2p ID in production), and
admission is taken BEFORE the first byte is read — that is the tier that bounds streams which never
become requests at all: no prefix, half a prefix, a body that never arrives. Reading first and
bounding afterwards left those outside every bound but the per-stream deadline, and libp2p
multiplexes as many streams as a peer likes over one connection, so "one request per stream" bounds
nothing on its own. A stream that is not admitted is reset by the caller and told nothing: writing a
refusal into a stream whose peer is still writing its request is the deadlock the read-first ordering
inside this function exists to avoid.

INTERRUPTIBILITY IS THE TRANSPORT'S, NOT THIS FUNCTION'S. Serve does bounded, blocking I/O on
whatever it is given, and a context cannot interrupt a read that has already begun on an
io.ReadWriter. What makes a stalled peer bounded here is the DEADLINE the caller sets on the stream
(handleStream does), plus the admission slot being finite; the ctx check below only stops work that
has not started. A transport with no deadline support gives this function no cancellation contract at
all, and that is a property of the transport, not something Serve can promise.

A returned error means the exchange failed and nothing useful was written — including ErrNotAdmitted,
which means nothing was even read. A refusal by the provider is NOT an error here: it is a named
outcome, written to the peer, and the exchange succeeded in delivering it.
*/
func (s *EvidenceServer) Serve(ctx context.Context, rw io.ReadWriter, from string) error {
	if err := s.admission.acquire(from); err != nil {
		return err
	}
	defer s.admission.release(from)

	// THE REQUEST IS READ FIRST, once admitted, even when this server is at its ASSEMBLY bound.
	// Refusing after admission but before reading would leave a requester still writing into a
	// stream nobody is draining, which deadlocks on any transport that does not buffer; the read is
	// one frame bounded by MaxRequestBytes, far cheaper than the assembly the second tier protects.
	var req evidenceRequestMsg
	if err := readFrame(bufio.NewReader(rw), &req, s.limits.MaxRequestBytes); err != nil {
		return fmt.Errorf("reading request: %w", err)
	}
	if len(req.HeldIdentity) == 0 {
		// A request that names no certificate cannot be answered: round alone is not an identity,
		// and answering it would mean choosing which of several certificates for that round the
		// requester "probably" meant (§2.2).
		return s.refuse(rw, outcomeMalformedRequest, "a request must name the certificate it is pinned to, not only a round")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	select {
	case s.inFlight <- struct{}{}:
		defer func() { <-s.inFlight }()
	default:
		// Refused immediately, not queued. A queue under load is somewhere for an attacker's work
		// to accumulate; an immediate refusal lets an honest requester spend its attempt elsewhere.
		return s.refuse(rw, outcomeBusy, "too many requests in flight")
	}

	ev, err := s.provider.Assemble(EvidenceRequest{HeldRound: req.HeldRound, HeldIdentity: req.HeldIdentity})
	if err != nil {
		return s.refuse(rw, outcomeFor(err), err.Error())
	}

	// The provider applies the requester's bounds to its own answer before sending it. It knows the
	// defaults both ends run with, so an answer over them is one this side can see will be refused,
	// and sending it anyway would spend the requester's attempt to reach a refusal already known
	// here. A named outcome instead lets the requester go somewhere else immediately.
	if n := len(ev.Tail) + 1; n > s.limits.MaxCertificates {
		return s.refuse(rw, outcomeTooLarge,
			fmt.Sprintf("the chain for that round is %d certificates, over the %d this transport carries", n, s.limits.MaxCertificates))
	}
	if err := writeFrame(rw, &evidenceResponseMsg{Outcome: outcomeEvidence, Evidence: &ev}, s.limits.MaxResponseBytes); err != nil {
		// Only the size refusal is recoverable, and only because it wrote nothing: after any other
		// write failure the peer has seen part of a frame and must not be sent a second one.
		if errors.Is(err, errFrameTooLarge) {
			return s.refuse(rw, outcomeTooLarge, "the chain for that round is larger than this transport carries")
		}
		return err
	}
	return nil
}

// Pending reports how many streams this server currently holds admitted, and how many distinct peers
// hold them. For diagnostics and for tests that assert slots are released on every exit path.
func (s *EvidenceServer) Pending() (streams int, peers int) {
	return s.admission.pending()
}

// refuse writes one named outcome. It is the only way a refusal reaches the wire, so the detail cap
// that keeps a refusal inside the frame bound cannot be forgotten at one call site.
func (s *EvidenceServer) refuse(w io.Writer, outcome uint64, why string) error {
	return writeFrame(w, &evidenceResponseMsg{Outcome: outcome, Detail: detail(why)}, s.limits.MaxResponseBytes)
}

/*
RequestAnchorEvidence asks one provider for one bundle.

ONE provider and ONE attempt, deliberately. Trying several, in some order, until one answers is the
requester's policy — it depends on what the predicate said about the last candidate (§4.1: a
candidate refusal ends the candidate, not the attempt), and that is a decision this file must not
make on the requester's behalf. What is returned here is a bundle nobody has verified.

The whole call, dialing included, runs under the caller's context narrowed by limits.Deadline, so an
earlier caller deadline wins and dialing spends the same budget as the exchange rather than resetting
it.
*/
func RequestAnchorEvidence(ctx context.Context, h EvidenceHost, p peer.ID, req EvidenceRequest, limits EvidenceTransportLimits) (AnchorEvidence, error) {
	if err := limits.validate(); err != nil {
		return AnchorEvidence{}, err
	}
	if len(req.HeldIdentity) == 0 {
		return AnchorEvidence{}, fmt.Errorf("%w: a request must name the certificate it is pinned to", ErrEvidenceTransport)
	}

	ctx, cancel := context.WithTimeout(ctx, limits.Deadline)
	defer cancel()

	stream, err := h.CreateStream(ctx, p, ProtocolAnchorEvidence)
	if err != nil {
		return AnchorEvidence{}, fmt.Errorf("%w: opening a stream to %s: %w", ErrEvidenceTransport, p, err)
	}

	ev, err := requestOverStream(ctx, stream, req, limits)
	if err != nil {
		return AnchorEvidence{}, fmt.Errorf("requesting anchor evidence from %s: %w", p, err)
	}
	return ev, nil
}

/*
evidenceStream is what the client half needs of a stream: bounded I/O, a deadline, and a reset that
aborts I/O already in progress. A libp2p stream provides all three; narrowing to them is what lets
the cancellation behaviour below be tested over a pipe rather than only over a real host.
*/
type evidenceStream interface {
	io.ReadWriter
	SetDeadline(t time.Time) error
	CloseWrite() error
	Close() error
	Reset() error
}

/*
requestOverStream runs one exchange on an already-open stream, and is where cancellation is made real.

WHY A WATCHDOG AND NOT A CHECK. Once a read or a write on a stream has begun, no context check can
interrupt it: the goroutine is inside the transport. Cancellation has to act on the STREAM, so a
watcher resets it when the context ends, which is what unblocks the I/O — the deferred reset on the
failure path cannot, because it only runs once that I/O has already returned. The watcher is stopped
and joined before this function returns, so a completed exchange leaves nothing behind that could
reset a stream later.

WHY THE DEADLINE IS THE CONTEXT'S. Setting `now + limits.Deadline` after dialing restarts the budget
the caller already began spending, and ignores an earlier deadline the caller may have set. The
stream deadline is therefore the derived context's own deadline, so both ends of the exchange and the
dial that preceded it are inside one budget.
*/
func requestOverStream(ctx context.Context, st evidenceStream, req EvidenceRequest, limits EvidenceTransportLimits) (AnchorEvidence, error) {
	if dl, ok := ctx.Deadline(); ok {
		if err := st.SetDeadline(dl); err != nil {
			_ = st.Reset()
			return AnchorEvidence{}, fmt.Errorf("%w: setting stream deadline: %w", ErrEvidenceTransport, err)
		}
	}

	stop := make(chan struct{})
	watching := make(chan struct{})
	go func() {
		defer close(watching)
		select {
		case <-ctx.Done():
			// The reset is the cancellation: it aborts whatever read or write is in flight.
			_ = st.Reset()
		case <-stop:
		}
	}()
	ev, err := exchangeEvidence(st, req, limits)
	close(stop)
	<-watching

	if err != nil {
		_ = st.Reset()
		// A cancelled or expired context is reported as what it is. Without this the caller sees
		// whatever I/O error the reset produced, which says nothing about why the attempt ended.
		if cerr := ctx.Err(); cerr != nil {
			return AnchorEvidence{}, fmt.Errorf("%w: %w", ErrEvidenceTransport, cerr)
		}
		return AnchorEvidence{}, err
	}
	_ = st.Close()
	return ev, nil
}

// exchangeEvidence is the client half without libp2p: write the request, read the response, check
// what can be checked without trusting anything.
func exchangeEvidence(rw io.ReadWriter, req EvidenceRequest, limits EvidenceTransportLimits) (AnchorEvidence, error) {
	if err := writeFrame(rw, &evidenceRequestMsg{HeldRound: req.HeldRound, HeldIdentity: req.HeldIdentity}, limits.MaxRequestBytes); err != nil {
		return AnchorEvidence{}, fmt.Errorf("sending request: %w", err)
	}
	if cw, ok := rw.(interface{ CloseWrite() error }); ok {
		// Half-close, so a provider reading the stream sees the request end rather than waiting for
		// its deadline. Best effort: an unbounded read is bounded by the deadline either way.
		_ = cw.CloseWrite()
	}

	var resp evidenceResponseMsg
	if err := readFrame(bufio.NewReader(rw), &resp, limits.MaxResponseBytes); err != nil {
		return AnchorEvidence{}, fmt.Errorf("reading response: %w", err)
	}
	if resp.Outcome != outcomeEvidence {
		return AnchorEvidence{}, errorForOutcome(resp.Outcome, resp.Detail)
	}

	// Structural checks only, and only the ones that let this side stop early. Everything that
	// decides whether the evidence is TRUE — signatures, trust bases, partition, shard,
	// configuration, epoch, contiguity, the terminal binding — belongs to VerifyAnchorEvidence
	// against this node's own configuration, and none of it is done or duplicated here.
	if resp.Evidence == nil || resp.Evidence.Source == nil || resp.Evidence.SourceTechnical == nil {
		return AnchorEvidence{}, fmt.Errorf("%w: a success response with no bundle in it", ErrEvidenceTransport)
	}
	if n := len(resp.Evidence.Tail) + 1; n > limits.MaxCertificates {
		return AnchorEvidence{}, fmt.Errorf("%w: %d certificates, over the %d bound", ErrEvidenceTransport, n, limits.MaxCertificates)
	}
	return *resp.Evidence, nil
}

// writeFrame writes one length-prefixed CBOR message, refusing to send one over the cap rather than
// truncating it. Same uvarint-prefixed framing as network/cbor.go, so the wire convention is the
// repository's own; what differs is that the length is bounded on both sides.
func writeFrame(w io.Writer, msg any, max int) error {
	body, err := types.Cbor.Marshal(msg)
	if err != nil {
		return fmt.Errorf("%w: encoding %T: %w", ErrEvidenceTransport, msg, err)
	}
	if len(body) > max {
		return fmt.Errorf("%w: %w: %T encodes to %d bytes, over the %d frame bound", ErrEvidenceTransport, errFrameTooLarge, msg, len(body), max)
	}
	prefix := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(prefix, uint64(len(body)))
	if _, err := w.Write(append(prefix[:n], body...)); err != nil {
		return fmt.Errorf("%w: writing frame: %w", ErrEvidenceTransport, err)
	}
	return nil
}

/*
readFrame reads one length-prefixed CBOR message, and is where the transport's independent bound
actually applies.

THE ORDER IS THE POINT. The declared length is checked against max BEFORE anything is allocated for
the body and before the decoder is handed a single byte, so a peer announcing a gigabyte costs this
side one varint. Then exactly that many bytes are read into a buffer whose size is already known to
be within the bound, so a lying length cannot stream more than it declared, and a short frame is an
error rather than a partially decoded message.
*/
func readFrame(r *bufio.Reader, msg any, max int) error {
	length, err := binary.ReadUvarint(r)
	if err != nil {
		return fmt.Errorf("%w: reading frame length: %w", ErrEvidenceTransport, err)
	}
	if length == 0 {
		return fmt.Errorf("%w: zero-length frame", ErrEvidenceTransport)
	}
	if length > uint64(max) {
		return fmt.Errorf("%w: frame declares %d bytes, over the %d bound", ErrEvidenceTransport, length, max)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return fmt.Errorf("%w: reading %d-byte frame: %w", ErrEvidenceTransport, length, err)
	}
	if err := types.Cbor.Unmarshal(body, msg); err != nil {
		return fmt.Errorf("%w: decoding %T: %w", ErrEvidenceTransport, msg, err)
	}
	return nil
}
