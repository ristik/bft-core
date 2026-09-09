package shardnode

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

	// MaxConcurrentServes caps how many requests one provider answers at once. Beyond it, requests
	// are refused immediately with a named busy outcome rather than queued: a queue is a place for
	// an attacker to accumulate work, and a fast refusal lets an honest requester ask elsewhere.
	MaxConcurrentServes int
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

// EvidenceServer answers evidence requests from a provider, under its own bounds.
type EvidenceServer struct {
	provider EvidenceProvider
	limits   EvidenceTransportLimits
	log      *slog.Logger
	inFlight chan struct{}
}

func NewEvidenceServer(provider EvidenceProvider, limits EvidenceTransportLimits, log *slog.Logger) (*EvidenceServer, error) {
	if provider == nil {
		return nil, errors.New("evidence transport: a server needs a provider")
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	return &EvidenceServer{
		provider: provider,
		limits:   limits,
		log:      log,
		inFlight: make(chan struct{}, limits.MaxConcurrentServes),
	}, nil
}

// Register installs the stream handler on a host. A node that has a serving buffer calls this once
// at startup; a node that does not simply never registers the protocol, and dialing it fails at the
// libp2p level — which is a correct "ask somebody else" answer without this file being involved.
func (s *EvidenceServer) Register(h EvidenceHost) {
	h.RegisterProtocolHandler(ProtocolAnchorEvidence, s.handleStream)
}

func (s *EvidenceServer) handleStream(stream libp2pnetwork.Stream) {
	// The deadline covers reading the request and writing the response together, so a peer that
	// opens a stream and stalls costs one slot for one deadline and nothing more.
	if err := stream.SetDeadline(time.Now().Add(s.limits.Deadline)); err != nil {
		_ = stream.Reset()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.limits.Deadline)
	defer cancel()

	if err := s.Serve(ctx, stream); err != nil {
		if s.log != nil {
			s.log.Debug("serving anchor evidence", "peer", stream.Conn().RemotePeer().String(), "err", err.Error())
		}
		_ = stream.Reset()
		return
	}
	_ = stream.CloseWrite()
	_ = stream.Close()
}

/*
Serve reads one request and writes one response. One of each, then done: there is no loop, so a
stream cannot be held open feeding a provider work, and "how many requests may one connection cost"
has the answer "one" by construction rather than by policy.

A returned error means the exchange itself failed and nothing useful was written. A refusal by the
provider is NOT an error here — it is a named outcome, written to the peer, and the exchange
succeeded in delivering it.
*/
func (s *EvidenceServer) Serve(ctx context.Context, rw io.ReadWriter) error {
	// THE REQUEST IS READ FIRST, even when this server is at its concurrency bound. Refusing before
	// reading would leave a requester still writing into a stream nobody is draining, which
	// deadlocks on any transport that does not buffer, and the read being refused is one frame
	// bounded by MaxRequestBytes — far cheaper than the assembly the bound actually protects.
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
	// Reset on every failure path, so a provider is not left holding a slot for a requester that
	// has stopped listening; a completed exchange closes cleanly instead.
	done := false
	defer func() {
		if !done {
			_ = stream.Reset()
		}
	}()
	if err := stream.SetDeadline(time.Now().Add(limits.Deadline)); err != nil {
		return AnchorEvidence{}, fmt.Errorf("%w: setting stream deadline: %w", ErrEvidenceTransport, err)
	}

	ev, err := exchangeEvidence(stream, req, limits)
	if err != nil {
		return AnchorEvidence{}, fmt.Errorf("requesting anchor evidence from %s: %w", p, err)
	}
	done = true
	_ = stream.Close()
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
