package archivewiring

import (
	"bytes"
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
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/shardnode"
)

const ProtocolArchive = "/unicity/certified-archive/1.0.0"
const transferChunk = 64 << 10
const resetFrameMarker = byte(0xff)
const maxArchiveFrameBytes = archive.MaxBundleBytes + archive.MaxRequestBytes + 8

var ErrTransport = errors.New("archive wiring: replica transport failed")
var ErrReplica = errors.New("archive wiring: replica refused or changed record")
var ErrPeerNotAllowed = errors.New("archive wiring: archive peer is not allowed")
var ErrPeerLimit = errors.New("archive wiring: archive peer stream limit reached")
var ErrPendingLimit = errors.New("archive wiring: global archive stream limit reached")
var ErrVerifier = errors.New("archive wiring: archive request verifier failed")
var ErrHandler = errors.New("archive wiring: archive request handler failed")

type StreamResetError struct {
	Peer      peer.ID
	Operation string
	Reason    error
}

func (e *StreamResetError) Error() string {
	return fmt.Sprintf("archive stream reset by %s during %s: %v", e.Peer, e.Operation, e.Reason)
}

func (e *StreamResetError) Unwrap() error { return e.Reason }

type Limits struct {
	Deadline time.Duration
	Pending  int
	PerPeer  int
}

func DefaultLimits() Limits { return Limits{Deadline: 20 * time.Second, Pending: 4, PerPeer: 4} }

func (l Limits) valid() bool {
	return l.Deadline > 0 && l.Pending > 0 && l.Pending <= 64 && l.PerPeer > 0 && l.PerPeer <= l.Pending
}

// Verifier authenticates the record against local configured trust and the
// certified association before a replica stores any remote bytes.
type Verifier func(context.Context, archive.Request, *archive.Record) error
type BundleVerifier func(context.Context, archive.BundleRequest, []byte) error

type Server struct {
	store        *archive.Store
	ctx          context.Context
	subject      archive.Context
	want         []byte
	verify       Verifier
	bundleVerify BundleVerifier
	log          *slog.Logger
	limits       Limits
	allowed      map[peer.ID]struct{}
	authorize    func(peer.ID) bool
	mu           sync.Mutex
	pending      int
	byPeer       map[peer.ID]int
}

func (s *Server) SetBundleVerifier(v BundleVerifier) { s.bundleVerify = v }

func (s *Server) SetLogger(log *slog.Logger) { s.log = log }

// SetPeerAuthorizer makes the server authorize peers through the given predicate instead of the static set it was built with: the
// validators of the ACTIVE assignment, which changes at every rotation. Call before Register.
func (s *Server) SetPeerAuthorizer(allowed func(peer.ID) bool) { s.authorize = allowed }

func NewServer(store *archive.Store, contextValue archive.Context, verify Verifier, allowed []peer.ID, limits Limits) (*Server, error) {
	if store == nil || verify == nil || !limits.valid() || len(allowed) == 0 {
		return nil, archive.ErrInvalid
	}
	var probe archive.Request
	probe.Context = contextValue
	probe.BlockHash[0] = 1
	want, err := archive.EncodeRequest(probe)
	if err != nil {
		return nil, err
	}
	peers := make(map[peer.ID]struct{}, len(allowed))
	for _, id := range allowed {
		if id == "" {
			return nil, archive.ErrInvalid
		}
		peers[id] = struct{}{}
	}
	return &Server{store: store, subject: contextValue, want: want[:len(want)-32], verify: verify, limits: limits, allowed: peers, byPeer: make(map[peer.ID]int), log: slog.Default()}, nil
}

func (s *Server) Register(ctx context.Context, host shardnode.EvidenceHost) {
	s.ctx = ctx
	host.RegisterProtocolHandler(ProtocolArchive, s.handle)
}

func (s *Server) reservePending(id peer.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.authorize != nil {
		if !s.authorize(id) {
			return ErrPeerNotAllowed
		}
	} else if _, ok := s.allowed[id]; !ok {
		return ErrPeerNotAllowed
	}
	if s.pending >= s.limits.Pending {
		return ErrPendingLimit
	}
	s.pending++
	return nil
}

// reservePeer follows reservePending. Holding the global slot while checking
// the peer limit keeps the number of untrusted request frames bounded even
// before the operation byte has been inspected.
func (s *Server) reservePeer(id peer.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byPeer[id] >= s.limits.PerPeer {
		s.pending--
		return ErrPeerLimit
	}
	s.byPeer[id]++
	return nil
}

func (s *Server) releasePending() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending--
}

func (s *Server) leave(id peer.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending--
	s.byPeer[id]--
	if s.byPeer[id] == 0 {
		delete(s.byPeer, id)
	}
}

func (s *Server) handle(stream libp2pnetwork.Stream) {
	defer stream.Close()
	id := stream.Conn().RemotePeer()
	_ = stream.SetDeadline(time.Now().Add(s.limits.Deadline))
	if err := s.reservePending(id); err != nil {
		if errors.Is(err, ErrPeerNotAllowed) {
			// A peer this node does not (yet) authorize is told so, by name, without reading its request: a joiner that reached
			// a retained validator before the validator installed the assignment step that admits it can then retry exactly this
			// refusal (shardnode.ErrHandoffPeerNotReady) instead of seeing a bare reset. Only the fixed two-byte reset frame is
			// written, and the stream is closed, not reset, so the frame is delivered.
			s.rejectNamed(stream, id, err)
			return
		}
		s.reject(stream, id, "unknown", err, false)
		return
	}
	reserved := true
	defer func() {
		if reserved {
			s.releasePending()
		}
	}()
	ctx, cancel := context.WithTimeout(s.ctx, s.limits.Deadline)
	defer cancel()
	frame, err := readFrame(stream, maxArchiveFrameBytes)
	if err != nil || len(frame) == 0 {
		if err == nil {
			err = archive.ErrInvalid
		}
		s.reject(stream, id, "unknown", fmt.Errorf("%w: %w", ErrHandler, err), false)
		return
	}
	operation := archiveOperation(frame[0])
	if err := s.reservePeer(id); err != nil {
		reserved = false // reservePeer releases the global reservation on refusal.
		s.reject(stream, id, operation, err, true)
		return
	}
	reserved = false
	defer s.leave(id)
	if err := s.serveFrame(ctx, stream, frame); err != nil {
		err = typedHandlerError(err)
		s.reject(stream, id, operation, err, true)
	}
}

func (s *Server) reject(stream libp2pnetwork.Stream, id peer.ID, operation string, err error, requestConsumed bool) {
	reason := resetReasonName(err)
	log := s.log
	if log == nil {
		log = slog.Default()
	}
	log.WarnContext(context.Background(), "archive stream reset", "peer", id.String(), "operation", operation, "reason", reason, "error", err)
	if requestConsumed {
		if writeFrame(stream, resetFrame(err)) == nil {
			return
		}
	}
	_ = stream.Reset()
}

// rejectNamed is reject for a peer refused before its request is read: it logs like reject, writes the typed reset frame and leaves the
// close to the caller's deferred stream.Close, which delivers the frame (a Reset would discard it).
func (s *Server) rejectNamed(stream libp2pnetwork.Stream, id peer.ID, err error) {
	log := s.log
	if log == nil {
		log = slog.Default()
	}
	log.WarnContext(context.Background(), "archive stream reset", "peer", id.String(), "operation", "unknown", "reason", resetReasonName(err), "error", err)
	if writeFrame(stream, resetFrame(err)) != nil {
		_ = stream.Reset()
	}
}

// Serve handles one exchange. The frame cap is checked before allocation or
// archive decoding, and reads and writes are split into bounded byte slices.
func (s *Server) Serve(ctx context.Context, rw io.ReadWriter) error {
	frame, err := readFrame(rw, maxArchiveFrameBytes)
	if err != nil || len(frame) < 2 {
		return fmt.Errorf("%w: %w", ErrHandler, ErrTransport)
	}
	return s.serveFrame(ctx, rw, frame)
}

func (s *Server) serveFrame(ctx context.Context, rw io.ReadWriter, frame []byte) error {
	if len(frame) < 2 {
		return fmt.Errorf("%w: %w", ErrHandler, archive.ErrInvalid)
	}
	op := frame[0]
	if op == 4 || op == 5 {
		return typedHandlerError(s.serveBundle(ctx, rw, op, frame[1:]))
	}
	if op == 3 {
		query, err := archive.DecodeRoundRequest(frame[1:])
		if err != nil || !sameArchiveContext(query.Context, s.subject) {
			return fmt.Errorf("%w: %w", ErrHandler, archive.ErrInvalid)
		}
		found, record, err := s.store.GetLatest(query)
		if err != nil {
			return writeFrame(rw, []byte{byte(archive.Unavailable)})
		}
		encoded, err := archive.EncodeResponse(archive.Response{Request: found, Outcome: archive.OK, Record: record})
		if err != nil {
			return err
		}
		return typedHandlerError(writeFrame(rw, append([]byte{byte(archive.OK)}, encoded...)))
	}
	var q archive.Request
	var rec *archive.Record
	var err error
	switch op {
	case 1:
		decoded, e := archive.DecodeResponse(frame[1:])
		if e != nil || decoded.Outcome != archive.OK {
			return fmt.Errorf("%w: %w", ErrHandler, archive.ErrInvalid)
		}
		q, rec = decoded.Request, decoded.Record
	case 2:
		q, err = archive.DecodeRequest(frame[1:])
		if err != nil {
			return fmt.Errorf("%w: %w", ErrHandler, err)
		}
	default:
		return fmt.Errorf("%w: %w", ErrHandler, archive.ErrInvalid)
	}
	qb, _ := archive.EncodeRequest(q)
	if !bytes.Equal(qb[:len(qb)-32], s.want) {
		if op == 2 {
			encoded, err := archive.EncodeResponse(archive.Response{Request: q, Outcome: archive.Invalid})
			if err != nil {
				return err
			}
			return typedHandlerError(writeFrame(rw, encoded))
		}
		return fmt.Errorf("%w: %w", ErrHandler, archive.ErrInvalid)
	}
	if op == 1 {
		if err := s.verify(ctx, q, rec); err != nil {
			return fmt.Errorf("%w: %w: %w", ErrVerifier, ErrReplica, err)
		}
		if err := s.store.Put(q, rec); err != nil {
			return fmt.Errorf("%w: %w", ErrHandler, err)
		}
		return typedHandlerError(writeFrame(rw, []byte{1}))
	}
	answer := s.store.Serve(q)
	encoded, err := archive.EncodeResponse(answer)
	if err != nil {
		return err
	}
	return typedHandlerError(writeFrame(rw, encoded))
}

func (s *Server) serveBundle(ctx context.Context, rw io.ReadWriter, op byte, payload []byte) error {
	if op == 4 {
		q, err := archive.DecodeBundleRequest(payload)
		if err != nil || !sameArchiveContext(q.Context, s.subject) {
			return fmt.Errorf("%w: %w", ErrHandler, archive.ErrInvalid)
		}
		raw, err := s.store.GetBundle(q)
		if errors.Is(err, archive.ErrUnavailable) {
			return writeFrame(rw, []byte{0})
		}
		if err != nil {
			return fmt.Errorf("%w: %w", ErrHandler, err)
		}
		return typedHandlerError(writeFrame(rw, append([]byte{1}, raw...)))
	}
	if len(payload) < 2 {
		return fmt.Errorf("%w: %w", ErrHandler, archive.ErrInvalid)
	}
	n := int(binary.BigEndian.Uint16(payload[:2]))
	if n == 0 || n > archive.MaxRequestBytes || len(payload) <= 2+n || len(payload)-2-n > archive.MaxBundleBytes {
		return fmt.Errorf("%w: %w", ErrHandler, archive.ErrInvalid)
	}
	q, err := archive.DecodeBundleRequest(payload[2 : 2+n])
	if err != nil || !sameArchiveContext(q.Context, s.subject) || s.bundleVerify == nil {
		return fmt.Errorf("%w: %w", ErrHandler, archive.ErrInvalid)
	}
	raw := payload[2+n:]
	if err := s.bundleVerify(ctx, q, raw); err != nil {
		return fmt.Errorf("%w: %w: %w", ErrVerifier, ErrReplica, err)
	}
	if _, err := RetainBundle(ctx, s.store, q, raw, s.bundleVerify, s.log); err != nil {
		return fmt.Errorf("%w: %w", ErrHandler, err)
	}
	return typedHandlerError(writeFrame(rw, []byte{1}))
}

func typedHandlerError(err error) error {
	if err == nil || errors.Is(err, ErrHandler) || errors.Is(err, ErrVerifier) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrHandler, err)
}

func archiveOperation(op byte) string {
	switch op {
	case 1:
		return "put"
	case 2:
		return "get"
	case 3:
		return "get-latest"
	case 4:
		return "bundle-get"
	case 5:
		return "bundle-put"
	default:
		return "unknown"
	}
}

func resetReasonName(err error) string {
	switch {
	case errors.Is(err, ErrPeerNotAllowed):
		return "not_allowed"
	case errors.Is(err, ErrPeerLimit):
		return "per_peer_limit"
	case errors.Is(err, ErrPendingLimit):
		return "pending_limit"
	case errors.Is(err, archive.ErrBundleConflict):
		return "bundle_conflict"
	case errors.Is(err, ErrVerifier):
		return "verifier_error"
	default:
		return "handler_error"
	}
}

func resetFrame(err error) []byte {
	code := byte(5) // handler error
	switch {
	case errors.Is(err, ErrPeerNotAllowed):
		code = 1
	case errors.Is(err, ErrPeerLimit):
		code = 2
	case errors.Is(err, ErrPendingLimit):
		code = 3
	case errors.Is(err, archive.ErrBundleConflict):
		code = 6 // checked before the generic handler code: it is the same failure class, with the semantic sentinel kept
	case errors.Is(err, ErrVerifier):
		code = 4
	case errors.Is(err, ErrHandler):
		code = 5
	}
	return []byte{resetFrameMarker, code}
}

func decodeResetFrame(frame []byte, id peer.ID, payload []byte) error {
	if len(frame) == 0 || frame[0] != resetFrameMarker {
		return nil
	}
	if len(frame) != 2 {
		return ErrReplica
	}
	var reason error
	switch frame[1] {
	case 1:
		reason = ErrPeerNotAllowed
	case 2:
		reason = ErrPeerLimit
	case 3:
		reason = ErrPendingLimit
	case 4:
		reason = ErrVerifier
	case 5:
		reason = ErrHandler
	case 6:
		// Still a handler failure (existing callers match ErrHandler), and the semantic sentinel survives the wire.
		reason = fmt.Errorf("%w: %w", ErrHandler, archive.ErrBundleConflict)
	default:
		return ErrReplica
	}
	operation := "unknown"
	if len(payload) > 0 {
		operation = archiveOperation(payload[0])
	}
	return &StreamResetError{Peer: id, Operation: operation, Reason: reason}
}

func FetchBundle(ctx context.Context, host shardnode.EvidenceHost, id peer.ID, q archive.BundleRequest, limits Limits) ([]byte, error) {
	if host == nil || id == "" || !limits.valid() {
		return nil, archive.ErrInvalid
	}
	request, err := archive.EncodeBundleRequest(q)
	if err != nil {
		return nil, err
	}
	answer, err := exchange(ctx, host, id, append([]byte{4}, request...), limits)
	if err != nil {
		return nil, err
	}
	if len(answer) == 1 && answer[0] == 0 {
		return nil, archive.ErrUnavailable
	}
	if len(answer) < 2 || answer[0] != 1 || len(answer)-1 > archive.MaxBundleBytes {
		return nil, ErrReplica
	}
	return answer[1:], nil
}

// PutBundleAndReadBack stores the bundle on the replica and reads it back. The replica may keep a different valid copy of the same handoff
// (it retains the first it was given), so the read-back must be the same bytes or, when verify is set, the same handoff under verification.
func PutBundleAndReadBack(ctx context.Context, host shardnode.EvidenceHost, id peer.ID, q archive.BundleRequest, raw []byte, limits Limits, verify BundleVerifier) error {
	if len(raw) == 0 || len(raw) > archive.MaxBundleBytes {
		return archive.ErrInvalid
	}
	request, err := archive.EncodeBundleRequest(q)
	if err != nil || len(request) > 65535 {
		return archive.ErrInvalid
	}
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(request)))
	payload := append([]byte{5, n[0], n[1]}, request...)
	payload = append(payload, raw...)
	answer, err := exchange(ctx, host, id, payload, limits)
	if err != nil {
		return err
	}
	if !bytes.Equal(answer, []byte{1}) {
		return ErrReplica
	}
	got, err := FetchBundle(ctx, host, id, q, limits)
	if err != nil {
		return ErrReplica
	}
	if !readBackMatches(ctx, q, verify, got, raw) {
		return ErrReplica
	}
	return nil
}

// readBackMatches: the replica holds the same bytes, or (when it can be verified) the same handoff.
func readBackMatches(ctx context.Context, q archive.BundleRequest, verify BundleVerifier, got, raw []byte) bool {
	if bytes.Equal(got, raw) {
		return true
	}
	if verify == nil {
		return false
	}
	same, err := SameBundle(ctx, q, verify, got, raw)
	return err == nil && same
}

// PutAndReadBack verifies the exact manifest digest from a separately fetched
// complete copy. Transport success alone is never a durable acknowledgement.
func PutAndReadBack(ctx context.Context, host shardnode.EvidenceHost, id peer.ID, q archive.Request, rec *archive.Record, limits Limits) error {
	if host == nil || id == "" || !limits.valid() {
		return archive.ErrInvalid
	}
	want, err := archive.ManifestDigest(q, rec)
	if err != nil {
		return err
	}
	encoded, err := archive.EncodeResponse(archive.Response{Request: q, Outcome: archive.OK, Record: rec})
	if err != nil {
		return err
	}
	answer, err := exchange(ctx, host, id, append([]byte{1}, encoded...), limits)
	if err != nil {
		return err
	}
	if !bytes.Equal(answer, []byte{1}) {
		return ErrReplica
	}
	request, _ := archive.EncodeRequest(q)
	answer, err = exchange(ctx, host, id, append([]byte{2}, request...), limits)
	if err != nil {
		return err
	}
	readBack, err := archive.DecodeFor(q, answer)
	if err != nil || readBack.Outcome != archive.OK || readBack.Record == nil {
		return ErrReplica
	}
	got, err := archive.ManifestDigest(q, readBack.Record)
	if err != nil || got != want {
		return ErrReplica
	}
	return nil
}

// Fetch reads an exact record from one configured replica. Authentication is
// the caller's responsibility; DecodeFor only checks framing and echo.
func Fetch(ctx context.Context, host shardnode.EvidenceHost, id peer.ID, q archive.Request, limits Limits) (*archive.Record, error) {
	if host == nil || id == "" || !limits.valid() {
		return nil, archive.ErrInvalid
	}
	raw, err := archive.EncodeRequest(q)
	if err != nil {
		return nil, err
	}
	answer, err := exchange(ctx, host, id, append([]byte{2}, raw...), limits)
	if err != nil {
		return nil, err
	}
	response, err := archive.DecodeFor(q, answer)
	if err != nil || response.Outcome != archive.OK || response.Record == nil {
		return nil, ErrReplica
	}
	return response.Record, nil
}

// FetchLatest locates one record by certified shard round. The returned
// record and the server's choice are untrusted until the restorer verifies
// the certificate and compares its state root with the pinned tip.
func FetchLatest(ctx context.Context, host shardnode.EvidenceHost, id peer.ID, query archive.RoundRequest, limits Limits) (archive.Request, *archive.Record, error) {
	if host == nil || id == "" || !limits.valid() {
		return archive.Request{}, nil, archive.ErrInvalid
	}
	raw, err := archive.EncodeRoundRequest(query)
	if err != nil {
		return archive.Request{}, nil, err
	}
	answer, err := exchange(ctx, host, id, append([]byte{3}, raw...), limits)
	if err != nil {
		return archive.Request{}, nil, err
	}
	if len(answer) == 1 && answer[0] == byte(archive.Unavailable) {
		return archive.Request{}, nil, archive.ErrUnavailable
	}
	if len(answer) < 2 || answer[0] != byte(archive.OK) {
		return archive.Request{}, nil, ErrReplica
	}
	response, err := archive.DecodeResponse(answer[1:])
	if err != nil || response.Outcome != archive.OK || response.Record == nil || !sameArchiveContext(response.Request.Context, query.Context) {
		return archive.Request{}, nil, ErrReplica
	}
	return response.Request, response.Record, nil
}

func exchange(parent context.Context, host shardnode.EvidenceHost, id peer.ID, payload []byte, limits Limits) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, limits.Deadline)
	defer cancel()
	var last error
	for attempt := 0; attempt <= 8; attempt++ {
		answer, err := exchangeOnce(ctx, host, id, payload)
		if !errors.Is(err, ErrPeerLimit) || attempt == 8 {
			return answer, err
		}
		last = err
		backoff := attempt
		if backoff > 3 {
			backoff = 3
		}
		delay := time.Duration(1<<backoff) * 100 * time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, errors.Join(last, ctx.Err())
		case <-timer.C:
		}
	}
	return nil, last
}

func exchangeOnce(ctx context.Context, host shardnode.EvidenceHost, id peer.ID, payload []byte) ([]byte, error) {
	stream, err := host.CreateStream(ctx, id, ProtocolArchive)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	defer stream.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	if err := writeFrame(stream, payload); err != nil {
		_ = stream.Reset()
		return nil, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	answer, err := readFrame(stream, maxArchiveFrameBytes)
	if err != nil {
		_ = stream.Reset()
		return nil, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	if resetErr := decodeResetFrame(answer, id, payload); resetErr != nil {
		return nil, resetErr
	}
	return answer, nil
}

func readFrame(r io.Reader, max int) ([]byte, error) {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || uint64(n) > uint64(max) {
		return nil, archive.ErrInvalid
	}
	out := make([]byte, 0)
	var chunk [transferChunk]byte
	for remaining := int(n); remaining > 0; {
		step := remaining
		if step > len(chunk) {
			step = len(chunk)
		}
		if _, err := io.ReadFull(r, chunk[:step]); err != nil {
			return nil, err
		}
		out = append(out, chunk[:step]...)
		remaining -= step
	}
	return out, nil
}

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > archive.MaxBundleBytes+archive.MaxRequestBytes+8 {
		return archive.ErrInvalid
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(payload)))
	if n, err := w.Write(size[:]); err != nil {
		return err
	} else if n != len(size) {
		return io.ErrShortWrite
	}
	for off := 0; off < len(payload); {
		end := off + transferChunk
		if end > len(payload) {
			end = len(payload)
		}
		n, err := w.Write(payload[off:end])
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		off += n
	}
	return nil
}
