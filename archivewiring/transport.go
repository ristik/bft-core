package archivewiring

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/shardnode"
)

const ProtocolArchive = "/unicity/certified-archive/1.0.0"
const transferChunk = 64 << 10

var ErrTransport = errors.New("archive wiring: replica transport failed")
var ErrReplica = errors.New("archive wiring: replica refused or changed record")

type Limits struct {
	Deadline time.Duration
	Pending  int
	PerPeer  int
}

func DefaultLimits() Limits { return Limits{Deadline: 20 * time.Second, Pending: 4, PerPeer: 1} }

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
	limits       Limits
	allowed      map[peer.ID]struct{}
	mu           sync.Mutex
	pending      int
	byPeer       map[peer.ID]int
}

func (s *Server) SetBundleVerifier(v BundleVerifier) { s.bundleVerify = v }

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
	return &Server{store: store, subject: contextValue, want: want[:len(want)-32], verify: verify, limits: limits, allowed: peers, byPeer: make(map[peer.ID]int)}, nil
}

func (s *Server) Register(ctx context.Context, host shardnode.EvidenceHost) {
	s.ctx = ctx
	host.RegisterProtocolHandler(ProtocolArchive, s.handle)
}

func (s *Server) enter(id peer.ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.allowed[id]; !ok || s.pending >= s.limits.Pending || s.byPeer[id] >= s.limits.PerPeer {
		return false
	}
	s.pending++
	s.byPeer[id]++
	return true
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
	if !s.enter(id) {
		_ = stream.Reset()
		return
	}
	defer s.leave(id)
	_ = stream.SetDeadline(time.Now().Add(s.limits.Deadline))
	ctx, cancel := context.WithTimeout(s.ctx, s.limits.Deadline)
	defer cancel()
	if err := s.Serve(ctx, stream); err != nil {
		_ = stream.Reset()
	}
}

// Serve handles one exchange. The frame cap is checked before allocation or
// archive decoding, and reads and writes are split into bounded byte slices.
func (s *Server) Serve(ctx context.Context, rw io.ReadWriter) error {
	frame, err := readFrame(rw, archive.MaxBundleBytes+archive.MaxRequestBytes+8)
	if err != nil || len(frame) < 2 {
		return ErrTransport
	}
	op := frame[0]
	if op == 4 || op == 5 {
		return s.serveBundle(ctx, rw, op, frame[1:])
	}
	if op == 3 {
		query, err := archive.DecodeRoundRequest(frame[1:])
		if err != nil || !sameArchiveContext(query.Context, s.subject) {
			return archive.ErrInvalid
		}
		found, record, err := s.store.GetLatest(query)
		if err != nil {
			return writeFrame(rw, []byte{byte(archive.Unavailable)})
		}
		encoded, err := archive.EncodeResponse(archive.Response{Request: found, Outcome: archive.OK, Record: record})
		if err != nil {
			return err
		}
		return writeFrame(rw, append([]byte{byte(archive.OK)}, encoded...))
	}
	var q archive.Request
	var rec *archive.Record
	switch op {
	case 1:
		decoded, e := archive.DecodeResponse(frame[1:])
		if e != nil || decoded.Outcome != archive.OK {
			return archive.ErrInvalid
		}
		q, rec = decoded.Request, decoded.Record
	case 2:
		q, err = archive.DecodeRequest(frame[1:])
		if err != nil {
			return err
		}
	default:
		return archive.ErrInvalid
	}
	qb, _ := archive.EncodeRequest(q)
	if !bytes.Equal(qb[:len(qb)-32], s.want) {
		if op == 2 {
			encoded, err := archive.EncodeResponse(archive.Response{Request: q, Outcome: archive.Invalid})
			if err != nil {
				return err
			}
			return writeFrame(rw, encoded)
		}
		return archive.ErrInvalid
	}
	if op == 1 {
		if err := s.verify(ctx, q, rec); err != nil {
			return fmt.Errorf("%w: %v", ErrReplica, err)
		}
		if err := s.store.Put(q, rec); err != nil {
			return err
		}
		return writeFrame(rw, []byte{1})
	}
	answer := s.store.Serve(q)
	encoded, err := archive.EncodeResponse(answer)
	if err != nil {
		return err
	}
	return writeFrame(rw, encoded)
}

func (s *Server) serveBundle(ctx context.Context, rw io.ReadWriter, op byte, payload []byte) error {
	if op == 4 {
		q, err := archive.DecodeBundleRequest(payload)
		if err != nil || !sameArchiveContext(q.Context, s.subject) {
			return archive.ErrInvalid
		}
		raw, err := s.store.GetBundle(q)
		if errors.Is(err, archive.ErrUnavailable) {
			return writeFrame(rw, []byte{0})
		}
		if err != nil {
			return err
		}
		return writeFrame(rw, append([]byte{1}, raw...))
	}
	if len(payload) < 2 {
		return archive.ErrInvalid
	}
	n := int(binary.BigEndian.Uint16(payload[:2]))
	if n == 0 || n > archive.MaxRequestBytes || len(payload) <= 2+n || len(payload)-2-n > archive.MaxBundleBytes {
		return archive.ErrInvalid
	}
	q, err := archive.DecodeBundleRequest(payload[2 : 2+n])
	if err != nil || !sameArchiveContext(q.Context, s.subject) || s.bundleVerify == nil {
		return archive.ErrInvalid
	}
	raw := payload[2+n:]
	if err := s.bundleVerify(ctx, q, raw); err != nil {
		return fmt.Errorf("%w: %v", ErrReplica, err)
	}
	if err := s.store.PutBundle(q, raw); err != nil {
		return err
	}
	return writeFrame(rw, []byte{1})
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

func PutBundleAndReadBack(ctx context.Context, host shardnode.EvidenceHost, id peer.ID, q archive.BundleRequest, raw []byte, limits Limits) error {
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
	if err != nil || !bytes.Equal(got, raw) {
		return ErrReplica
	}
	return nil
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
	answer, err := readFrame(stream, archive.MaxBundleBytes+archive.MaxRequestBytes+8)
	if err != nil {
		_ = stream.Reset()
		return nil, fmt.Errorf("%w: %v", ErrTransport, err)
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
