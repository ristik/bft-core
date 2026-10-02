package shardnode

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// This is a non-consensus request/response protocol. The requester pins the
// certified target and its retained ancestor. Peers supply bytes, not trust.
const ProtocolJournalSuffix = "/unicity/shard-journal-suffix/1.0.0"

type JournalFetchRequest struct {
	_            struct{} `cbor:",toarray"`
	TargetHash   []byte
	AfterHash    []byte
	HeldRound    uint64
	HeldIdentity []byte
}

type JournalFetchEntry struct {
	_             struct{} `cbor:",toarray"`
	Block         Block
	ParentState   []byte
	Round         uint64
	AuthorizingUC *types.UnicityCertificate
	AuthorizingTR *certification.TechnicalRecord
	ResultingUC   *types.UnicityCertificate
	ResultingTR   *certification.TechnicalRecord
}

type journalFetchResponse struct {
	_       struct{} `cbor:",toarray"`
	Error   string
	Entries []JournalFetchEntry
}

type JournalTransportLimits struct {
	MaxBlocks         int
	MaxRequestBytes   int
	MaxResponseBytes  int
	MaxTotalBytes     int64
	Deadline          time.Duration
	MaxPending        int
	MaxPendingPerPeer int
}

func DefaultJournalTransportLimits() JournalTransportLimits {
	return JournalTransportLimits{MaxBlocks: 256, MaxRequestBytes: 4096, MaxResponseBytes: 72 << 20, MaxTotalBytes: 64 << 20, Deadline: 10 * time.Second, MaxPending: 8, MaxPendingPerPeer: 2}
}

func (l JournalTransportLimits) validate() error {
	if l.MaxBlocks <= 0 || l.MaxBlocks > 4096 || l.MaxRequestBytes < 128 || l.MaxResponseBytes < 1024 || l.MaxTotalBytes <= 0 || l.Deadline <= 0 || l.MaxPending <= 0 || l.MaxPendingPerPeer <= 0 || l.MaxPendingPerPeer > l.MaxPending {
		return errors.New("journal transport: invalid limits")
	}
	return nil
}

func checkJournalFetch(req JournalFetchRequest) error {
	if len(req.AfterHash) != 32 || len(req.TargetHash) != 32 && (len(req.TargetHash) != 0 || req.HeldRound == 0 || len(req.HeldIdentity) == 0 || len(req.HeldIdentity) > 2048) {
		return errors.New("journal transport: request needs a 32-byte ancestor and a certified target hash or held quiet certificate identity")
	}
	return nil
}

type JournalFetchProvider interface {
	FetchJournal(context.Context, JournalFetchRequest) ([]JournalFetchEntry, error)
}

type JournalServer struct {
	provider  JournalFetchProvider
	limits    JournalTransportLimits
	admission *streamAdmission
	allowed   map[peer.ID]struct{}
	// authorize, when set, decides who may fetch (the active assignment's validators); allowed is the fixed list of a deployment that
	// follows no assignment.
	authorize func(peer.ID) bool
}

// RestrictToPeers must be called before Register. The configured shard
// validator set, not an incoming request, supplies these identities.
func (s *JournalServer) RestrictToPeers(peers []peer.ID) {
	s.allowed = make(map[peer.ID]struct{}, len(peers))
	for _, id := range peers {
		s.allowed[id] = struct{}{}
	}
}

// SetPeerAuthorizer makes the active assignment decide who may fetch from this node's journal, in place of a fixed list. Call before
// Register.
func (s *JournalServer) SetPeerAuthorizer(allow func(peer.ID) bool) { s.authorize = allow }

func NewJournalServer(provider JournalFetchProvider, limits JournalTransportLimits) (*JournalServer, error) {
	if provider == nil {
		return nil, errors.New("journal transport: missing provider")
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	return &JournalServer{provider: provider, limits: limits, admission: newStreamAdmission(limits.MaxPending, limits.MaxPendingPerPeer)}, nil
}

func (s *JournalServer) Register(host EvidenceHost) {
	host.RegisterProtocolHandler(ProtocolJournalSuffix, s.handle)
}

// permits: the authorizer when one is set (the active assignment), else the fixed list, else everyone (a deployment that configured none).
func (s *JournalServer) permits(remote peer.ID) bool {
	if s.authorize != nil {
		return s.authorize(remote)
	}
	if s.allowed != nil {
		_, ok := s.allowed[remote]
		return ok
	}
	return true
}

func (s *JournalServer) handle(st libp2pnetwork.Stream) {
	defer st.Close()
	remote := st.Conn().RemotePeer()
	if !s.permits(remote) {
		_ = st.Reset()
		return
	}
	from := remote.String()
	if err := s.admission.acquire(from); err != nil {
		_ = st.Reset()
		return
	}
	defer s.admission.release(from)
	_ = st.SetDeadline(time.Now().Add(s.limits.Deadline))
	ctx, cancel := context.WithTimeout(context.Background(), s.limits.Deadline)
	defer cancel()
	if err := s.Serve(ctx, st); err != nil {
		_ = st.Reset()
		return
	}
	_ = st.CloseWrite()
}

// Serve is one bounded exchange. A refused request carries a diagnostic but
// never a partial suffix, so a requester can try another peer safely.
func (s *JournalServer) Serve(ctx context.Context, rw io.ReadWriter) error {
	var req JournalFetchRequest
	if err := readFrame(bufio.NewReader(rw), &req, s.limits.MaxRequestBytes); err != nil {
		return err
	}
	if err := checkJournalFetch(req); err != nil {
		return writeFrame(rw, journalFetchResponse{Error: err.Error()}, s.limits.MaxResponseBytes)
	}
	entries, err := s.provider.FetchJournal(ctx, req)
	if err != nil {
		return writeFrame(rw, journalFetchResponse{Error: detail(err.Error())}, s.limits.MaxResponseBytes)
	}
	if len(entries) == 0 || len(entries) > s.limits.MaxBlocks {
		return writeFrame(rw, journalFetchResponse{Error: "suffix outside block limit"}, s.limits.MaxResponseBytes)
	}
	var total int64
	for _, e := range entries {
		total += int64(len(e.Block.Raw))
		if total > s.limits.MaxTotalBytes {
			return writeFrame(rw, journalFetchResponse{Error: "suffix outside byte limit"}, s.limits.MaxResponseBytes)
		}
	}
	if err := writeFrame(rw, journalFetchResponse{Entries: entries}, s.limits.MaxResponseBytes); err != nil {
		if errors.Is(err, errFrameTooLarge) {
			return writeFrame(rw, journalFetchResponse{Error: "suffix outside response frame limit"}, s.limits.MaxResponseBytes)
		}
		return err
	}
	return nil
}

func RequestJournalEntries(ctx context.Context, host EvidenceHost, p peer.ID, req JournalFetchRequest, limits JournalTransportLimits) ([]JournalFetchEntry, error) {
	if host == nil {
		return nil, errors.New("journal transport: missing host")
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if err := checkJournalFetch(req); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, limits.Deadline)
	defer cancel()
	st, err := host.CreateStream(ctx, p, ProtocolJournalSuffix)
	if err != nil {
		return nil, fmt.Errorf("journal transport: opening stream to %s: %w", p, err)
	}
	defer st.Close()
	if dl, ok := ctx.Deadline(); ok {
		if err := st.SetDeadline(dl); err != nil {
			_ = st.Reset()
			return nil, err
		}
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			_ = st.Reset()
		case <-done:
		}
	}()
	var resp journalFetchResponse
	err = writeFrame(st, req, limits.MaxRequestBytes)
	if err == nil {
		err = readFrame(bufio.NewReader(st), &resp, limits.MaxResponseBytes)
	}
	close(done)
	<-stopped
	if err != nil {
		_ = st.Reset()
		return nil, fmt.Errorf("journal transport: peer %s: %w", p, err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("journal transport: peer %s refused: %s", p, resp.Error)
	}
	if len(resp.Entries) == 0 || len(resp.Entries) > limits.MaxBlocks {
		return nil, fmt.Errorf("journal transport: peer %s returned %d entries outside limit", p, len(resp.Entries))
	}
	var total int64
	for _, e := range resp.Entries {
		total += int64(len(e.Block.Raw))
		if total > limits.MaxTotalBytes {
			return nil, fmt.Errorf("journal transport: peer %s exceeded byte limit", p)
		}
	}
	return resp.Entries, nil
}
