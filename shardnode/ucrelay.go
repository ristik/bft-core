package shardnode

import (
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

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// UCRelayProtocol is the stream protocol on which an active shard validator serves the certificate it holds to its peers: the backup to
// the roots' direct push (phase 2). A relayed pair is untrusted bytes; the receiver admits it through exactly the verification and
// admission of a root's response, so a peer can withhold or replay authentic old evidence but cannot forge any.
const UCRelayProtocol = "/unicity/uc-relay/1.0.0"

const (
	ucRelayMaxResponse   = 1 << 20
	ucRelayDeadline      = 2 * time.Second
	ucRelayMaxPerPeer    = 2
	ucRelayMaxConcurrent = 16
)

// ErrUCRelay is a relay exchange that is not one bounded, canonical frame.
var ErrUCRelay = errors.New("shardnode: invalid UC relay exchange")

type ucRelayPair struct {
	_         struct{} `cbor:",toarray"`
	UC        []byte
	Technical []byte
}

// Held is the client's held certificate and its technical record, nil when it holds none yet.
func (c *BFTClient) Held() (*types.UnicityCertificate, *certification.TechnicalRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.luc == nil || c.heldTR == nil {
		return nil, nil
	}
	return c.luc, c.heldTR
}

// UCRelayServer serves the held pair to the peers allowed admits, bounded in total and per peer.
type UCRelayServer struct {
	held    func() (*types.UnicityCertificate, *certification.TechnicalRecord)
	allowed func(peer.ID) bool
	mu      sync.Mutex
	total   int
	perPeer map[peer.ID]int
}

// NewUCRelayServer serves held to the peers allowed admits (the active and staged shard peers).
func NewUCRelayServer(held func() (*types.UnicityCertificate, *certification.TechnicalRecord), allowed func(peer.ID) bool) *UCRelayServer {
	return &UCRelayServer{held: held, allowed: allowed, perPeer: map[peer.ID]int{}}
}

func (s *UCRelayServer) reserve(id peer.ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.total >= ucRelayMaxConcurrent || s.perPeer[id] >= ucRelayMaxPerPeer {
		return false
	}
	s.total++
	s.perPeer[id]++
	return true
}

func (s *UCRelayServer) release(id peer.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total--
	if s.perPeer[id]--; s.perPeer[id] <= 0 {
		delete(s.perPeer, id)
	}
}

// Handler is the libp2p stream handler. The request carries nothing: the answer is the held pair.
func (s *UCRelayServer) Handler(st libp2pnetwork.Stream) {
	defer st.Close()
	id := st.Conn().RemotePeer()
	if (s.allowed != nil && !s.allowed(id)) || !s.reserve(id) {
		_ = st.Reset()
		return
	}
	defer s.release(id)
	_ = st.SetDeadline(time.Now().Add(ucRelayDeadline))
	uc, tr := s.held()
	if uc == nil || tr == nil {
		_ = st.Reset()
		return
	}
	ub, err := types.Cbor.Marshal(uc)
	if err != nil {
		_ = st.Reset()
		return
	}
	tb, err := types.Cbor.Marshal(tr)
	if err != nil {
		_ = st.Reset()
		return
	}
	body, err := types.Cbor.Marshal(ucRelayPair{UC: ub, Technical: tb})
	if err != nil || len(body) > ucRelayMaxResponse {
		_ = st.Reset()
		return
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(body)))
	if _, err := st.Write(append(n[:], body...)); err != nil {
		_ = st.Reset()
	}
}

// StreamOpener opens a stream to a peer (network.Peer.CreateStream).
type StreamOpener interface {
	CreateStream(ctx context.Context, id peer.ID, protocol string) (libp2pnetwork.Stream, error)
}

// FetchHeldPair asks one peer for the pair it holds.
func FetchHeldPair(ctx context.Context, host StreamOpener, id peer.ID) (*types.UnicityCertificate, *certification.TechnicalRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, ucRelayDeadline)
	defer cancel()
	st, err := host.CreateStream(ctx, id, UCRelayProtocol)
	if err != nil {
		return nil, nil, err
	}
	defer st.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetDeadline(dl)
	}
	_ = st.CloseWrite()
	var n [4]byte
	if _, err := io.ReadFull(st, n[:]); err != nil {
		return nil, nil, err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size == 0 || size > ucRelayMaxResponse {
		return nil, nil, fmt.Errorf("%w: frame of %d bytes", ErrUCRelay, size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(st, body); err != nil {
		return nil, nil, err
	}
	var pair ucRelayPair
	if err := types.Cbor.Unmarshal(body, &pair); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrUCRelay, err)
	}
	var uc types.UnicityCertificate
	var tr certification.TechnicalRecord
	if types.Cbor.Unmarshal(pair.UC, &uc) != nil || types.Cbor.Unmarshal(pair.Technical, &tr) != nil {
		return nil, nil, ErrUCRelay
	}
	return &uc, &tr, nil
}

// ucRelayClient is the backup path of an active node: when the roots have given no useful progress for After, it asks up to two of its
// active peers for the pair they hold and offers what it gets through the same admission as a root's response. Asking is rate-limited to
// once per After; a duplicate, stale or invalid answer refreshes nothing (the progress clock moves only on an adopted certificate).
type ucRelayClient struct {
	host    StreamOpener
	sources func() []peer.ID
	after   time.Duration
	asked   time.Time
	next    int
}

// SetRelay enables the UC relay backup: when no certificate has been adopted for after, up to two of sources are asked. Call before Run.
func (c *BFTClient) SetRelay(host StreamOpener, sources func() []peer.ID, after time.Duration) {
	if host == nil || sources == nil || after <= 0 {
		return
	}
	c.relay = &ucRelayClient{host: host, sources: sources, after: after}
}

// relayDue reports whether the backup should ask now (Run's loop only).
func (c *BFTClient) relayDue(now time.Time) bool {
	if c.relay == nil || c.isFollower() {
		return false
	}
	since := now.Sub(c.clock().Delivered()) // nothing adopted, repeats included: delivery is stalled
	return since >= c.relay.after && now.Sub(c.relay.asked) >= c.relay.after
}

// relayFetch asks up to two sources, rotating through them, and offers each pair it gets to the admission. Run's loop only.
func (c *BFTClient) relayFetch(ctx context.Context, now time.Time) {
	r := c.relay
	r.asked = now
	sources := r.sources()
	for k := 0; k < 2 && k < len(sources); k++ {
		id := sources[(r.next+k)%len(sources)]
		uc, tr, err := FetchHeldPair(ctx, r.host, id)
		if err != nil {
			if c.log != nil {
				c.log.DebugContext(ctx, "UC relay source unavailable", slog.String("peer", id.String()), slog.String("err", err.Error()))
			}
			continue
		}
		cr := &certification.CertificationResponse{Partition: c.partitionID, Shard: c.shardID, UC: *uc, Technical: *tr}
		if err := c.handleCertificationResponse(ctx, cr); err != nil && c.log != nil {
			c.log.DebugContext(ctx, "relayed certificate not admitted", slog.String("peer", id.String()), slog.String("err", err.Error()))
		}
	}
	if len(sources) > 0 {
		r.next = (r.next + 2) % len(sources)
	}
}
