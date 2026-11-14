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
	// buckets is each peer's request budget (a token bucket, ucRelayRate per second up to ucRelayBurst).
	buckets map[peer.ID]*relayBucket
	now     func() time.Time
	// the serialized frame of the held pair, rebuilt only when the held pair changes
	cachedUC *types.UnicityCertificate
	cachedTR *certification.TechnicalRecord
	cached   []byte
}

type relayBucket struct {
	tokens float64
	at     time.Time
}

const (
	ucRelayRate         = 2.0 // requests per second per peer
	ucRelayBurst        = 4
	ucRelayTrackedPeers = 1024
)

// NewUCRelayServer serves held to the peers allowed admits (the active and staged shard peers).
func NewUCRelayServer(held func() (*types.UnicityCertificate, *certification.TechnicalRecord), allowed func(peer.ID) bool) *UCRelayServer {
	return &UCRelayServer{held: held, allowed: allowed, perPeer: map[peer.ID]int{}, buckets: map[peer.ID]*relayBucket{}, now: time.Now}
}

func (s *UCRelayServer) reserve(id peer.ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.total >= ucRelayMaxConcurrent || s.perPeer[id] >= ucRelayMaxPerPeer {
		return false
	}
	now := s.now()
	b := s.buckets[id]
	if b == nil {
		if len(s.buckets) >= ucRelayTrackedPeers {
			for other := range s.buckets { // bounded state: drop an idle peer's budget (it refills to the burst anyway)
				if s.perPeer[other] == 0 {
					delete(s.buckets, other)
					break
				}
			}
		}
		b = &relayBucket{tokens: ucRelayBurst, at: now}
		s.buckets[id] = b
	}
	b.tokens = min(ucRelayBurst, b.tokens+now.Sub(b.at).Seconds()*ucRelayRate)
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
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
	frame, err := s.frame()
	if err != nil {
		_ = st.Reset()
		return
	}
	if _, err := st.Write(frame); err != nil {
		_ = st.Reset()
	}
}

// frame is the serialized answer for the held pair, encoded once per held pair (the client replaces the held pointers on adoption).
func (s *UCRelayServer) frame() ([]byte, error) {
	uc, tr := s.held()
	if uc == nil || tr == nil {
		return nil, ErrUCRelay
	}
	s.mu.Lock()
	if s.cachedUC == uc && s.cachedTR == tr && s.cached != nil {
		out := s.cached
		s.mu.Unlock()
		return out, nil
	}
	s.mu.Unlock()
	ub, err := types.Cbor.Marshal(uc)
	if err != nil {
		return nil, err
	}
	tb, err := types.Cbor.Marshal(tr)
	if err != nil {
		return nil, err
	}
	body, err := types.Cbor.Marshal(ucRelayPair{UC: ub, Technical: tb})
	if err != nil || len(body) > ucRelayMaxResponse {
		return nil, ErrUCRelay
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(body)))
	out := append(n[:], body...)
	s.mu.Lock()
	s.cachedUC, s.cachedTR, s.cached = uc, tr, out
	s.mu.Unlock()
	return out, nil
}

// StreamOpener opens a stream to a peer (network.Peer.CreateStream).
type StreamOpener interface {
	CreateStream(ctx context.Context, id peer.ID, protocol string) (libp2pnetwork.Stream, error)
}

// FetchHeldPair asks one peer for the pair it holds. A cancelled ctx ends the exchange wherever it is, a stream read included (the stream
// is reset).
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
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = st.Reset() // interrupts a blocked read
		case <-stop:
		}
	}()
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

// ucRelayClient is the backup path of an active node: when the roots have given no useful progress for after, it asks two of its active
// peers, in parallel and OUTSIDE the client's event loop, for the pair they hold, and queues what it gets into the loop's serialized
// admission (the same verification and admission as a root's response). At most one batch runs at a time, bounded by the relay deadline;
// the next is not started before after has passed since the last one ended, and eligibility (an active role, still no progress) is
// checked again before each. A batch is cancelled, stream reads included, the moment a certificate is adopted or the role ends. A
// duplicate, stale or invalid answer refreshes nothing (the progress clock moves only on an adopted certificate).
type ucRelayClient struct {
	host    StreamOpener
	sources func() []peer.ID
	after   time.Duration
	results chan relayedPair

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	ended   time.Time
	next    int
	// batch is the identity of the latest batch; invalidBefore discards every result of a batch below it. Retirement and useful progress
	// invalidate (a result already queued is then dropped at admission); a batch that simply completes keeps its queued answers usable.
	batch, invalidBefore uint64
}

// relayedPair is one relay answer, with the role token and the batch it was asked under: it is admitted only while that role and batch
// are still current (astra on #1054, r2).
type relayedPair struct {
	cr    *certification.CertificationResponse
	token uint64
	batch uint64
}

// SetRelay enables the UC relay backup: when no certificate has been adopted for after, two of sources are asked. Call before Run.
func (c *BFTClient) SetRelay(host StreamOpener, sources func() []peer.ID, after time.Duration) {
	if host == nil || sources == nil || after <= 0 {
		return
	}
	c.relay = &ucRelayClient{host: host, sources: sources, after: after, results: make(chan relayedPair, 2)}
}

// relayResults is the channel Run admits relayed pairs from; nil without a relay.
func (c *BFTClient) relayResults() <-chan relayedPair {
	if c.relay == nil {
		return nil
	}
	return c.relay.results
}

// relayDue reports whether a new batch should start now: an active role, nothing adopted for after (repeats included), no batch running,
// and after passed since the last one ended.
func (c *BFTClient) relayDue(now time.Time) bool {
	r := c.relay
	if r == nil || c.isFollower() {
		return false
	}
	if now.Sub(c.clock().Delivered()) < r.after {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.running && now.Sub(r.ended) >= r.after
}

// relayCancel ends and invalidates the latest batch (an adopted certificate, or the role ended): its fetches stop and its answers, queued
// or still to come, are dropped at admission. Safe on a client without a relay.
func (c *BFTClient) relayCancel() {
	r := c.relay
	if r == nil {
		return
	}
	r.mu.Lock()
	cancel := r.cancel
	r.invalidBefore = r.batch + 1
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// relayStart starts one bounded batch in the background: two sources, rotating, fetched in parallel; each verified-by-admission answer is
// queued for Run. It returns at once.
func (c *BFTClient) relayStart(ctx context.Context) {
	r := c.relay
	sources := r.sources()
	if len(sources) == 0 {
		return
	}
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return
	}
	token, active := c.role.Load().current() // the role the batch is asked under, rechecked at every enqueue and at admission
	if !active {
		r.mu.Unlock()
		return
	}
	batch, cancel := context.WithTimeout(ctx, ucRelayDeadline)
	r.running, r.cancel = true, cancel
	r.batch++
	batchID := r.batch
	picked := make([]peer.ID, 0, 2)
	for k := 0; k < 2 && k < len(sources); k++ {
		picked = append(picked, sources[(r.next+k)%len(sources)])
	}
	r.next = (r.next + 2) % len(sources)
	r.mu.Unlock()
	go func() {
		var wg sync.WaitGroup
		for _, id := range picked {
			wg.Add(1)
			go func(id peer.ID) {
				defer wg.Done()
				uc, tr, err := FetchHeldPair(batch, r.host, id)
				if err != nil {
					if c.log != nil {
						c.log.DebugContext(batch, "UC relay source unavailable", slog.String("peer", id.String()), slog.String("err", err.Error()))
					}
					return
				}
				if !c.role.Load().admits(token) {
					return // the role ended (or was re-published) while this peer answered: nothing is queued
				}
				cr := &certification.CertificationResponse{Partition: c.partitionID, Shard: c.shardID, UC: *uc, Technical: *tr}
				select {
				case r.results <- relayedPair{cr: cr, token: token, batch: batchID}:
				default: // the loop has two queued already: this one would add nothing
				}
			}(id)
		}
		wg.Wait()
		cancel()
		r.mu.Lock()
		r.running, r.cancel, r.ended = false, nil, time.Now()
		r.mu.Unlock()
	}()
}

// relayAdmissible reports whether a queued relay answer may still be admitted: its role token is the current, active one and its batch has
// not been invalidated. A retirement, a re-publication or useful progress since the batch began drops it, even if it was queued already.
func (c *BFTClient) relayAdmissible(p relayedPair) bool {
	r := c.relay
	if r == nil || !c.role.Load().admits(p.token) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return p.batch >= r.invalidBefore
}
