package recordsfeed

import (
	"errors"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// The records feed's authorization is per operation (bft-core#1048):
//
//   - a cut (kindCut) is served only to the peers the server's allowed function accepts (the roots and the shards' validators);
//   - a record read (kindRecords) is served to those peers under the server's ordinary budget, and, when public reads are enabled
//     (SetPublicRecords), to any other peer under a separate public budget.
//
// A record is public and self-authenticating: a reader verifies every record it gets, link by link, against a checkpoint or cut it
// authenticated by itself, so serving one grants nothing. What the public budget protects is the server: a peer it does not know gets
// bounded concurrency, request rate, response bytes and time, apart from the validators' budget, and never a cut or anything else.

// PublicLimits bound the record reads of peers the server does not authorize.
type PublicLimits struct {
	// Pending and PerPeer bound the public streams served at once, in all and for one peer.
	Pending, PerPeer int
	// Rate and Burst are one peer's request budget (a token bucket keyed by the authenticated peer ID); GlobalRate and GlobalBurst are
	// that of all public readers together.
	Rate        float64
	Burst       int
	GlobalRate  float64
	GlobalBurst int
	// ByteRate and ByteBurst are one peer's response-byte budget, GlobalByteRate and GlobalByteBurst all public readers'. A burst must
	// hold the largest response (MaxBatchBytes), or such a response could never be served.
	ByteRate        float64
	ByteBurst       int
	GlobalByteRate  float64
	GlobalByteBurst int
	// MaxBatch is the most records one public request returns (at most MaxBatch).
	MaxBatch int
	// HeaderDeadline bounds the wait for the request frame (a peer that opens a stream and withholds its request frees the slot quickly),
	// Deadline the whole exchange.
	HeaderDeadline, Deadline time.Duration
	// MaxTrackedPeers bounds the per-peer rate state; idle entries are dropped first.
	MaxTrackedPeers int
}

// DefaultPublicLimits are the public budget a root serves record reads under.
func DefaultPublicLimits() PublicLimits {
	return PublicLimits{
		Pending: 8, PerPeer: 1,
		Rate: 4, Burst: 8, GlobalRate: 32, GlobalBurst: 64,
		ByteRate: 2 << 20, ByteBurst: 2 * MaxBatchBytes, GlobalByteRate: 8 << 20, GlobalByteBurst: 4 * MaxBatchBytes,
		MaxBatch:       MaxBatch,
		HeaderDeadline: 2 * time.Second, Deadline: 10 * time.Second,
		MaxTrackedPeers: 4096,
	}
}

// ErrPublicLimits reports public limits that cannot work (a zero bound, or a byte burst below the largest response).
var ErrPublicLimits = errors.New("recordsfeed: invalid public read limits")

func (l PublicLimits) valid() bool {
	return l.Pending > 0 && l.PerPeer > 0 && l.PerPeer <= l.Pending && l.Rate > 0 && l.Burst >= 1 && l.GlobalRate > 0 && l.GlobalBurst >= 1 &&
		l.ByteRate > 0 && l.ByteBurst >= MaxBatchBytes && l.GlobalByteRate > 0 && l.GlobalByteBurst >= MaxBatchBytes &&
		l.MaxBatch > 0 && l.MaxBatch <= MaxBatch && l.HeaderDeadline > 0 && l.Deadline >= l.HeaderDeadline && l.MaxTrackedPeers > 0
}

// operationAllowed is the per-operation authorization boundary: authorized is whether the server's allowed function accepts the peer.
func operationAllowed(kind uint8, authorized, public bool) bool {
	switch kind {
	case kindRecords:
		return authorized || public
	case kindCut:
		return authorized
	default:
		return false
	}
}

type tokenBucket struct {
	tokens float64
	at     time.Time
}

func (b *tokenBucket) refill(now time.Time, rate float64, burst int) {
	b.tokens = min(float64(burst), b.tokens+now.Sub(b.at).Seconds()*rate)
	b.at = now
}

// publicBudget is the state of the public limits: concurrency, request and byte buckets per peer and in all.
type publicBudget struct {
	limits PublicLimits
	now    func() time.Time

	mu        sync.Mutex
	pending   int
	perPeer   map[peer.ID]int
	requests  map[peer.ID]*tokenBucket
	bytes     map[peer.ID]*tokenBucket
	allReqs   tokenBucket
	allBytes  tokenBucket
	rejected  uint64
	bytesSent uint64
}

func newPublicBudget(l PublicLimits, now func() time.Time) *publicBudget {
	t := now()
	return &publicBudget{limits: l, now: now, perPeer: map[peer.ID]int{}, requests: map[peer.ID]*tokenBucket{}, bytes: map[peer.ID]*tokenBucket{},
		allReqs: tokenBucket{tokens: float64(l.GlobalBurst), at: t}, allBytes: tokenBucket{tokens: float64(l.GlobalByteBurst), at: t}}
}

// admit takes a concurrency slot and one request token of the peer and of all public readers, or nothing.
func (b *publicBudget) admit(id peer.ID) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	l := b.limits
	if b.pending >= l.Pending || b.perPeer[id] >= l.PerPeer {
		b.rejected++
		return false
	}
	req := b.bucketLocked(b.requests, id, now, l.Burst)
	req.refill(now, l.Rate, l.Burst)
	b.allReqs.refill(now, l.GlobalRate, l.GlobalBurst)
	if req.tokens < 1 || b.allReqs.tokens < 1 {
		b.rejected++
		return false
	}
	req.tokens--
	b.allReqs.tokens--
	b.pending++
	b.perPeer[id]++
	return true
}

// spend takes n response bytes from the peer's and the global byte budgets, or nothing.
func (b *publicBudget) spend(id peer.ID, n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	l := b.limits
	own := b.bucketLocked(b.bytes, id, now, l.ByteBurst)
	own.refill(now, l.ByteRate, l.ByteBurst)
	b.allBytes.refill(now, l.GlobalByteRate, l.GlobalByteBurst)
	if own.tokens < float64(n) || b.allBytes.tokens < float64(n) {
		b.rejected++
		return false
	}
	own.tokens -= float64(n)
	b.allBytes.tokens -= float64(n)
	b.bytesSent += uint64(n)
	return true
}

func (b *publicBudget) release(id peer.ID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pending--
	if b.perPeer[id]--; b.perPeer[id] <= 0 {
		delete(b.perPeer, id)
	}
}

// bucketLocked is the peer's bucket in m, made full when new. The tracked peers are bounded: first the idle peers whose buckets have
// refilled (they lose nothing by it), then the longest idle one.
func (b *publicBudget) bucketLocked(m map[peer.ID]*tokenBucket, id peer.ID, now time.Time, burst int) *tokenBucket {
	if t := m[id]; t != nil {
		return t
	}
	if len(m) >= b.limits.MaxTrackedPeers {
		var oldest peer.ID
		var oldestAt time.Time
		for other, t := range m {
			if b.perPeer[other] > 0 {
				continue
			}
			if t.tokens >= float64(burst) || now.Sub(t.at) > time.Hour {
				delete(m, other)
				continue
			}
			if oldest == "" || t.at.Before(oldestAt) {
				oldest, oldestAt = other, t.at
			}
		}
		if len(m) >= b.limits.MaxTrackedPeers && oldest != "" {
			delete(m, oldest)
		}
	}
	t := &tokenBucket{tokens: float64(burst), at: now}
	m[id] = t
	return t
}

// PublicStats are the public budget's counters (diagnostics).
type PublicStats struct {
	Pending   int
	Rejected  uint64
	BytesSent uint64
}
