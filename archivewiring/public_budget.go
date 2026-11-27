package archivewiring

import (
	"errors"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// PublicBudget bounds the sustained work of public reads (bft-core#1066, astra's review of #1070): Limits bound how many public streams are
// served at once, this bounds what they cost over time. Work is counted in record reads (a store read with its representation lookup),
// debited BEFORE each read; bytes are the encoded size of every record read, debited after the read whether or not it is sent (a record
// dropped at a chain read's byte bound cost its read). Each has a token bucket per peer, keyed by the authenticated peer ID, and one for all
// public readers together, so new identities cannot reset it. The design is the records feed's public budget (bft-core#1056).
//
// Byte debits may take a bucket below zero (a record's size is known only once it is read): a bucket in debt admits no read until it has
// refilled to zero, so the debt is paid at the bucket's rate.
type PublicBudget struct {
	// Rate and Burst are one peer's record reads per second and burst; GlobalRate and GlobalBurst those of all public readers.
	Rate        float64
	Burst       int
	GlobalRate  float64
	GlobalBurst int
	// ByteRate and ByteBurst are one peer's read bytes per second and burst; GlobalByteRate and GlobalByteBurst all public readers'.
	ByteRate        float64
	ByteBurst       int
	GlobalByteRate  float64
	GlobalByteBurst int
	// MaxTrackedPeers bounds the per-peer state. Only an entry that has refilled completely and has no stream in flight is dropped for a
	// new peer, so dropping it gives nobody tokens; when none can be dropped, a new peer is refused until one can.
	MaxTrackedPeers int
}

// DefaultPublicBudget lets one follower catch up far faster than it executes (a chain read is MaxChainRecords records) while a crowd of
// identities shares the global buckets.
func DefaultPublicBudget() PublicBudget {
	return PublicBudget{
		Rate: 256, Burst: 4 * MaxChainRecords, GlobalRate: 1024, GlobalBurst: 16 * MaxChainRecords,
		ByteRate: 16 << 20, ByteBurst: 64 << 20, GlobalByteRate: 64 << 20, GlobalByteBurst: 256 << 20,
		MaxTrackedPeers: 4096,
	}
}

var ErrPublicBudget = errors.New("archive wiring: invalid public read budget")

func (b PublicBudget) valid(pending int) bool {
	return b.Rate > 0 && b.Burst >= 1 && b.GlobalRate > 0 && b.GlobalBurst >= 1 && b.ByteRate > 0 && b.ByteBurst >= 1 &&
		b.GlobalByteRate > 0 && b.GlobalByteBurst >= 1 && b.MaxTrackedPeers >= pending
}

type tokenBucket struct {
	tokens float64
	at     time.Time
}

func (b *tokenBucket) refill(now time.Time, rate float64, burst int) {
	b.tokens = min(float64(burst), b.tokens+now.Sub(b.at).Seconds()*rate)
	b.at = now
}

type budgetEntry struct {
	work, bytes tokenBucket
	inFlight    int
}

// publicBudget is the state of a PublicBudget.
type publicBudget struct {
	limits PublicBudget
	now    func() time.Time

	mu       sync.Mutex
	peers    map[peer.ID]*budgetEntry
	allWork  tokenBucket
	allBytes tokenBucket
}

func newPublicBudget(l PublicBudget, now func() time.Time) *publicBudget {
	t := now()
	return &publicBudget{limits: l, now: now, peers: map[peer.ID]*budgetEntry{},
		allWork: tokenBucket{tokens: float64(l.GlobalBurst), at: t}, allBytes: tokenBucket{tokens: float64(l.GlobalByteBurst), at: t}}
}

// begin starts a public stream of the peer: false when the peer cannot be tracked (the table is full of depleted or busy entries).
func (b *publicBudget) begin(id peer.ID) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.entryLocked(id, b.now())
	if e == nil {
		return false
	}
	e.inFlight++
	return true
}

func (b *publicBudget) end(id peer.ID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.peers[id]; e != nil && e.inFlight > 0 {
		e.inFlight--
	}
}

// take debits one record read from the peer's and the global work budgets, or nothing: false when either has no token or either byte
// budget is in debt.
func (b *publicBudget) take(id peer.ID) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	e := b.entryLocked(id, now)
	b.allWork.refill(now, b.limits.GlobalRate, b.limits.GlobalBurst)
	b.allBytes.refill(now, b.limits.GlobalByteRate, b.limits.GlobalByteBurst)
	if e == nil || e.work.tokens < 1 || b.allWork.tokens < 1 || e.bytes.tokens < 0 || b.allBytes.tokens < 0 {
		return false
	}
	e.work.tokens--
	b.allWork.tokens--
	return true
}

// charge debits n read bytes from the peer's and the global byte budgets, into debt if need be.
func (b *publicBudget) charge(id peer.ID, n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if e := b.entryLocked(id, now); e != nil {
		e.bytes.tokens -= float64(n)
	}
	b.allBytes.refill(now, b.limits.GlobalByteRate, b.limits.GlobalByteBurst)
	b.allBytes.tokens -= float64(n)
}

// entryLocked is the peer's entry, refilled to now, or nil when the peer cannot be tracked. A new peer gets full buckets only in place of
// an entry that has refilled completely by now and has no stream in flight: such an entry is exactly what a new one would be.
func (b *publicBudget) entryLocked(id peer.ID, now time.Time) *budgetEntry {
	l := b.limits
	refill := func(e *budgetEntry) {
		e.work.refill(now, l.Rate, l.Burst)
		e.bytes.refill(now, l.ByteRate, l.ByteBurst)
	}
	if e := b.peers[id]; e != nil {
		refill(e)
		return e
	}
	if len(b.peers) >= l.MaxTrackedPeers {
		for other, e := range b.peers {
			if e.inFlight > 0 {
				continue
			}
			refill(e)
			if e.work.tokens >= float64(l.Burst) && e.bytes.tokens >= float64(l.ByteBurst) {
				delete(b.peers, other)
				break
			}
		}
		if len(b.peers) >= l.MaxTrackedPeers {
			return nil
		}
	}
	e := &budgetEntry{work: tokenBucket{tokens: float64(l.Burst), at: now}, bytes: tokenBucket{tokens: float64(l.ByteBurst), at: now}}
	b.peers[id] = e
	return e
}

// readMeter charges one public stream's reads to its peer's budget; a nil meter (an authorized peer) charges nothing.
type readMeter struct {
	budget *publicBudget
	id     peer.ID
}

func (m *readMeter) take() bool { return m == nil || m.budget.take(m.id) }

func (m *readMeter) charge(n int) {
	if m != nil {
		m.budget.charge(m.id, n)
	}
}
