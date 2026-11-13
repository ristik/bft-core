package rootchain

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Near-future certification requests (#1032). A shard node sends its request for round N+1 as soon as it holds the certificate of
// round N; a root that has not applied the commit of round N yet still expects round N. Such a request is not counted, not
// subscribed and not answered under the old context: it is held, bounded, until the node's committed context advances, and then
// admitted from scratch under the context then in force (membership, signature, shard, round, epoch, previous state, timestamp,
// proof and weights). A request that is still not admissible then is rejected as any other. Only the round directly after the
// expected one is held, and only a request that passed membership and signature under the current context.
//
// Nothing already held is ever evicted by a later request: a shard holds at most earlyRoundsPerShard rounds, each its own set, so a
// request for a newer round (the context advanced before the held set was replayed) never displaces a held set that may be a ready
// quorum; it is refused instead when the bounds are reached, and the held sets leave only by replay or expiry. The proof is verified
// only at admission, so the bytes a held request may carry are bounded per request and in total.

const (
	// earlyRequestTTL is how long a near-future request is held at most. Commits apply within a few root rounds.
	earlyRequestTTL = 4 * time.Second
	// earlyRequestsPerShard bounds the requests held for one shard, over its rounds (one per node and round).
	earlyRequestsPerShard = 32
	// earlyRoundsPerShard bounds the distinct rounds held for one shard.
	earlyRoundsPerShard = 2
	// earlyRequestShards bounds the shards with held requests.
	earlyRequestShards = 128
	// earlyRequestMaxBytes bounds the encoding of one held request: a larger one (its proof is not verified before admission) is
	// refused as before rather than held.
	earlyRequestMaxBytes = 2 << 20
	// earlyRequestBudget bounds the encoded bytes of all held requests.
	earlyRequestBudget = 16 << 20
	// earlyRequestSweep is how often held requests are expired.
	earlyRequestSweep = 250 * time.Millisecond
	// earlyRequestFallback is how often held requests are admitted again when no certificate of their shard prompted it (a fallback:
	// every commit of a shard emits its certificate, which prompts the replay). Each held request is re-verified at most
	// earlyRequestTTL/earlyRequestFallback times without a commit of its shard.
	earlyRequestFallback = 2 * time.Second
	// earlyRequestsPerSigner bounds the encoded bytes one node id may have held over all shards.
	earlyRequestsPerSigner = 4 << 20
)

var (
	// errEarlyConflict refuses a near-future request whose node already has a different held request for the same round.
	errEarlyConflict = errors.New("conflicting near-future request of the node")
	// errEarlyFull refuses a near-future request beyond the bounds of the buffer.
	errEarlyFull = errors.New("near-future request buffer is full")
	// errEarlyTooLarge refuses to hold a request whose encoding exceeds earlyRequestMaxBytes.
	errEarlyTooLarge = errors.New("near-future request too large to hold")
)

type earlyEntry struct {
	req      *certification.BlockCertificationRequest
	epoch    uint64 // the root epoch installed when the request was first held: a replay never carries it into another one
	digest   [sha256.Size]byte
	size     int
	deadline time.Time
}

type earlyShard struct {
	partition types.PartitionID
	shard     types.ShardID
	rounds    map[uint64]map[string]earlyEntry // request round -> node -> entry
}

func (s *earlyShard) len() int {
	n := 0
	for _, r := range s.rounds {
		n += len(r)
	}
	return n
}

// earlyRequests is the bounded buffer of near-future requests, per shard, round and node.
type earlyRequests struct {
	mu     sync.Mutex
	now    func() time.Time
	ttl    time.Duration
	bytes  int            // encoded bytes held
	signer map[string]int // encoded bytes held per node id, over all shards
	shards map[types.PartitionShardID]*earlyShard
	// ready is the shards whose committed context advanced since their requests were held, and notify wakes the partition loop for
	// them: a signal is never lost, however many shards advance at once
	ready  map[types.PartitionShardID]shardRef
	notify chan struct{}
}

func newEarlyRequests() *earlyRequests {
	return &earlyRequests{now: time.Now, ttl: earlyRequestTTL, shards: make(map[types.PartitionShardID]*earlyShard),
		signer: make(map[string]int), ready: make(map[types.PartitionShardID]shardRef), notify: make(chan struct{}, 1)}
}

// markReady records that the shard's committed context advanced, when it has held requests, and wakes the partition loop.
func (b *earlyRequests) markReady(partition types.PartitionID, shard types.ShardID) {
	key := types.PartitionShardID{PartitionID: partition, ShardID: shard.Key()}
	b.mu.Lock()
	_, held := b.shards[key]
	if held {
		b.ready[key] = shardRef{partition: partition, shard: shard}
	}
	b.mu.Unlock()
	if held {
		select {
		case b.notify <- struct{}{}:
		default: // already signalled: the pending wake-up drains every ready shard
		}
	}
}

// takeReady returns and forgets the shards marked ready.
func (b *earlyRequests) takeReady() []shardRef {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]shardRef, 0, len(b.ready))
	for k, r := range b.ready {
		out = append(out, r)
		delete(b.ready, k)
	}
	return out
}

// expire drops the entries past their deadline.
func (b *earlyRequests) expire() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expireLocked(b.now())
}

// hold keeps req, a request for the round after the expected one whose sender passed membership and signature under the current
// context. deadline zero is now+ttl; a replayed entry keeps its first deadline, so re-holding never extends it. The same bytes again
// are idempotent; other bytes of the same node and round are a conflict and the first one stays. Nothing held is displaced.
func (b *earlyRequests) hold(req *certification.BlockCertificationRequest, deadline time.Time) error {
	return b.holdUnder(req, deadline, 0)
}

// holdUnder is hold, recording the root epoch installed when the request is held.
func (b *earlyRequests) holdUnder(req *certification.BlockCertificationRequest, deadline time.Time, epoch uint64) error {
	raw, err := types.Cbor.Marshal(req)
	if err != nil {
		return fmt.Errorf("encoding the request: %w", err)
	}
	if len(raw) > earlyRequestMaxBytes {
		return fmt.Errorf("%w: %d bytes, at most %d", errEarlyTooLarge, len(raw), earlyRequestMaxBytes)
	}
	digest := sha256.Sum256(raw)
	now := b.now()
	if deadline.IsZero() {
		deadline = now.Add(b.ttl)
	}
	if !deadline.After(now) {
		return fmt.Errorf("near-future request expired")
	}
	key := types.PartitionShardID{PartitionID: req.PartitionID, ShardID: req.ShardID.Key()}
	round := req.IRRound()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expireLocked(now)
	s := b.shards[key]
	if s != nil {
		if e, ok := s.rounds[round][req.NodeID]; ok {
			if e.digest != digest {
				return fmt.Errorf("%w %s in round %d", errEarlyConflict, req.NodeID, round)
			}
			return nil
		}
	}
	if b.bytes+len(raw) > earlyRequestBudget {
		return fmt.Errorf("%w: %d bytes held", errEarlyFull, b.bytes)
	}
	if b.signer[req.NodeID]+len(raw) > earlyRequestsPerSigner {
		return fmt.Errorf("%w: %d bytes held for node %s", errEarlyFull, b.signer[req.NodeID], req.NodeID)
	}
	if s == nil {
		if len(b.shards) >= earlyRequestShards {
			return fmt.Errorf("%w: %d shards", errEarlyFull, len(b.shards))
		}
		s = &earlyShard{partition: req.PartitionID, shard: req.ShardID, rounds: make(map[uint64]map[string]earlyEntry)}
		b.shards[key] = s
	}
	set := s.rounds[round]
	if set == nil {
		if len(s.rounds) >= earlyRoundsPerShard {
			return fmt.Errorf("%w: %d rounds of shard %s-%s", errEarlyFull, len(s.rounds), req.PartitionID, req.ShardID)
		}
	}
	if s.len() >= earlyRequestsPerShard {
		return fmt.Errorf("%w: %d requests of shard %s-%s", errEarlyFull, s.len(), req.PartitionID, req.ShardID)
	}
	if set == nil {
		set = make(map[string]earlyEntry)
		s.rounds[round] = set
	}
	set[req.NodeID] = earlyEntry{req: req, epoch: epoch, digest: digest, size: len(raw), deadline: deadline}
	b.charge(req.NodeID, len(raw))
	return nil
}

// take removes and returns the unexpired requests held for the shard, every round, oldest round first.
func (b *earlyRequests) take(partition types.PartitionID, shard types.ShardID) []earlyEntry {
	key := types.PartitionShardID{PartitionID: partition, ShardID: shard.Key()}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expireLocked(b.now())
	s := b.shards[key]
	if s == nil {
		return nil
	}
	delete(b.shards, key)
	delete(b.ready, key)
	var rounds []uint64
	for r := range s.rounds {
		rounds = append(rounds, r)
	}
	if len(rounds) == 2 && rounds[0] > rounds[1] {
		rounds[0], rounds[1] = rounds[1], rounds[0]
	}
	out := make([]earlyEntry, 0, s.len())
	for _, r := range rounds {
		for _, e := range s.rounds[r] {
			out = append(out, e)
			b.charge(e.req.NodeID, -e.size)
		}
	}
	return out
}

// shardRef names a shard with held requests.
type shardRef struct {
	partition types.PartitionID
	shard     types.ShardID
}

// shardsHeld is the shards with unexpired held requests.
func (b *earlyRequests) shardsHeld() []shardRef {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expireLocked(b.now())
	out := make([]shardRef, 0, len(b.shards))
	for _, s := range b.shards {
		out = append(out, shardRef{partition: s.partition, shard: s.shard})
	}
	return out
}

// len is the number of held requests.
func (b *earlyRequests) len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expireLocked(b.now())
	n := 0
	for _, s := range b.shards {
		n += s.len()
	}
	return n
}

// charge accounts n encoded bytes (negative: released) to the buffer and the node.
func (b *earlyRequests) charge(node string, n int) {
	b.bytes += n
	if b.signer[node] += n; b.signer[node] <= 0 {
		delete(b.signer, node)
	}
}

func (b *earlyRequests) expireLocked(now time.Time) {
	for k, s := range b.shards {
		for r, set := range s.rounds {
			for id, e := range set {
				if !e.deadline.After(now) {
					delete(set, id)
					b.charge(id, -e.size)
				}
			}
			if len(set) == 0 {
				delete(s.rounds, r)
			}
		}
		if len(s.rounds) == 0 {
			delete(b.shards, k)
			delete(b.ready, k)
		}
	}
}
