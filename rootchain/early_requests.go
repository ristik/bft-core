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

const (
	// earlyRequestTTL is how long a near-future request is held at most. Commits apply within a few root rounds.
	earlyRequestTTL = 4 * time.Second
	// earlyRequestsPerShard bounds the requests held for one shard (one per node).
	earlyRequestsPerShard = 32
	// earlyRequestShards bounds the shards with held requests.
	earlyRequestShards = 128
	// earlyRequestSweep is how often held requests are retried and expired when no certificate prompted it.
	earlyRequestSweep = 250 * time.Millisecond
)

var (
	// errEarlyConflict refuses a near-future request whose node already has a different held request for the same round.
	errEarlyConflict = errors.New("conflicting near-future request of the node")
	// errEarlyFull refuses a near-future request beyond the bounds of the buffer.
	errEarlyFull = errors.New("near-future request buffer is full")
	// errEarlyBehind refuses a request for a round behind the round already held for its shard.
	errEarlyBehind = errors.New("near-future request is behind the held round")
)

type earlyEntry struct {
	req      *certification.BlockCertificationRequest
	digest   [sha256.Size]byte
	deadline time.Time
}

type earlyShard struct {
	partition types.PartitionID
	shard     types.ShardID
	round     uint64 // the request round every held entry carries
	byNode    map[string]earlyEntry
}

// earlyRequests is the bounded buffer of near-future requests, per shard and node.
type earlyRequests struct {
	mu     sync.Mutex
	now    func() time.Time
	ttl    time.Duration
	shards map[types.PartitionShardID]*earlyShard
}

func newEarlyRequests() *earlyRequests {
	return &earlyRequests{now: time.Now, ttl: earlyRequestTTL, shards: make(map[types.PartitionShardID]*earlyShard)}
}

func requestDigest(req *certification.BlockCertificationRequest) ([sha256.Size]byte, error) {
	raw, err := types.Cbor.Marshal(req)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(raw), nil
}

// hold keeps req, a request for the round after the expected one whose sender passed membership and signature under the current
// context. deadline zero is now+ttl; a replayed entry keeps its first deadline, so re-holding never extends it. The same bytes again
// are idempotent; other bytes of the same node and round are a conflict and the first one stays.
func (b *earlyRequests) hold(req *certification.BlockCertificationRequest, deadline time.Time) error {
	digest, err := requestDigest(req)
	if err != nil {
		return fmt.Errorf("encoding the request: %w", err)
	}
	now := b.now()
	if deadline.IsZero() {
		deadline = now.Add(b.ttl)
	}
	if !deadline.After(now) {
		return fmt.Errorf("near-future request expired")
	}
	key := types.PartitionShardID{PartitionID: req.PartitionID, ShardID: req.ShardID.Key()}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expireLocked(now)
	s := b.shards[key]
	round := req.IRRound()
	if s != nil && s.round != round {
		if round < s.round {
			return fmt.Errorf("%w: round %d, held %d", errEarlyBehind, round, s.round)
		}
		s = nil // the held round is behind: the context it was ahead of has passed
		delete(b.shards, key)
	}
	if s == nil {
		if len(b.shards) >= earlyRequestShards {
			return fmt.Errorf("%w: %d shards", errEarlyFull, len(b.shards))
		}
		s = &earlyShard{partition: req.PartitionID, shard: req.ShardID, round: round, byNode: make(map[string]earlyEntry)}
		b.shards[key] = s
	}
	if e, ok := s.byNode[req.NodeID]; ok {
		if e.digest != digest {
			return fmt.Errorf("%w %s in round %d", errEarlyConflict, req.NodeID, round)
		}
		return nil
	}
	if len(s.byNode) >= earlyRequestsPerShard {
		return fmt.Errorf("%w: %d requests of shard %s-%s", errEarlyFull, len(s.byNode), req.PartitionID, req.ShardID)
	}
	s.byNode[req.NodeID] = earlyEntry{req: req, digest: digest, deadline: deadline}
	return nil
}

// take removes and returns the unexpired requests held for the shard.
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
	out := make([]earlyEntry, 0, len(s.byNode))
	for _, e := range s.byNode {
		out = append(out, e)
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
		n += len(s.byNode)
	}
	return n
}

func (b *earlyRequests) expireLocked(now time.Time) {
	for k, s := range b.shards {
		for id, e := range s.byNode {
			if !e.deadline.After(now) {
				delete(s.byNode, id)
			}
		}
		if len(s.byNode) == 0 {
			delete(b.shards, k)
		}
	}
}
