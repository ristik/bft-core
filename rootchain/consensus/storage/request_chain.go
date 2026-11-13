package storage

import (
	"bytes"
	"fmt"
	"slices"
	"sort"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-go-base/types"
)

// RequestChain is the validated activation chain of one shard: a trusted anchor, then every activation and continuation the committed
// history issued for the shard, each checked against the one before it exactly once (#1032). It is immutable: Extend validates only the
// appended links and returns a new chain, so a resolution against an older chain is never affected by a later activation. The cost of
// a resolution is therefore independent of the number of installed epochs; the chain is never revalidated from the anchor per request.
type RequestChain struct {
	network   uint64
	partition types.PartitionID
	shard     types.ShardID
	acts      []*RequestActivation
	base      []int // base[i]: the index of the real activation (or anchor) that entry i is, or continues
}

// RequestChainSource is the optional capability of a RequestHistory that serves the validated chain itself, maintained incrementally,
// instead of a slice the resolver validates on every resolution.
type RequestChainSource interface {
	RequestChain(partition types.PartitionID, shard types.ShardID) (*RequestChain, error)
}

// NewRequestChain validates the whole chain: chain[0] is the anchor, every activation is of the anchor's shard and network, and each
// follows the one before it (consecutive shard epochs, rising activation rounds, rising root epochs; a continuation repeats the
// assignment under the next root interval). Missing or unlinked history is ErrAssignmentHistory, another network a request context
// mismatch.
func NewRequestChain(network uint64, chain ...*RequestActivation) (*RequestChain, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("%w: no activation history", ErrAssignmentHistory)
	}
	first := chain[0]
	if first == nil || first.start != 0 || first.continuation {
		return nil, fmt.Errorf("%w: history does not begin at a trusted anchor", ErrAssignmentHistory)
	}
	c := &RequestChain{network: network, partition: first.pdr.PartitionID, shard: first.pdr.ShardID}
	return c.extend(chain...)
}

// Extend is the chain with the given activations appended, each validated against its predecessor; the receiver is unchanged.
func (c *RequestChain) Extend(next ...*RequestActivation) (*RequestChain, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: no activation history", ErrAssignmentHistory)
	}
	if len(next) == 0 {
		return c, nil
	}
	return c.extend(next...)
}

func (c *RequestChain) extend(next ...*RequestActivation) (*RequestChain, error) {
	out := &RequestChain{network: c.network, partition: c.partition, shard: c.shard,
		acts: slices.Grow(slices.Clone(c.acts), len(next)), base: slices.Grow(slices.Clone(c.base), len(next))}
	for _, a := range next {
		i := len(out.acts)
		if a == nil || a.pdr.PartitionID != c.partition || !a.pdr.ShardID.Equal(c.shard) {
			return nil, fmt.Errorf("%w: activation %d is not of shard %s-%s", ErrAssignmentHistory, i, c.partition, c.shard)
		}
		if i == 0 {
			out.acts, out.base = append(out.acts, a), append(out.base, 0)
			continue
		}
		p := out.acts[i-1]
		if a.start <= p.start || a.rootEpoch <= p.rootEpoch || a.pdr.NetworkID != p.pdr.NetworkID {
			return nil, fmt.Errorf("%w: activation %d does not follow activation %d", ErrAssignmentHistory, i, i-1)
		}
		base := i
		if a.continuation {
			// the same assignment under the next root interval: identical configuration, context, version and original commitment, the
			// next root epoch, and the very body the previous interval was authorised by
			if a.pdr.Epoch != p.pdr.Epoch || a.rootEpoch != p.rootEpoch+1 || p.rootEpoch == ^uint64(0) || !bytes.Equal(a.predecessorRootBody, p.rootBody) ||
				!bytes.Equal(a.confHash, p.confHash) || a.ctx != p.ctx || a.version != p.version || !bytes.Equal(a.trHash, p.trHash) || !samePDR(a.pdr, p.pdr) {
				return nil, fmt.Errorf("%w: continuation %d is not the continuation of activation %d", ErrAssignmentHistory, i, i-1)
			}
			base = out.base[i-1]
		} else if p.pdr.Epoch == ^uint64(0) || a.pdr.Epoch != p.pdr.Epoch+1 {
			return nil, fmt.Errorf("%w: activation %d does not follow activation %d", ErrAssignmentHistory, i, i-1)
		}
		out.acts, out.base = append(out.acts, a), append(out.base, base)
	}
	// the network is authenticated by the history (and, per snapshot, the previous UC), never asserted beside them; checked after the
	// links, as the snapshot always did
	for i := len(c.acts); i < len(out.acts); i++ {
		if a := out.acts[i]; uint64(a.pdr.NetworkID) != c.network {
			return nil, fmt.Errorf("%w: snapshot network %d, activation %d is of network %d", quorumweight.ErrRequestContext, c.network, i, a.pdr.NetworkID)
		}
	}
	return out, nil
}

// Len is the number of entries of the chain, the anchor included.
func (c *RequestChain) Len() int { return len(c.acts) }

// Tip is the last entry of the chain.
func (c *RequestChain) Tip() *RequestActivation { return c.acts[len(c.acts)-1] }

// Network is the network every activation of the chain belongs to.
func (c *RequestChain) Network() uint64 { return c.network }

// Activations is a copy of the chain's entries, anchor first.
func (c *RequestChain) Activations() []*RequestActivation { return slices.Clone(c.acts) }

// inForce is the index of the latest entry starting at or before round, or -1. Starts strictly rise along a validated chain.
func (c *RequestChain) inForce(round uint64) int {
	return sort.Search(len(c.acts), func(i int) bool { return c.acts[i].start > round }) - 1
}

// ofShardEpoch is the index of the first entry (the real activation, never one of its continuations) of the given shard epoch, or -1.
// Shard epochs never fall along a validated chain.
func (c *RequestChain) ofShardEpoch(epoch uint64) int {
	i := sort.Search(len(c.acts), func(i int) bool { return c.acts[i].pdr.Epoch >= epoch })
	if i < len(c.acts) && c.acts[i].pdr.Epoch == epoch {
		return i
	}
	return -1
}
