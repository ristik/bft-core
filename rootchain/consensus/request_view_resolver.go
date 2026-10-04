package consensus

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ParentSource supplies the verified parent shard state a proposal builds on, with the identity of the block it belongs to and
// the change of the shard still in its pipeline. It is never the last committed ShardInfo by assumption: the source names its
// own ancestry.
type ParentSource func(partition types.PartitionID, shard types.ShardID) (parent *storage.ShardInfo, parentID []byte, pending *types.InputRecord, err error)

// RequestViewResolver is the ViewResolver of the view-aware branch: every view is resolved from the committed activation history
// and the verified parent, through the cache when one is given. Missing history or parent is an error.
type RequestViewResolver struct {
	history storage.RequestHistory
	hashAlg crypto.Hash
	parent  ParentSource
	cache   *storage.RequestViewCache
}

// ErrNoParentSource is returned when a resolver is built without the source of the verified parent state.
var ErrNoParentSource = errors.New("no parent source")

func NewRequestViewResolver(h storage.RequestHistory, hashAlg crypto.Hash, parent ParentSource, cache *storage.RequestViewCache) (*RequestViewResolver, error) {
	if h == nil {
		return nil, fmt.Errorf("%w: no committed request history", storage.ErrAssignmentHistory)
	}
	if parent == nil {
		return nil, ErrNoParentSource
	}
	return &RequestViewResolver{history: h, hashAlg: hashAlg, parent: parent, cache: cache}, nil
}

func (r *RequestViewResolver) ResolveView(partition types.PartitionID, shard types.ShardID, round uint64, purpose storage.RequestPurpose) (*storage.RequestRoundView, error) {
	parent, parentID, pending, err := r.parent(partition, shard)
	if err != nil {
		return nil, fmt.Errorf("%w: parent state of %s-%s: %w", storage.ErrAssignmentHistory, partition, shard, err)
	}
	return storage.ResolveParentView(r.history, pending, parent, parentID, round, r.hashAlg, purpose, r.cache)
}
