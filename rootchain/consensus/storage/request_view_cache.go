package storage

// Epoch cache of authenticated request views (Q2-C2, briefs/q2-design-v2.md section 3.4). Assignments are cached by
// AssignmentKey and round views by ViewKey, only after the resolver authenticated them. A key that meets different canonical
// contents is refused, never replaced; a failed resolution is never cached; a miss is reconstructed from the committed history
// by the caller's snapshot. Nothing here is persisted: a restart starts empty and rebuilds identical keys.

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
)

type cachedView struct {
	view   *RequestRoundView
	digest [sha256.Size]byte
}

// RequestViewCache holds resolved views. Entries referenced by callers stay alive through their own pointers; the cache only
// forgets reconstructible entries.
type RequestViewCache struct {
	mu          sync.Mutex
	views       map[string]cachedView
	assignments map[string][sha256.Size]byte
}

func NewRequestViewCache() *RequestViewCache {
	return &RequestViewCache{views: make(map[string]cachedView), assignments: make(map[string][sha256.Size]byte)}
}

// assignmentDigest is the canonical content of the assignment behind the key: the authorised configuration and the activation.
func (v *RequestRoundView) assignmentDigest() ([sha256.Size]byte, error) {
	raw, err := types.Cbor.Marshal(v.pdr)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("encoding configuration: %w", err)
	}
	h := sha256.New()
	lp(h, []byte("UNICITY_Q2_ASSIGNMENT_CONTENT"))
	lp(h, raw)
	lpu(h, v.version)
	lpu(h, v.start)
	lp(h, v.trDigest)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// contentDigest is the canonical content of the whole view: the assignment, the expected record, the anchor and the pending change.
func (v *RequestRoundView) contentDigest() ([sha256.Size]byte, error) {
	a, err := v.assignmentDigest()
	if err != nil {
		return a, err
	}
	h := sha256.New()
	lp(h, []byte("UNICITY_Q2_VIEW_CONTENT"))
	lp(h, a[:])
	lp(h, []byte(v.RoundTag()))
	lp(h, []byte(v.expectedTR.Leader))
	lp(h, v.expectedTR.StatHash)
	lp(h, v.expectedTR.FeeHash)
	lp(h, v.ucDigest)
	if v.pending != nil {
		raw, err := v.pending.Bytes()
		if err != nil {
			return a, fmt.Errorf("encoding pending change: %w", err)
		}
		lp(h, raw)
	}
	if v.collection {
		lpu(h, 1)
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// Put stores an authenticated view. The same key with the same content is idempotent; the same key with other content, for the
// view or for its assignment, is a quorumweight.ErrRequestContext and nothing is stored or replaced.
func (c *RequestViewCache) Put(v *RequestRoundView) error {
	if v == nil {
		return fmt.Errorf("%w: no view to cache", quorumweight.ErrRequestContext)
	}
	ad, err := v.assignmentDigest()
	if err != nil {
		return fmt.Errorf("%w: %w", quorumweight.ErrRequestContext, err)
	}
	cd, err := v.contentDigest()
	if err != nil {
		return fmt.Errorf("%w: %w", quorumweight.ErrRequestContext, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if known, ok := c.assignments[string(v.assignKey)]; ok && known != ad {
		return fmt.Errorf("%w: assignment %x is cached with other contents", quorumweight.ErrRequestContext, v.assignKey)
	}
	if known, ok := c.views[string(v.viewKey)]; ok && known.digest != cd {
		return fmt.Errorf("%w: view %x is cached with other contents", quorumweight.ErrRequestContext, v.viewKey)
	}
	c.assignments[string(v.assignKey)] = ad
	if _, ok := c.views[string(v.viewKey)]; !ok {
		c.views[string(v.viewKey)] = cachedView{view: v, digest: cd}
	}
	return nil
}

// Get is the cached view of the key, if any.
func (c *RequestViewCache) Get(viewKey []byte) (*RequestRoundView, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.views[string(viewKey)]
	return e.view, ok
}

// Resolve answers from the cache when the resolver's view is already known and stores it otherwise. The view is always
// authenticated by the snapshot first, so the cache never answers for a snapshot that would refuse; a refusal is returned and
// not remembered, and a later resolution against a new verified snapshot starts clean.
func (c *RequestViewCache) Resolve(q RequestQuery, snap *RequestSnapshot) (*RequestRoundView, error) {
	v, err := ResolveRequestContext(q, snap)
	if err != nil {
		return nil, err
	}
	if err := c.Put(v); err != nil {
		return nil, err
	}
	if cached, ok := c.Get(v.viewKey); ok {
		return cached, nil
	}
	return v, nil
}

// Supersede forgets the views of the shard that do not build on the given parent: the round advanced, an assignment was
// activated, or the parent, anchor or version changed. It returns how many views were retired. Reconstruction from the
// committed history makes every one of them recoverable.
func (c *RequestViewCache) Supersede(partition types.PartitionID, shard types.ShardID, parentID []byte) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for k, e := range c.views {
		t := e.view.target
		if t.Partition == partition && t.Shard.Equal(shard) && !bytes.Equal(t.ParentID, parentID) {
			delete(c.views, k)
			n++
		}
	}
	return n
}

// Len is the number of cached views.
func (c *RequestViewCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.views)
}
