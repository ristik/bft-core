package leader

import (
	"container/list"
	"errors"
	"sync"

	"github.com/unicitynetwork/bft-go-base/types"
)

// TableKey is the full identity of one epoch's schedule. A table is never keyed by round alone: two epochs, two networks or two bodies
// can overlap in rounds and still have different schedules. Config is the committed body/configuration identity.
type TableKey struct {
	Network uint64
	Genesis [32]byte
	Epoch   uint64
	Config  [32]byte
	Start   uint64 // A*
}

// ErrCacheSize is returned for a cache with no capacity.
var ErrCacheSize = errors.New("weighted leader: cache needs room for at least one table")

// TableCache keeps a bounded number of built selectors (each at most 64 KiB) by TableKey, least recently used out first. A selector
// that was evicted is rebuilt from the same verified context within the same construction bound (at most n*B steps), and concurrent
// requests for one missing key share a single construction.
type TableCache struct {
	mu    sync.Mutex
	max   int
	lru   *list.List // of *cacheEntry, most recent first
	byKey map[TableKey]*list.Element
	built int // constructions performed, for tests and benchmarks
}

type cacheEntry struct {
	key  TableKey
	once sync.Once
	w    *Weighted
	err  error
}

// NewTableCache returns a cache that holds at most max tables.
func NewTableCache(max int) (*TableCache, error) {
	if max < 1 {
		return nil, ErrCacheSize
	}
	return &TableCache{max: max, lru: list.New(), byKey: map[TableKey]*list.Element{}}, nil
}

// Get returns the selector of the key, building it from the verified committee when it is absent. The committee must be the one the
// key's epoch committed; the cache cannot check that, so callers pass only authenticated context. A failed construction is not cached.
func (c *TableCache) Get(key TableKey, nodes []*types.NodeInfo) (*Weighted, error) {
	c.mu.Lock()
	el, ok := c.byKey[key]
	if ok {
		c.lru.MoveToFront(el)
	} else {
		el = c.lru.PushFront(&cacheEntry{key: key})
		c.byKey[key] = el
		for c.lru.Len() > c.max {
			last := c.lru.Back()
			c.lru.Remove(last)
			delete(c.byKey, last.Value.(*cacheEntry).key)
		}
	}
	e := el.Value.(*cacheEntry)
	c.mu.Unlock()

	e.once.Do(func() {
		e.w, e.err = NewWeighted(key.Start, nodes)
		c.mu.Lock()
		c.built++
		if e.err != nil { // never keep a failure
			if el, ok := c.byKey[key]; ok && el.Value.(*cacheEntry) == e {
				c.lru.Remove(el)
				delete(c.byKey, key)
			}
		}
		c.mu.Unlock()
	})
	return e.w, e.err
}

// Builds is the number of constructions the cache has performed.
func (c *TableCache) Builds() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.built
}

// Len is the number of tables held.
func (c *TableCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}
