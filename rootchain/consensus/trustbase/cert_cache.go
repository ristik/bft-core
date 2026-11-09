package trustbase

import (
	"container/list"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// A verified-certificate cache scoped to ONE TrustBaseStore (ristik/bft-core#982, briefs/dev2-timeout-dedupe-design.md, arch's answer): the
// successful result of QuorumCert.VerifyWith and TimeoutCert.Verify, keyed by the SHA-256 of the complete certificate encoding, its kind and the
// verification context (the epochs the verification depends on with their resolved signing configurations). A hit means "this exact certificate
// verified under this exact context"; it never means the certificate was processed, or is valid for the local branch, and it is never used to
// accept a different certificate. Bounded LRU, empty at start, never persisted, never shared between stores.
//
// Invalidation: every change of what verification reads (the genesis pin, an installed trust base, the signing history or authority, the UTB
// profile) advances a generation counter AFTER the change is published. A verifier captures the generation before it reads anything; its result
// may be remembered only while the generation is still the one it captured, and an entry is a hit only while the generation is still the one it
// was stored under. So a verification that began before a change can never leave a success behind for the changed context.

// CertKind separates the two certificate kinds in the key.
type CertKind byte

const (
	CertQC CertKind = 1
	CertTC CertKind = 2
)

const defaultCertCacheCapacity = 4096

// CertContext names the epochs a verification depends on and the signing configuration each resolved to when the key was built.
type CertContext struct {
	N      int
	Epochs [4]uint64
	Cfgs   [4]votesig.Config
}

// CertKey is the identity of one verified certificate.
type CertKey struct {
	Kind   CertKind
	Digest [32]byte
	Ctx    CertContext
}

// CertCacheStats are the counters since the previous TakeCertCacheStats.
type CertCacheStats struct {
	Hits, Misses        [3]int // by CertKind (index 1 QC, 2 TC)
	Inserts, Evictions  int
	StaleInsertsRefused int // results of verifications that began before a context change
	KeyBuilds           int
	KeyBuildTime        time.Duration
	Entries             int
}

type certCacheEntry struct {
	key CertKey
	gen uint64
}

type certCache struct {
	mu    sync.Mutex
	cap   int
	lru   *list.List
	index map[CertKey]*list.Element
	stats CertCacheStats
}

func newCertCache(capacity int) *certCache {
	return &certCache{cap: capacity, lru: list.New(), index: map[CertKey]*list.Element{}}
}

func (s *TrustBaseStore) certs() *certCache {
	if c := s.certCacheP.Load(); c != nil {
		return c
	}
	s.certCacheP.CompareAndSwap(nil, newCertCache(defaultCertCacheCapacity))
	return s.certCacheP.Load()
}

// SetCertCacheCapacity replaces the cache by an empty one of the given capacity; 0 disables it. For tests and measurement.
func (s *TrustBaseStore) SetCertCacheCapacity(n int) { s.certCacheP.Store(newCertCache(n)) }

// VerifyGeneration is the current generation of the verification context. Capture it BEFORE reading anything the verification depends on.
func (s *TrustBaseStore) VerifyGeneration() uint64 {
	if s == nil {
		return 0
	}
	return s.verifyGen.Load()
}

func (s *TrustBaseStore) bumpVerifyGeneration() { s.verifyGen.Add(1) }

// CertVerified reports whether this exact certificate verified under this exact context, in the current generation.
func (s *TrustBaseStore) CertVerified(k CertKey) bool {
	if s == nil {
		return false
	}
	c := s.certs()
	gen := s.verifyGen.Load()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cap <= 0 {
		return false
	}
	if el, ok := c.index[k]; ok {
		if el.Value.(*certCacheEntry).gen == gen {
			c.lru.MoveToFront(el)
			c.stats.Hits[k.Kind]++
			return true
		}
		c.lru.Remove(el) // from an older context
		delete(c.index, k)
	}
	c.stats.Misses[k.Kind]++
	return false
}

// RememberCert records a successful verification, but only if the context did not change since gen was captured.
func (s *TrustBaseStore) RememberCert(k CertKey, gen uint64) {
	if s == nil {
		return
	}
	c := s.certs()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cap <= 0 {
		return
	}
	if s.verifyGen.Load() != gen {
		c.stats.StaleInsertsRefused++
		return
	}
	if el, ok := c.index[k]; ok {
		el.Value.(*certCacheEntry).gen = gen
		c.lru.MoveToFront(el)
		return
	}
	c.index[k] = c.lru.PushFront(&certCacheEntry{key: k, gen: gen})
	c.stats.Inserts++
	if c.lru.Len() > c.cap {
		old := c.lru.Back()
		c.lru.Remove(old)
		delete(c.index, old.Value.(*certCacheEntry).key)
		c.stats.Evictions++
	}
}

// NoteCertKeyBuild records the cost of building one key (encoding and hashing).
func (s *TrustBaseStore) NoteCertKeyBuild(d time.Duration) {
	c := s.certs()
	c.mu.Lock()
	c.stats.KeyBuilds++
	c.stats.KeyBuildTime += d
	c.mu.Unlock()
}

// TakeCertCacheStats returns the counters since the last call and resets them.
func (s *TrustBaseStore) TakeCertCacheStats() CertCacheStats {
	c := s.certs()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.stats
	out.Entries = c.lru.Len()
	c.stats = CertCacheStats{}
	return out
}

// CertContextFor resolves the signing configuration of every given epoch (at most four distinct ones). ok is false when one is unknown or
// there are too many: the caller then verifies without the cache.
func (s *TrustBaseStore) CertContextFor(epochs ...uint64) (CertContext, bool) {
	var ctx CertContext
	sort.Slice(epochs, func(i, j int) bool { return epochs[i] < epochs[j] })
	for i, e := range epochs {
		if i > 0 && e == epochs[i-1] {
			continue
		}
		if ctx.N == len(ctx.Epochs) {
			return CertContext{}, false
		}
		cfg, err := s.SigningConfig(e)
		if err != nil {
			return CertContext{}, false
		}
		ctx.Epochs[ctx.N], ctx.Cfgs[ctx.N] = e, cfg
		ctx.N++
	}
	return ctx, ctx.N > 0
}

var _ = atomic.Uint64{}
