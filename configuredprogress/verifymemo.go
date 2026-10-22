package configuredprogress

import (
	"sync"
	"sync/atomic"
)

// maxVerifyMemo bounds the memo; at the bound it is cleared rather than evicted from, which is simple and safe (a miss only re-verifies).
const maxVerifyMemo = 1 << 15

// verifyMemo remembers successful certificate signature verifications made while loading the progress image and the journal (bft-core#728: reloading a
// journal of a few hundred entries repeated the same secp256k1 recoveries five times a second). It implements rootinput.VerifyMemo, which keys every entry by
// everything the verification reads, so a hit means the same certificate was already verified under the same trust base, partition, shard and configuration.
// Only successes are stored. It is cleared whenever the store installs something the verdict could depend on.
type verifyMemo struct {
	mu         sync.Mutex
	seen       map[[32]byte]struct{}
	generation uint64
	remembered atomic.Uint64 // successes recorded: the verifications actually performed, for the work-count tests
}

func (m *verifyMemo) Verified(key [32]byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.seen[key]
	return ok
}

func (m *verifyMemo) Remember(key [32]byte) {
	m.remembered.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil || len(m.seen) >= maxVerifyMemo {
		m.seen = make(map[[32]byte]struct{})
	}
	m.seen[key] = struct{}{}
}

// reset forgets everything and counts the clearing.
func (m *verifyMemo) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seen = nil
	m.generation++
}

func (m *verifyMemo) size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.seen)
}

func (m *verifyMemo) gen() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.generation
}

// ResetVerificationMemo clears the store's memo of verified certificates. The store calls it itself when it installs a restore anchor, a replayed tip, the
// journal or its initial state; a caller that installs a trust base, a root-epoch authority state or a shard configuration the store reads through its Context
// may call it too. (Correctness does not depend on that: the memo key contains the trust base's content and the configuration hash, so a changed one misses.)
func (s *Store) ResetVerificationMemo() { s.vm.reset() }

// memoContext is c with the store's memo attached: used only by the progress and journal loads. Every other verification, including every one a writer
// makes before it signs or commits, runs without it.
func (s *Store) memoContext(c Context) Context {
	c.Observation.VerifyMemo = &s.vm
	return c
}
