package f6arecord

import (
	"bytes"
	"errors"
	"maps"
	"sort"
	"sync"
)

/*
faultStore is the model of the transactional store the record contract assumes: a key-value store whose
transactions are all-or-nothing at commit and durable once commit returns. It is the property bbolt
provides with its default options (NoSync false: the data and meta pages are synced before Commit
returns, and a crash before the meta page is written leaves the previous meta page current).

It is a MODEL of that property, not evidence that bbolt or the filesystem provides it. The contract
states the assumption, and a later storage unit has to establish it for the chosen backend.

Faults it can inject, each deterministic:

  - crashBeforeCommit: the process dies after staging writes and before commit; nothing is applied.
  - corrupt: bytes of a committed value change on the medium (a torn or damaged page that the backend
    did not detect). The record's own digest must catch it on reload.
  - rollbackTo: the whole store is replaced by an earlier snapshot, as a restored backup or a cloned
    disk would do. Every value is internally perfect, and nothing in the store can tell it is stale.
  - wipe: an empty replacement disk.
*/
type faultStore struct {
	mu        sync.Mutex
	committed map[string][]byte
	snapshots []map[string][]byte
}

var errCrashed = errors.New("model: process crashed before commit")

func newFaultStore() *faultStore { return &faultStore{committed: map[string][]byte{}} }

type faultTx struct {
	s       *faultStore
	staged  map[string][]byte
	deleted map[string]bool
	done    bool
}

func (s *faultStore) begin() *faultTx {
	return &faultTx{s: s, staged: map[string][]byte{}, deleted: map[string]bool{}}
}

func (t *faultTx) put(key string, value []byte) {
	t.staged[key] = bytes.Clone(value)
	delete(t.deleted, key)
}
func (t *faultTx) del(key string) { t.deleted[key] = true; delete(t.staged, key) }

// commit applies every staged change at once. crashBeforeCommit models a crash at the last instant
// before the backend's commit point: the transaction leaves no trace.
func (t *faultTx) commit(crashBeforeCommit bool) error {
	if t.done {
		return errors.New("model: transaction already finished")
	}
	t.done = true
	if crashBeforeCommit {
		return errCrashed
	}
	t.s.mu.Lock()
	defer t.s.mu.Unlock()
	for k := range t.deleted {
		delete(t.s.committed, k)
	}
	for k, v := range t.staged {
		t.s.committed[k] = v
	}
	t.s.snapshots = append(t.s.snapshots, cloneMap(t.s.committed))
	return nil
}

func (s *faultStore) get(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.committed[key]
	return bytes.Clone(v), ok
}

func (s *faultStore) keys(prefix string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k := range s.committed {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// corrupt flips one bit of a committed value, as undetected medium damage would.
func (s *faultStore) corrupt(key string, byteIndex int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.committed[key]
	if !ok || byteIndex >= len(v) {
		return false
	}
	v = bytes.Clone(v)
	v[byteIndex] ^= 0x01
	s.committed[key] = v
	return true
}

// truncate shortens a committed value, as a torn write the backend did not detect would.
func (s *faultStore) truncate(key string, length int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.committed[key]
	if !ok || length >= len(v) {
		return false
	}
	s.committed[key] = bytes.Clone(v[:length])
	return true
}

// rollbackTo replaces the store with the state after the n-th successful commit (0-based).
func (s *faultStore) rollbackTo(n int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n < 0 || n >= len(s.snapshots) {
		return false
	}
	s.committed = cloneMap(s.snapshots[n])
	return true
}

func (s *faultStore) wipe() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.committed = map[string][]byte{}
}

func cloneMap(m map[string][]byte) map[string][]byte {
	out := maps.Clone(m)
	for k, v := range out {
		out[k] = bytes.Clone(v)
	}
	return out
}
