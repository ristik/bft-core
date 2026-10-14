// Package utbstore is the permanent store of finalized signed trust-base entries (types.RootTrustBaseV2): the history a client or peer authenticates from
// its pin. It keeps every entry from the pinned genesis forward (it is not pruned with root blocks or a freshness window), serves the stored canonical
// bytes, and never lets a candidate, vote fragment or unverified record in.
//
// Append is the single way in. It verifies the entry strictly from the stored predecessor (types.RootTrustBaseV2.VerifySuccessor: chain, epoch+1, start,
// predecessor EntryID, the predecessor members' strict quorum), the deployment's member limit, and then writes atomically. Replaying an entry of an epoch
// already stored is idempotent when it has the same unsigned bytes (same EntryID) and a valid witness, and keeps the first stored witness: a different
// valid signature subset is not a fork. The same epoch with different unsigned bytes is a hard conflict. A gap is refused; nothing is skipped.
package utbstore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/utb"
)

var (
	ErrGenesis      = errors.New("utbstore: genesis does not match the pin")
	ErrIncompatible = errors.New("utbstore: stored history is not the pinned chain")
	ErrEntry        = errors.New("utbstore: entry refused")
	ErrConflict     = errors.New("utbstore: an entry of this epoch with different unsigned bytes is already stored")
	ErrGap          = errors.New("utbstore: entry does not directly follow the stored tip")
	ErrNotFound     = errors.New("utbstore: no such epoch")
)

const (
	maxEntryBytes = 64 << 10 // generous bound for 16 members; entries beyond it cannot be stored
	prefix        = "utb/e/"
)

var (
	schemaKey   = []byte("utb/schema")
	genesisKey  = []byte("utb/genesis")
	schemaValue = []byte{1}
)

// Tip names the highest finalized entry.
type Tip struct {
	Epoch   uint64
	EntryID [types.TrustBaseV2IDLen]byte
}

// Store is safe for concurrent use.
type Store struct {
	mu      sync.RWMutex
	db      keyvaluedb.KeyValueDB
	entries []*types.RootTrustBaseV2 // index i is epoch genesis+i
	raw     [][]byte
}

// Open initializes an empty database with the genesis entry or loads and re-verifies an existing one. genesis must be a valid genesis entry whose
// EntryID equals pin (the deployment's authenticated genesis identity); a database holding another genesis, a gap, a corrupt or a non-chaining
// entry is refused.
func Open(db keyvaluedb.KeyValueDB, genesis *types.RootTrustBaseV2, pin [types.TrustBaseV2IDLen]byte) (*Store, error) {
	if db == nil || genesis == nil {
		return nil, ErrGenesis
	}
	if err := genesis.VerifyGenesis(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGenesis, err)
	}
	if len(genesis.RootNodes) > utb.MaxMembers {
		return nil, fmt.Errorf("%w: %d members", ErrGenesis, len(genesis.RootNodes))
	}
	id, err := genesis.EntryID()
	if err != nil || id != pin {
		return nil, ErrGenesis
	}
	graw, err := genesis.MarshalCBOR()
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	var stored []byte
	found, err := db.Read(genesisKey, &stored)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIncompatible, err)
	}
	if !found {
		if err := s.initialize(graw, genesis.Epoch); err != nil {
			return nil, err
		}
		s.entries, s.raw = []*types.RootTrustBaseV2{genesis}, [][]byte{graw}
		return s, nil
	}
	if !bytes.Equal(stored, graw) {
		return nil, fmt.Errorf("%w: another genesis is stored", ErrIncompatible)
	}
	var schema []byte
	if ok, err := db.Read(schemaKey, &schema); err != nil || !ok || !bytes.Equal(schema, schemaValue) {
		return nil, fmt.Errorf("%w: schema", ErrIncompatible)
	}
	s.entries, s.raw = []*types.RootTrustBaseV2{genesis}, [][]byte{graw}
	for epoch := genesis.Epoch + 1; ; epoch++ {
		var b []byte
		ok, err := db.Read(key(epoch), &b)
		if err != nil {
			return nil, fmt.Errorf("%w: epoch %d: %v", ErrIncompatible, epoch, err)
		}
		if !ok {
			break
		}
		e, err := s.verify(b)
		if err != nil {
			return nil, fmt.Errorf("%w: epoch %d: %v", ErrIncompatible, epoch, err)
		}
		s.entries, s.raw = append(s.entries, e), append(s.raw, bytes.Clone(b))
	}
	// nothing may exist beyond the first gap
	last := s.entries[len(s.entries)-1].Epoch
	it := s.db.First()
	defer it.Close()
	for ; it.Valid(); it.Next() {
		k := it.Key()
		if bytes.HasPrefix(k, []byte(prefix)) && (len(k) != len(prefix)+8 || binary.BigEndian.Uint64(k[len(prefix):]) > last) {
			return nil, fmt.Errorf("%w: an entry beyond a gap or a malformed key", ErrIncompatible)
		}
	}
	return s, nil
}

func key(epoch uint64) []byte {
	k := make([]byte, len(prefix)+8)
	copy(k, prefix)
	binary.BigEndian.PutUint64(k[len(prefix):], epoch)
	return k
}

func (s *Store) initialize(graw []byte, epoch uint64) error {
	tx, err := s.db.StartTx()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, kv := range []struct {
		k []byte
		v []byte
	}{{schemaKey, schemaValue}, {genesisKey, graw}} {
		if err := tx.Write(kv.k, kv.v); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// verify decodes b strictly and checks it as the successor of the current tip (s.entries is non-empty).
func (s *Store) verify(b []byte) (*types.RootTrustBaseV2, error) {
	if len(b) > maxEntryBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrEntry, len(b))
	}
	e, err := types.DecodeRootTrustBaseV2(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEntry, err)
	}
	if len(e.RootNodes) > utb.MaxMembers {
		return nil, fmt.Errorf("%w: %d members", ErrEntry, len(e.RootNodes))
	}
	if err := e.VerifySuccessor(s.entries[len(s.entries)-1]); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEntry, err)
	}
	return e, nil
}

// Append adds a finalized entry given as its canonical bytes. It reports whether the entry was new. See the package comment for the replay rules.
func (s *Store) Append(b []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(b) > maxEntryBytes {
		return false, fmt.Errorf("%w: %d bytes", ErrEntry, len(b))
	}
	e, err := types.DecodeRootTrustBaseV2(b)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrEntry, err)
	}
	tip := s.entries[len(s.entries)-1]
	first := s.entries[0].Epoch
	switch {
	case e.Epoch < first:
		return false, fmt.Errorf("%w: epoch %d precedes the genesis %d", ErrGap, e.Epoch, first)
	case e.Epoch <= tip.Epoch:
		have := s.entries[e.Epoch-first]
		haveID, err := have.EntryID()
		if err != nil {
			return false, err
		}
		id, err := e.EntryID()
		if err != nil {
			return false, err
		}
		if id != haveID {
			return false, fmt.Errorf("%w (epoch %d)", ErrConflict, e.Epoch)
		}
		if e.Epoch == first { // the genesis is authenticated by the pin, it has no witness
			if e.Signatures != nil {
				return false, fmt.Errorf("%w: a genesis carrying signatures", ErrEntry)
			}
			return false, nil
		}
		// the supplied witness must itself be valid (an invalid extra never passes because the EntryID is cached); the first stored witness is kept
		if err := e.VerifySuccessor(s.entries[e.Epoch-first-1]); err != nil {
			return false, fmt.Errorf("%w: %v", ErrEntry, err)
		}
		return false, nil
	case e.Epoch != tip.Epoch+1:
		return false, fmt.Errorf("%w: epoch %d, tip %d", ErrGap, e.Epoch, tip.Epoch)
	}
	if _, err := s.verify(b); err != nil {
		return false, err
	}
	tx, err := s.db.StartTx()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err := tx.Write(key(e.Epoch), b); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	s.entries, s.raw = append(s.entries, e), append(s.raw, bytes.Clone(b))
	return true, nil
}

// Tip is the highest finalized entry.
func (s *Store) Tip() Tip {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t := s.entries[len(s.entries)-1]
	id, _ := t.EntryID()
	return Tip{Epoch: t.Epoch, EntryID: id}
}

// Genesis is the first stored epoch.
func (s *Store) GenesisEpoch() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.entries[0].Epoch
}

// Get returns the stored canonical bytes of an epoch, as stored (a replayed entry with another valid witness never replaces them).
func (s *Store) Get(epoch uint64) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	first := s.entries[0].Epoch
	if epoch < first || epoch > s.entries[len(s.entries)-1].Epoch {
		return nil, ErrNotFound
	}
	return bytes.Clone(s.raw[epoch-first]), nil
}

// Range returns a contiguous ascending prefix of [from, to] within the entry and byte budgets, and the first epoch not returned (0 and false when the
// range is complete). It is a snapshot of the finalized history at call time. At least one entry is returned when the range is non-empty, or the
// budget was too small (ErrBudget): never an empty page with a continuation.
func (s *Store) Range(from, to uint64, maxEntries, maxBytes int) (entries [][]byte, next uint64, more bool, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	first, last := s.entries[0].Epoch, s.entries[len(s.entries)-1].Epoch
	if from < first {
		from = first
	}
	if to > last {
		to = last
	}
	if from > to {
		return nil, 0, false, ErrNotFound
	}
	used := 0
	for e := from; e <= to; e++ {
		b := s.raw[e-first]
		if len(entries) >= maxEntries || used+len(b) > maxBytes {
			if len(entries) == 0 {
				return nil, 0, false, ErrBudget
			}
			return entries, e, true, nil
		}
		entries, used = append(entries, bytes.Clone(b)), used+len(b)
	}
	return entries, 0, false, nil
}

// ErrBudget: not even one entry fits the caller's budget.
var ErrBudget = errors.New("utbstore: budget too small for one entry")
