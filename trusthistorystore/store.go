// Package trusthistorystore persists the inert M2 trust lineage on the same
// transactional key/value infrastructure used by the root trust-base store.
package trusthistorystore

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"sync"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/m2contract"
	bfttypes "github.com/unicitynetwork/bft-go-base/types"
)

var (
	ErrIncompatible  = errors.New("trusthistorystore: incompatible or unrecognized store")
	ErrIdentity      = errors.New("trusthistorystore: execution identity mismatch")
	ErrAnchor        = errors.New("trusthistorystore: v1 anchor mismatch")
	ErrEncoding      = errors.New("trusthistorystore: noncanonical or damaged record")
	ErrHistory       = errors.New("trusthistorystore: invalid trust history")
	ErrProof         = errors.New("trusthistorystore: activation proof unavailable or invalid")
	ErrNotFound      = errors.New("trusthistorystore: trust epoch or round not found")
	ErrAlreadyExists = errors.New("trusthistorystore: epoch already exists")
	ErrUnsupportedV2 = errors.New("trusthistorystore: v2 runtime activation is disabled")
)

const schemaVersion uint64 = 1

var schemaKey = []byte("m2trust/schema")
var identityKey = []byte("m2trust/execution")
var anchorKey = []byte("m2trust/anchor")

const entryPrefix = "m2trust/epoch/"
const maxRecordBytes = 1 << 20

// ActivationVerifier must authenticate the D4 finalized root commit binding
// this exact body, A*, and commit ID. Nil never admits a v2 entry.
type ActivationVerifier interface {
	VerifyActivation(context.Context, evmroot.TrustBaseBodyV2, evmroot.ActivatedTrustBase, []byte) error
}

type anchorDisk struct {
	Anchor     evmroot.V1Anchor
	Start, End uint64
	Canonical  []byte
}
type entryDisk struct {
	Body             evmroot.TrustBaseBodyV2
	Activation       evmroot.ActivatedTrustBase
	End              uint64
	Canonical, Proof []byte
}

// Record is a checked result of epoch or round lookup. Exactly one variant is set.
type Record struct {
	Epoch, Start, End uint64
	V1                *bfttypes.RootTrustBaseV1
	V2                *evmroot.TrustBaseBodyV2
	BodyID            [32]byte
}

type Store struct {
	mu       sync.RWMutex
	db       keyvaluedb.KeyValueDB
	anchor   *bfttypes.RootTrustBaseV1
	identity [32]byte
	verifier ActivationVerifier
	history  m2contract.TrustHistory
	cache    map[uint64]Record
	proofs   map[uint64][]byte
}

// Open initializes an empty database or refuses every incompatible existing
// schema, anchor, execution identity, record, and unverified v2 transition.
func Open(ctx context.Context, db keyvaluedb.KeyValueDB, anchor *bfttypes.RootTrustBaseV1, identity [32]byte, verifier ActivationVerifier) (*Store, error) {
	if db == nil || anchor == nil {
		return nil, ErrAnchor
	}
	if identity == ([32]byte{}) {
		return nil, ErrIdentity
	}
	hash, err := anchor.Hash(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAnchor, err)
	}
	a := evmroot.V1Anchor{Version: 1, NetworkID: uint64(anchor.GetNetworkID()), Epoch: anchor.GetEpoch(), HashIncludingSigs: hash}
	s := &Store{db: db, anchor: anchor, identity: identity, verifier: verifier, cache: make(map[uint64]Record), proofs: make(map[uint64][]byte), history: m2contract.TrustHistory{Anchor: a, AnchorStart: anchor.GetEpochStart()}}
	if err := s.load(ctx); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *Store) load(ctx context.Context) error {
	it := s.db.First()
	var keys [][]byte
	var values [][]byte
	for ; it.Valid(); it.Next() {
		key := bytes.Clone(it.Key())
		var value []byte
		if err := it.Value(&value); err != nil {
			_ = it.Close()
			return fmt.Errorf("%w: %v", ErrIncompatible, err)
		}
		if len(value) > maxRecordBytes {
			_ = it.Close()
			return ErrIncompatible
		}
		keys = append(keys, key)
		values = append(values, bytes.Clone(value))
	}
	if err := it.Close(); err != nil {
		return err
	}
	if len(keys) == 0 {
		return s.initialize()
	}
	var haveSchema, haveIdentity, haveAnchor bool
	entries := make(map[uint64]entryDisk)
	for i, key := range keys {
		raw := values[i]
		switch {
		case bytes.Equal(key, schemaKey):
			if haveSchema {
				return ErrIncompatible
			}
			haveSchema = true
			var version uint64
			if err := bfttypes.Cbor.Unmarshal(raw, &version); err != nil || version != schemaVersion {
				return ErrIncompatible
			}
		case bytes.Equal(key, identityKey):
			if haveIdentity {
				return ErrIncompatible
			}
			haveIdentity = true
			var id []byte
			if err := bfttypes.Cbor.Unmarshal(raw, &id); err != nil || len(id) != 32 {
				return ErrIncompatible
			}
			if !bytes.Equal(id, s.identity[:]) {
				return ErrIdentity
			}
		case bytes.Equal(key, anchorKey):
			if haveAnchor {
				return ErrIncompatible
			}
			haveAnchor = true
			var a anchorDisk
			if err := bfttypes.Cbor.Unmarshal(raw, &a); err != nil {
				return ErrIncompatible
			}
			if a.Anchor.Version != 1 || a.Anchor.NetworkID != s.history.Anchor.NetworkID || a.Anchor.Epoch != s.history.Anchor.Epoch || !bytes.Equal(a.Anchor.HashIncludingSigs, s.history.Anchor.HashIncludingSigs) || a.Start != s.history.AnchorStart {
				return ErrAnchor
			}
			canonical, err := (m2contract.V1AnchorRecord{Anchor: a.Anchor, Start: a.Start, End: a.End}).Encode()
			if err != nil || !bytes.Equal(canonical, a.Canonical) {
				return ErrEncoding
			}
			s.history.AnchorEnd = a.End
		case bytes.HasPrefix(key, []byte(entryPrefix)):
			if len(key) != len(entryPrefix)+8 {
				return ErrIncompatible
			}
			epoch := readUint64(key[len(entryPrefix):])
			if _, exists := entries[epoch]; exists {
				return ErrIncompatible
			}
			var e entryDisk
			if err := bfttypes.Cbor.Unmarshal(raw, &e); err != nil {
				return ErrIncompatible
			}
			if e.Body.Epoch != epoch {
				return ErrHistory
			}
			entries[epoch] = e
		default:
			return ErrIncompatible
		}
	}
	if !haveSchema || !haveIdentity || !haveAnchor {
		return ErrIncompatible
	}
	for epoch := s.history.Anchor.Epoch + 1; len(entries) > 0; epoch++ {
		e, ok := entries[epoch]
		if !ok {
			return ErrHistory
		}
		delete(entries, epoch)
		in := m2contract.TrustInterval{Body: e.Body, Activation: e.Activation, End: e.End}
		canonical, err := in.Encode()
		if err != nil || !bytes.Equal(canonical, e.Canonical) {
			return ErrEncoding
		}
		if s.verifier == nil {
			return ErrProof
		}
		if err := s.verifier.VerifyActivation(ctx, e.Body, e.Activation, e.Proof); err != nil {
			return fmt.Errorf("%w: %v", ErrProof, err)
		}
		s.history.Intervals = append(s.history.Intervals, in)
		s.proofs[epoch] = bytes.Clone(e.Proof)
	}
	if err := s.history.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrHistory, err)
	}
	return nil
}
func (s *Store) initialize() error {
	raw, err := (m2contract.V1AnchorRecord{Anchor: s.history.Anchor, Start: s.history.AnchorStart, End: 0}).Encode()
	if err != nil {
		return err
	}
	tx, err := s.db.StartTx()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, item := range []struct {
		k []byte
		v any
	}{{schemaKey, schemaVersion}, {identityKey, s.identity[:]}, {anchorKey, anchorDisk{Anchor: s.history.Anchor, Start: s.history.AnchorStart, End: 0, Canonical: raw}}} {
		if err := writeRecord(tx, item.k, item.v); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func writeRecord(tx keyvaluedb.DBTransaction, key []byte, v any) error {
	raw, err := bfttypes.Cbor.Marshal(v)
	if err != nil {
		return err
	}
	return tx.Write(key, raw)
}

func uint64Key(epoch uint64) []byte {
	k := []byte(entryPrefix)
	for i := 7; i >= 0; i-- {
		k = append(k, byte(epoch>>(8*i)))
	}
	return k
}
func readUint64(b []byte) uint64 {
	var n uint64
	for _, v := range b {
		n = n<<8 | uint64(v)
	}
	return n
}

// Evict drops only the memory cache. Every lookup re-derives from verified,
// owned history loaded from the durable database.
func (s *Store) Evict() { s.mu.Lock(); defer s.mu.Unlock(); s.cache = make(map[uint64]Record) }
func cloneRecord(r Record) Record {
	if r.V2 != nil {
		b := *r.V2
		b.Members = append(evmroot.WeightSet(nil), b.Members...)
		for i := range b.Members {
			b.Members[i].ConsensusKey = bytes.Clone(b.Members[i].ConsensusKey)
		}
		b.StateSummary = bytes.Clone(b.StateSummary)
		b.ChangeRecordHash = bytes.Clone(b.ChangeRecordHash)
		b.PredecessorHash = bytes.Clone(b.PredecessorHash)
		r.V2 = &b
	}
	return r
}
func (s *Store) ByEpoch(epoch uint64) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.cache[epoch]; ok {
		return cloneRecord(r), nil
	}
	var r Record
	if epoch == s.history.Anchor.Epoch {
		r = Record{Epoch: epoch, Start: s.history.AnchorStart, End: s.history.AnchorEnd, V1: s.anchor}
	} else {
		found := false
		for _, in := range s.history.Intervals {
			if in.Body.Epoch == epoch {
				id := in.Body.Identity()
				b := in.Body
				r = Record{Epoch: epoch, Start: in.Activation.EpochStart, End: in.End, V2: &b, BodyID: id}
				found = true
				break
			}
		}
		if !found {
			return Record{}, ErrNotFound
		}
	}
	s.cache[epoch] = cloneRecord(r)
	return cloneRecord(r), nil
}
func (s *Store) ByRound(round uint64) (Record, error) {
	s.mu.RLock()
	epoch, err := s.history.At(round)
	s.mu.RUnlock()
	if err != nil {
		return Record{}, fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	return s.ByEpoch(epoch)
}

// AppendVerified persists a successor only after a caller-provided D4 verifier
// authenticates the finalized commit. This API does not activate runtime use.
func (s *Store) AppendVerified(ctx context.Context, in m2contract.TrustInterval, proof []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.verifier == nil {
		return ErrProof
	}
	if in.Body.Epoch <= s.history.Anchor.Epoch+uint64(len(s.history.Intervals)) {
		return ErrAlreadyExists
	}
	if err := s.verifier.VerifyActivation(ctx, in.Body, in.Activation, proof); err != nil {
		return fmt.Errorf("%w: %v", ErrProof, err)
	}
	if len(s.history.Intervals) > 0 && s.history.Intervals[len(s.history.Intervals)-1].End != 0 {
		return ErrAlreadyExists
	}
	next := s.history
	next.Intervals = append(append([]m2contract.TrustInterval(nil), s.history.Intervals...), in)
	if len(s.history.Intervals) == 0 {
		next.AnchorEnd = in.Activation.EpochStart
	} else {
		next.Intervals[len(next.Intervals)-2].End = in.Activation.EpochStart
	}
	if err := next.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrHistory, err)
	}
	canonical, err := in.Encode()
	if err != nil {
		return err
	}
	tx, err := s.db.StartTx()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if len(s.history.Intervals) == 0 {
		a := anchorDisk{Anchor: next.Anchor, Start: next.AnchorStart, End: next.AnchorEnd}
		a.Canonical, err = (m2contract.V1AnchorRecord{Anchor: a.Anchor, Start: a.Start, End: a.End}).Encode()
		if err != nil {
			return err
		}
		if err := writeRecord(tx, anchorKey, a); err != nil {
			return err
		}
	} else {
		prior := next.Intervals[len(next.Intervals)-2]
		p := entryDisk{Body: prior.Body, Activation: prior.Activation, End: prior.End, Proof: bytes.Clone(s.proofs[prior.Body.Epoch])}
		p.Canonical, err = prior.Encode()
		if err != nil {
			return err
		}
		if err := writeRecord(tx, uint64Key(prior.Body.Epoch), p); err != nil {
			return err
		}
	}
	if err := writeRecord(tx, uint64Key(in.Body.Epoch), entryDisk{Body: in.Body, Activation: in.Activation, End: in.End, Canonical: canonical, Proof: bytes.Clone(proof)}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.history = next
	s.proofs[in.Body.Epoch] = bytes.Clone(proof)
	s.cache = make(map[uint64]Record)
	return nil
}
