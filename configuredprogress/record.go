package configuredprogress

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"sort"

	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/rootinput"
	bolt "go.etcd.io/bbolt"
)

func observationFromLoaded(ctx context.Context, c Context, l certifiedstore.Loaded) (rootinput.VerifiedObservationV2, error) {
	u, err := l.Certificate()
	if err != nil {
		return rootinput.VerifiedObservationV2{}, err
	}
	tr, err := l.Technical()
	if err != nil {
		return rootinput.VerifiedObservationV2{}, err
	}
	return rootinput.AuthenticateHistoricalObservationV2(ctx, c.Observation, u, tr)
}

func encodeOuterRecord(ctx context.Context, c Context, dd [32]byte, r certifiedstore.Record) ([]byte, []byte, certifiedstore.Loaded, rootinput.VerifiedObservationV2, error) {
	if r.BlockNumber == 0 {
		return nil, nil, certifiedstore.Loaded{}, rootinput.VerifiedObservationV2{}, fmt.Errorf("%w: block zero has no v2 ordinary record", ErrConflict)
	}
	legacy, l, err := certifiedstore.EncodeVerifiedRecord(ctx, c.Record, r)
	if err != nil {
		return nil, nil, certifiedstore.Loaded{}, rootinput.VerifiedObservationV2{}, err
	}
	if len(legacy) > certifiedstore.MaxRecordBytes {
		return nil, nil, certifiedstore.Loaded{}, rootinput.VerifiedObservationV2{}, ErrBounds
	}
	obs, err := observationFromLoaded(ctx, c, l)
	if err != nil {
		return nil, nil, certifiedstore.Loaded{}, rootinput.VerifiedObservationV2{}, err
	}
	if obs.Class() == evmroot.OriginBootstrapV2 {
		return nil, nil, certifiedstore.Loaded{}, rootinput.VerifiedObservationV2{}, fmt.Errorf("%w: ordinary record carries bootstrap evidence", ErrConflict)
	}
	if obs.Class() == evmroot.OriginFirstCertifiedV2 {
		if l.BlockNumber() != 1 || l.Snapshot().HeaderParentHash() != c.Origin.BlockHash() {
			return nil, nil, certifiedstore.Loaded{}, rootinput.VerifiedObservationV2{}, fmt.Errorf("%w: first-certified record is not B1 with predecessor B0", ErrConflict)
		}
	}
	rw := recordWire{Version: FormatVersion, DescriptorDigest: dd[:], Legacy: legacy}
	p, err := marshal(rw)
	if err != nil {
		return nil, nil, certifiedstore.Loaded{}, rootinput.VerifiedObservationV2{}, err
	}
	raw, err := encodeEnvelope(kindRecord, p, MaxOuterRecordBytes)
	if err != nil {
		return nil, nil, certifiedstore.Loaded{}, rootinput.VerifiedObservationV2{}, err
	}
	return recordKey(l.PartitionRound(), l.BlockHash()), raw, l, obs, nil
}

func verifyOuterRecord(ctx context.Context, c Context, dd [32]byte, key, raw []byte) (certifiedstore.Loaded, error) {
	p, err := decodeEnvelope(raw, kindRecord, MaxOuterRecordBytes)
	if err != nil {
		return certifiedstore.Loaded{}, err
	}
	var rw recordWire
	if err = decodePayload(p, &rw); err != nil {
		return certifiedstore.Loaded{}, err
	}
	if rw.Version != FormatVersion || !bytes.Equal(rw.DescriptorDigest, dd[:]) {
		return certifiedstore.Loaded{}, ErrContext
	}
	if len(rw.Legacy) == 0 || len(rw.Legacy) > certifiedstore.MaxRecordBytes {
		return certifiedstore.Loaded{}, ErrBounds
	}
	l, err := certifiedstore.VerifyEncodedRecord(ctx, c.Record, rw.Legacy)
	if err != nil {
		return certifiedstore.Loaded{}, err
	}
	if l.BlockNumber() == 0 || !bytes.Equal(recordKey(l.PartitionRound(), l.BlockHash()), key) {
		return certifiedstore.Loaded{}, fmt.Errorf("%w: non-canonical record key", ErrUntrusted)
	}
	obs, err := observationFromLoaded(ctx, c, l)
	if err != nil {
		return certifiedstore.Loaded{}, err
	}
	if obs.Class() == evmroot.OriginBootstrapV2 {
		return certifiedstore.Loaded{}, ErrUntrusted
	}
	if obs.Class() == evmroot.OriginFirstCertifiedV2 && (l.BlockNumber() != 1 || l.Snapshot().HeaderParentHash() != c.Origin.BlockHash()) {
		return certifiedstore.Loaded{}, fmt.Errorf("%w: first-certified predecessor", ErrUntrusted)
	}
	return l, nil
}

type PreparedRecord struct{ p *preparedRecord }
type preparedRecord struct {
	store                 *Store
	before                *durableImage
	key, raw, nextControl []byte
	loaded                certifiedstore.Loaded
	noOp                  bool
}

// PrepareRecord verifies an ordinary record and binds publication to the exact observed/control/head image.
func (s *Store) PrepareRecord(ctx context.Context, c Context, r certifiedstore.Record) (PreparedRecord, error) {
	var ownErr error
	c, ownErr = ownContext(c)
	if ownErr != nil {
		return PreparedRecord{}, ownErr
	}
	st, _, err := s.Load(ctx, c)
	if err != nil {
		return PreparedRecord{}, err
	}
	i := st.i
	if i.first == nil || i.observed == nil {
		return PreparedRecord{}, fmt.Errorf("%w: ordinary progress has not been observed", ErrConflict)
	}
	key, raw, l, obs, err := encodeOuterRecord(ctx, c, i.descriptorDigest, r)
	if err != nil {
		return PreparedRecord{}, err
	}
	rel, err := compareObservations(obs, i.observed.observation)
	if err != nil || rel == relationStale {
		return PreparedRecord{}, fmt.Errorf("%w: record certificate is newer/conflicting with observed: %v", ErrConflict, err)
	}
	if i.hasHead {
		headObs, err := observationFromLoaded(ctx, c, i.head)
		if err != nil {
			return PreparedRecord{}, err
		}
		hr, err := compareObservations(headObs, obs)
		if err != nil {
			return PreparedRecord{}, err
		}
		if hr == relationStale {
			return PreparedRecord{}, fmt.Errorf("%w: record is older than head", ErrConflict)
		}
		if bytes.Equal(key, i.headName) {
			if hr != relationDuplicate && hr != relationRepeat {
				return PreparedRecord{}, fmt.Errorf("%w: canonical head key names another authenticated record", ErrConflict)
			}
			// Signature-subset or repeat bytes do not replace the already durable equivalent block.
			return PreparedRecord{p: &preparedRecord{store: s, before: i, key: key, raw: i.headRaw, loaded: i.head, noOp: true}}, nil
		}
		if hr == relationDuplicate || hr == relationRepeat {
			return PreparedRecord{}, fmt.Errorf("%w: record does not advance ordinary head", ErrConflict)
		}
	}
	if i.control.Revision == math.MaxUint64 {
		return PreparedRecord{}, fmt.Errorf("%w: revision overflow", ErrBounds)
	}
	cw := i.control
	cw.Revision++
	cw.HeadKey = bytes.Clone(key)
	cp, err := marshal(cw)
	if err != nil {
		return PreparedRecord{}, err
	}
	next, err := encodeEnvelope(kindControl, cp, MaxControlBytes)
	if err != nil {
		return PreparedRecord{}, err
	}
	return PreparedRecord{p: &preparedRecord{store: s, before: i, key: key, raw: raw, nextControl: next, loaded: l}}, nil
}

// CommitRecord atomically publishes record, control head/revision and bounded retention deletions.
func (s *Store) CommitRecord(p PreparedRecord) (certifiedstore.Loaded, error) {
	if p.p == nil || p.p.store != s {
		return certifiedstore.Loaded{}, ErrStale
	}
	pr := p.p
	if pr.noOp {
		err := s.db.View(func(tx *bolt.Tx) error {
			if !imageMatches(tx.Bucket(bucketName), pr.before) {
				return ErrStale
			}
			return nil
		})
		if err != nil {
			return certifiedstore.Loaded{}, err
		}
		return pr.loaded, nil
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if !imageMatches(b, pr.before) {
			return ErrStale
		}
		blockHash, err := blockHashFromRecordKey(pr.key)
		if err != nil {
			return err
		}
		indexKey := hashIndexKey(blockHash)
		indexValue, err := encodeHashIndex(pr.key)
		if err != nil {
			return err
		}
		if old := b.Get(indexKey); old != nil {
			if len(old) > MaxHashIndexValueBytes {
				return ErrBounds
			}
			locator, err := decodeHashIndex(old)
			if err != nil || !bytes.Equal(locator, pr.key) {
				return fmt.Errorf("%w: block hash index collision", ErrUntrusted)
			}
			if b.Get(locator) == nil {
				return fmt.Errorf("%w: dangling block hash index", ErrUntrusted)
			}
		}
		if err := b.Put(pr.key, pr.raw); err != nil {
			return err
		}
		if err := b.Put(indexKey, indexValue); err != nil {
			return err
		}
		if err := s.at("after-record-put"); err != nil {
			return err
		}
		if err := b.Put(controlKey, pr.nextControl); err != nil {
			return err
		}
		if err := s.at("after-head-control-put"); err != nil {
			return err
		}
		var keys [][]byte
		c := b.Cursor()
		for k, _ := c.Seek([]byte("record/")); k != nil && bytes.HasPrefix(k, []byte("record/")); k, _ = c.Next() {
			if !validRecordKey(k) {
				return fmt.Errorf("%w: malformed record key", ErrUntrusted)
			}
			keys = append(keys, bytes.Clone(k))
			if len(keys) > MaxRetain+1 {
				return fmt.Errorf("%w: excess retained records", ErrBounds)
			}
		}
		sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i], keys[j]) < 0 })
		for len(keys) > s.settings.Retain {
			k := keys[0]
			keys = keys[1:]
			if bytes.Equal(k, pr.key) {
				keys = append(keys, k)
				continue
			}
			hash, err := blockHashFromRecordKey(k)
			if err != nil {
				return err
			}
			idxKey := hashIndexKey(hash)
			if idx := b.Get(idxKey); idx != nil {
				if len(idx) > MaxHashIndexValueBytes {
					return ErrBounds
				}
				locator, err := decodeHashIndex(idx)
				if err != nil || !bytes.Equal(locator, k) {
					return fmt.Errorf("%w: retained-record index mismatch", ErrUntrusted)
				}
				if err := b.Delete(idxKey); err != nil {
					return err
				}
			}
			if err := b.Delete(k); err != nil {
				return err
			}
			if err := s.at("after-retention-delete"); err != nil {
				return err
			}
		}
		return s.at("before-record-commit")
	})
	if err != nil {
		return certifiedstore.Loaded{}, err
	}
	return pr.loaded, nil
}
