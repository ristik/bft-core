package configuredprogress

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/registryproof"
	bolt "go.etcd.io/bbolt"
)

const MaxHashIndexValueBytes = 128

var hashIndexPrefix = []byte("record-hash/v1/")

type hashIndexWire struct {
	_         struct{} `cbor:",toarray"`
	Version   uint64
	RecordKey []byte
}

// HashReader binds an owned checked configured context once. It is suitable for the inactive
// parent-witness provider adapter and exposes no locator or record metadata.
type HashReader struct {
	store   *Store
	context Context
}

func (s *Store) BindHashReader(c Context) (*HashReader, error) {
	owned, err := ownContext(c)
	if err != nil {
		return nil, err
	}
	if err := owned.check(); err != nil {
		return nil, err
	}
	return &HashReader{store: s, context: owned}, nil
}

func (r *HashReader) EvidenceByHash(ctx context.Context, hash common.Hash) (registryproof.Evidence, bool, error) {
	if r == nil || r.store == nil {
		return registryproof.Evidence{}, false, ErrContext
	}
	loaded, err := r.store.ReadByHash(ctx, r.context, hash)
	if err != nil {
		if err == ErrUnavailable {
			return registryproof.Evidence{}, false, nil
		}
		return registryproof.Evidence{}, false, err
	}
	return loaded.Witness(), true, nil
}

func hashIndexKey(hash common.Hash) []byte {
	return []byte(fmt.Sprintf("%s%064x", hashIndexPrefix, hash[:]))
}

func encodeHashIndex(record []byte) ([]byte, error) {
	if !validRecordKey(record) {
		return nil, fmt.Errorf("%w: index locator is not a canonical record key", ErrUntrusted)
	}
	raw, err := marshal(hashIndexWire{Version: 1, RecordKey: bytes.Clone(record)})
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxHashIndexValueBytes {
		return nil, ErrBounds
	}
	return raw, nil
}

func decodeHashIndex(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxHashIndexValueBytes {
		return nil, fmt.Errorf("%w: hash index value bound", ErrUntrusted)
	}
	var w hashIndexWire
	if err := decodePayload(raw, &w); err != nil {
		return nil, err
	}
	if w.Version != 1 || !validRecordKey(w.RecordKey) {
		return nil, fmt.Errorf("%w: hash index version/locator", ErrUntrusted)
	}
	return bytes.Clone(w.RecordKey), nil
}

func blockHashFromRecordKey(key []byte) (common.Hash, error) {
	if !validRecordKey(key) {
		return common.Hash{}, ErrUntrusted
	}
	b, err := hex.DecodeString(string(key[len(key)-64:]))
	if err != nil || len(b) != common.HashLength {
		return common.Hash{}, ErrUntrusted
	}
	return common.BytesToHash(b), nil
}

// ReadByHash performs one bounded consistent read of authoritative metadata, head, locator and
// candidate, then re-verifies every copied byte. The index locates only; it grants no authority.
func (s *Store) ReadByHash(ctx context.Context, c Context, hash common.Hash) (certifiedstore.Loaded, error) {
	if hash == (common.Hash{}) {
		return certifiedstore.Loaded{}, fmt.Errorf("%w: block zero/zero hash is unsupported", ErrConflict)
	}
	var err error
	c, err = ownContext(c)
	if err != nil {
		return certifiedstore.Loaded{}, err
	}
	if err = c.check(); err != nil {
		return certifiedstore.Loaded{}, err
	}
	var desc, control, headName, headRaw, candidateKey, candidateRaw []byte
	err = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return ErrUnavailable
		}
		d, ctrl := b.Get(descriptorKey), b.Get(controlKey)
		if d == nil || ctrl == nil {
			return ErrUnavailable
		}
		if len(d) > MaxDescriptorBytes || len(ctrl) > MaxControlBytes {
			return ErrBounds
		}
		desc, control = bytes.Clone(d), bytes.Clone(ctrl)
		cp, e := decodeEnvelope(control, kindControl, MaxControlBytes)
		if e != nil {
			return e
		}
		var cw controlWire
		if e = decodePayload(cp, &cw); e != nil {
			return e
		}
		if cw.HeadKey != nil {
			if !validRecordKey(cw.HeadKey) {
				return fmt.Errorf("%w: malformed head key", ErrUntrusted)
			}
			headName = bytes.Clone(cw.HeadKey)
			h := b.Get(cw.HeadKey)
			if h == nil {
				return ErrUnavailable
			}
			if len(h) > MaxOuterRecordBytes {
				return ErrBounds
			}
			headRaw = bytes.Clone(h)
		}
		idx := b.Get(hashIndexKey(hash))
		if idx == nil {
			return ErrUnavailable
		}
		if len(idx) > MaxHashIndexValueBytes {
			return ErrBounds
		}
		candidateKey, e = decodeHashIndex(bytes.Clone(idx))
		if e != nil {
			return e
		}
		candidate := b.Get(candidateKey)
		if candidate == nil {
			return fmt.Errorf("%w: dangling hash index", ErrUntrusted)
		}
		if len(candidate) > MaxOuterRecordBytes {
			return ErrBounds
		}
		candidateRaw = bytes.Clone(candidate)
		return nil
	})
	if err != nil {
		return certifiedstore.Loaded{}, err
	}
	image, err := verifyRawImage(ctx, c, desc, control, headName, headRaw)
	if err != nil {
		return certifiedstore.Loaded{}, err
	}
	if image.first == nil || image.observed == nil || !image.hasHead {
		return certifiedstore.Loaded{}, fmt.Errorf("%w: indexed reads require published ordinary progress", ErrUntrusted)
	}
	wantHash, err := blockHashFromRecordKey(candidateKey)
	if err != nil || wantHash != hash {
		return certifiedstore.Loaded{}, fmt.Errorf("%w: index names another block", ErrUntrusted)
	}
	loaded, err := verifyOuterRecord(ctx, c, image.descriptorDigest, candidateKey, candidateRaw)
	if err != nil {
		return certifiedstore.Loaded{}, err
	}
	if loaded.BlockNumber() == 0 || loaded.BlockHash() != hash {
		return certifiedstore.Loaded{}, fmt.Errorf("%w: indexed record subject mismatch", ErrUntrusted)
	}
	candidateObs, err := observationFromLoaded(ctx, c, loaded)
	if err != nil {
		return certifiedstore.Loaded{}, err
	}
	rel, compareErr := compareObservations(candidateObs, image.observed.observation)
	if compareErr != nil || rel == relationStale {
		return certifiedstore.Loaded{}, fmt.Errorf("%w: indexed record newer/conflicting with observed", ErrUntrusted)
	}
	if image.hasHead {
		headObs, err := observationFromLoaded(ctx, c, image.head)
		if err != nil {
			return certifiedstore.Loaded{}, err
		}
		rel, compareErr = compareObservations(candidateObs, headObs)
		if compareErr != nil || rel == relationStale {
			return certifiedstore.Loaded{}, fmt.Errorf("%w: indexed record newer/conflicting with head", ErrUntrusted)
		}
	}
	return loaded, nil
}
