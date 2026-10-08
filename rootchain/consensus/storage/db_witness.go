package storage

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"go.etcd.io/bbolt"
)

var keyWitness = []byte("p85/witness/")

// MaxWitnessBytes bounds one retained control witness: the closure archive bundle bound.
const MaxWitnessBytes = 64 << 20

var (
	// ErrWitnessStore reports a witness that cannot be retained.
	ErrWitnessStore = errors.New("P85 witness store: witness refused")
	// ErrNoWitnessStore reports a block store that cannot retain control witnesses.
	ErrNoWitnessStore = errors.New("P85 witness store: the block store cannot retain witnesses")
)

// WitnessStore retains control witnesses by their SHA-256, the identifier a control commits to. A witness is immutable evidence: it is
// kept for replay and never rewritten. A store that wraps another must forward both methods.
type WitnessStore interface {
	StoreWitness(hash [32]byte, data []byte) error
	// Witness returns the retained bytes, or nil when none are retained.
	Witness(hash [32]byte) ([]byte, error)
	// HasWitness reports whether the witness is retained, without reading it (a witness can be tens of megabytes).
	HasWitness(hash [32]byte) (bool, error)
}

func witnessKey(hash [32]byte) []byte { return append(append([]byte(nil), keyWitness...), hash[:]...) }

// StoreWitness retains data under its SHA-256; data that does not hash to it is refused. A repeat is a no-op.
func (db BoltDB) StoreWitness(hash [32]byte, data []byte) error {
	if len(data) == 0 || len(data) > MaxWitnessBytes || sha256.Sum256(data) != hash {
		return fmt.Errorf("%w: %d bytes do not hash to %x", ErrWitnessStore, len(data), hash)
	}
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketMetadata)
		if b == nil {
			return errors.New("metadata bucket not found")
		}
		if b.Get(witnessKey(hash)) != nil {
			return nil // the key is the hash of the bytes: the same witness
		}
		return b.Put(witnessKey(hash), data)
	})
}

// HasWitness reports whether a witness is retained under the hash.
func (db BoltDB) HasWitness(hash [32]byte) (has bool, err error) {
	err = db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketMetadata)
		if b == nil {
			return errors.New("metadata bucket not found")
		}
		has = b.Get(witnessKey(hash)) != nil
		return nil
	})
	return has, err
}

// Witness returns the retained witness, or nil.
func (db BoltDB) Witness(hash [32]byte) (out []byte, err error) {
	err = db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketMetadata)
		if b == nil {
			return errors.New("metadata bucket not found")
		}
		if v := b.Get(witnessKey(hash)); v != nil {
			out = bytes.Clone(v)
		}
		return nil
	})
	return out, err
}
