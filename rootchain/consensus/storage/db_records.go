package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/rootrecords"
	"github.com/unicitynetwork/bft-go-base/types"
	"go.etcd.io/bbolt"
)

var (
	keyRecord      = []byte("p85/record/")
	keyRecordCount = []byte("p85/records")

	// ErrRecordLog reports a record that does not extend, or contradicts, the retained log.
	ErrRecordLog = errors.New("P85 record log: record does not extend the retained log")
)

// RecordStore is the part of a block store that retains the P85 source log. The log is append-only and written when the block that
// projected a record commits, before that block becomes the root, so a crash between the two repeats an idempotent append. A store that
// wraps another (the frontier proxy) must forward all three methods: a chain that projects records cannot commit without them.
type RecordStore interface {
	AppendRecords(recs []rootrecords.Record) error
	RecordCount() (uint64, error)
	Records(from uint64, max int) ([]rootrecords.Record, error)
}

// ErrNoRecordStore reports a commit of a block that projected records on a store that cannot retain them.
var ErrNoRecordStore = errors.New("P85 record log: the block store cannot retain records")

func recordKey(index uint64) []byte {
	return binary.BigEndian.AppendUint64(append([]byte(nil), keyRecord...), index)
}

func readRecordCount(b *bbolt.Bucket) (uint64, error) {
	if b.Get(keyRecordCount) == nil {
		return 0, nil
	}
	return readUint64(b, keyRecordCount)
}

// AppendRecords retains records in order. A record already retained must be byte-identical (a repeated append after a crash); any other
// must carry the next index and link to the retained tip.
func (db BoltDB) AppendRecords(recs []rootrecords.Record) error {
	if len(recs) == 0 {
		return nil
	}
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketMetadata)
		if b == nil {
			return errors.New("metadata bucket not found")
		}
		return appendRecordsTx(b, recs)
	})
}

// appendRecordsTx is AppendRecords inside an open transaction on the metadata bucket.
func appendRecordsTx(b *bbolt.Bucket, recs []rootrecords.Record) error {
	if len(recs) == 0 {
		return nil
	}
	count, err := readRecordCount(b)
	if err != nil {
		return err
	}
	for _, r := range recs {
		enc, err := types.Cbor.Marshal(r)
		if err != nil {
			return fmt.Errorf("serializing record %d: %w", r.Index, err)
		}
		switch {
		case r.Index < count:
			if !bytes.Equal(b.Get(recordKey(r.Index)), enc) {
				return fmt.Errorf("%w: record %d differs from the retained one", ErrRecordLog, r.Index)
			}
			continue
		case r.Index > count:
			return fmt.Errorf("%w: record %d after %d retained", ErrRecordLog, r.Index, count)
		}
		var tip [32]byte
		if count > 0 {
			var last rootrecords.Record
			if err := types.Cbor.Unmarshal(b.Get(recordKey(count-1)), &last); err != nil {
				return fmt.Errorf("reading the retained tip: %w", err)
			}
			tip = last.ID
		}
		if r.Predecessor != tip || r.ID != rootrecords.RecordID(r.Index, r.Predecessor, r.Kind, r.Progress, r.UCTime, r.Data) {
			return fmt.Errorf("%w: record %d does not link to the retained tip", ErrRecordLog, r.Index)
		}
		if err := b.Put(recordKey(r.Index), enc); err != nil {
			return fmt.Errorf("storing record %d: %w", r.Index, err)
		}
		count++
	}
	return writeUint64(b, keyRecordCount, count)
}

// RecordCount is the number of retained records.
func (db BoltDB) RecordCount() (n uint64, err error) {
	return n, db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketMetadata)
		if b == nil {
			return errors.New("metadata bucket not found")
		}
		n, err = readRecordCount(b)
		return err
	})
}

// Records returns up to max retained records starting at index from, in order.
func (db BoltDB) Records(from uint64, max int) (out []rootrecords.Record, err error) {
	return out, db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketMetadata)
		if b == nil {
			return errors.New("metadata bucket not found")
		}
		count, err := readRecordCount(b)
		if err != nil {
			return err
		}
		for i := from; i < count && len(out) < max; i++ {
			var r rootrecords.Record
			if err := types.Cbor.Unmarshal(b.Get(recordKey(i)), &r); err != nil {
				return fmt.Errorf("reading record %d: %w", i, err)
			}
			out = append(out, r)
		}
		return nil
	})
}
