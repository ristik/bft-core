// d2c-journal-edit changes one isolated D2-C execution journal record for negative testing.
package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/fxamacker/cbor/v2"
	bolt "go.etcd.io/bbolt"
)

var bucket = []byte("configured-progress/v2")
var prefix = []byte("journal/c/")

// Journal records are versioned envelopes containing a CBOR array payload. Keep
// the small wire structs here so the harness can inspect the record without
// reaching into configuredprogress's unexported codec.
type envelopeWire struct {
	_             struct{} `cbor:",toarray"`
	Version, Kind uint64
	Payload       []byte
	Digest        []byte
}

type candidateWire struct {
	_                                             struct{} `cbor:",toarray"`
	Version                                       uint64
	Descriptor                                    []byte
	Status                                        uint64
	Round, Number, ParentNumber                   uint64
	Hash, StateRoot, ParentHash, ParentState, Raw []byte
	BlockSize, StateSize                          uint64
	LocallyBuilt                                  bool
	AuthorizingUC, AuthorizingTR                  []byte
	ResultingUC, ResultingTR                      []byte
}

func main() {
	if len(os.Args) != 4 || os.Args[1] != "delete-certified-height" {
		panic("usage: d2c-journal-edit.go delete-certified-height DB HEIGHT")
	}
	height, err := strconv.ParseUint(os.Args[3], 10, 64)
	if err != nil {
		panic(err)
	}
	db, err := bolt.Open(os.Args[2], 0600, &bolt.Options{ReadOnly: false})
	if err != nil {
		panic(err)
	}
	defer db.Close()
	var removed string
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return fmt.Errorf("configured progress bucket missing")
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if len(k) <= len(prefix) || string(k[:len(prefix)]) != string(prefix) {
				continue
			}
			var envelope envelopeWire
			if err := cbor.Unmarshal(v, &envelope); err != nil {
				return err
			}
			if envelope.Version != 2 || envelope.Kind != 3 {
				return fmt.Errorf("candidate envelope has version=%d kind=%d", envelope.Version, envelope.Kind)
			}
			var candidate candidateWire
			if err := cbor.Unmarshal(envelope.Payload, &candidate); err != nil {
				return fmt.Errorf("decode candidate payload: %w", err)
			}
			if candidate.Status == 1 && candidate.Number == height {
				if len(removed) != 0 {
					return fmt.Errorf("multiple certified candidates at height %d", height)
				}
				removed = fmt.Sprintf("0x%x", candidate.Hash)
				if err := c.Delete(); err != nil {
					return err
				}
				return nil
			}
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
	if removed == "" {
		panic(fmt.Sprintf("no certified candidate at height %d", height))
	}
	fmt.Printf("deleted certified candidate journal entry height=%d hash=%s\n", height, removed)
}
