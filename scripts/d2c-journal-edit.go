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
			var fields []any
			if err := cbor.Unmarshal(v, &fields); err != nil {
				return err
			}
			if len(fields) < 7 {
				return fmt.Errorf("candidate record has %d fields", len(fields))
			}
			status, ok1 := fields[2].(uint64)
			number, ok2 := fields[4].(uint64)
			if ok1 && ok2 && status == 1 && number == height {
				if len(removed) != 0 {
					return fmt.Errorf("multiple certified candidates at height %d", height)
				}
				removed = fmt.Sprintf("0x%x", k[len(prefix):])
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
