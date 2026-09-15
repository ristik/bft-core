package certifiedstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// ErrDirectorySync is an Open that could not make the store file's directory entry durable.
var ErrDirectorySync = errors.New("certifiedstore: syncing the store's parent directory failed")

/*
syncDirectory makes a directory's entries durable. bbolt syncs the pages of the file it creates but never
the directory that names the file, so without this a crash shortly after the store is first created can
lose the file itself while every commit inside it reported success. Tests replace it to inject a failure.
*/
var syncDirectory = func(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- the directory of the operator-configured store path
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}

var (
	bucketName = []byte("certified-record/v1")
	headKey    = []byte("head")
	genesisKey = []byte("record/genesis")
	recordPfx  = []byte("record/")
)

// MaxRetain bounds Settings.Retain.
const MaxRetain = 1 << 16

// Settings are explicit storage parameters.
type Settings struct {
	// Retain is how many non-genesis records are kept, counting the one being published. The genesis
	// record is always kept, and the record being published is never deleted.
	Retain int
}

func (s Settings) validate() error {
	if s.Retain < 1 || s.Retain > MaxRetain {
		return fmt.Errorf("%w: Retain is %d, want 1 to %d", ErrSettings, s.Retain, MaxRetain)
	}
	return nil
}

/*
Store is the bbolt-backed certified-record store. It keeps bbolt's default options, including syncing on
every commit (NoSync false): see docs/design/f6b-certified-record-store.md for what a successful commit
does and does not guarantee.
*/
type Store struct {
	db       *bolt.DB
	settings Settings

	// checkpoint, when set by tests, is called at named points of Publish. A returned error fails
	// publication at that point; a checkpoint may also end the process to model a crash.
	checkpoint func(name string) error
}

// Open opens or creates the store at path.
func Open(path string, settings Settings) (*Store, error) {
	if err := settings.validate(); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, err
	}
	if db.NoSync {
		_ = db.Close()
		return nil, fmt.Errorf("%w: the backend was opened without syncing", ErrSettings)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketName)
		return err
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	// On every Open, not only when the file was created: a store is not usable for readiness until the
	// entry naming it is durable, and an earlier process may have created the file and crashed before
	// syncing. The directory itself must already exist durably; Open does not create directories.
	dir := filepath.Dir(path)
	if err := syncDirectory(dir); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%w: %s: %w", ErrDirectorySync, dir, err)
	}
	return &Store{db: db, settings: settings}, nil
}

// Close closes the backend.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) at(name string) error {
	if s.checkpoint == nil {
		return nil
	}
	return s.checkpoint(name)
}

func recordKey(r Record) []byte {
	if r.BlockNumber == 0 {
		return bytes.Clone(genesisKey)
	}
	return []byte(fmt.Sprintf("%s%020d/%x", recordPfx, r.PartitionRound, r.BlockHash))
}

var errPublishFailed = errors.New("certifiedstore: publication failed")

/*
Publish writes r as the current record. The record must verify under c first: a record that would not
load is never written, so no partial or unverifiable record becomes current. Then ONE transaction puts the
record, points the head at it, and deletes non-genesis records beyond Settings.Retain, oldest first, never
the record being published. If anything fails before the transaction commits, the store is unchanged:
the previous head, its record and every record retention would have deleted remain.
*/
func (s *Store) Publish(ctx context.Context, c Context, r Record) error {
	enc, sr, err := encodeRecord(c, r)
	if err != nil {
		return err
	}
	if _, err := verify(ctx, c, sr); err != nil {
		return fmt.Errorf("%w: the record does not verify: %w", errPublishFailed, err)
	}
	if err := s.at("before-publish"); err != nil {
		return fmt.Errorf("%w: %w", errPublishFailed, err)
	}
	key := recordKey(r)
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return errors.New("certifiedstore: bucket missing")
		}
		if err := b.Put(key, enc); err != nil {
			return err
		}
		if err := s.at("after-record-put"); err != nil {
			return err
		}
		if err := b.Put(headKey, key); err != nil {
			return err
		}
		if err := s.at("after-head-put"); err != nil {
			return err
		}
		var others [][]byte
		cur := b.Cursor()
		for k, _ := cur.Seek(recordPfx); k != nil && bytes.HasPrefix(k, recordPfx); k, _ = cur.Next() {
			if bytes.Equal(k, genesisKey) || bytes.Equal(k, key) {
				continue
			}
			others = append(others, bytes.Clone(k))
		}
		sort.Slice(others, func(i, j int) bool { return bytes.Compare(others[i], others[j]) < 0 })
		keep := s.settings.Retain
		if r.BlockNumber != 0 {
			keep-- // the record being published is one of the retained non-genesis records
		}
		for len(others) > keep {
			if err := b.Delete(others[0]); err != nil {
				return err
			}
			others = others[1:]
			if err := s.at("after-retention-delete"); err != nil {
				return err
			}
		}
		return s.at("before-commit")
	})
	if err != nil {
		return fmt.Errorf("%w: %w", errPublishFailed, err)
	}
	return s.at("after-commit")
}

// Load returns the head record, re-verified under c. There is no fallback: a missing, damaged, foreign or
// unverifiable head record is a refusal, whatever older records the store retains.
func (s *Store) Load(ctx context.Context, c Context) (Loaded, error) {
	var raw []byte
	var headMissing, recordMissing bool
	var headName []byte
	if err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			headMissing = true
			return nil
		}
		k := b.Get(headKey)
		if k == nil {
			headMissing = true
			return nil
		}
		headName = bytes.Clone(k)
		v := b.Get(k)
		if v == nil {
			recordMissing = true
			return nil
		}
		raw = bytes.Clone(v) // bbolt memory is valid only inside the transaction
		return nil
	}); err != nil {
		return Loaded{}, err
	}
	switch {
	case headMissing:
		return Loaded{}, ErrNoRecord
	case recordMissing:
		return Loaded{}, fmt.Errorf("%w: head names %q, which is not there", ErrRecordUntrusted, headName)
	}
	sr, err := decodeRecord(raw)
	if err != nil {
		return Loaded{}, err
	}
	return verify(ctx, c, sr)
}

// Keys lists the stored keys, for inspection and tests.
func (s *Store) Keys() ([]string, error) {
	var out []string
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, _ []byte) error {
			out = append(out, string(k))
			return nil
		})
	})
	return out, err
}
