package certifiedstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// ErrDirectorySync is an Open that could not make the store file's directory entry durable.
var ErrDirectorySync = errors.New("certifiedstore: syncing the store's parent directory failed")

// ErrStaleRecord is a publication that would replace a head naming the same or a later certified round, or a
// genesis record that would replace an ordinary head (#14 W2).
var ErrStaleRecord = errors.New("certifiedstore: the store's head already names this round or a later one")

// ErrHeadChanged is a Commit whose store head is no longer the one Prepare verified and decided against.
var ErrHeadChanged = errors.New("certifiedstore: the store's head changed after the record was prepared")

// ErrStorePath is a store path Open will not use: its final component is a symbolic link, or is not a regular
// file once opened.
var ErrStorePath = errors.New("certifiedstore: the store path is not a regular file in its own directory")

// afterPathCheck runs between Open's path check and the backend open. Tests replace it to change the path in
// that interval; it does nothing otherwise.
var afterPathCheck = func(string) {}

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
	// The directory synced below must be the one holding the database entry. bbolt follows a symbolic link
	// in the final path component, so through links/db -> actual/db it would create actual/db while
	// filepath.Dir(path) names links. Such a path is refused before anything is created through it.
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s is a symbolic link", ErrStorePath, path)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s: %w", ErrStorePath, path, err)
	}
	afterPathCheck(path)
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
	// Checked again once the file exists: the entry at path must be a regular file, not a link substituted
	// after the first check, for syncing its directory to persist it. This covers a misconfigured or changed
	// path; a party able to rewrite the directory between these checks could also delete the store.
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		_ = db.Close()
		if err == nil {
			err = fmt.Errorf("mode %s", fi.Mode())
		}
		return nil, fmt.Errorf("%w: %s after opening: %w", ErrStorePath, path, err)
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

// keyFor is the canonical key of the record for block number, certified at round, with block hash.
func keyFor(number, round uint64, blockHash []byte) []byte {
	if number == 0 {
		return bytes.Clone(genesisKey)
	}
	return []byte(fmt.Sprintf("%s%020d/%x", recordPfx, round, blockHash))
}

func recordKey(r Record) []byte { return keyFor(r.BlockNumber, r.PartitionRound, r.BlockHash.Bytes()) }

var errPublishFailed = errors.New("certifiedstore: publication failed")

/*
verifyHead decides whether the value a head key names is a record this store can stand behind: present,
decodable, verified under c, and stored under its own canonical key. The key is unsigned storage metadata, so
nothing about the record, its round in particular, is read from the key: an authentic record copied under
another key is refused (review of #162).
*/
func verifyHead(ctx context.Context, c Context, name, value []byte) (Loaded, error) {
	if value == nil {
		return Loaded{}, fmt.Errorf("%w: head names %q, which is not there", ErrRecordUntrusted, name)
	}
	sr, err := decodeRecord(value)
	if err != nil {
		return Loaded{}, err
	}
	l, err := verify(ctx, c, sr)
	if err != nil {
		return Loaded{}, err
	}
	if want := keyFor(sr.BlockNumber, sr.PartitionRound, sr.BlockHash); !bytes.Equal(want, name) {
		return Loaded{}, fmt.Errorf("%w: head key %q does not name its record, whose key is %q", ErrRecordUntrusted, name, want)
	}
	return l, nil
}

// Prepared is a record verified for publication together with the head it was decided against. Only Prepare
// makes one, and only the store that made it commits it.
type Prepared struct {
	p *preparedRecord
}

type preparedRecord struct {
	store      *Store
	key, enc   []byte
	number     uint64
	headName   []byte // nil when the store had no head
	headDigest [sha256.Size]byte
}

/*
Prepare does the verification publication needs, outside any store transaction: it encodes r and verifies it
under c, then reads the current head, verifies that record under c and binds it to its key (verifyHead), and
decides against it. Republishing the head record is allowed. An ordinary record may replace the genesis record
or an ordinary record of an earlier round; a head of the same round naming another block, or of a later round,
is not replaced (ErrStaleRecord), and neither is an ordinary head by the genesis record. A missing, damaged,
foreign, unverifiable or wrongly keyed head is refused and not replaced.

Nothing is written. Commit writes the prepared record provided the head is still, byte for byte, the one
decided against here.
*/
func (s *Store) Prepare(ctx context.Context, c Context, r Record) (Prepared, error) {
	enc, sr, err := encodeRecord(c, r)
	if err != nil {
		return Prepared{}, err
	}
	if _, err := verify(ctx, c, sr); err != nil {
		return Prepared{}, fmt.Errorf("%w: the record does not verify: %w", errPublishFailed, err)
	}
	key := recordKey(r)

	var name, value []byte
	if err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return errors.New("certifiedstore: bucket missing")
		}
		if k := b.Get(headKey); k != nil {
			name = bytes.Clone(k)
			if v := b.Get(k); v != nil {
				value = bytes.Clone(v) // bbolt memory is valid only inside the transaction
			}
		}
		return nil
	}); err != nil {
		return Prepared{}, fmt.Errorf("%w: reading the head: %w", errPublishFailed, err)
	}

	p := &preparedRecord{store: s, key: key, enc: enc, number: r.BlockNumber}
	if name != nil {
		head, err := verifyHead(ctx, c, name, value)
		if err != nil {
			return Prepared{}, fmt.Errorf("%w: the current head cannot be verified, so it is not replaced: %w", errPublishFailed, err)
		}
		if !bytes.Equal(name, key) && head.BlockNumber() != 0 {
			if r.BlockNumber == 0 {
				return Prepared{}, fmt.Errorf("%w: head is round %d; the genesis record does not replace it", ErrStaleRecord, head.PartitionRound())
			}
			if head.PartitionRound() >= r.PartitionRound {
				return Prepared{}, fmt.Errorf("%w: head is round %d, the record is for round %d", ErrStaleRecord, head.PartitionRound(), r.PartitionRound)
			}
		}
		p.headName, p.headDigest = name, sha256.Sum256(value)
	}
	return Prepared{p: p}, nil
}

/*
Commit writes a prepared record as the current record in ONE transaction: the record, the head pointer, and
deletion of non-genesis records beyond Settings.Retain, oldest first, never the record being published. The
transaction first requires the head to be exactly the one Prepare verified (ErrHeadChanged otherwise), so the
decision Prepare made still holds when the write commits and no verification happens inside the transaction.
If anything fails before the transaction commits, the store is unchanged.
*/
func (s *Store) Commit(p Prepared) error {
	if p.p == nil || p.p.store != s {
		return fmt.Errorf("%w: the record was not prepared by this store", errPublishFailed)
	}
	pr := p.p
	if err := s.at("before-publish"); err != nil {
		return fmt.Errorf("%w: %w", errPublishFailed, err)
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return errors.New("certifiedstore: bucket missing")
		}
		cur := b.Get(headKey)
		if (cur == nil) != (pr.headName == nil) || !bytes.Equal(cur, pr.headName) {
			return fmt.Errorf("%w: head %q, prepared against %q", ErrHeadChanged, cur, pr.headName)
		}
		if cur != nil {
			if v := b.Get(cur); v == nil || sha256.Sum256(v) != pr.headDigest {
				return fmt.Errorf("%w: the record head %q names changed after preparation", ErrHeadChanged, cur)
			}
		}
		if err := b.Put(pr.key, pr.enc); err != nil {
			return err
		}
		if err := s.at("after-record-put"); err != nil {
			return err
		}
		if err := b.Put(headKey, pr.key); err != nil {
			return err
		}
		if err := s.at("after-head-put"); err != nil {
			return err
		}
		var others [][]byte
		c := b.Cursor()
		for k, _ := c.Seek(recordPfx); k != nil && bytes.HasPrefix(k, recordPfx); k, _ = c.Next() {
			if bytes.Equal(k, genesisKey) || bytes.Equal(k, pr.key) {
				continue
			}
			others = append(others, bytes.Clone(k))
		}
		sort.Slice(others, func(i, j int) bool { return bytes.Compare(others[i], others[j]) < 0 })
		keep := s.settings.Retain
		if pr.number != 0 {
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

/*
Publish is Prepare followed by Commit: r must verify under c, the current head must verify and be bound to its
key, r must not be stale against it, and then ONE transaction writes the record, the head pointer and the
retention deletions. If anything fails before the transaction commits, the store is unchanged: the previous
head, its record and every record retention would have deleted remain.
*/
func (s *Store) Publish(ctx context.Context, c Context, r Record) error {
	p, err := s.Prepare(ctx, c, r)
	if err != nil {
		return err
	}
	return s.Commit(p)
}

// Load returns the head record, re-verified under c and bound to its key. There is no fallback: a missing,
// damaged, foreign, unverifiable or wrongly keyed head record is a refusal, whatever older records the store
// retains.
func (s *Store) Load(ctx context.Context, c Context) (Loaded, error) {
	var name, value []byte
	if err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return nil
		}
		k := b.Get(headKey)
		if k == nil {
			return nil
		}
		name = bytes.Clone(k)
		if v := b.Get(k); v != nil {
			value = bytes.Clone(v) // bbolt memory is valid only inside the transaction
		}
		return nil
	}); err != nil {
		return Loaded{}, err
	}
	if name == nil {
		return Loaded{}, ErrNoRecord
	}
	return verifyHead(ctx, c, name, value)
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
