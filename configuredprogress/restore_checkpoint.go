package configuredprogress

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
)

const restoreCheckpointKind uint64 = 13

var restoreCheckpointKey = []byte("archive-restore-checkpoint/v1")

// RestoreCheckpoint identifies the operator's restore request and the exact
// archive target selected for it. The journal descriptor identifies the chain.
type RestoreCheckpoint struct {
	Pin            [32]byte
	Target         [32]byte
	VerifiedHeight uint64
	VerifiedPrefix [32]byte
	Finalizing     bool
}

func readRestoreCheckpoint(b *bolt.Bucket) (RestoreCheckpoint, error) {
	var c RestoreCheckpoint
	if b == nil {
		return c, nil
	}
	value := b.Get(restoreCheckpointKey)
	if value == nil {
		return c, nil
	}
	raw, err := decodeEnvelope(value, restoreCheckpointKind, 256)
	if err != nil {
		return c, err
	}
	if len(raw) != 105 || raw[104] > 1 {
		return c, ErrUntrusted
	}
	copy(c.Pin[:], raw[:32])
	copy(c.Target[:], raw[32:64])
	c.VerifiedHeight = binary.BigEndian.Uint64(raw[64:72])
	copy(c.VerifiedPrefix[:], raw[72:104])
	c.Finalizing = raw[104] == 1
	if c.Pin == ([32]byte{}) || c.Target == ([32]byte{}) ||
		(c.VerifiedHeight == 0) != (c.VerifiedPrefix == ([32]byte{})) || c.Finalizing && c.VerifiedHeight == 0 {
		return RestoreCheckpoint{}, ErrUntrusted
	}
	return c, nil
}

// ReadRestoreCheckpoint checks an existing file without initializing or
// modifying it. The restore command uses this before it opens any BFT stores.
func ReadRestoreCheckpoint(path string) (RestoreCheckpoint, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return RestoreCheckpoint{}, err
	}
	if !fi.Mode().IsRegular() {
		return RestoreCheckpoint{}, ErrSettings
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true, Timeout: 3 * time.Second})
	if err != nil {
		return RestoreCheckpoint{}, err
	}
	defer db.Close()
	var c RestoreCheckpoint
	err = db.View(func(tx *bolt.Tx) error {
		c, err = readRestoreCheckpoint(tx.Bucket(bucketName))
		return err
	})
	return c, err
}

func (s *Store) RestoreCheckpoint() (RestoreCheckpoint, error) {
	var c RestoreCheckpoint
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		c, err = readRestoreCheckpoint(tx.Bucket(bucketName))
		return err
	})
	return c, err
}

// BeginArchiveRestore records intent before the first archive or EL write.
// The caller must have authenticated the pin and checked the fresh EL state.
func (s *Store) BeginArchiveRestore(ctx context.Context, c Context, limits JournalLimits, checkpoint RestoreCheckpoint) error {
	if !s.journal || checkpoint.Pin == ([32]byte{}) || checkpoint.Target == ([32]byte{}) ||
		checkpoint.VerifiedHeight != 0 || checkpoint.VerifiedPrefix != ([32]byte{}) || checkpoint.Finalizing {
		return ErrSettings
	}
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return err
	}
	if state.i.control.Revision != 0 {
		return ErrConflict
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if !imageMatches(b, state.i) {
			return ErrStale
		}
		if err := readJournalMeta(b, state.i.descriptorDigest, limits); err != nil {
			return err
		}
		old, err := readRestoreCheckpoint(b)
		if err != nil {
			return err
		}
		if old != (RestoreCheckpoint{}) {
			return fmt.Errorf("%w: archive restore checkpoint already exists", ErrConflict)
		}
		count, observed, _, err := journalCount(b)
		if err != nil {
			return err
		}
		if count != 0 || observed != 0 || b.Get(restoreAnchorKey) != nil || b.Get(journalCoverageBaseKey) != nil {
			return ErrConflict
		}
		return writeRestoreCheckpoint(b, checkpoint)
	})
}

// AdvanceArchiveRestore records the next verified block before forkchoice can
// make it the EL head. The prefix binds the exact archive representations
// that passed paired verification. Compare-and-swap prevents stale writers.
func (s *Store) AdvanceArchiveRestore(before RestoreCheckpoint, prefix [32]byte) (RestoreCheckpoint, error) {
	next := before
	next.VerifiedHeight++
	next.VerifiedPrefix = prefix
	if !s.journal || before.Pin == ([32]byte{}) || before.Finalizing || next.VerifiedHeight == 0 || prefix == ([32]byte{}) {
		return before, ErrSettings
	}
	return s.updateRestoreCheckpoint(before, next)
}

// AuthorizeRestoreFinality records intent before committing the execution
// target. The EL can persist a finalized prefix of that target on restart.
func (s *Store) AuthorizeRestoreFinality(before RestoreCheckpoint) (RestoreCheckpoint, error) {
	if !s.journal || before.Pin == ([32]byte{}) || before.VerifiedHeight == 0 || before.Finalizing {
		return before, ErrSettings
	}
	next := before
	next.Finalizing = true
	return s.updateRestoreCheckpoint(before, next)
}

func (s *Store) updateRestoreCheckpoint(before, next RestoreCheckpoint) (RestoreCheckpoint, error) {
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		current, err := readRestoreCheckpoint(b)
		if err != nil {
			return err
		}
		if current != before || b.Get(restoreAnchorKey) != nil {
			return ErrStale
		}
		return writeRestoreCheckpoint(b, next)
	})
	if err != nil {
		return before, err
	}
	return next, nil
}

func writeRestoreCheckpoint(b *bolt.Bucket, checkpoint RestoreCheckpoint) error {
	var raw [105]byte
	copy(raw[:32], checkpoint.Pin[:])
	copy(raw[32:64], checkpoint.Target[:])
	binary.BigEndian.PutUint64(raw[64:72], checkpoint.VerifiedHeight)
	copy(raw[72:104], checkpoint.VerifiedPrefix[:])
	if checkpoint.Finalizing {
		raw[104] = 1
	}
	encoded, err := encodeEnvelope(restoreCheckpointKind, raw[:], 256)
	if err != nil {
		return err
	}
	return b.Put(restoreCheckpointKey, encoded)
}

// CheckArchiveRestoreComplete keeps ordinary shard startup from adopting
// the stores of an unfinished restore.
func (s *Store) CheckArchiveRestoreComplete() error {
	return s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		checkpoint, err := readRestoreCheckpoint(b)
		if err != nil {
			return err
		}
		if checkpoint != (RestoreCheckpoint{}) && b.Get(restoreAnchorKey) == nil {
			return fmt.Errorf("%w: archive restore interrupted; repeat shard-node restore with the same pin and paths", ErrUnavailable)
		}
		return nil
	})
}
