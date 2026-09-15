package certifiedstore

import (
	"bytes"
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	bolt "go.etcd.io/bbolt"
)

// ReadRecord returns one retained record selected by an exact block hash and an explicit partition-round
// lookup hint. The hint locates the existing round/hash key; it is not authority. The value is copied in one
// bounded read transaction, then subjected to the same complete verification and canonical-key binding as
// Load. There is no scan, fallback to the head, or mutation.
//
// Genesis has no round in its storage key. It is selected only when blockHash is the configured EVM genesis
// hash, and the verified genesis record must still name partitionRound. The caller supplies partitionRound
// only as a locator hint; all round claims come from record verification, and a wrong hint is absent or an
// exact-subject mismatch. Hash-only archive discovery requires a separately reviewed bounded index.
func (s *Store) ReadRecord(ctx context.Context, c Context, partitionRound uint64, blockHash common.Hash) (Loaded, error) {
	// Check the Context's existing basic invariants before deriving a key. The caller supplies a checked
	// local deployment context; this read does not regenerate or establish that deployment configuration.
	if err := c.check(); err != nil {
		return Loaded{}, err
	}
	if blockHash == (common.Hash{}) {
		return Loaded{}, fmt.Errorf("%w: requested block hash is zero", ErrWrongBlock)
	}

	var key []byte
	if blockHash == c.Registry.EVMGenesisHash {
		key = bytes.Clone(genesisKey)
	} else {
		// Any nonzero block number selects the ordinary key shape. The number is not encoded in that key;
		// complete verification below authenticates the candidate's number, hash, round and context.
		key = keyFor(1, partitionRound, blockHash[:])
	}

	var value []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return ErrNoRecord
		}
		v := b.Get(key)
		if v == nil {
			return ErrNoRecord
		}
		if len(v) > MaxRecordBytes {
			return fmt.Errorf("%w: %d bytes exceeds %d", ErrRecordUntrusted, len(v), MaxRecordBytes)
		}
		value = bytes.Clone(v) // bbolt memory is valid only inside the transaction
		return nil
	})
	if err != nil {
		return Loaded{}, err
	}

	loaded, err := verifyHead(ctx, c, key, value)
	if err != nil {
		return Loaded{}, err
	}
	if loaded.BlockHash() != blockHash {
		return Loaded{}, fmt.Errorf("%w: stored block %s, requested %s", ErrWrongBlock, loaded.BlockHash(), blockHash)
	}
	if loaded.PartitionRound() != partitionRound {
		return Loaded{}, fmt.Errorf("%w: stored round %d, requested %d", ErrWrongRound, loaded.PartitionRound(), partitionRound)
	}
	return loaded, nil
}
