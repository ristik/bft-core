package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"go.etcd.io/bbolt"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	bucketBlocks       = []byte("blocks")
	bucketCertificates = []byte("certificates")
	bucketVotes        = []byte("votes")
	bucketSafety       = []byte("safety") // safety module state
	bucketMetadata     = []byte("metadata")

	keyDbVersion    = []byte("version")
	keyTimeoutCert  = []byte("tc")
	keyVote         = []byte("vote")
	keyHighestVoted = []byte("votedRound")
	keyHighestQc    = []byte("qcRound")
	keyEpochAnchor  = []byte("epochAnchor")
	keyHandoffBody  = []byte("handoff/body/")
	keyHandoffProof = []byte("handoff/bundle/")
	// keyHandoffCandidate retains the verified H3 assignment candidate by the
	// successor body it authorizes; it is committed-history input for the
	// derived EVM configuration, never a local schedule.
	keyHandoffCandidate = []byte("handoff/candidate/")
)

func handoffMetadataKey(prefix, id []byte) []byte {
	key := make([]byte, 0, len(prefix)+len(id))
	key = append(key, prefix...)
	return append(key, id...)
}

func validHandoffBodySize(n int) bool   { return n > 0 && n <= 1<<20 }
func validHandoffBundleSize(n int) bool { return n > 0 && n <= 64<<20 }

// StoreHandoffBody retains a verified freeze companion so any root peer can
// later serve the successor body named by the committed control record.
func (db BoltDB) StoreHandoffBody(id, body []byte) error {
	if len(id) != 32 || !validHandoffBodySize(len(body)) {
		return ErrHandoffRecord
	}
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketMetadata)
		if b == nil {
			return ErrHandoffRecord
		}
		key := handoffMetadataKey(keyHandoffBody, id)
		if existing := b.Get(key); existing != nil && !bytes.Equal(existing, body) {
			return ErrHandoffRecord
		}
		return b.Put(key, body)
	})
}

func (db BoltDB) HandoffBody(id []byte) ([]byte, error) {
	if len(id) != 32 {
		return nil, ErrHandoffRecord
	}
	var data []byte
	err := db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketMetadata)
		if b == nil {
			return ErrHandoffRecord
		}
		data = bytes.Clone(b.Get(handoffMetadataKey(keyHandoffBody, id)))
		return nil
	})
	return data, err
}

// StoreHandoffCandidate retains the verified H3 candidate preimage. Rewriting
// different bytes under the same body id is refused.
func (db BoltDB) StoreHandoffCandidate(id, candidate []byte) error {
	if len(id) != 32 || len(candidate) == 0 || len(candidate) > 1<<20 {
		return ErrHandoffRecord
	}
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketMetadata)
		if b == nil {
			return ErrHandoffRecord
		}
		key := handoffMetadataKey(keyHandoffCandidate, id)
		if existing := b.Get(key); existing != nil && !bytes.Equal(existing, candidate) {
			return ErrHandoffRecord
		}
		return b.Put(key, candidate)
	})
}

func (db BoltDB) HandoffCandidate(id []byte) ([]byte, error) {
	if len(id) != 32 {
		return nil, ErrHandoffRecord
	}
	var data []byte
	err := db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketMetadata)
		if b == nil {
			return ErrHandoffRecord
		}
		data = bytes.Clone(b.Get(handoffMetadataKey(keyHandoffCandidate, id)))
		return nil
	})
	return data, err
}

func (db BoltDB) StoreHandoffBundle(epoch uint64, data []byte) error {
	if epoch < 2 || !validHandoffBundleSize(len(data)) {
		return ErrHandoffRecord
	}
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], epoch)
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketMetadata)
		if b == nil {
			return ErrHandoffRecord
		}
		key := handoffMetadataKey(keyHandoffProof, number[:])
		if existing := b.Get(key); existing != nil && !bytes.Equal(existing, data) {
			return ErrHandoffRecord
		}
		return b.Put(key, data)
	})
}

func (db BoltDB) HandoffBundle(epoch uint64) ([]byte, error) {
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], epoch)
	var data []byte
	err := db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketMetadata)
		if b == nil {
			return ErrHandoffRecord
		}
		data = bytes.Clone(b.Get(handoffMetadataKey(keyHandoffProof, number[:])))
		return nil
	})
	return data, err
}

/*
Implementation of persistent storage for the BlockTree and SafetyModule using bbolt database.
*/
type BoltDB struct {
	db *bbolt.DB
}

const currentDBVersion uint64 = 1

// BoltOption configures a store opened by NewBoltStorage.
type BoltOption func(*bbolt.DB)

// WithNoSync opens the store without syncing each commit to disk (bbolt's NoSync). It is for throwaway
// stores only — test fixtures whose assertions are about consensus rather than durability: a crash can
// lose or corrupt any commit made this way. Production callers never pass it, and TestNewBoltStorage_Sync
// pins that a store opened without it syncs.
//
// Why it exists (#127): the consensus round path makes several synced commits per node per round
// before a vote is sent. On macOS a bbolt sync is F_FULLFSYNC — measured at ~115 ms mean with four
// stores committing concurrently, against ~4 ms in Linux on the same machine — so the four-node test
// fixtures ran rounds of 500–600 ms instead of ~100 ms and ran out of their Linux-calibrated budgets.
func WithNoSync() BoltOption { return func(db *bbolt.DB) { db.NoSync = true } }

func NewBoltStorage(file string, opts ...BoltOption) (db BoltDB, err error) {
	_, err = os.Stat(file)
	newDB := err != nil && errors.Is(err, fs.ErrNotExist)

	db.db, err = bbolt.Open(file, 0600, &bbolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return db, fmt.Errorf("open database: %w", err)
	}
	for _, opt := range opts {
		opt(db.db)
	}
	defer func() {
		if err != nil {
			_ = db.db.Close()
			db.db = nil
		}
	}()

	if newDB {
		if err := db.db.Update(initBuckets); err != nil {
			return db, fmt.Errorf("initializing new database: %w", err)
		}
		return db, nil
	}

	ver, err := db.getVersion()
	if err != nil {
		return db, fmt.Errorf("reading database version: %w", err)
	}
	if ver != currentDBVersion {
		return db, fmt.Errorf("unsupported database version %d, expected %d", ver, currentDBVersion)
	}
	return db, nil
}

// initBuckets creates the bucket layout and writes the current version marker
// into a fresh bbolt database.
func initBuckets(tx *bbolt.Tx) error {
	if _, err := tx.CreateBucket(bucketBlocks); err != nil {
		return fmt.Errorf("creating bucket for blocks: %w", err)
	}
	if _, err := tx.CreateBucket(bucketCertificates); err != nil {
		return fmt.Errorf("creating bucket for certificates: %w", err)
	}
	if _, err := tx.CreateBucket(bucketVotes); err != nil {
		return fmt.Errorf("creating bucket for votes: %w", err)
	}
	b, err := tx.CreateBucket(bucketSafety)
	if err != nil {
		return fmt.Errorf("creating bucket for safety: %w", err)
	}
	if err := writeUint64(b, keyHighestQc, rctypes.GenesisRootRound); err != nil {
		return fmt.Errorf("storing highest QC round: %w", err)
	}
	if err := writeUint64(b, keyHighestVoted, rctypes.GenesisRootRound); err != nil {
		return fmt.Errorf("storing highest voted round: %w", err)
	}
	if _, err := tx.CreateBucket(bucketMetadata); err != nil {
		return fmt.Errorf("creating bucket for metadata: %w", err)
	}
	return setVersion(tx, currentDBVersion)
}

func (db BoltDB) Close() error { return db.db.Close() }

var errNoBlocksBucket = errors.New("blocks bucket not found")

/*
LoadBlocks returns all the blocks in the database.
The list is sorted in descending order of round number.
*/
func (db BoltDB) LoadBlocks() (blocks []*ExecutedBlock, err error) {
	return blocks, db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		if b == nil {
			return errNoBlocksBucket
		}

		c := b.Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			var b ExecutedBlock
			if err := types.Cbor.Unmarshal(v, &b); err != nil {
				return fmt.Errorf("loading block %x: %w", k, err)
			}
			blocks = append(blocks, &b)
		}
		return nil
	})
}

/*
WriteBlock stores "block" into database. If "root" is "true" older
blocks (based on round number) will be deleted.
*/
func (db BoltDB) WriteBlock(block *ExecutedBlock, root bool) error {
	data, err := types.Cbor.Marshal(block)
	if err != nil {
		return fmt.Errorf("serializing block: %w", err)
	}
	key := binary.BigEndian.AppendUint64(make([]byte, 0, 8), block.GetRound())

	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		if b == nil {
			return errNoBlocksBucket
		}
		if err := b.Put(key, data); err != nil {
			return fmt.Errorf("storing block: %w", err)
		}

		if !root {
			return nil
		}
		if block.CommitQc == nil && !isEpochAnchorRoot(block) {
			return errors.New("root block must have commit QC")
		}
		if isEpochAnchorRoot(block) {
			// A handoff proof may arrive after the old chain has advanced beyond
			// the fixed successor start. None of that old suffix belongs under
			// the new anchor, regardless of its numerical round.
			var oldKeys [][]byte
			c := b.Cursor()
			for k, _ := c.First(); k != nil; k, _ = c.Next() {
				if !bytes.Equal(k, key) {
					oldKeys = append(oldKeys, bytes.Clone(k))
				}
			}
			for _, oldKey := range oldKeys {
				if err := b.Delete(oldKey); err != nil {
					return fmt.Errorf("delete old epoch block %x: %w", oldKey, err)
				}
			}
			return nil
		}

		// we do not keep history so anything older than the root can be deleted
		c := b.Cursor()
		if k, _ := c.Seek(key); !bytes.Equal(k, key) {
			return fmt.Errorf("seeking %x but landed on %x", key, k)
		}
		for k, _ := c.Prev(); k != nil; k, _ = c.Prev() {
			if err := c.Delete(); err != nil {
				return fmt.Errorf("delete key %x: %w", k, err)
			}
		}
		return nil
	})
}

var errNoCertificatesBucket = errors.New("certificates bucket not found")

func (db BoltDB) WriteTC(tc *rctypes.TimeoutCert) error {
	data, err := types.Cbor.Marshal(tc)
	if err != nil {
		return fmt.Errorf("serializing TimeoutCert: %w", err)
	}
	blockKey := binary.BigEndian.AppendUint64(make([]byte, 0, 8), tc.GetRound())

	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketCertificates)
		if b == nil {
			return errNoCertificatesBucket
		}
		if err := b.Put(keyTimeoutCert, data); err != nil {
			return err
		}
		// if there is block for the round deleted it
		if b = tx.Bucket(bucketBlocks); b == nil {
			return errNoBlocksBucket
		}
		return b.Delete(blockKey)
	})
}

func (db BoltDB) ReadLastTC() (tc *rctypes.TimeoutCert, _ error) {
	// we currently only keep the latest TC, stored to [bucketCertificates -> keyTimeoutCert]
	return tc, db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketCertificates)
		if b == nil {
			return errNoCertificatesBucket
		}
		if k, v := b.Cursor().Seek(keyTimeoutCert); bytes.Equal(k, keyTimeoutCert) {
			return types.Cbor.Unmarshal(v, &tc)
		}
		return nil
	})
}

var errNoVoteBucket = errors.New("vote bucket not found")

const (
	Unknown VoteType = iota
	VoteMsg
	TimeoutVoteMsg
)

type VoteType uint8

type VoteStore struct {
	VoteType VoteType
	VoteMsg  types.RawCBOR
}

func (db BoltDB) WriteVote(vote any) (err error) {
	voteInfo := VoteStore{}
	switch vote.(type) {
	case *abdrc.VoteMsg, abdrc.VoteMsg:
		voteInfo.VoteType = VoteMsg
	case *abdrc.TimeoutMsg, abdrc.TimeoutMsg:
		voteInfo.VoteType = TimeoutVoteMsg
	default:
		return fmt.Errorf("unknown vote type %T", vote)
	}

	if voteInfo.VoteMsg, err = types.Cbor.Marshal(vote); err != nil {
		return fmt.Errorf("vote message serialization failed: %w", err)
	}

	encoded, err := types.Cbor.Marshal(voteInfo)
	if err != nil {
		return fmt.Errorf("vote info serialization failed: %w", err)
	}

	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketVotes)
		if b == nil {
			return errNoVoteBucket
		}
		return b.Put(keyVote, encoded)
	})
}

func (db BoltDB) ReadLastVote() (msg any, err error) {
	return msg, db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketVotes)
		if b == nil {
			return errNoVoteBucket
		}

		voteInfo := VoteStore{}
		if k, v := b.Cursor().Seek(keyVote); bytes.Equal(k, keyVote) {
			if err := types.Cbor.Unmarshal(v, &voteInfo); err != nil {
				return fmt.Errorf("deserializing vote info: %w", err)
			}
		} else {
			return nil
		}

		switch voteInfo.VoteType {
		case VoteMsg:
			msg = &abdrc.VoteMsg{}
		case TimeoutVoteMsg:
			msg = &abdrc.TimeoutMsg{}
		default:
			return fmt.Errorf("unsupported vote kind: %d", voteInfo.VoteType)
		}
		if err := types.Cbor.Unmarshal(voteInfo.VoteMsg, msg); err != nil {
			return fmt.Errorf("deserializing vote message (%T): %w", msg, err)
		}
		return nil
	})
}

var errNoSafetyBucket = errors.New("safety module bucket not found")

// SafetySnapshot is the persisted safety frontier read from one database view.
// It is a storage snapshot only; it does not certify global freshness or authority.
// Vote and recovery serialization remain separate concerns for the callers.
type SafetySnapshot struct {
	HighestQCRound    uint64
	HighestVotedRound uint64
}

// ReadSafetySnapshot returns both persisted safety rounds from one coherent read
// transaction. It returns an error for any unavailable or malformed field rather
// than substituting a genesis value.
func (db BoltDB) ReadSafetySnapshot() (snapshot SafetySnapshot, err error) {
	if db.db == nil {
		return snapshot, errors.New("database is uninitialized")
	}

	err = db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSafety)
		if b == nil {
			return errNoSafetyBucket
		}

		highestQC, err := readUint64(b, keyHighestQc)
		if err != nil {
			return fmt.Errorf("reading highest QC round: %w", err)
		}
		highestVoted, err := readUint64(b, keyHighestVoted)
		if err != nil {
			return fmt.Errorf("reading highest voted round: %w", err)
		}
		snapshot = SafetySnapshot{
			HighestQCRound:    highestQC,
			HighestVotedRound: highestVoted,
		}
		return nil
	})
	if err != nil {
		return SafetySnapshot{}, err
	}
	return snapshot, nil
}

func (db BoltDB) GetHighestVotedRound() (round uint64) {
	err := db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSafety)
		if b == nil {
			return errNoSafetyBucket
		}
		var err error
		round, err = readUint64(b, keyHighestVoted)
		return err
	})
	if err != nil {
		return rctypes.GenesisRootRound
	}
	return round
}

func (db BoltDB) SetHighestVotedRound(round uint64) error {
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSafety)
		if b == nil {
			return errNoSafetyBucket
		}
		hVR, err := readUint64(b, keyHighestVoted)
		if err != nil {
			return err
		}
		return writeUint64(b, keyHighestVoted, max(round, hVR))
	})
}

func (db BoltDB) GetHighestQcRound() (round uint64) {
	err := db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSafety)
		if b == nil {
			return errNoSafetyBucket
		}
		var err error
		round, err = readUint64(b, keyHighestQc)
		return err
	})
	if err != nil {
		return rctypes.GenesisRootRound
	}
	return round
}

func (db BoltDB) SetHighestQcRound(qcRound, votedRound uint64) error {
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSafety)
		if b == nil {
			return errNoSafetyBucket
		}
		hQC, err := readUint64(b, keyHighestQc)
		if err != nil {
			return err
		}
		hVR, err := readUint64(b, keyHighestVoted)
		if err != nil {
			return err
		}
		/* should we return error when attempting to set earlier round? ie
		if hQC < qcRound {
			return fmt.Errorf("attempt to reset QC round back - stored %d, proposed new %d", hQC, qcRound)
		}*/

		if err = writeUint64(b, keyHighestQc, max(qcRound, hQC)); err != nil {
			return err
		}
		return writeUint64(b, keyHighestVoted, max(votedRound, hVR))
	})
}

// InstallEpochAnchorSafety crosses one epoch at a time. An old or skipped
// anchor cannot lower the lock or clear votes and timeouts.
func (db BoltDB) InstallEpochAnchorSafety(a *rctypes.EpochAnchor) error {
	if err := a.IsValid(); err != nil {
		return err
	}
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSafety)
		if b == nil {
			return errNoSafetyBucket
		}
		if prior := b.Get(keyEpochAnchor); prior != nil {
			var installed rctypes.EpochAnchor
			if err := types.Cbor.Unmarshal(prior, &installed); err != nil {
				return err
			}
			if sameEpochAnchor(&installed, a) {
				return nil
			}
			if installed.Epoch == ^uint64(0) || a.Epoch != installed.Epoch+1 || a.Slot <= installed.Slot {
				return rctypes.ErrEpochAnchor
			}
		}
		encoded, err := types.Cbor.Marshal(a)
		if err != nil {
			return err
		}
		if err := b.Put(keyEpochAnchor, encoded); err != nil {
			return err
		}
		if err := writeUint64(b, keyHighestVoted, a.Slot); err != nil {
			return err
		}
		if err := writeUint64(b, keyHighestQc, a.Slot); err != nil {
			return err
		}
		if err := tx.Bucket(bucketVotes).Delete(keyVote); err != nil {
			return err
		}
		return tx.Bucket(bucketCertificates).Delete(keyTimeoutCert)
	})
}

// InstallEpochAnchorRoot atomically persists the successor root and its safety
// record so restart sees either the prior epoch or the complete anchor.
func (db BoltDB) InstallEpochAnchorRoot(block *ExecutedBlock, a *rctypes.EpochAnchor) error {
	return db.installEpochAnchorRootWithFault(block, a, nil)
}

func (db BoltDB) installEpochAnchorRootWithFault(block *ExecutedBlock, a *rctypes.EpochAnchor, afterWrite func(string) error) error {
	if block == nil || block.BlockData == nil || a == nil || a.IsValid() != nil ||
		!isEpochAnchorRoot(block) || block.BlockData.Round != a.Slot || block.BlockData.Epoch != a.Epoch ||
		!bytes.Equal(block.BlockData.Anchor.GenesisID, a.GenesisID) || !bytes.Equal(block.BlockData.Anchor.StateRoot, a.StateRoot) {
		return rctypes.ErrEpochAnchor
	}
	data, err := types.Cbor.Marshal(block)
	if err != nil {
		return fmt.Errorf("serializing epoch anchor root: %w", err)
	}
	key := binary.BigEndian.AppendUint64(make([]byte, 0, 8), block.GetRound())
	anchorData, err := types.Cbor.Marshal(a)
	if err != nil {
		return err
	}
	step := func(name string) error {
		if afterWrite == nil {
			return nil
		}
		return afterWrite(name)
	}
	return db.db.Update(func(tx *bbolt.Tx) error {
		blocks := tx.Bucket(bucketBlocks)
		safety := tx.Bucket(bucketSafety)
		votes := tx.Bucket(bucketVotes)
		certificates := tx.Bucket(bucketCertificates)
		if blocks == nil || safety == nil || votes == nil || certificates == nil {
			return errNoSafetyBucket
		}
		installed := safety.Get(keyEpochAnchor)
		advance := installed == nil
		if installed != nil {
			var prior rctypes.EpochAnchor
			if err := types.Cbor.Unmarshal(installed, &prior); err != nil {
				return err
			}
			if !sameEpochAnchor(&prior, a) {
				if prior.Epoch == ^uint64(0) || a.Epoch != prior.Epoch+1 || a.Slot <= prior.Slot {
					return rctypes.ErrEpochAnchor
				}
				advance = true
			}
		}
		if err := blocks.Put(key, data); err != nil {
			return err
		}
		if err := step("root-put"); err != nil {
			return err
		}
		var oldKeys [][]byte
		cursor := blocks.Cursor()
		for k, _ := cursor.First(); k != nil; k, _ = cursor.Next() {
			if !bytes.Equal(k, key) {
				oldKeys = append(oldKeys, bytes.Clone(k))
			}
		}
		for i, oldKey := range oldKeys {
			if err := blocks.Delete(oldKey); err != nil {
				return err
			}
			if err := step(fmt.Sprintf("old-block-delete-%d", i)); err != nil {
				return err
			}
		}
		if advance {
			if err := safety.Put(keyEpochAnchor, anchorData); err != nil {
				return err
			}
			if err := step("safety-anchor"); err != nil {
				return err
			}
			if err := writeUint64(safety, keyHighestVoted, a.Slot); err != nil {
				return err
			}
			if err := step("highest-voted"); err != nil {
				return err
			}
			if err := writeUint64(safety, keyHighestQc, a.Slot); err != nil {
				return err
			}
			if err := step("highest-qc"); err != nil {
				return err
			}
			if err := votes.Delete(keyVote); err != nil {
				return err
			}
			if err := step("vote-delete"); err != nil {
				return err
			}
			if err := certificates.Delete(keyTimeoutCert); err != nil {
				return err
			}
			if err := step("timeout-delete"); err != nil {
				return err
			}
		}
		return nil
	})
}

func sameEpochAnchor(a, b *rctypes.EpochAnchor) bool {
	return a != nil && b != nil && a.Epoch == b.Epoch && a.Slot == b.Slot &&
		bytes.Equal(a.GenesisID, b.GenesisID) && bytes.Equal(a.StateRoot, b.StateRoot)
}

func (db BoltDB) ReadEpochAnchorSafety() (*rctypes.EpochAnchor, error) {
	var a *rctypes.EpochAnchor
	err := db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSafety)
		if b == nil {
			return errNoSafetyBucket
		}
		if data := b.Get(keyEpochAnchor); data != nil {
			return types.Cbor.Unmarshal(data, &a)
		}
		return nil
	})
	return a, err
}

func (db BoltDB) getVersion() (ver uint64, _ error) {
	return ver, db.db.View(func(tx *bbolt.Tx) (err error) {
		b := tx.Bucket(bucketMetadata)
		if b == nil {
			return errors.New("metadata bucket not found")
		}
		ver, err = readUint64(b, keyDbVersion)
		return err
	})
}

func setVersion(tx *bbolt.Tx, version uint64) error {
	b := tx.Bucket(bucketMetadata)
	if b == nil {
		return errors.New("metadata bucket not found")
	}
	return writeUint64(b, keyDbVersion, version)
}

func readUint64(b *bbolt.Bucket, key []byte) (uint64, error) {
	v := b.Get(key)
	if v == nil {
		return 0, fmt.Errorf("key %x not found", key)
	}
	if len(v) != 8 {
		return 0, fmt.Errorf("expected value of the %x to be 8 bytes, got %d", key, len(v))
	}
	return binary.BigEndian.Uint64(v), nil
}

func writeUint64(b *bbolt.Bucket, key []byte, value uint64) error {
	return b.Put(key, binary.BigEndian.AppendUint64(nil, value))
}
