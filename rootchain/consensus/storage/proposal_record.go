package storage

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"go.etcd.io/bbolt"
)

var (
	keyProposalRecord          = []byte("proposal")
	ErrProposalAlreadyReserved = errors.New("proposal round is at or below the durable signing record")
	ErrCorruptProposalRecord   = errors.New("invalid durable proposal signing record")
	ErrLegacyProposalStore     = errors.New("proposal signing requires a legacy adoption fence")
)

const freshProposalRecord = 1

// ProposalRecord is the highest proposal slot reserved by this root's key and
// the hash passed to its signer. Successor epochs can reuse old round numbers.
type ProposalRecord struct {
	Epoch, Round uint64
	Hash         [sha256.Size]byte
}

// Covers reports whether this slot is already reserved or older than the record.
func (p ProposalRecord) Covers(epoch, round uint64) bool {
	return p.Round != 0 && (epoch < p.Epoch || epoch == p.Epoch && round <= p.Round)
}

func readProposalRecord(bucket *bbolt.Bucket) (p ProposalRecord, err error) {
	if bucket == nil {
		return p, errNoSafetyBucket
	}
	data := bucket.Get(keyProposalRecord)
	if data == nil {
		return p, ErrLegacyProposalStore
	}
	if len(data) == 1 && data[0] == freshProposalRecord {
		return p, nil
	}
	if len(data) != 16+sha256.Size || binary.BigEndian.Uint64(data[8:16]) == 0 {
		return p, ErrCorruptProposalRecord
	}
	p.Epoch = binary.BigEndian.Uint64(data[:8])
	p.Round = binary.BigEndian.Uint64(data[8:16])
	copy(p.Hash[:], data[16:])
	return p, nil
}

// FenceLegacyProposals forbids proposals through the last epoch the old
// executable could have used. It preserves any existing fence or reservation.
func (db BoltDB) FenceLegacyProposals(epoch uint64) error {
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSafety)
		_, err := readProposalRecord(b)
		if !errors.Is(err, ErrLegacyProposalStore) {
			return err
		}
		return writeProposalRecord(b, ProposalRecord{Epoch: epoch, Round: ^uint64(0)})
	})
}

func (db BoltDB) ReadProposalRecord() (p ProposalRecord, err error) {
	err = db.db.View(func(tx *bbolt.Tx) error {
		p, err = readProposalRecord(tx.Bucket(bucketSafety))
		return err
	})
	return p, err
}

// ReserveProposal atomically refuses every slot at or below the durable record.
// The signer may be invoked only after the reservation commits.
func (db BoltDB) ReserveProposal(p ProposalRecord) error {
	if p.Round == 0 {
		return ErrCorruptProposalRecord
	}
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSafety)
		prior, err := readProposalRecord(b)
		if err != nil {
			return err
		}
		if prior.Covers(p.Epoch, p.Round) {
			return fmt.Errorf("%w: epoch %d round %d, reserved through epoch %d round %d", ErrProposalAlreadyReserved, p.Epoch, p.Round, prior.Epoch, prior.Round)
		}
		return writeProposalRecord(b, p)
	})
}

func writeProposalRecord(b *bbolt.Bucket, p ProposalRecord) error {
	data := binary.BigEndian.AppendUint64(make([]byte, 0, 16+sha256.Size), p.Epoch)
	data = binary.BigEndian.AppendUint64(data, p.Round)
	return b.Put(keyProposalRecord, append(data, p.Hash[:]...))
}
