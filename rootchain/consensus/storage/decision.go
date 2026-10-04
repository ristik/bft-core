package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"go.etcd.io/bbolt"
)

// DecisionKind separates the signing decisions a node makes in one round: a vote and a timeout are different statements,
// and the safety module signs at most one of each per (epoch, round).
type DecisionKind byte

const (
	DecisionVote    DecisionKind = 1
	DecisionTimeout DecisionKind = 2
)

var (
	bucketDecisions = []byte("decisions")

	// ErrDecisionConflict is returned when a different statement is already recorded for the same (epoch, round, kind).
	ErrDecisionConflict = errors.New("conflicting signing decision already recorded")
	// ErrEmptyDecision is returned for a decision recorded without its statement or without its signed message.
	ErrEmptyDecision = errors.New("decision needs a statement and a signed message")
	// ErrCorruptDecision is returned for a stored decision that cannot be split into statement and message.
	ErrCorruptDecision = errors.New("stored signing decision is corrupt")
)

func decisionKey(kind DecisionKind, epoch, round uint64) []byte {
	k := make([]byte, 0, 17)
	k = append(k, byte(kind))
	k = binary.BigEndian.AppendUint64(k, epoch)
	return binary.BigEndian.AppendUint64(k, round)
}

// decisionValue is the stored form: the length of the statement, the statement, then the complete signed message.
func decisionValue(statement, message []byte) []byte {
	v := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(statement)+len(message)), uint32(len(statement)))
	v = append(v, statement...)
	return append(v, message...)
}

func splitDecisionValue(v []byte) (statement, message []byte, err error) {
	if len(v) < 4 {
		return nil, nil, ErrCorruptDecision
	}
	n := binary.BigEndian.Uint32(v)
	if uint64(n) > uint64(len(v)-4) {
		return nil, nil, ErrCorruptDecision
	}
	return bytes.Clone(v[4 : 4+n]), bytes.Clone(v[4+n:]), nil
}

// SignedDecision returns the statement and the complete signed message recorded for (kind, epoch, round), or nils when there
// is none.
func (db BoltDB) SignedDecision(kind DecisionKind, epoch, round uint64) (statement, message []byte, err error) {
	err = db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketDecisions)
		if b == nil {
			return nil
		}
		v := b.Get(decisionKey(kind, epoch, round))
		if v == nil {
			return nil
		}
		var serr error
		statement, message, serr = splitDecisionValue(v)
		return serr
	})
	return statement, message, err
}

// Decision returns the statement recorded for (kind, epoch, round), or nil when there is none.
func (db BoltDB) Decision(kind DecisionKind, epoch, round uint64) ([]byte, error) {
	statement, _, err := db.SignedDecision(kind, epoch, round)
	return statement, err
}

// RecordSignedDecision durably records, in one transaction, the statement about to be released for (kind, epoch, round)
// together with the complete signed message that carries it (the vote or timeout with its HighQC and the signatures). The
// caller returns the message only after this call succeeded, so the message that left the node is always the one on disk and
// a restart can send it again. It is idempotent for the same statement (the message first recorded is kept) and returns
// ErrDecisionConflict, without writing, for a different one. The bucket is created on first use so that databases written
// before the scheme 2 signing existed need no migration.
func (db BoltDB) RecordSignedDecision(kind DecisionKind, epoch, round uint64, statement, message []byte) error {
	if len(statement) == 0 || len(message) == 0 {
		return ErrEmptyDecision
	}
	return db.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketDecisions)
		if err != nil {
			return fmt.Errorf("creating bucket for decisions: %w", err)
		}
		key := decisionKey(kind, epoch, round)
		if v := b.Get(key); v != nil {
			recorded, _, err := splitDecisionValue(v)
			if err != nil {
				return err
			}
			if !bytes.Equal(recorded, statement) {
				return fmt.Errorf("%w: kind %d epoch %d round %d", ErrDecisionConflict, kind, epoch, round)
			}
			return nil
		}
		return b.Put(key, decisionValue(statement, message))
	})
}
