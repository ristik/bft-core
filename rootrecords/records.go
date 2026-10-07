// Package rootrecords is the root-side projection that custody imports: an ordered, linked log of the control records custody reads
// (session closure, acknowledgement, recovery acknowledgement, liability closure, retirement), each anchored at the canonical ordinary
// progress p and the quorum-approved UC time of the moment it was ordered (docs/design/pos-architecture.md section 4).
//
// Nothing here reads a proof, a seal round or an arrival time: progress moves only on ordinary committed rounds of the current epoch,
// a closure is keyed by (epoch, H record, H round) so no proof encoding can reset it, and UC time is the seal timestamp of verified
// root certificates on one lineage. The record layout and payload words are those of unicity-pos-contracts P85Types.sol.
package rootrecords

import (
	"errors"
	"fmt"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// Kind is the custody record kind; the values are the contract enum's.
type Kind uint8

const (
	KindNone Kind = iota
	KindSessionClosed
	KindAck
	KindRecoveryAck
	KindClosure
	KindRetirement
)

var (
	// ErrKind reports a record kind outside the five custody reads.
	ErrKind = errors.New("rootrecords: unknown record kind")
	// ErrPayload reports a record payload that is not exactly the kind's words.
	ErrPayload = errors.New("rootrecords: malformed record payload")
	// ErrIndex reports a record whose index is not the next sequential one.
	ErrIndex = errors.New("rootrecords: record index is not sequential")
	// ErrPredecessor reports a record that does not link to the previous record.
	ErrPredecessor = errors.New("rootrecords: record does not link to its predecessor")
	// ErrRecordID reports a record identifier that is not derived from the record's content.
	ErrRecordID = errors.New("rootrecords: record identifier does not match its content")
	// ErrMonotonic reports a record whose progress or UC time is below its predecessor's.
	ErrMonotonic = errors.New("rootrecords: progress or UC time moved backwards")
)

// payloadWords is the exact word count of each kind's abi-encoded payload (P85Types.sol structs, all static).
var payloadWords = map[Kind]int{KindSessionClosed: 1, KindAck: 4, KindRecoveryAck: 9, KindClosure: 6, KindRetirement: 3}

// Record is one projected control record, the contract's RootRecord.
type Record struct {
	Index       uint64
	ID          [32]byte
	Predecessor [32]byte
	Kind        Kind
	Progress    uint64
	UCTime      uint64
	Data        []byte
}

// Anchor is the canonical progress and UC time a record is ordered at.
type Anchor struct {
	Progress uint64
	UCTime   uint64
}

func word(v uint64) []byte {
	w := make([]byte, 32)
	for i := 0; i < 8; i++ {
		w[31-i] = byte(v >> (8 * i))
	}
	return w
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// RecordID is keccak256(abi.encode(index, predecessor, kind, progress, ucTime, data)), the identifier custody links by. Every field
// of the record, payload included, is committed, so a record cannot be re-anchored or re-labelled without changing its identifier.
func RecordID(index uint64, predecessor [32]byte, kind Kind, progress, ucTime uint64, data []byte) [32]byte {
	pad := (32 - len(data)%32) % 32
	enc := concat(word(index), predecessor[:], word(uint64(kind)), word(progress), word(ucTime), word(6*32), word(uint64(len(data))), data, make([]byte, pad))
	var id [32]byte
	copy(id[:], ethcrypto.Keccak256(enc))
	return id
}

func checkPayload(kind Kind, data []byte) error {
	n, ok := payloadWords[kind]
	if !ok {
		return fmt.Errorf("%w: %d", ErrKind, kind)
	}
	if len(data) != 32*n {
		return fmt.Errorf("%w: kind %d carries %d bytes, want %d", ErrPayload, kind, len(data), 32*n)
	}
	return nil
}

// Log is the append-only, linked record sequence.
type Log struct{ records []Record }

// Len is the number of records.
func (l *Log) Len() uint64 { return uint64(len(l.records)) }

// At returns record i.
func (l *Log) At(i uint64) (Record, bool) {
	if i >= l.Len() {
		return Record{}, false
	}
	return l.records[i].clone(), true
}

// clone gives a record its own payload: the log is append-only, so no returned value may alias a stored one.
func (r Record) clone() Record {
	r.Data = append([]byte(nil), r.Data...)
	return r
}

// Records returns a deep copy of the sequence.
func (l *Log) Records() []Record {
	out := make([]Record, len(l.records))
	for i, r := range l.records {
		out[i] = r.clone()
	}
	return out
}

// Append orders one record at the anchor. The anchor may not be below the previous record's.
func (l *Log) Append(kind Kind, data []byte, at Anchor) (Record, error) {
	if err := checkPayload(kind, data); err != nil {
		return Record{}, err
	}
	r := Record{Index: l.Len(), Kind: kind, Progress: at.Progress, UCTime: at.UCTime, Data: append([]byte(nil), data...)}
	if n := len(l.records); n > 0 {
		prev := l.records[n-1]
		if at.Progress < prev.Progress || at.UCTime < prev.UCTime {
			return Record{}, fmt.Errorf("%w: (%d,%d) after (%d,%d)", ErrMonotonic, at.Progress, at.UCTime, prev.Progress, prev.UCTime)
		}
		r.Predecessor = prev.ID
	}
	r.ID = RecordID(r.Index, r.Predecessor, r.Kind, r.Progress, r.UCTime, r.Data)
	l.records = append(l.records, r)
	return r.clone(), nil
}

// Verify re-derives a received sequence from its first record: sequential indexes, linked predecessors, content-derived identifiers,
// exact payload widths and non-decreasing anchors. It is what an importer runs before trusting a projection.
func Verify(records []Record) error {
	var prev Record
	for i, r := range records {
		if r.Index != uint64(i) {
			return fmt.Errorf("%w: position %d carries index %d", ErrIndex, i, r.Index)
		}
		if err := checkPayload(r.Kind, r.Data); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
		if i > 0 {
			if r.Predecessor != prev.ID {
				return fmt.Errorf("%w: record %d", ErrPredecessor, i)
			}
			if r.Progress < prev.Progress || r.UCTime < prev.UCTime {
				return fmt.Errorf("%w: record %d", ErrMonotonic, i)
			}
		} else if r.Predecessor != ([32]byte{}) {
			return fmt.Errorf("%w: first record names a predecessor", ErrPredecessor)
		}
		if r.ID != RecordID(r.Index, r.Predecessor, r.Kind, r.Progress, r.UCTime, r.Data) {
			return fmt.Errorf("%w: record %d", ErrRecordID, i)
		}
		prev = r
	}
	return nil
}
