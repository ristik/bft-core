// Package rootrecords is the root-side projection that custody imports: an ordered, linked log of the control records custody reads
// (session closure, acknowledgement, recovery acknowledgement, liability closure, retirement), each anchored at the canonical ordinary
// progress p and the quorum-approved UC time of the moment it was ordered (docs/design/pos-architecture.md section 4). A validator-registry
// generation adds three kinds (docs/design/validator-registry/schema-v1.md section 7): Boundary, the EVM transition that follows every
// acknowledgement; OutputRejected, which precedes the SessionClosed of a rejected result; and HolderRetirement, the holder-scoped
// retirement authorization.
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
	KindRetirement // pre-VR generations only
	// KindBoundary is the EVM transition of an acknowledged result: it immediately follows the result's Ack or RecoveryAck.
	KindBoundary
	// KindOutputRejected names why a result was rejected: it immediately precedes the result's SessionClosed.
	KindOutputRejected
	// KindHolderRetirement authorizes the retirement of one identity generation at one liability holder.
	KindHolderRetirement
	// KindPoPMissed names the result's members whose handoff-PoP miss a root quorum certified (#1319): between the result's Expired
	// OutputRejected and its SessionClosed, only when a member is certified.
	KindPoPMissed
)

var (
	// ErrKind reports a record kind outside the nine the log carries.
	ErrKind = errors.New("rootrecords: unknown record kind")
	// ErrPayload reports a record payload that is not exactly the kind's words.
	ErrPayload = errors.New("rootrecords: malformed record payload")
	// ErrIndex reports a record whose index is not the next sequential one.
	ErrIndex = errors.New("rootrecords: record index is not sequential")
	// ErrPredecessor reports a record that does not link to the previous record.
	ErrPredecessor = errors.New("rootrecords: record does not link to its predecessor")
	// ErrRecordID reports a record identifier that is not derived from the record's content.
	ErrRecordID = errors.New("rootrecords: record identifier does not match its content")
	// ErrClosedEpoch reports a closed epoch on a record that is not a Closure.
	ErrClosedEpoch = errors.New("rootrecords: only a closure names a closed epoch")
	// ErrMonotonic reports a record whose progress or UC time is below its predecessor's.
	ErrMonotonic = errors.New("rootrecords: progress or UC time moved backwards")
)

// payloadWords is the exact word count of each kind's abi-encoded payload (P85Types.sol structs, all static; kinds 6 to 8 are the frozen
// widths of validator-registry schema v1, section 7, kind 9 its #1319 extension).
var payloadWords = map[Kind]int{KindSessionClosed: 1, KindAck: 4, KindRecoveryAck: 9, KindClosure: 6, KindRetirement: 3,
	KindBoundary: 7, KindOutputRejected: 4, KindHolderRetirement: 4, KindPoPMissed: 3}

// Record is one projected control record, the contract's RootRecord.
type Record struct {
	Index       uint64
	ID          [32]byte
	Predecessor [32]byte
	Kind        Kind
	Progress    uint64
	UCTime      uint64
	Data        []byte
	// ClosedEpoch is the closed root epoch a Closure belongs to (the registry stores it beside the record and keys its closure
	// uniqueness by it); zero for every other kind. It is not part of the record identity.
	ClosedEpoch uint64
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
	// Every kind's narrow words are canonical (a uint64 word has zero high bytes: the SealRegistry reverts on anything else), and kinds 6
	// to 8 obey their cross-field rules, exactly as vrschema freezes them (vrschema.CheckRecordPayload and DecodeBoundary,
	// DecodeOutputRejected, DecodeHolderRetirement; TestFrozenRecordVectors and TestPayloadRulesAreVrschemas hold the two equal). The
	// rules are restated here because vrschema imports q3format, whose tests import this package through the root store. The projection
	// never builds anything else and an importer refuses anything else, so no consumer sees a payload it would decode otherwise.
	err := checkWords(kind, data)
	if err != nil {
		return fmt.Errorf("%w: kind %d: %w", ErrPayload, kind, err)
	}
	return nil
}

// Word types of a payload: a 32-byte word, or a narrow unsigned integer of the given bits (a bool is 1 bit wide and must be 0 or 1).
const (
	wBytes = 0
	wBool  = 1
)

// payloadWordBits are the frozen word types of every kind (validator-registry schema v1 section 7, vrschema.RecordWordTypes): 0 for
// bytes32, otherwise the width in bits.
var payloadWordBits = map[Kind][]uint{
	KindSessionClosed:    {wBytes},
	KindAck:              {wBytes, 64, 64, 64},
	KindRecoveryAck:      {wBytes, wBytes, 64, 64, 64, 64, 64, 64, 64},
	KindClosure:          {wBytes, 64, wBytes, wBytes, wBytes, wBytes},
	KindRetirement:       {64, 64, wBytes},
	KindBoundary:         {wBytes, 64, 64, 64, 64, wBool, 16},
	KindOutputRejected:   {wBytes, 8, 64, 16},
	KindHolderRetirement: {8, 64, 64, wBytes},
	KindPoPMissed:        {wBytes, 64, 16},
}

// MaxHolders is MAX_HOLDERS: a HolderRetirement names a holder below it.
const MaxHolders = 8

// OutputRejected reasons (record kind 7).
const (
	RejectExpired     uint8 = 1
	RejectInvalidated uint8 = 2
	RejectInvalid     uint8 = 3
)

var (
	errNarrow = errors.New("non-canonical narrow field")
	errRange  = errors.New("value out of range")
)

// narrowAt is the value of payload word i, or false when it has bits above `bits`.
func narrowAt(data []byte, i int, bits uint) (uint64, bool) {
	w := data[32*i : 32*i+32]
	for _, b := range w[:24] {
		if b != 0 {
			return 0, false
		}
	}
	v := uint64(0)
	for _, b := range w[24:] {
		v = v<<8 | uint64(b)
	}
	if bits < 64 && v>>bits != 0 {
		return 0, false
	}
	return v, true
}

// checkWords checks a payload of exactly the kind's width: canonical narrow words, then the cross-field rules of kinds 6 to 8.
func checkWords(kind Kind, data []byte) error {
	for i, bits := range payloadWordBits[kind] {
		if bits == wBytes {
			continue
		}
		if _, ok := narrowAt(data, i, bits); !ok {
			return fmt.Errorf("word %d: %w", i, errNarrow)
		}
	}
	v := func(i int) uint64 { x, _ := narrowAt(data, i, 64); return x }
	zero := func(i int) bool { return [32]byte(data[32*i:32*i+32]) == [32]byte{} }
	switch kind {
	case KindBoundary:
		// nonzero result; installedRootEpoch = changesEpoch, plus one when recovered
		if zero(0) {
			return fmt.Errorf("%w: zero result id", errRange)
		}
		if want := v(1) + v(5); want < v(1) || v(2) != want {
			return fmt.Errorf("%w: installed root epoch %d for changes epoch %d (recovered %v)", errRange, v(2), v(1), v(5) == 1)
		}
	case KindOutputRejected:
		// nonzero result; reason 1..3; memberId only with Invalid; readyBitmap only with Expired
		reason := v(1)
		switch {
		case zero(0):
			return fmt.Errorf("%w: zero result id", errRange)
		case reason < uint64(RejectExpired) || reason > uint64(RejectInvalid):
			return fmt.Errorf("%w: reason %d", errRange, reason)
		case v(2) != 0 && reason != uint64(RejectInvalid):
			return fmt.Errorf("%w: memberId outside Invalid", errRange)
		case v(3) != 0 && reason != uint64(RejectExpired):
			return fmt.Errorf("%w: readyBitmap outside Expired", errRange)
		}
	case KindHolderRetirement:
		if v(0) >= MaxHolders {
			return fmt.Errorf("%w: holder %d", errRange, v(0))
		}
	case KindPoPMissed:
		// nonzero result; a nonzero missed bitmap
		if zero(0) {
			return fmt.Errorf("%w: zero result id", errRange)
		}
		if v(2) == 0 {
			return fmt.Errorf("%w: an empty missed bitmap", errRange)
		}
	}
	return nil
}

// BoundaryPayload is the 224-byte kind 6 payload: resultID, changesEpoch, installedRootEpoch, installedShardEpoch, activationRound,
// recovered, rejectedBitmap.
func BoundaryPayload(resultID [32]byte, changesEpoch, installedRootEpoch, installedShardEpoch, activationRound uint64, recovered bool,
	rejectedBitmap uint16) []byte {
	r := uint64(0)
	if recovered {
		r = 1
	}
	return concat(resultID[:], word(changesEpoch), word(installedRootEpoch), word(installedShardEpoch), word(activationRound), word(r),
		word(uint64(rejectedBitmap)))
}

// OutputRejectedPayload is the 128-byte kind 7 payload: resultID, reason, memberId, readyBitmap.
func OutputRejectedPayload(resultID [32]byte, reason uint8, memberID uint64, readyBitmap uint16) []byte {
	return concat(resultID[:], word(uint64(reason)), word(memberID), word(uint64(readyBitmap)))
}

// PoPMissedPayload is the 96-byte kind 9 payload: resultID, deadline, missedBitmap.
func PoPMissedPayload(resultID [32]byte, deadline uint64, missedBitmap uint16) []byte {
	return concat(resultID[:], word(deadline), word(uint64(missedBitmap)))
}

// HolderRetirementPayload is the 128-byte kind 8 payload: holder, id, generation, refDigest.
func HolderRetirementPayload(holder uint8, id, generation uint64, refDigest [32]byte) []byte {
	return concat(word(uint64(holder)), word(id), word(generation), refDigest[:])
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
func Verify(records []Record) error { return VerifyAfter(nil, records) }

// VerifyAfter checks records that extend a verified log whose last record is prev (nil: the log is empty): consecutive indices from the
// one after prev, valid payloads, exact links, monotone anchors and content-derived identifiers.
func VerifyAfter(prev *Record, records []Record) error {
	next := uint64(0)
	if prev != nil {
		next = prev.Index + 1
	}
	for i, r := range records {
		if r.Index != next+uint64(i) {
			return fmt.Errorf("%w: position %d carries index %d, want %d", ErrIndex, i, r.Index, next+uint64(i))
		}
		if err := checkPayload(r.Kind, r.Data); err != nil {
			return fmt.Errorf("record %d: %w", r.Index, err)
		}
		if prev != nil {
			if r.Predecessor != prev.ID {
				return fmt.Errorf("%w: record %d", ErrPredecessor, r.Index)
			}
			if r.Progress < prev.Progress || r.UCTime < prev.UCTime {
				return fmt.Errorf("%w: record %d", ErrMonotonic, r.Index)
			}
		} else if r.Predecessor != ([32]byte{}) {
			return fmt.Errorf("%w: first record names a predecessor", ErrPredecessor)
		}
		if r.ClosedEpoch != 0 && r.Kind != KindClosure {
			return fmt.Errorf("%w: record %d", ErrClosedEpoch, r.Index)
		}
		if r.ID != RecordID(r.Index, r.Predecessor, r.Kind, r.Progress, r.UCTime, r.Data) {
			return fmt.Errorf("%w: record %d", ErrRecordID, r.Index)
		}
		cur := r
		prev = &cur
	}
	return nil
}
