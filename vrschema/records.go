package vrschema

import "fmt"

// Root-record payloads are the kind's exact ABI words (all static). Kinds 1 to 5 are unchanged from rootrecords; kinds 6 to 8 are new.

// RecordWordTypes are the frozen word types of every kind: "bytes32", "uint64", "uint8", "bool", "uint16" (bitmap of at most 16 bits).
var RecordWordTypes = map[uint8][]string{
	RecSessionClosed:    {"bytes32"},
	RecAck:              {"bytes32", "uint64", "uint64", "uint64"},
	RecRecoveryAck:      {"bytes32", "bytes32", "uint64", "uint64", "uint64", "uint64", "uint64", "uint64", "uint64"},
	RecClosure:          {"bytes32", "uint64", "bytes32", "bytes32", "bytes32", "bytes32"},
	RecRetirement:       {"uint64", "uint64", "bytes32"},
	RecBoundary:         {"bytes32", "uint64", "uint64", "uint64", "uint64", "bool", "uint16"},
	RecOutputRejected:   {"bytes32", "uint8", "uint64", "uint16"},
	RecHolderRetirement: {"uint8", "uint64", "uint64", "bytes32"},
}

// Gas pricing inputs of the import (ureth records.rs): the admission charge is 2000 + 16 * companionBytes + 1000 * entries, the
// companion is at most 16384 bytes and 32 entries, and the execution bound IMPORT_EXECUTION_GAS is measured on 32 nine-word records.
// Kinds 6 to 8 are at most 7 words, so neither bound moves. VR's own per-record work is HookRecordGas (design section 3.3.4), measured by
// VT-02.
const (
	ImportScanBaseGas  = 2_000
	ImportScanByteGas  = 16
	ImportEntryGas     = 1_000
	ImportMaxBytes     = 16_384
	ImportMaxEntries   = 32
	ImportMaxWordsSeen = 9
)

// CheckRecordPayload refuses a payload that is not exactly the kind's width or whose narrow words are not canonical.
func CheckRecordPayload(kind uint8, data []byte) error {
	ts, ok := RecordWordTypes[kind]
	if !ok {
		return fmt.Errorf("%w: record kind %d", ErrUnknownKind, kind)
	}
	if len(data) != 32*len(ts) {
		return fmt.Errorf("%w: kind %d carries %d bytes, want %d", ErrLength, kind, len(data), 32*len(ts))
	}
	for i, t := range ts {
		w := wordAt(data, i)
		var err error
		switch t {
		case "uint64":
			_, err = WordUint(w, 64)
		case "uint8":
			_, err = WordUint(w, 8)
		case "uint16":
			_, err = WordUint(w, 16)
		case "bool":
			_, err = WordBool(w)
		}
		if err != nil {
			return fmt.Errorf("word %d: %w", i, err)
		}
	}
	return nil
}

// Boundary is record kind 6.
type Boundary struct {
	ResultID            Word   `json:"-"`
	ChangesEpoch        uint64 `json:"changesEpoch"`
	InstalledRootEpoch  uint64 `json:"installedRootEpoch"`
	InstalledShardEpoch uint64 `json:"installedShardEpoch"`
	ActivationRound     uint64 `json:"activationRound"`
	Recovered           bool   `json:"recovered"`
	RejectedBitmap      uint16 `json:"rejectedBitmap"`
}

// Encode is the 224-byte payload.
func (b Boundary) Encode() []byte {
	return words(b.ResultID, U64(b.ChangesEpoch), U64(b.InstalledRootEpoch), U64(b.InstalledShardEpoch), U64(b.ActivationRound),
		BoolWord(b.Recovered), U64(uint64(b.RejectedBitmap)))
}

// DecodeBoundary is the strict decoder. A primary boundary installs J (installedRootEpoch == changesEpoch); a recovery installs K one
// epoch later (installedRootEpoch == changesEpoch + 1). The result id is nonzero.
func DecodeBoundary(data []byte) (Boundary, error) {
	var b Boundary
	if err := CheckRecordPayload(RecBoundary, data); err != nil {
		return b, err
	}
	b.ResultID = wordAt(data, 0)
	b.ChangesEpoch, _ = WordU64(wordAt(data, 1))
	b.InstalledRootEpoch, _ = WordU64(wordAt(data, 2))
	b.InstalledShardEpoch, _ = WordU64(wordAt(data, 3))
	b.ActivationRound, _ = WordU64(wordAt(data, 4))
	b.Recovered, _ = WordBool(wordAt(data, 5))
	bm, _ := WordU64(wordAt(data, 6))
	b.RejectedBitmap = uint16(bm)
	if b.ResultID == (Word{}) {
		return b, fmt.Errorf("%w: zero result id", ErrRange)
	}
	want := b.ChangesEpoch
	if b.Recovered {
		want++
	}
	if b.InstalledRootEpoch != want || want < b.ChangesEpoch {
		return b, fmt.Errorf("%w: installed root epoch %d for changes epoch %d (recovered %v)", ErrRange, b.InstalledRootEpoch, b.ChangesEpoch, b.Recovered)
	}
	return b, nil
}

// OutputRejected is record kind 7.
type OutputRejected struct {
	ResultID    Word   `json:"-"`
	Reason      uint8  `json:"reason"`
	MemberID    uint64 `json:"memberId"`
	ReadyBitmap uint16 `json:"readyBitmap"`
}

// Encode is the 128-byte payload.
func (o OutputRejected) Encode() []byte {
	return words(o.ResultID, U64(uint64(o.Reason)), U64(o.MemberID), U64(uint64(o.ReadyBitmap)))
}

// DecodeOutputRejected is the strict decoder: reason 1..3; memberId nonzero only for Invalid (the member the admission failure names,
// zero when it names none); readyBitmap only for Expired (bit i: the i-th successor member by ascending id was ready).
func DecodeOutputRejected(data []byte) (OutputRejected, error) {
	var o OutputRejected
	if err := CheckRecordPayload(RecOutputRejected, data); err != nil {
		return o, err
	}
	o.ResultID = wordAt(data, 0)
	r, _ := WordU64(wordAt(data, 1))
	o.Reason = uint8(r)
	o.MemberID, _ = WordU64(wordAt(data, 2))
	bm, _ := WordU64(wordAt(data, 3))
	o.ReadyBitmap = uint16(bm)
	switch {
	case o.ResultID == (Word{}):
		return o, fmt.Errorf("%w: zero result id", ErrRange)
	case o.Reason < RejExpired || o.Reason > RejInvalid:
		return o, fmt.Errorf("%w: reason %d", ErrRange, o.Reason)
	case o.MemberID != 0 && o.Reason != RejInvalid:
		return o, fmt.Errorf("%w: memberId outside Invalid", ErrRange)
	case o.ReadyBitmap != 0 && o.Reason != RejExpired:
		return o, fmt.Errorf("%w: readyBitmap outside Expired", ErrRange)
	}
	return o, nil
}

// HolderRetirement is record kind 8.
type HolderRetirement struct {
	Holder     uint8  `json:"holder"`
	ID         uint64 `json:"id"`
	Generation uint64 `json:"generation"`
	RefDigest  Word   `json:"-"`
}

// Encode is the 128-byte payload.
func (h HolderRetirement) Encode() []byte {
	return words(U64(uint64(h.Holder)), U64(h.ID), U64(h.Generation), h.RefDigest)
}

// DecodeHolderRetirement is the strict decoder: holder < MAX_HOLDERS.
func DecodeHolderRetirement(data []byte) (HolderRetirement, error) {
	var h HolderRetirement
	if err := CheckRecordPayload(RecHolderRetirement, data); err != nil {
		return h, err
	}
	x, _ := WordU64(wordAt(data, 0))
	if x >= MaxHolders {
		return h, fmt.Errorf("%w: holder %d", ErrRange, x)
	}
	h.Holder = uint8(x)
	h.ID, _ = WordU64(wordAt(data, 1))
	h.Generation, _ = WordU64(wordAt(data, 2))
	h.RefDigest = wordAt(data, 3)
	return h, nil
}
