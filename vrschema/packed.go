package vrschema

import (
	"errors"
	"fmt"
)

// Module returns are ABI `bytes`: the 64-byte envelope (offset word = 32, length word = len(content)) followed by the content, which
// is always a whole number of words, so no padding follows. VRCodec decodes the raw returndata: it first refuses a size above the step's
// cap, then a bad envelope, then a content length other than the exact one, then non-canonical fields.

// CodecError is the frozen decoder verdict; vectors name it.
type CodecError string

const (
	CodecOK       CodecError = "OK"
	CodecOversize CodecError = "Oversize"
	CodecEnvelope CodecError = "Envelope"
	CodecLength   CodecError = "Length"
	CodecNarrow   CodecError = "Narrow"
	CodecBool     CodecError = "Bool"
	CodecRange    CodecError = "Range"
	CodecOrder    CodecError = "Order"
	CodecCount    CodecError = "Count"
	CodecZero     CodecError = "ResultIdZeroness"
	CodecPadding  CodecError = "Padding"
)

// Metadata getters return exact static ABI words (design section 3.2), never more than MaxRetMetadata = 32 x 8 bytes.
const MaxRetMetadata = 32 * 8

// MetadataWords are the exact word counts of the metadata getters.
var MetadataWords = map[string]int{"moduleTag": 1, "capabilities": 1, "gasBounds": 8, "maxElectionInterval": 1, "liabilityHolder": 2}

var (
	errCount = errors.New("vrschema: member count out of range or not the header's")
	errZero  = errors.New("vrschema: resultId zero-ness does not match the outcome")
)

// Classify maps a decoder error to its frozen code.
func Classify(err error) CodecError {
	switch {
	case err == nil:
		return CodecOK
	case errors.Is(err, ErrOversize):
		return CodecOversize
	case errors.Is(err, ErrEnvelope):
		return CodecEnvelope
	case errors.Is(err, ErrLength):
		return CodecLength
	case errors.Is(err, ErrNarrow):
		return CodecNarrow
	case errors.Is(err, ErrBool):
		return CodecBool
	case errors.Is(err, ErrRange):
		return CodecRange
	case errors.Is(err, ErrOrder):
		return CodecOrder
	case errors.Is(err, errCount):
		return CodecCount
	case errors.Is(err, errZero):
		return CodecZero
	case errors.Is(err, ErrPadding):
		return CodecPadding
	}
	return CodecError("Other:" + err.Error())
}

// Envelope wraps content as abi.encode(bytes content) for a whole-word content.
func Envelope(content []byte) []byte {
	off, l := U64(32), U64(uint64(len(content)))
	return append(append(append([]byte{}, off[:]...), l[:]...), content...)
}

func openEnvelope(ret []byte, cap int) ([]byte, error) {
	if len(ret) > cap {
		return nil, ErrOversize
	}
	if len(ret) < 64 || len(ret)%32 != 0 {
		return nil, ErrEnvelope
	}
	off, err1 := WordU64(wordAt(ret, 0))
	l, err2 := WordU64(wordAt(ret, 1))
	if err1 != nil || err2 != nil || off != 32 || l != uint64(len(ret)-64) {
		return nil, ErrEnvelope
	}
	return ret[64:], nil
}

// PackedElect is elect's packed return.
type PackedElect struct {
	Outcome  uint8 `json:"outcome"`
	Ready    bool  `json:"ready"`
	ResultID Word  `json:"-"`
}

// EncodeElect is the returndata of elect.
func EncodeElect(p PackedElect) []byte {
	return Envelope(words(U64(uint64(p.Outcome)), BoolWord(p.Ready), p.ResultID))
}

// DecodeElect: exactly 64 + 96 bytes; outcome 0..3; ready a canonical bool and set only with Reserved; resultId nonzero iff Reserved.
func DecodeElect(ret []byte) (PackedElect, error) {
	var p PackedElect
	c, err := openEnvelope(ret, MaxRetElect)
	if err != nil {
		return p, err
	}
	if len(c) != 96 {
		return p, ErrLength
	}
	o, err := WordUint(wordAt(c, 0), 8)
	if err != nil {
		return p, err
	}
	if o > uint64(ElectNoCandidate) {
		return p, fmt.Errorf("%w: outcome %d", ErrRange, o)
	}
	if p.Ready, err = WordBool(wordAt(c, 1)); err != nil {
		return p, err
	}
	p.Outcome, p.ResultID = uint8(o), wordAt(c, 2)
	reserved := p.Outcome == ElectReserved
	if reserved != (p.ResultID != Word{}) {
		return p, errZero
	}
	if p.Ready && !reserved {
		return p, fmt.Errorf("%w: ready without a reservation", ErrRange)
	}
	return p, nil
}

// OutputHeader is the Ready header of packedOutput.
type OutputHeader struct {
	ResultID       Word   `json:"-"`
	Predecessor    Word   `json:"-"`
	Attempt        uint64 `json:"attempt"`
	SnapshotDigest Word   `json:"-"`
	PolicyDigest   Word   `json:"-"`
}

// PackedOutput is outputOf's packed return.
type PackedOutput struct {
	Status  uint8
	Header  OutputHeader
	Members []Member
}

// EncodeOutput is the returndata of outputOf. A Pending or NotMine output is the status word only.
func EncodeOutput(p PackedOutput) []byte {
	c := words(U64(uint64(p.Status)))
	if p.Status == StatusReady {
		c = append(c, words(p.Header.ResultID, p.Header.Predecessor, U64(p.Header.Attempt), p.Header.SnapshotDigest, p.Header.PolicyDigest,
			U64(uint64(len(p.Members))))...)
		for _, m := range p.Members {
			c = append(c, m.Words()...)
		}
	}
	return Envelope(c)
}

// DecodeOutput decodes outputOf's returndata: Ready is exactly 64 + 32 + 192 + 320n with 1 <= n <= 16 equal to the header's count and
// strictly ascending ids; Pending and NotMine are exactly 64 + 32; NotReady is not an outputOf status.
func DecodeOutputReturn(ret []byte) (PackedOutput, error) {
	var p PackedOutput
	c, err := openEnvelope(ret, MaxRetReady)
	if err != nil {
		return p, err
	}
	if len(c) < 32 {
		return p, ErrLength
	}
	s, err := WordUint(wordAt(c, 0), 8)
	if err != nil {
		return p, err
	}
	if s > uint64(StatusNotMine) {
		return p, fmt.Errorf("%w: status %d", ErrRange, s)
	}
	p.Status = uint8(s)
	if p.Status != StatusReady {
		if len(ret) > MaxRetPending || len(c) != 32 {
			return p, ErrLength
		}
		return p, nil
	}
	if len(c) < 32+192 || (len(c)-224)%320 != 0 {
		return p, ErrLength
	}
	n, err := WordU64(wordAt(c, 6))
	if err != nil {
		return p, err
	}
	if n < 1 || n > MaxCommittee || int(n) != (len(c)-224)/320 {
		return p, errCount
	}
	p.Header.ResultID, p.Header.Predecessor, p.Header.SnapshotDigest, p.Header.PolicyDigest = wordAt(c, 1), wordAt(c, 2), wordAt(c, 4), wordAt(c, 5)
	if p.Header.Attempt, err = WordU64(wordAt(c, 3)); err != nil {
		return p, err
	}
	for i := 0; i < int(n); i++ {
		m, err := DecodeMember(c[224+320*i : 224+320*(i+1)])
		if err != nil {
			return p, err
		}
		if i > 0 && p.Members[i-1].ID >= m.ID {
			return p, ErrOrder
		}
		p.Members = append(p.Members, m)
	}
	return p, nil
}

// EncodeAdoption is adoptionReady's returndata.
func EncodeAdoption(status uint8) []byte { return Envelope(words(U64(uint64(status)))) }

// DecodeAdoption: exactly 64 + 32, status Ready or NotReady.
func DecodeAdoption(ret []byte) (uint8, error) {
	c, err := openEnvelope(ret, MaxRetAdoption)
	if err != nil {
		return 0, err
	}
	if len(c) != 32 {
		return 0, ErrLength
	}
	s, err := WordUint(wordAt(c, 0), 8)
	if err != nil {
		return 0, err
	}
	if s != uint64(StatusReady) && s != uint64(StatusNotReady) {
		return 0, fmt.Errorf("%w: adoption status %d", ErrRange, s)
	}
	return uint8(s), nil
}

// DecodeVoid: a void step returns exactly nothing.
func DecodeVoid(ret []byte) error {
	if len(ret) != 0 {
		return ErrOversize
	}
	return nil
}

// DecodeMetadataWords: a metadata getter returns exactly k static words; each narrow field is checked by its caller's widths.
func DecodeMetadataWords(ret []byte, k int, bits []int) ([]uint64, error) {
	if len(ret) > MaxRetMetadata {
		return nil, ErrOversize
	}
	if len(ret) != 32*k {
		return nil, ErrLength
	}
	out := make([]uint64, 0, k)
	for i := 0; i < k; i++ {
		if bits[i] == 256 {
			out = append(out, 0)
			continue
		}
		v, err := WordUint(wordAt(ret, i), bits[i])
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// Context is the 8-word elect argument.
type Context struct {
	Origin         Word
	Progress       uint64
	UCTime         uint64
	KnownRootEpoch uint64
	LastAcked      Word
	Limits         CommitteeLimits
	DueWork        uint32
	ForceRemoved   uint16 // bit i: committee()[i] (ascending id) has a Scheduled ForceRemove
}

// LimitsWord is nMin << 64 | nTarget << 32 | nMax.
func (l CommitteeLimits) LimitsWord() Word {
	var w Word
	put := func(v uint32, at int) {
		w[at], w[at+1], w[at+2], w[at+3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
	}
	put(l.NMin, 20)
	put(l.NTarget, 24)
	put(l.NMax, 28)
	return w
}

// Encode is the 256-byte context, passed as ABI bytes.
func (c Context) Encode() []byte {
	return words(c.Origin, U64(c.Progress), U64(c.UCTime), U64(c.KnownRootEpoch), c.LastAcked, c.Limits.LimitsWord(), U64(uint64(c.DueWork)),
		U64(uint64(c.ForceRemoved)))
}

// DecodeContext is the module-side strict decoder.
func DecodeContext(b []byte) (Context, error) {
	var c Context
	if len(b) != 256 {
		return c, ErrLength
	}
	var err error
	c.Origin, c.LastAcked = wordAt(b, 0), wordAt(b, 4)
	for i, p := range []*uint64{&c.Progress, &c.UCTime, &c.KnownRootEpoch} {
		if *p, err = WordU64(wordAt(b, i+1)); err != nil {
			return c, err
		}
	}
	lw := wordAt(b, 5)
	if !isZero(lw[:20]) {
		return c, ErrNarrow
	}
	get := func(at int) uint32 {
		return uint32(lw[at])<<24 | uint32(lw[at+1])<<16 | uint32(lw[at+2])<<8 | uint32(lw[at+3])
	}
	c.Limits = CommitteeLimits{get(20), get(24), get(28)}
	d, err := WordUint(wordAt(b, 6), 32)
	if err != nil {
		return c, err
	}
	f, err := WordUint(wordAt(b, 7), 16)
	if err != nil {
		return c, err
	}
	c.DueWork, c.ForceRemoved = uint32(d), uint16(f)
	return c, nil
}

// AttachContext is the attach and adoptionReady argument.
type AttachContext struct {
	LastAcked      Word
	KnownRootEpoch uint64
	Progress       uint64
	UCTime         uint64
	IdentityCount  uint64
	Namespace      [20]byte // liabilityNamespace = VR
	PrevModule     [20]byte
	PrevTag        Word
	HolderIndex    uint8 // 0xff when the module is not a liability holder
	Committee      []Member
	InitData       []byte
}

// AttachContextVersion is word0 of the attach context.
const AttachContextVersion = 1

// NoHolder is HolderIndex for a module without LIABILITY_HOLDER.
const NoHolder = 0xff

// Encode is the attach context: 12 header words, then n x 10 member words, then initData zero-padded to a word.
func (a AttachContext) Encode() ([]byte, error) {
	if len(a.Committee) < 1 || len(a.Committee) > MaxCommittee || len(a.InitData) > MaxChangePayload {
		return nil, ErrRange
	}
	b := words(U64(AttachContextVersion), a.LastAcked, U64(a.KnownRootEpoch), U64(a.Progress), U64(a.UCTime), U64(a.IdentityCount),
		AddrWord(a.Namespace), AddrWord(a.PrevModule), a.PrevTag, U64(uint64(a.HolderIndex)), U64(uint64(len(a.Committee))), U64(uint64(len(a.InitData))))
	for i, m := range a.Committee {
		if i > 0 && a.Committee[i-1].ID >= m.ID {
			return nil, ErrOrder
		}
		b = append(b, m.Words()...)
	}
	b = append(b, a.InitData...)
	return append(b, make([]byte, (32-len(a.InitData)%32)%32)...), nil
}

// DecodeAttachContext is the module-side strict decoder.
func DecodeAttachContext(b []byte) (AttachContext, error) {
	var a AttachContext
	if len(b) < 12*32 || len(b)%32 != 0 {
		return a, ErrLength
	}
	v, err := WordU64(wordAt(b, 0))
	if err != nil || v != AttachContextVersion {
		return a, fmt.Errorf("%w: attach context version", ErrRange)
	}
	a.LastAcked, a.PrevTag = wordAt(b, 1), wordAt(b, 8)
	for i, p := range []*uint64{&a.KnownRootEpoch, &a.Progress, &a.UCTime, &a.IdentityCount} {
		if *p, err = WordU64(wordAt(b, i+2)); err != nil {
			return a, err
		}
	}
	if a.Namespace, err = WordAddr(wordAt(b, 6)); err != nil {
		return a, err
	}
	if a.PrevModule, err = WordAddr(wordAt(b, 7)); err != nil {
		return a, err
	}
	h, err := WordUint(wordAt(b, 9), 8)
	if err != nil {
		return a, err
	}
	if h >= MaxHolders && h != NoHolder {
		return a, fmt.Errorf("%w: holder index", ErrRange)
	}
	a.HolderIndex = uint8(h)
	n, err := WordU64(wordAt(b, 10))
	if err != nil || n < 1 || n > MaxCommittee {
		return a, errCount
	}
	l, err := WordU64(wordAt(b, 11))
	if err != nil || l > MaxChangePayload {
		return a, ErrOversize
	}
	want := 12*32 + int(n)*320 + (int(l)+31)/32*32
	if len(b) != want {
		return a, ErrLength
	}
	for i := 0; i < int(n); i++ {
		m, err := DecodeMember(b[384+320*i : 384+320*(i+1)])
		if err != nil {
			return a, err
		}
		if i > 0 && a.Committee[i-1].ID >= m.ID {
			return a, ErrOrder
		}
		a.Committee = append(a.Committee, m)
	}
	start := 384 + int(n)*320
	a.InitData = append([]byte(nil), b[start:start+int(l)]...)
	if !isZero(b[start+int(l):]) {
		return a, ErrPadding
	}
	return a, nil
}
