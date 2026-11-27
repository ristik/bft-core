package nb2ref

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
)

const (
	FlatWireVersion   = 0x0101
	FlatProtocol      = 10
	FlatStateBytes    = 290
	FlatPageBytes     = 4096
	FlatMaxPages      = 32
	FlatMaxOperations = 16
	FlatMaxCalldata   = 393216
	FlatMaxReceipt    = 65536
	FlatMaxGaps       = 1024
	FlatMaxPair       = 40960
	FlatMaxRootMint   = 66048
	FlatMaxChildMint  = 512
	FlatMaxAllocation = 20480
	flatPreludeBytes  = 14
)

var (
	ErrFlatPacket      = errors.New("nb2 flat: BadPacket")
	ErrFlatPredecessor = errors.New("nb2 flat: BadPredecessor")
	ErrFlatPage        = errors.New("nb2 flat: BadPage")
	ErrFlatStep        = errors.New("nb2 flat: BadStep")
)

type FlatEntry uint8

const (
	FlatRun FlatEntry = iota + 1
	FlatAdvanceGaps
	FlatRedeemRecovered
)

func (e FlatEntry) Selector() [4]byte {
	var signature string
	switch e {
	case FlatRun:
		signature = "run(bytes)"
	case FlatAdvanceGaps:
		signature = "advanceGaps(bytes)"
	case FlatRedeemRecovered:
		signature = "redeemRecovered(bytes)"
	default:
		return [4]byte{}
	}
	h := HE([]byte(signature))
	return [4]byte(h[:4])
}

func (e FlatEntry) Calldata(packet []byte) ([]byte, error) {
	if e < FlatRun || e > FlatRedeemRecovered || len(packet) > FlatMaxCalldata-68 || (len(packet)+31)&^31 > FlatMaxCalldata-68 {
		return nil, ErrFlatPacket
	}
	sel := e.Selector()
	out := make([]byte, 68+(len(packet)+31)&^31)
	copy(out, sel[:])
	out[35] = 32
	binary.BigEndian.PutUint64(out[60:68], uint64(len(packet)))
	copy(out[68:], packet)
	return out, nil
}

// DecodeCalldata returns an alias only after checking the exact canonical ABI.
func (e FlatEntry) DecodeCalldata(data []byte) ([]byte, error) {
	sel := e.Selector()
	if e < FlatRun || e > FlatRedeemRecovered || len(data) < 68 || len(data) > FlatMaxCalldata ||
		[4]byte(data[:4]) != sel || !zeroFlat(data[4:35]) || data[35] != 32 || !zeroFlat(data[36:60]) {
		return nil, ErrFlatPacket
	}
	n := binary.BigEndian.Uint64(data[60:68])
	if n > uint64(len(data)-68) || (n+31)&^31 != uint64(len(data)-68) || !zeroFlat(data[68+n:]) {
		return nil, ErrFlatPacket
	}
	return data[68 : 68+n], nil
}

func zeroFlat(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

// FlatHash is the protocol 10 continuation commitment.
func FlatHash(label string, fields ...[]byte) [32]byte {
	tag := HE([]byte("UNICITY/NB2/CONT/1.1/" + label))
	return HE(append([][]byte{tag[:]}, fields...)...)
}

func flatU16(n uint16) []byte { return binary.BigEndian.AppendUint16(nil, n) }
func flatU32(n uint32) []byte { return binary.BigEndian.AppendUint32(nil, n) }
func flatU64(n uint64) []byte { return binary.BigEndian.AppendUint64(nil, n) }

type FlatHeader struct {
	Length uint64
	Root   [32]byte
}

func (h FlatHeader) appendTo(out []byte) []byte {
	out = binary.BigEndian.AppendUint16(out, FlatWireVersion)
	out = binary.BigEndian.AppendUint64(out, h.Length)
	return append(out, h.Root[:]...)
}

type FlatOpcode uint8

const (
	FlatRootMint FlatOpcode = iota + 1
	FlatChildMint
	FlatTransfer
)

type FlatState struct {
	Phase                               FlatOpcode
	Seq, Pos, LevelsLeft, TransfersLeft uint64
	SeenRoot, ClaimRoot                 [32]byte
	Owner                               [33]byte
	State, TokenID, Amount              [32]byte
	ParentLink, ParentManifest          [32]byte
}

func (s FlatState) Bytes() []byte {
	out := make([]byte, 0, FlatStateBytes)
	out = append(out, byte(s.Phase))
	for _, n := range [...]uint64{s.Seq, s.Pos, s.LevelsLeft, s.TransfersLeft} {
		out = binary.BigEndian.AppendUint64(out, n)
	}
	out = append(out, s.SeenRoot[:]...)
	out = append(out, s.ClaimRoot[:]...)
	out = append(out, s.Owner[:]...)
	for _, h := range [...][32]byte{s.State, s.TokenID, s.Amount, s.ParentLink, s.ParentManifest} {
		out = append(out, h[:]...)
	}
	return out
}

func (s FlatState) Digest(session [32]byte) [32]byte {
	return FlatHash("STATE", session[:], s.Bytes())
}

func DecodeFlatState(raw []byte) (FlatState, error) {
	if len(raw) != FlatStateBytes {
		return FlatState{}, ErrFlatPacket
	}
	r := flatReader{raw: raw}
	s := FlatState{
		Phase: FlatOpcode(r.u8()), Seq: r.u64(), Pos: r.u64(),
		LevelsLeft: r.u64(), TransfersLeft: r.u64(), SeenRoot: r.hash(), ClaimRoot: r.hash(),
	}
	copy(s.Owner[:], r.take(33))
	s.State, s.TokenID, s.Amount, s.ParentLink, s.ParentManifest = r.hash(), r.hash(), r.hash(), r.hash(), r.hash()
	return s, r.err
}

type flatReader struct {
	raw []byte
	err error
}

func (r *flatReader) take(n int) []byte {
	if r.err != nil || n < 0 || n > len(r.raw) {
		r.err = ErrFlatPacket
		return nil
	}
	out := r.raw[:n]
	r.raw = r.raw[n:]
	return out
}

func (r *flatReader) u8() uint8 {
	if b := r.take(1); b != nil {
		return b[0]
	}
	return 0
}
func (r *flatReader) u16() uint16 {
	if b := r.take(2); b != nil {
		return binary.BigEndian.Uint16(b)
	}
	return 0
}
func (r *flatReader) u64() uint64 {
	if b := r.take(8); b != nil {
		return binary.BigEndian.Uint64(b)
	}
	return 0
}
func (r *flatReader) hash() (h [32]byte) { copy(h[:], r.take(32)); return h }

func (r *flatReader) blob(max int) []byte {
	b := r.take(4)
	if b == nil {
		return nil
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(max) {
		r.err = ErrFlatPacket
		return nil
	}
	return r.take(int(n))
}
func (r *flatReader) done() bool { return r.err == nil && len(r.raw) == 0 }

func (r *flatReader) header() FlatHeader {
	v := r.u16()
	h := FlatHeader{Length: r.u64(), Root: r.hash()}
	if v != FlatWireVersion || h.Length < flatPreludeBytes {
		r.err = ErrFlatPacket
	}
	return h
}

func flatBlob(out, data []byte) []byte {
	out = binary.BigEndian.AppendUint32(out, uint32(len(data)))
	return append(out, data...)
}

// FlatDeployment holds the already authenticated generation dependencies.
// Registry is an authenticated, stable view for each oracle invocation.
type FlatDeployment struct {
	Salt, Pins, Runtime [32]byte
	Recovery            [20]byte
}

func (d FlatDeployment) Session(c *Config, domain [32]byte, h FlatHeader) [32]byte {
	generation := FlatHash("GEN", d.Salt[:], domain[:])
	return FlatHash("SESSION", flatU16(FlatWireVersion), generation[:], domain[:],
		c.Vault[:], d.Recovery[:], d.Runtime[:], d.Pins[:], flatU64(h.Length), h.Root[:])
}

type FlatPin struct {
	Role    uint16
	Address [20]byte
	Digest  [32]byte
}

func FlatRelease(descriptors [6][]byte) [32]byte {
	fields := make([]byte, 0, 192)
	for _, descriptor := range descriptors {
		h := HU(descriptor)
		fields = append(fields, h[:]...)
	}
	return FlatHash("RELEASE", fields)
}

func FlatPins(release [32]byte, pins []FlatPin) ([32]byte, error) {
	if len(pins) < 5 || len(pins) > math.MaxUint16-250 {
		return [32]byte{}, ErrFlatPacket
	}
	fields := binary.BigEndian.AppendUint16(nil, uint16(len(pins)))
	addresses := make(map[[20]byte]bool, len(pins))
	for i, p := range pins {
		role := i + 1
		if i >= 5 {
			role = i + 251
		}
		if int(p.Role) != role || p.Address == ([20]byte{}) || addresses[p.Address] ||
			(i > 5 && bytes.Compare(pins[i-1].Address[:], p.Address[:]) >= 0) {
			return [32]byte{}, ErrFlatPacket
		}
		switch role {
		case 3:
			if p.Address != ([20]byte{18: 1}) {
				return [32]byte{}, ErrFlatPacket
			}
		case 4:
			if p.Address != ([20]byte{18: 1, 19: 2}) {
				return [32]byte{}, ErrFlatPacket
			}
		}
		addresses[p.Address] = true
		fields = binary.BigEndian.AppendUint16(fields, p.Role)
		fields = append(fields, p.Address[:]...)
		fields = append(fields, p.Digest[:]...)
	}
	return FlatHash("PINS", release[:], fields), nil
}
