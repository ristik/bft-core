package vrschema

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// Word is one 32-byte EVM word, big-endian.
type Word = [32]byte

// Error codes shared by every strict decoder. A decoder never panics and never accepts a second encoding of the same value.
var (
	ErrLength      = errors.New("vrschema: wrong length")
	ErrEnvelope    = errors.New("vrschema: malformed ABI bytes envelope")
	ErrNarrow      = errors.New("vrschema: non-canonical narrow field (nonzero high bytes)")
	ErrBool        = errors.New("vrschema: non-canonical bool")
	ErrReserved    = errors.New("vrschema: nonzero reserved bits")
	ErrRange       = errors.New("vrschema: value out of range")
	ErrOrder       = errors.New("vrschema: not strictly ascending")
	ErrOversize    = errors.New("vrschema: oversize")
	ErrOffset      = errors.New("vrschema: non-canonical ABI offset")
	ErrPadding     = errors.New("vrschema: nonzero ABI padding")
	ErrUnknownKind = errors.New("vrschema: unknown kind")
	ErrCanonical   = errors.New("vrschema: non-canonical encoding")
)

func keccak(parts ...[]byte) (out Word) {
	copy(out[:], ethcrypto.Keccak256(parts...))
	return out
}

// Keccak is keccak256 over the concatenation of parts.
func Keccak(parts ...[]byte) Word { return keccak(parts...) }

// DomainWord is keccak256 of a domain text, the first ABI word of every EVM-side digest.
func DomainWord(text string) Word { return keccak([]byte(text)) }

// U64 is a uint64 as a big-endian word.
func U64(v uint64) Word {
	var w Word
	for i := 0; i < 8; i++ {
		w[31-i] = byte(v >> (8 * i))
	}
	return w
}

// AddrWord is an address left-padded to a word.
func AddrWord(a [20]byte) Word {
	var w Word
	copy(w[12:], a[:])
	return w
}

// BoolWord is a canonical bool word.
func BoolWord(b bool) Word {
	if b {
		return U64(1)
	}
	return Word{}
}

// WordU64 reads a uint64 word and refuses nonzero high bytes.
func WordU64(w Word) (uint64, error) {
	if !isZero(w[:24]) {
		return 0, ErrNarrow
	}
	var v uint64
	for i := 24; i < 32; i++ {
		v = v<<8 | uint64(w[i])
	}
	return v, nil
}

// WordUint reads an unsigned integer of `bits` width (8..64) from a word.
func WordUint(w Word, bits int) (uint64, error) {
	v, err := WordU64(w)
	if err != nil {
		return 0, err
	}
	if bits < 64 && v>>uint(bits) != 0 {
		return 0, ErrNarrow
	}
	return v, nil
}

// WordAddr reads an address word.
func WordAddr(w Word) ([20]byte, error) {
	var a [20]byte
	if !isZero(w[:12]) {
		return a, ErrNarrow
	}
	copy(a[:], w[12:])
	return a, nil
}

// WordBool reads a canonical bool word.
func WordBool(w Word) (bool, error) {
	v, err := WordU64(w)
	if err != nil || v > 1 {
		return false, ErrBool
	}
	return v == 1, nil
}

func isZero(b []byte) bool { return bytes.Equal(b, make([]byte, len(b))) }

func words(ws ...Word) []byte {
	out := make([]byte, 0, 32*len(ws))
	for _, w := range ws {
		out = append(out, w[:]...)
	}
	return out
}

func wordAt(b []byte, i int) (w Word) {
	copy(w[:], b[32*i:32*i+32])
	return w
}

// ---- packed storage words (fields packed from the low-order byte, Solidity's struct packing) ----

// Field is one packed field of a storage word: Offset bytes from the low-order end, Size bytes wide.
type Field struct {
	Name   string `json:"name"`
	Offset int    `json:"offset"`
	Size   int    `json:"size"`
	Kind   string `json:"kind"` // "uint", "bool", "address"
}

// PackedWord is the layout of one packed storage word; every byte outside the fields is reserved and must be zero.
type PackedWord []Field

// Pack writes the field values (uint64 for uint/bool, the low 20 bytes of an address passed as [20]byte) into a word.
func (p PackedWord) Pack(vals map[string]any) (Word, error) {
	var w Word
	for _, f := range p {
		v, ok := vals[f.Name]
		if !ok {
			continue
		}
		var raw []byte
		switch x := v.(type) {
		case uint64:
			if f.Kind == "bool" && x > 1 {
				return w, ErrBool
			}
			if f.Size < 8 && x>>(8*uint(f.Size)) != 0 {
				return w, ErrRange
			}
			b := U64(x)
			raw = b[32-f.Size:]
		case [20]byte:
			raw = x[:]
		case bool:
			if x {
				raw = []byte{1}
			} else {
				raw = []byte{0}
			}
		default:
			return w, fmt.Errorf("vrschema: field %s: unsupported value %T", f.Name, v)
		}
		copy(w[32-f.Offset-f.Size:32-f.Offset], raw)
	}
	return w, nil
}

// Unpack reads every field, refusing nonzero reserved bytes and non-canonical bools. uint and bool fields are returned as uint64, an
// address as [20]byte.
func (p PackedWord) Unpack(w Word) (map[string]any, error) {
	used := make([]bool, 32)
	out := make(map[string]any, len(p))
	for _, f := range p {
		seg := w[32-f.Offset-f.Size : 32-f.Offset]
		for i := 32 - f.Offset - f.Size; i < 32-f.Offset; i++ {
			used[i] = true
		}
		switch f.Kind {
		case "address":
			var a [20]byte
			copy(a[:], seg)
			out[f.Name] = a
		default:
			var v uint64
			for _, b := range seg {
				v = v<<8 | uint64(b)
			}
			if f.Kind == "bool" && v > 1 {
				return nil, fmt.Errorf("%w: %s", ErrBool, f.Name)
			}
			out[f.Name] = v
		}
	}
	for i, u := range used {
		if !u && w[i] != 0 {
			return nil, fmt.Errorf("%w: byte %d from the low end", ErrReserved, 31-i)
		}
	}
	return out, nil
}

// ---- slot arithmetic ----

// Erc7201 is keccak256(abi.encode(uint256(keccak256(id)) - 1)) & ~bytes32(uint256(0xff)).
func Erc7201(id string) Word {
	h := new(big.Int).SetBytes(ethcrypto.Keccak256([]byte(id)))
	h.Sub(h, big.NewInt(1))
	var w Word
	h.FillBytes(w[:])
	out := keccak(w[:])
	out[31] = 0
	return out
}

// SlotAdd is base + k as a 256-bit integer (mod 2^256).
func SlotAdd(base Word, k uint64) Word {
	x := new(big.Int).SetBytes(base[:])
	x.Add(x, new(big.Int).SetUint64(k))
	x.Mod(x, new(big.Int).Lsh(big.NewInt(1), 256))
	var w Word
	x.FillBytes(w[:])
	return w
}

// MapSlot is the Solidity mapping slot keccak256(abi.encode(key, base)) for a key already encoded as a word.
func MapSlot(key Word, base Word) Word { return keccak(key[:], base[:]) }

// BytesDataSlot is the first data slot keccak256(slot) of a long Solidity bytes value stored at slot.
func BytesDataSlot(slot Word) Word { return keccak(slot[:]) }
