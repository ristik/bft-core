package vrschema

import (
	"fmt"
	"strconv"
	"strings"
)

// A minimal strict ABI codec for the flat tuples the change payloads use: address, bool, bytes32, uintN (N <= 64), bytes and string.
// Encode produces the standard abi.encode bytes. DecodeABI accepts exactly those bytes and nothing else: every head offset must be the
// canonical one (dynamic tails in field order, each directly after the previous), narrow integers and padding must be zero, a string
// is any bytes (no UTF-8 rule) and the input must end exactly at the last tail.

func abiDynamic(t string) bool { return t == "bytes" || t == "string" }

func abiUintBits(t string) (int, bool) {
	if !strings.HasPrefix(t, "uint") {
		return 0, false
	}
	n, err := strconv.Atoi(t[4:])
	if err != nil || n < 8 || n > 64 || n%8 != 0 {
		return 0, false
	}
	return n, true
}

// EncodeABI is abi.encode(vals...) for the given flat field types. Values: [20]byte for address, bool, Word for bytes32, uint64 for
// every uintN, []byte for bytes and string for string.
func EncodeABI(types []string, vals []any) ([]byte, error) {
	if len(types) != len(vals) {
		return nil, fmt.Errorf("vrschema: %d types for %d values", len(types), len(vals))
	}
	head := make([]byte, 0, 32*len(types))
	var tail []byte
	for i, t := range types {
		if abiDynamic(t) {
			var b []byte
			switch x := vals[i].(type) {
			case []byte:
				b = x
			case string:
				b = []byte(x)
			default:
				return nil, fmt.Errorf("vrschema: field %d: %T for %s", i, vals[i], t)
			}
			off := U64(uint64(32*len(types) + len(tail)))
			head = append(head, off[:]...)
			l := U64(uint64(len(b)))
			tail = append(tail, l[:]...)
			tail = append(tail, b...)
			tail = append(tail, make([]byte, (32-len(b)%32)%32)...)
			continue
		}
		var w Word
		switch t {
		case "address":
			a, ok := vals[i].([20]byte)
			if !ok {
				return nil, fmt.Errorf("vrschema: field %d: %T for address", i, vals[i])
			}
			w = AddrWord(a)
		case "bool":
			b, ok := vals[i].(bool)
			if !ok {
				return nil, fmt.Errorf("vrschema: field %d: %T for bool", i, vals[i])
			}
			w = BoolWord(b)
		case "bytes32":
			x, ok := vals[i].(Word)
			if !ok {
				return nil, fmt.Errorf("vrschema: field %d: %T for bytes32", i, vals[i])
			}
			w = x
		default:
			bits, ok := abiUintBits(t)
			v, ok2 := vals[i].(uint64)
			if !ok || !ok2 || (bits < 64 && v>>uint(bits) != 0) {
				return nil, fmt.Errorf("vrschema: field %d: %v for %s", i, vals[i], t)
			}
			w = U64(v)
		}
		head = append(head, w[:]...)
	}
	return append(head, tail...), nil
}

// DecodeABI is the strict inverse of EncodeABI.
func DecodeABI(types []string, data []byte) ([]any, error) {
	n := len(types)
	if len(data) < 32*n || len(data)%32 != 0 {
		return nil, ErrLength
	}
	out := make([]any, n)
	next := 32 * n
	for i, t := range types {
		w := wordAt(data, i)
		if abiDynamic(t) {
			off, err := WordU64(w)
			if err != nil || off != uint64(next) {
				return nil, ErrOffset
			}
			if next+32 > len(data) {
				return nil, ErrLength
			}
			l, err := WordU64(wordAt(data[next:], 0))
			if err != nil || l > uint64(len(data)-next-32) {
				return nil, ErrLength
			}
			start := next + 32
			end := start + int(l)
			padded := start + (int(l)+31)/32*32
			if padded > len(data) {
				return nil, ErrLength
			}
			if !isZero(data[end:padded]) {
				return nil, ErrPadding
			}
			b := append([]byte(nil), data[start:end]...)
			if t == "string" {
				out[i] = string(b) // byte canonicality only: any bytes (Solidity does not validate UTF-8)
			} else {
				out[i] = b
			}
			next = padded
			continue
		}
		switch t {
		case "address":
			a, err := WordAddr(w)
			if err != nil {
				return nil, err
			}
			out[i] = a
		case "bool":
			b, err := WordBool(w)
			if err != nil {
				return nil, err
			}
			out[i] = b
		case "bytes32":
			out[i] = w
		default:
			bits, ok := abiUintBits(t)
			if !ok {
				return nil, fmt.Errorf("vrschema: type %s", t)
			}
			v, err := WordUint(w, bits)
			if err != nil {
				return nil, err
			}
			out[i] = v
		}
	}
	if next != len(data) {
		return nil, ErrLength
	}
	return out, nil
}
