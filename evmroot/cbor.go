package evmroot

// A minimal, self-contained deterministic CBOR encoder (RFC 8949 §4.2.1
// core deterministic encoding) covering exactly the value kinds the D1
// canonical root-input profile needs: unsigned integers, byte strings, text
// strings and definite-length arrays.
//
// It is written from scratch here, deliberately *not* reusing
// bft-go-base's CBOR library, so this package is an independent second
// implementation of the encoding the profile pins — the acceptance
// contract for D1 asks for exactly that: "a small independent vector
// generator covering domain and hash distinctions". A byte-for-byte match
// between vectors generated here and vectors produced by any consumer that
// reuses the consensus code's CBOR is evidence the encoding is genuinely
// canonical and not an artifact of one library's defaults.
//
// Rules enforced:
//   - definite lengths only;
//   - integers in the shortest form that holds the value;
//   - no floats, no maps, no tags, no indefinite strings, no negative ints
//     (the profile has no field that needs them; adding one is a versioned
//     change, not a silent extension).

import "math"

// cborItem is one value that can be appended to a deterministic CBOR
// stream.
type cborItem interface{ encode(dst []byte) []byte }

// cUint is a CBOR unsigned integer (major type 0).
type cUint uint64

// cBytes is a CBOR byte string (major type 2).
type cBytes []byte

// cText is a CBOR text string (major type 3). The profile's domain strings
// (UNICITY_EVM_RANDAO, UNICITY_EVM_BEACON) are ASCII; UTF-8 validity is the
// caller's responsibility.
type cText string

// cArray is a CBOR definite-length array (major type 4).
type cArray []cborItem

// cNull is the CBOR simple value `null` (0xf6). The profile uses it for a
// genuinely absent optional field — an absent block hash on a quiet round
// (h_b = ⊥), an absent parent hash at genesis — never for a present but
// zero-length value. This matches the bft-go-base convention that nil
// serialises as CBOR null, not as an empty byte string.
type cNull struct{}

func (cNull) encode(dst []byte) []byte { return append(dst, 0xf6) }

// optBytes encodes b as a CBOR byte string, or as null when b is empty —
// the one place the profile allows "no value" rather than a fixed-width
// digest.
func optBytes(b []byte) cborItem {
	if len(b) == 0 {
		return cNull{}
	}
	return cBytes(b)
}

func appendHead(dst []byte, major byte, arg uint64) []byte {
	m := major << 5
	switch {
	case arg < 24:
		return append(dst, m|byte(arg))
	case arg <= math.MaxUint8:
		return append(dst, m|24, byte(arg))
	case arg <= math.MaxUint16:
		return append(dst, m|25, byte(arg>>8), byte(arg))
	case arg <= math.MaxUint32:
		return append(dst, m|26, byte(arg>>24), byte(arg>>16), byte(arg>>8), byte(arg))
	default:
		return append(dst, m|27,
			byte(arg>>56), byte(arg>>48), byte(arg>>40), byte(arg>>32),
			byte(arg>>24), byte(arg>>16), byte(arg>>8), byte(arg))
	}
}

func (v cUint) encode(dst []byte) []byte { return appendHead(dst, 0, uint64(v)) }

func (v cBytes) encode(dst []byte) []byte {
	dst = appendHead(dst, 2, uint64(len(v)))
	return append(dst, v...)
}

func (v cText) encode(dst []byte) []byte {
	dst = appendHead(dst, 3, uint64(len(v)))
	return append(dst, v...)
}

func (v cArray) encode(dst []byte) []byte {
	dst = appendHead(dst, 4, uint64(len(v)))
	for _, it := range v {
		dst = it.encode(dst)
	}
	return dst
}

// marshalCBOR encodes one item to a fresh slice.
func marshalCBOR(it cborItem) []byte { return it.encode(nil) }
