package rsmt

import "crypto/sha256"

// LeafValue derives the value the aggregator's tree stores for a leaf inserted in a round: SHA-256(CBOR([transactionHash, referenceTime])),
// a two-element array of a byte string and an unsigned integer, both in the shortest (deterministic) head form.
//
// The envelope declares transaction hashes; the tree stores LeafValue(txHash, tau) with tau the round's reference time, which is
// InputRecord.Timestamp. The verifier derives the stored value rather than accepting a supplied one, so a shard that built its tree under
// another reference time produces a root this verifier does not reproduce.
//
// Matches `leaf_value` in crates/rsmt-verify/src/leaf_value.rs of rugregator (introduced in 7f566ea, shortest-form heads in 945d0cc; the
// pinned rugregator is dd5b1406a17fdeb415799045c5e81609619a870a). The shared test vector there is asserted in leafvalue_test.go.
func LeafValue(transactionHash []byte, referenceTime uint64) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x82}) // array(2)
	var head [9]byte
	h.Write(head[:cborHead(2, uint64(len(transactionHash)), &head)])
	h.Write(transactionHash)
	h.Write(head[:cborHead(0, referenceTime, &head)])
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// cborHead writes the shortest-form CBOR head of major type t and argument n into out and returns its length.
func cborHead(t byte, n uint64, out *[9]byte) int {
	major := t << 5
	switch {
	case n <= 23:
		out[0] = major | byte(n)
		return 1
	case n <= 0xff:
		out[0], out[1] = major|24, byte(n)
		return 2
	case n <= 0xffff:
		out[0], out[1], out[2] = major|25, byte(n>>8), byte(n)
		return 3
	case n <= 0xffffffff:
		out[0] = major | 26
		for i := 0; i < 4; i++ {
			out[1+i] = byte(n >> (24 - 8*i))
		}
		return 5
	default:
		out[0] = major | 27
		for i := 0; i < 8; i++ {
			out[1+i] = byte(n >> (56 - 8*i))
		}
		return 9
	}
}
