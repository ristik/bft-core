package b1ref

import (
	"bytes"
	"math/bits"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier/rsmt"
)

// Member evaluates an RSMT_MEMBER_V1 input:
// header | root[32] | key[32] | valueLength:u32 | value | bitmap[32] | siblings[32*popcount].
// It proves inclusion of (key, value) under the supplied root and says nothing
// about whether that root is certified.
func Member(in []byte) (Verdict, error) {
	if len(in) > MaxRSMTInputBytes {
		return Verdict{}, ErrInputTooLarge
	}
	count, err := header(in)
	if err != nil {
		return Verdict{}, err
	}
	if count != 1 {
		return Verdict{}, ErrCount
	}
	r := &reader{b: in, pos: 4}
	var root, key, bitmap [32]byte
	for _, dst := range []*[32]byte{&root, &key} {
		b, err := r.take(32)
		if err != nil {
			return Verdict{}, err
		}
		copy(dst[:], b)
	}
	valueLen, err := r.u32()
	if err != nil {
		return Verdict{}, err
	}
	if valueLen > MaxRSMTValueBytes {
		return Verdict{}, ErrValueTooLarge
	}
	value, err := r.take(valueLen)
	if err != nil {
		return Verdict{}, err
	}
	b, err := r.take(32)
	if err != nil {
		return Verdict{}, err
	}
	copy(bitmap[:], b)
	pop := 0
	for _, x := range bitmap {
		pop += bits.OnesCount8(x)
	}
	if r.left() != uint64(pop)*32 {
		return Verdict{}, ErrRSMTLength
	}
	siblings := make([][32]byte, pop)
	for i := range siblings {
		copy(siblings[i][:], in[r.pos+32*i:])
	}

	v := Verdict{Gas: RSMTGas(uint64(len(in)), uint64(pop))}
	switch {
	case root == [32]byte{}:
		v.Why = ErrRSMTZeroRoot
	case !bytes.Equal(foldMember(key, value, bitmap, siblings), root[:]):
		v.Why = ErrRSMTFold
	default:
		v.Valid = true
	}
	return v, nil
}

// foldMember folds the leaf hash back to the root: siblings are root-to-leaf
// and consumed in reverse; bitmap bit d is MSB-first.
func foldMember(key [32]byte, value []byte, bitmap [32]byte, siblings [][32]byte) []byte {
	h := rsmt.HashLeaf(key, value)
	idx := len(siblings)
	for d := 255; d >= 0; d-- {
		if bitmap[d/8]&(0x80>>uint(d%8)) == 0 {
			continue
		}
		idx--
		sib := siblings[idx]
		region := rsmt.PrefixRegion(key, d)
		if rsmt.KeyBitAt(key, d) == 1 {
			h = rsmt.HashNode(sib, h, uint8(d), region)
		} else {
			h = rsmt.HashNode(h, sib, uint8(d), region)
		}
	}
	return h[:]
}
