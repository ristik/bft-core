package evmstate

// Strict Ethereum Merkle-Patricia proof verification for the state witness, moved verbatim from bridgeprofile (mpt.go, mpt_entry.go,
// rlp.go) when the protocol 6/7 bridge was removed (bft-core#1106). Only the package and the error sentinels changed.

import (
	"bytes"
	"errors"

	"github.com/ethereum/go-ethereum/core/types"
)

// maxRLPDepth bounds the nesting of a decoded RLP item (bridgeprofile MaxRLPDepth).
const maxRLPDepth = 16

var (
	errMPTNode       = errors.New("evmstate: MPT node is noncanonical, mis-hashed or out of order")
	errMPTPath       = errors.New("evmstate: MPT path is not fully consumed by exactly the supplied nodes")
	errMPTAbsent     = errors.New("evmstate: MPT key is absent")
	errMPTExtraneous = errors.New("evmstate: MPT proof carries a duplicate or extraneous node")
	errRLP           = errors.New("evmstate: noncanonical or malformed RLP")
)

// verifyMPTEntry verifies a strict Ethereum Merkle-Patricia proof that key (the 32-byte hashed path) holds a value under root, or holds
// none. The supplied nodes are exactly the root-to-leaf (or root-to-divergence) path: a duplicate, unused or out-of-order node is
// refused for an exclusion proof as for an inclusion proof. It returns the stored value and present=true, or present=false for a key the
// trie provably does not hold (an empty trie needs no nodes). Other mismatches are errors.
func verifyMPTEntry(root [32]byte, key [32]byte, nodes [][]byte) (value []byte, present bool, err error) {
	if root == [32]byte(types.EmptyRootHash) {
		if len(nodes) != 0 {
			return nil, false, errMPTExtraneous
		}
		return nil, false, nil
	}
	v, used, err := mptWalk(root, key, nodes)
	switch err {
	case nil:
		return v, true, nil
	case errMPTAbsent:
		if used != len(nodes) {
			return nil, false, errMPTExtraneous
		}
		return nil, false, nil
	}
	return nil, false, err
}

// Strict Ethereum Merkle-Patricia trie inclusion verification. The supplied
// nodes are exactly the root-to-leaf path, in order: each hash reference
// consumes the next node, embedded nodes consume none, the key must be
// consumed completely, and a duplicate, unused or out-of-order node rejects.
// No RSMT call verifies an EVM MPT, and go-ethereum's proof reader (which
// tolerates extra nodes) is deliberately not used.

// mptVerify returns the value of key (32 bytes, hashed path) under root.
func mptVerify(root [32]byte, key [32]byte, nodes [][]byte) ([]byte, error) {
	v, _, err := mptWalk(root, key, nodes)
	return v, err
}

// mptWalk is mptVerify that also reports how many supplied nodes the walk consumed. On errMPTAbsent that is the length of the
// non-inclusion path, which a caller proving absence checks against len(nodes) (no node may be left unused).
func mptWalk(root [32]byte, key [32]byte, nodes [][]byte) (val []byte, used int, err error) {
	nib := make([]byte, 64)
	for i, b := range key {
		nib[2*i], nib[2*i+1] = b>>4, b&0x0f
	}
	if len(nodes) == 0 {
		return nil, used, errMPTNode
	}
	// The root is always hash-referenced, whatever its size.
	if keccak(nodes[0]) != root {
		return nil, used, errMPTNode
	}
	cur, derr := rlpDecode(nodes[0])
	if derr != nil {
		return nil, used, errMPTNode
	}
	used = 1
	for {
		if !cur.list {
			return nil, used, errMPTNode
		}
		var child rlpItem
		switch len(cur.kids) {
		case 17:
			if len(nib) == 0 {
				v := cur.kids[16]
				if v.list || len(v.str) == 0 {
					return nil, used, errMPTAbsent
				}
				v2, e := finishMPT(used, len(nodes), v.str)
				return v2, used, e
			}
			child = cur.kids[nib[0]]
			nib = nib[1:]
			if !child.list && len(child.str) == 0 {
				return nil, used, errMPTAbsent
			}
		case 2:
			path, leaf, ok := hexPrefix(cur.kids[0])
			if !ok {
				return nil, used, errMPTNode
			}
			if len(path) > len(nib) || !bytes.Equal(path, nib[:len(path)]) {
				return nil, used, errMPTAbsent
			}
			nib = nib[len(path):]
			v := cur.kids[1]
			if leaf {
				if len(nib) != 0 {
					return nil, used, errMPTPath // the leaf ends before the key does
				}
				if v.list || len(v.str) == 0 {
					return nil, used, errMPTNode
				}
				v2, e := finishMPT(used, len(nodes), v.str)
				return v2, used, e
			}
			if len(path) == 0 {
				return nil, used, errMPTNode // an extension must consume at least one nibble
			}
			child = v
		default:
			return nil, used, errMPTNode
		}
		// Resolve the child reference.
		switch {
		case child.list:
			if len(child.raw) >= 32 {
				return nil, used, errMPTNode // a node of 32 bytes or more is hash-referenced
			}
			cur = child
		case len(child.str) == 32:
			if used >= len(nodes) {
				return nil, used, errMPTPath // a hash reference with no supplied node
			}
			n := nodes[used]
			if len(n) < 32 || keccak(n) != [32]byte(child.str) {
				return nil, used, errMPTNode
			}
			if cur, err = rlpDecode(n); err != nil {
				return nil, used, errMPTNode
			}
			used++
		default:
			return nil, used, errMPTNode
		}
	}
}

func finishMPT(used, total int, v []byte) ([]byte, error) {
	if used != total {
		return nil, errMPTExtraneous
	}
	return v, nil
}

// hexPrefix decodes a compact-encoded path: flag nibble 0/1 extension even/odd,
// 2/3 leaf even/odd; an even path has a zero padding nibble.
func hexPrefix(it rlpItem) (nibbles []byte, leaf, ok bool) {
	if it.list || len(it.str) == 0 {
		return nil, false, false
	}
	f := it.str[0] >> 4
	if f > 3 {
		return nil, false, false
	}
	leaf = f >= 2
	odd := f&1 == 1
	if odd {
		nibbles = append(nibbles, it.str[0]&0x0f)
	} else if it.str[0]&0x0f != 0 {
		return nil, false, false
	}
	for _, b := range it.str[1:] {
		nibbles = append(nibbles, b>>4, b&0x0f)
	}
	return nibbles, leaf, true
}

// A strict, minimal RLP reader for header, account and trie-node checks. It
// rejects every non-minimal length, a single byte below 0x80 wrapped as a
// string, trailing bytes and nesting over maxRLPDepth. It never allocates from
// a declared length before comparing it with the remaining input.

type rlpItem struct {
	list bool
	str  []byte    // payload of a string
	kids []rlpItem // items of a list
	raw  []byte    // the exact encoding of this item
}

// rlpDecode decodes exactly one item spanning all of b.
func rlpDecode(b []byte) (rlpItem, error) {
	it, n, err := rlpRead(b, 0)
	if err != nil {
		return rlpItem{}, err
	}
	if n != len(b) {
		return rlpItem{}, errRLP
	}
	return it, nil
}

func rlpRead(b []byte, depth int) (rlpItem, int, error) {
	if len(b) == 0 {
		return rlpItem{}, 0, errRLP
	}
	if depth > maxRLPDepth {
		return rlpItem{}, 0, errRLP
	}
	p := b[0]
	switch {
	case p < 0x80:
		return rlpItem{str: b[:1], raw: b[:1]}, 1, nil
	case p <= 0xb7:
		n := int(p - 0x80)
		if len(b) < 1+n {
			return rlpItem{}, 0, errRLP
		}
		if n == 1 && b[1] < 0x80 {
			return rlpItem{}, 0, errRLP // a single low byte must be its own encoding
		}
		return rlpItem{str: b[1 : 1+n], raw: b[:1+n]}, 1 + n, nil
	case p <= 0xbf:
		ll := int(p - 0xb7)
		n, err := rlpLen(b[1:], ll)
		if err != nil || n < 56 || n > len(b)-1-ll {
			return rlpItem{}, 0, errRLP
		}
		return rlpItem{str: b[1+ll : 1+ll+n], raw: b[:1+ll+n]}, 1 + ll + n, nil
	}
	var hdr, n int
	if p <= 0xf7 {
		hdr, n = 1, int(p-0xc0)
	} else {
		ll := int(p - 0xf7)
		l, err := rlpLen(b[1:], ll)
		if err != nil || l < 56 {
			return rlpItem{}, 0, errRLP
		}
		hdr, n = 1+ll, l
	}
	if n > len(b)-hdr {
		return rlpItem{}, 0, errRLP
	}
	it := rlpItem{list: true, raw: b[:hdr+n]}
	for off := hdr; off < hdr+n; {
		kid, used, err := rlpRead(b[off:hdr+n], depth+1)
		if err != nil {
			return rlpItem{}, 0, err
		}
		it.kids = append(it.kids, kid)
		off += used
	}
	return it, hdr + n, nil
}

// rlpLen reads an ll-byte big-endian length with no leading zero.
func rlpLen(b []byte, ll int) (int, error) {
	if ll > 4 || len(b) < ll || b[0] == 0 {
		return 0, errRLP
	}
	n := 0
	for _, x := range b[:ll] {
		n = n<<8 | int(x)
	}
	return n, nil
}

// rlpUint reads a canonical RLP integer string: no leading zero byte, at most
// 32 bytes (the empty string is zero).
func (it rlpItem) uintBytes() ([]byte, bool) {
	if it.list || len(it.str) > 32 || (len(it.str) > 0 && it.str[0] == 0) {
		return nil, false
	}
	return it.str, true
}
