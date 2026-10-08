package bridgeprofile

import "bytes"

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

// mptWalk is mptVerify that also reports how many supplied nodes the walk consumed. On ErrMPTAbsent that is the length of the
// non-inclusion path, which a caller proving absence checks against len(nodes) (no node may be left unused).
func mptWalk(root [32]byte, key [32]byte, nodes [][]byte) (val []byte, used int, err error) {
	nib := make([]byte, 64)
	for i, b := range key {
		nib[2*i], nib[2*i+1] = b>>4, b&0x0f
	}
	if len(nodes) == 0 {
		return nil, used, ErrMPTNode
	}
	// The root is always hash-referenced, whatever its size.
	if keccak(nodes[0]) != root {
		return nil, used, ErrMPTNode
	}
	cur, derr := rlpDecode(nodes[0])
	if derr != nil {
		return nil, used, ErrMPTNode
	}
	used = 1
	for {
		if !cur.list {
			return nil, used, ErrMPTNode
		}
		var child rlpItem
		switch len(cur.kids) {
		case 17:
			if len(nib) == 0 {
				v := cur.kids[16]
				if v.list || len(v.str) == 0 {
					return nil, used, ErrMPTAbsent
				}
				v2, e := finishMPT(used, len(nodes), v.str)
				return v2, used, e
			}
			child = cur.kids[nib[0]]
			nib = nib[1:]
			if !child.list && len(child.str) == 0 {
				return nil, used, ErrMPTAbsent
			}
		case 2:
			path, leaf, ok := hexPrefix(cur.kids[0])
			if !ok {
				return nil, used, ErrMPTNode
			}
			if len(path) > len(nib) || !bytes.Equal(path, nib[:len(path)]) {
				return nil, used, ErrMPTAbsent
			}
			nib = nib[len(path):]
			v := cur.kids[1]
			if leaf {
				if len(nib) != 0 {
					return nil, used, ErrMPTPath // the leaf ends before the key does
				}
				if v.list || len(v.str) == 0 {
					return nil, used, ErrMPTNode
				}
				v2, e := finishMPT(used, len(nodes), v.str)
				return v2, used, e
			}
			if len(path) == 0 {
				return nil, used, ErrMPTNode // an extension must consume at least one nibble
			}
			child = v
		default:
			return nil, used, ErrMPTNode
		}
		// Resolve the child reference.
		switch {
		case child.list:
			if len(child.raw) >= 32 {
				return nil, used, ErrMPTNode // a node of 32 bytes or more is hash-referenced
			}
			cur = child
		case len(child.str) == 32:
			if used >= len(nodes) {
				return nil, used, ErrMPTPath // a hash reference with no supplied node
			}
			n := nodes[used]
			if len(n) < 32 || keccak(n) != [32]byte(child.str) {
				return nil, used, ErrMPTNode
			}
			if cur, err = rlpDecode(n); err != nil {
				return nil, used, ErrMPTNode
			}
			used++
		default:
			return nil, used, ErrMPTNode
		}
	}
}

func finishMPT(used, total int, v []byte) ([]byte, error) {
	if used != total {
		return nil, ErrMPTExtraneous
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
