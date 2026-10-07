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
	nib := make([]byte, 64)
	for i, b := range key {
		nib[2*i], nib[2*i+1] = b>>4, b&0x0f
	}
	if len(nodes) == 0 {
		return nil, ErrMPTNode
	}
	used := 0
	// The root is always hash-referenced, whatever its size.
	if keccak(nodes[0]) != root {
		return nil, ErrMPTNode
	}
	cur, err := rlpDecode(nodes[0])
	if err != nil {
		return nil, ErrMPTNode
	}
	used = 1
	for {
		if !cur.list {
			return nil, ErrMPTNode
		}
		var child rlpItem
		switch len(cur.kids) {
		case 17:
			if len(nib) == 0 {
				v := cur.kids[16]
				if v.list || len(v.str) == 0 {
					return nil, ErrMPTAbsent
				}
				return finishMPT(used, len(nodes), v.str)
			}
			child = cur.kids[nib[0]]
			nib = nib[1:]
			if !child.list && len(child.str) == 0 {
				return nil, ErrMPTAbsent
			}
		case 2:
			path, leaf, ok := hexPrefix(cur.kids[0])
			if !ok {
				return nil, ErrMPTNode
			}
			if len(path) > len(nib) || !bytes.Equal(path, nib[:len(path)]) {
				return nil, ErrMPTAbsent
			}
			nib = nib[len(path):]
			v := cur.kids[1]
			if leaf {
				if len(nib) != 0 {
					return nil, ErrMPTPath // the leaf ends before the key does
				}
				if v.list || len(v.str) == 0 {
					return nil, ErrMPTNode
				}
				return finishMPT(used, len(nodes), v.str)
			}
			if len(path) == 0 {
				return nil, ErrMPTNode // an extension must consume at least one nibble
			}
			child = v
		default:
			return nil, ErrMPTNode
		}
		// Resolve the child reference.
		switch {
		case child.list:
			if len(child.raw) >= 32 {
				return nil, ErrMPTNode // a node of 32 bytes or more is hash-referenced
			}
			cur = child
		case len(child.str) == 32:
			if used >= len(nodes) {
				return nil, ErrMPTPath // a hash reference with no supplied node
			}
			n := nodes[used]
			if len(n) < 32 || keccak(n) != [32]byte(child.str) {
				return nil, ErrMPTNode
			}
			var err error
			if cur, err = rlpDecode(n); err != nil {
				return nil, ErrMPTNode
			}
			used++
		default:
			return nil, ErrMPTNode
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
