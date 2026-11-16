package nb2ref

import (
	"bytes"
	"errors"
)

// Strict Ethereum Merkle-Patricia trie inclusion verification, from bridgeprofile/mpt.go, generalised to an unhashed key of
// any length (the receipt trie is keyed by RLP(transactionIndex)). The supplied nodes are exactly the root-to-leaf path in
// order: each hash reference consumes the next node, an embedded node (shorter than 32 bytes) consumes none, the key is
// consumed completely, and a duplicate, unused or out-of-order node rejects. The root is always hash-referenced.
// go-ethereum's proof reader, which tolerates extra nodes, is deliberately not used.

var errMPT = errors.New("nb2: MPT path does not verify")

// mptVerify returns the value stored at key under root.
func mptVerify(root [32]byte, key []byte, nodes [][]byte) ([]byte, error) {
	nib := make([]byte, 0, 2*len(key))
	for _, b := range key {
		nib = append(nib, b>>4, b&0x0f)
	}
	if len(nodes) == 0 || HE(nodes[0]) != root {
		return nil, errMPT
	}
	cur, err := rlpDecode(nodes[0])
	if err != nil {
		return nil, errMPT
	}
	used := 1
	for {
		if !cur.list {
			return nil, errMPT
		}
		var child rlpItem
		switch len(cur.kids) {
		case 17:
			if len(nib) == 0 {
				v := cur.kids[16]
				if v.list || len(v.str) == 0 {
					return nil, errMPT
				}
				return finishMPT(used, len(nodes), v.str)
			}
			child = cur.kids[nib[0]]
			nib = nib[1:]
			if !child.list && len(child.str) == 0 {
				return nil, errMPT // absent
			}
		case 2:
			path, leaf, ok := hexPrefix(cur.kids[0])
			if !ok || len(path) > len(nib) || !bytes.Equal(path, nib[:len(path)]) {
				return nil, errMPT
			}
			nib = nib[len(path):]
			v := cur.kids[1]
			if leaf {
				if len(nib) != 0 || v.list || len(v.str) == 0 {
					return nil, errMPT
				}
				return finishMPT(used, len(nodes), v.str)
			}
			if len(path) == 0 {
				return nil, errMPT // an extension consumes at least one nibble
			}
			child = v
		default:
			return nil, errMPT
		}
		switch {
		case child.list:
			if len(child.raw) >= 32 {
				return nil, errMPT // a node of 32 bytes or more is hash-referenced
			}
			cur = child
		case len(child.str) == 32:
			if used >= len(nodes) {
				return nil, errMPT
			}
			n := nodes[used]
			if len(n) < 32 || HE(n) != [32]byte(child.str) {
				return nil, errMPT
			}
			if cur, err = rlpDecode(n); err != nil {
				return nil, errMPT
			}
			used++
		default:
			return nil, errMPT
		}
	}
}

func finishMPT(used, total int, v []byte) ([]byte, error) {
	if used != total {
		return nil, errMPT // unused or duplicate trailing node
	}
	return v, nil
}

// hexPrefix decodes a compact-encoded path: flag 0/1 extension even/odd, 2/3 leaf even/odd; an even path pads with zero.
func hexPrefix(it rlpItem) (nibbles []byte, leaf, ok bool) {
	if it.list || len(it.str) == 0 {
		return nil, false, false
	}
	f := it.str[0] >> 4
	if f > 3 {
		return nil, false, false
	}
	leaf = f >= 2
	if f&1 == 1 {
		nibbles = append(nibbles, it.str[0]&0x0f)
	} else if it.str[0]&0x0f != 0 {
		return nil, false, false
	}
	for _, b := range it.str[1:] {
		nibbles = append(nibbles, b>>4, b&0x0f)
	}
	return nibbles, leaf, true
}

// rlpUintKey is RLP(i) for an unsigned index: 0x80 for zero, the byte itself below 0x80, else a short string.
func rlpUintKey(i uint64) []byte {
	switch {
	case i == 0:
		return []byte{0x80}
	case i < 0x80:
		return []byte{byte(i)}
	}
	var b []byte
	for v := i; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	return append([]byte{0x80 + byte(len(b))}, b...)
}
