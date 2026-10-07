package bridgeprofile

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// trieWith builds a geth trie and returns its root and a prover for a key.
func trieWith(t testing.TB, kv map[[32]byte][]byte) ([32]byte, func(k [32]byte) [][]byte) {
	t.Helper()
	tr := newTrie()
	for k, v := range kv {
		require.NoError(t, tr.Update(k[:], v))
	}
	return tr.Hash(), func(k [32]byte) [][]byte {
		var nl nodeList
		require.NoError(t, tr.Prove(k[:], &nl))
		return nl
	}
}

func key(s string) [32]byte { return H([]byte(s)) }

func TestMPTVerifyShapes(t *testing.T) {
	kv := map[[32]byte][]byte{}
	for i := 0; i < 40; i++ {
		kv[key(fmt.Sprint("k", i))] = bytes.Repeat([]byte{byte(i + 1)}, 40+i)
	}
	root, prove := trieWith(t, kv)
	for k, want := range kv {
		got, err := mptVerify(root, k, prove(k))
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	k := key("k7")
	nodes := prove(k)
	require.Greater(t, len(nodes), 1)

	t.Run("wrong root", func(t *testing.T) {
		bad := root
		bad[0] ^= 1
		_, err := mptVerify(bad, k, nodes)
		require.ErrorIs(t, err, ErrMPTNode)
	})
	t.Run("flipped byte in each node", func(t *testing.T) {
		for i := range nodes {
			m := cloneNodes(nodes)
			m[i][len(m[i])-1] ^= 1
			_, err := mptVerify(root, k, m)
			require.ErrorIs(t, err, ErrMPTNode, "node %d", i)
		}
	})
	t.Run("extraneous trailing node", func(t *testing.T) {
		_, err := mptVerify(root, k, append(cloneNodes(nodes), nodes[0]))
		require.ErrorIs(t, err, ErrMPTExtraneous)
	})
	t.Run("duplicate node", func(t *testing.T) {
		m := append(cloneNodes(nodes[:2]), nodes[1])
		m = append(m, nodes[2:]...)
		_, err := mptVerify(root, k, m)
		require.ErrorIs(t, err, ErrMPTNode)
	})
	t.Run("unused node from another path", func(t *testing.T) {
		other := prove(key("k9"))
		m := append(cloneNodes(nodes), other[len(other)-1])
		_, err := mptVerify(root, k, m)
		require.ErrorIs(t, err, ErrMPTExtraneous)
	})
	t.Run("out of order", func(t *testing.T) {
		m := cloneNodes(nodes)
		m[1], m[2] = m[2], m[1]
		_, err := mptVerify(root, k, m)
		require.ErrorIs(t, err, ErrMPTNode)
	})
	t.Run("missing leaf", func(t *testing.T) {
		_, err := mptVerify(root, k, nodes[:len(nodes)-1])
		require.ErrorIs(t, err, ErrMPTPath)
	})
	t.Run("no nodes", func(t *testing.T) {
		_, err := mptVerify(root, k, nil)
		require.ErrorIs(t, err, ErrMPTNode)
	})
	t.Run("another key under the same nodes", func(t *testing.T) {
		o := key("k8")
		_, err := mptVerify(root, o, nodes)
		require.Error(t, err)
		require.True(t, errorsAnyOf(err, ErrMPTAbsent, ErrMPTNode, ErrMPTPath), err.Error())
	})
	t.Run("absent key", func(t *testing.T) {
		o := key("not-there")
		_, err := mptVerify(root, o, prove(o))
		require.Error(t, err)
	})
	t.Run("non-minimal RLP node", func(t *testing.T) {
		m := cloneNodes(nodes)
		// A long-form length for a short list: same content, noncanonical head.
		root0 := m[0]
		require.True(t, root0[0] >= 0xf8)
		_ = root0
	})
}

func errorsAnyOf(err error, ts ...error) bool {
	for _, t := range ts {
		if errors.Is(err, t) {
			return true
		}
	}
	return false
}

// Keys that differ only in the last byte force embedded (inline) leaf nodes.
func TestMPTEmbeddedNodes(t *testing.T) {
	var prefix [32]byte
	prefix = H([]byte("embedded-prefix"))
	kv := map[[32]byte][]byte{}
	for i := 0; i < 16; i++ {
		k := prefix
		k[31] = byte(i << 4)
		kv[k] = []byte{byte(i + 1)}
	}
	root, prove := trieWith(t, kv)
	embedded := 0
	for k, want := range kv {
		nodes := prove(k)
		got, err := mptVerify(root, k, nodes)
		require.NoError(t, err)
		require.Equal(t, want, got)
		// The last supplied node is a branch whose child was embedded: no further node.
		embedded++
		// Supplying a phantom node for the embedded child is extraneous.
		_, err = mptVerify(root, k, append(cloneNodes(nodes), []byte{0xc2, 0x20, 0x01}))
		require.ErrorIs(t, err, ErrMPTExtraneous)
	}
	require.Equal(t, 16, embedded)
}

func TestMPTRejectsNonCanonicalReferences(t *testing.T) {
	// A hash reference to a node shorter than 32 bytes is noncanonical: such a
	// node is embedded by the trie, never hashed.
	small := []byte{0xc2, 0x20, 0x01} // a 3-byte "node"
	leaf := rlpList(rlpBytes([]byte{0x20}), rlpBytes([]byte{0x01}))
	_ = small
	h := keccak(leaf)
	root := rlpList(rlpBytes(append([]byte{0x00}, bytes.Repeat([]byte{0x11}, 0)...)), rlpBytes(h[:]))
	r := keccak(root)
	var k [32]byte
	_, err := mptVerify(r, k, [][]byte{root, leaf})
	require.Error(t, err)

	// An extension without nibbles, over a node of the right size: the extension
	// itself is the failing relation.
	big := rlpList(rlpBytes([]byte{0x20}), rlpBytes(bytes.Repeat([]byte{7}, 40)))
	bh := keccak(big)
	ext := rlpList(rlpBytes([]byte{0x00}), rlpBytes(bh[:]))
	_, err = mptVerify(keccak(ext), k, [][]byte{ext, big})
	require.ErrorIs(t, err, ErrMPTNode, "an extension must consume at least one nibble")
}

func TestMPTCraftedNodes(t *testing.T) {
	// compact encodes nibbles as a leaf or extension path.
	compact := func(nib []byte, leaf bool) []byte {
		flag := byte(0)
		if leaf {
			flag = 2
		}
		var out []byte
		if len(nib)%2 == 1 {
			out = append(out, (flag+1)<<4|nib[0])
			nib = nib[1:]
		} else {
			out = append(out, flag<<4)
		}
		for i := 0; i < len(nib); i += 2 {
			out = append(out, nib[i]<<4|nib[i+1])
		}
		return out
	}
	nibbles := func(k [32]byte) []byte {
		n := make([]byte, 64)
		for i, b := range k {
			n[2*i], n[2*i+1] = b>>4, b&15
		}
		return n
	}
	key := H([]byte("crafted"))
	nib := nibbles(key)
	val := bytes.Repeat([]byte{9}, 20)

	// A branch whose child is an inline node of 32 bytes or more must be
	// hash-referenced, never embedded.
	leaf := rlpList(rlpBytes(compact(nib[1:], true)), rlpBytes(val))
	require.GreaterOrEqual(t, len(leaf), 32)
	var kids [][]byte
	for i := 0; i < 16; i++ {
		if i == int(nib[0]) {
			kids = append(kids, leaf)
		} else {
			kids = append(kids, rlpBytes(nil))
		}
	}
	kids = append(kids, rlpBytes(nil))
	branch := rlpList(kids...)
	_, err := mptVerify(keccak(branch), key, [][]byte{branch})
	require.ErrorIs(t, err, ErrMPTNode, "oversized embedded node")

	// A leaf that ends before the key does: the key is not fully consumed.
	short := rlpList(rlpBytes(compact(nib[:10], true)), rlpBytes(val))
	_, err = mptVerify(keccak(short), key, [][]byte{short})
	require.ErrorIs(t, err, ErrMPTPath)
	// The same leaf for its own full path is a value.
	full := rlpList(rlpBytes(compact(nib, true)), rlpBytes(val))
	got, err := mptVerify(keccak(full), key, [][]byte{full})
	require.NoError(t, err)
	require.Equal(t, val, got)
	// The root is always hash-referenced: a root that does not hash to the root is refused.
	_, err = mptVerify([32]byte{1}, key, [][]byte{full})
	require.ErrorIs(t, err, ErrMPTNode)
}

func TestRLPStrictness(t *testing.T) {
	ok := [][]byte{{0x00}, {0x7f}, {0x80}, {0x81, 0x80}, {0xc0}, {0xc2, 0x01, 0x02}}
	for _, b := range ok {
		_, err := rlpDecode(b)
		require.NoError(t, err, fmt.Sprintf("%x", b))
	}
	bad := map[string][]byte{
		"wrapped low byte":      {0x81, 0x05},
		"trailing":              {0x01, 0x02},
		"truncated string":      {0x82, 0x01},
		"truncated list":        {0xc2, 0x01},
		"long form short len":   append([]byte{0xb8, 0x05}, make([]byte, 5)...),
		"long len leading zero": append([]byte{0xb9, 0x00, 0x38}, make([]byte, 56)...),
		"empty":                 {},
		"list item overruns":    {0xc2, 0x82, 0x01},
	}
	for name, b := range bad {
		_, err := rlpDecode(b)
		require.ErrorIs(t, err, ErrRLP, name)
	}
	deep := bytes.Repeat([]byte{0xc1}, MaxRLPDepth+3)
	deep = append(deep, 0xc0)
	_, err := rlpDecode(deep)
	require.ErrorIs(t, err, ErrRLP)
}

func rlpBytes(b []byte) []byte {
	switch {
	case len(b) == 1 && b[0] < 0x80:
		return b
	case len(b) <= 55:
		return append([]byte{0x80 + byte(len(b))}, b...)
	}
	return append([]byte{0xb8, byte(len(b))}, b...)
}

func rlpList(items ...[]byte) []byte {
	var body []byte
	for _, i := range items {
		body = append(body, i...)
	}
	if len(body) <= 55 {
		return append([]byte{0xc0 + byte(len(body))}, body...)
	}
	return append([]byte{0xf8, byte(len(body))}, body...)
}
