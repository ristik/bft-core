package bridgeprofile

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
)

func TestVerifyMPTEntryProvesInclusionAndExclusion(t *testing.T) {
	kv := map[[32]byte][]byte{}
	for i := 0; i < 40; i++ {
		kv[key(fmt.Sprint("k", i))] = bytes.Repeat([]byte{byte(i + 1)}, 40+i)
	}
	root, prove := trieWith(t, kv)
	for k, want := range kv {
		got, present, err := VerifyMPTEntry(root, k, prove(k))
		require.NoError(t, err)
		require.True(t, present)
		require.Equal(t, want, got)
	}
	// keys the trie does not hold: every divergence shape (empty branch slot, extension/leaf mismatch) is a provable absence
	absent := 0
	for i := 0; i < 200; i++ {
		k := key(fmt.Sprint("missing", i))
		got, present, err := VerifyMPTEntry(root, k, prove(k))
		require.NoError(t, err, "missing%d", i)
		require.False(t, present)
		require.Nil(t, got)
		absent++
	}
	require.Equal(t, 200, absent)

	k := key("missing7")
	nodes := prove(k)
	t.Run("an exclusion proof with a node left over", func(t *testing.T) {
		_, _, err := VerifyMPTEntry(root, k, append(cloneNodes(nodes), nodes[0]))
		require.ErrorIs(t, err, ErrMPTExtraneous)
	})
	t.Run("an exclusion proof with a node missing", func(t *testing.T) {
		long := key("missing0")
		for i := 0; i < 200 && len(prove(long)) < 2; i++ {
			long = key(fmt.Sprint("missing", i))
		}
		p := prove(long)
		require.Greater(t, len(p), 1)
		_, _, err := VerifyMPTEntry(root, long, p[:len(p)-1])
		require.Error(t, err, "a hash reference with no node behind it is not an absence")
	})
	t.Run("a wrong root", func(t *testing.T) {
		bad := root
		bad[0] ^= 1
		_, _, err := VerifyMPTEntry(bad, k, nodes)
		require.ErrorIs(t, err, ErrMPTNode)
	})
	t.Run("a present key is not absent and the reverse", func(t *testing.T) {
		in := key("k3")
		_, present, err := VerifyMPTEntry(root, in, prove(in))
		require.NoError(t, err)
		require.True(t, present)
		_, _, err = VerifyMPTEntry(root, in, prove(k))
		require.Error(t, err, "a path to another key does not prove this one")
	})
	t.Run("an empty trie", func(t *testing.T) {
		got, present, err := VerifyMPTEntry([32]byte(types.EmptyRootHash), k, nil)
		require.NoError(t, err)
		require.False(t, present)
		require.Nil(t, got)
		_, _, err = VerifyMPTEntry([32]byte(types.EmptyRootHash), k, [][]byte{{0x80}})
		require.ErrorIs(t, err, ErrMPTExtraneous)
	})
	t.Run("a one-leaf trie", func(t *testing.T) {
		one := key("only")
		r1, p1 := trieWith(t, map[[32]byte][]byte{one: bytes.Repeat([]byte{9}, 40)})
		v, present, err := VerifyMPTEntry(r1, one, p1(one))
		require.NoError(t, err)
		require.True(t, present)
		require.Equal(t, bytes.Repeat([]byte{9}, 40), v)
		_, present, err = VerifyMPTEntry(r1, k, p1(k))
		require.NoError(t, err)
		require.False(t, present)
	})
}
