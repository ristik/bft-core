package evmroot

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestB1RootInputHasOneCommittedUpdateHash(t *testing.T) {
	ri := RootInputV2{}
	legacy := ri.Encode()
	hash := sha256.Sum256([]byte("independent canonical update"))
	expected := append([]byte(nil), legacy...)
	expected[0] = 0x8c
	expected = append(expected, 0x58, 0x20)
	expected = append(expected, hash[:]...)
	ri.B1UpdateHash = hash[:]
	require.Equal(t, expected, ri.Encode())
	require.Equal(t, Hash32(sha256.Sum256(expected)), ri.ExtraData())
	for _, n := range []int{0, 1, 31, 33} {
		ri.B1UpdateHash = bytes.Repeat([]byte{1}, n)
		require.ErrorIs(t, ri.Validate(), ErrB1UpdateHash)
	}
}
