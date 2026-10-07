package evmassign

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestNodeIDWordKnownAnswer(t *testing.T) {
	// keccak256("abc"), the published Keccak-256 test vector, independent of the library under test.
	w, err := NodeIDWord("abc")
	require.NoError(t, err)
	require.Equal(t, "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", hex.EncodeToString(w[:]))
}

func TestNodeIDWordMatchesLegacyKeccak(t *testing.T) {
	const id = "16Uiu2HAmPZeJ2Ma1aXs8yxfM1uNwSFPxLtWRn9wGq8CZQhdFCgfM"
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(id))
	w, err := NodeIDWord(id)
	require.NoError(t, err)
	require.Equal(t, h.Sum(nil), w[:])
}

func TestNodeIDWordInjectiveOnDistinctIDs(t *testing.T) {
	a, err := NodeIDWord("node-a")
	require.NoError(t, err)
	b, err := NodeIDWord("node-b")
	require.NoError(t, err)
	require.NotEqual(t, a, b)
}

func TestNodeIDWordRejectsEmpty(t *testing.T) {
	_, err := NodeIDWord("")
	require.ErrorIs(t, err, ErrNodeID)
}
