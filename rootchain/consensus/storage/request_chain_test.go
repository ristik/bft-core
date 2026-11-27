package storage

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
)

// chainContinuation is the root-only continuation of a's assignment under the next root epoch, with its own body and start.
func chainContinuation(a *RequestActivation, start uint64, body byte) *RequestActivation {
	c := *a
	c.rootEpoch, c.start, c.rootBody = a.rootEpoch+1, start, bytes.Repeat([]byte{body}, 32)
	c.continuation, c.predecessorRootBody = true, bytes.Clone(a.rootBody)
	return &c
}

// Extensions of one chain never disturb each other or the chain they extend: the first may reuse its spare capacity, every later one
// copies.
func TestRequestChainExtensionsAreIndependent(t *testing.T) {
	f := newViewFixture(t)
	pdr, _ := f.pdr(0, 1, 1, fxBody0, f.member(0, 0, 1), f.member(1, 1, 1), f.member(2, 2, 1))
	anchor, err := NewRequestAnchor(pdr, crypto.SHA256, 1, fxBody0, fxVersion)
	require.NoError(t, err)
	base, err := NewRequestChain(fxNetwork, anchor)
	require.NoError(t, err)
	a1 := chainContinuation(anchor, 10, 0xC1)
	first, err := base.Extend(a1)
	require.NoError(t, err)
	second, err := base.Extend(chainContinuation(anchor, 11, 0xC2))
	require.NoError(t, err)
	require.Equal(t, 1, base.Len(), "the base is unchanged")
	require.Equal(t, a1.rootBody, first.acts[1].rootBody, "the second extension did not overwrite the first")
	require.Equal(t, bytes.Repeat([]byte{0xC2}, 32), second.acts[1].rootBody)

	// a long linear extension appends in place and keeps every intermediate chain intact
	chains := []*RequestChain{first}
	last := a1
	for i := range 50 {
		next := chainContinuation(last, last.start+1, byte(i))
		c, err := chains[len(chains)-1].Extend(next)
		require.NoError(t, err)
		chains, last = append(chains, c), next
	}
	for i, c := range chains {
		require.Equal(t, i+2, c.Len())
		require.Equal(t, a1.rootBody, c.acts[1].rootBody)
	}
	// extending an intermediate chain again copies
	branch, err := chains[3].Extend(chainContinuation(chains[3].Tip(), chains[3].Tip().start+1, 0xEE))
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte{0xEE}, 32), branch.Tip().rootBody)
	require.NotEqual(t, branch.Tip().rootBody, chains[4].Tip().rootBody, "the later chain is untouched")
}
