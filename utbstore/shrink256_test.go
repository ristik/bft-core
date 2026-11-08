package utbstore

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/utb"
	"github.com/unicitynetwork/bft-go-base/types"
)

// §49: the reverse of the maximum-size fixture. A 256-member entry is succeeded by a 4-member entry that carries all 256 predecessor signatures
// (the signatures are the PREDECESSOR's members, so the entry stays large while its committee shrinks). It is appended, served byte for byte and
// survives a reopen; the quorum is strict: a 257th signature (from a key outside the predecessor) and a sub-quorum set (170 of 171 needed) are each refused.
func TestShrinkFrom256To4With256PredecessorSignatures(t *testing.T) {
	ns := nodes(t, utb.MaxMembers+1) // the 257th is an outsider
	g, err := utb.BuildUnsigned(nil, facts(ns[:utb.MaxMembers], 1, 1, 0x11))
	require.NoError(t, err)
	build := func(signers []node) []byte {
		e, err := utb.BuildUnsigned(g, facts(ns[:4], 2, 100, 0x22))
		require.NoError(t, err)
		for _, s := range signers {
			require.NoError(t, e.Sign(s.id, s.signer))
		}
		return enc(t, e)
	}

	db := memorydb.New()
	s := open(t, db, g)
	full := build(ns[:utb.MaxMembers])
	require.Less(t, len(full), maxEntryBytes)
	added, err := s.Append(full)
	require.NoError(t, err)
	require.True(t, added)
	tip := s.Tip()
	require.EqualValues(t, 2, tip.Epoch)
	stored, err := types.DecodeRootTrustBaseV2(full)
	require.NoError(t, err)
	require.Len(t, stored.RootNodes, 4)
	require.Len(t, stored.Signatures, 256)
	got, err := s.Get(2)
	require.NoError(t, err)
	require.Equal(t, full, got)
	require.EqualValues(t, 2, open(t, db, g).Tip().Epoch, "survives a reopen")

	refuse := func(name string, raw []byte, want string) {
		t.Run(name, func(t *testing.T) {
			_, err := open(t, memorydb.New(), g).Append(raw)
			require.ErrorIs(t, err, ErrEntry)
			require.ErrorContains(t, err, want)
		})
	}
	// 257 signatures: all 256 members plus an outsider. Strict verification refuses a signature that is not a member's.
	refuse("a 257th signature from outside the predecessor", build(ns[:utb.MaxMembers+1]), "member")
	refuse("below the predecessor's quorum (170 of 256, threshold 171)", build(ns[:170]), "quorum")
	// the quorum is exactly 171 of 256 unit weights
	_, err = open(t, memorydb.New(), g).Append(build(ns[:171]))
	require.NoError(t, err)
}
