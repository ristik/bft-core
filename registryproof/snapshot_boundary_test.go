package registryproof_test

import (
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/registryproof"
	bfttypes "github.com/unicitynetwork/bft-go-base/types"
)

// These tests run outside the package, with only what a caller has: a verified Snapshot must not be
// turned into a different decision by editing anything the caller can reach.

// The review's reproduction (#156): block 2 verified, then relabelled as genesis. The edits can only be
// made to a Fields copy, and eligibility reads the verified record.
func TestReview156EditedSnapshotCannotBecomeGenesis(t *testing.T) {
	ctx, genesis, _, b2 := registryproof.FixtureChain(t)
	s0 := registryproof.GenesisState()
	ir := &bfttypes.InputRecord{PreviousHash: s0, Hash: s0}

	g, err := registryproof.Verify(ctx, genesis.Hash, genesis.Evidence)
	require.NoError(t, err)
	require.NoError(t, registryproof.GenesisParentEligible(3, ir, s0, g), "premise: the verified genesis is eligible for the same record")

	s, err := registryproof.Verify(ctx, b2.Hash, b2.Evidence)
	require.NoError(t, err)
	require.False(t, s.Genesis())

	f := s.Fields()
	f.Genesis = true
	f.Number = 0
	f.RoundAuthorized = 0
	f.CertifiedRound = 0
	f.ParentHash = genesis.Hash
	f.StateRoot = g.StateRoot()
	f.ClockRootRound = 0

	require.ErrorIs(t, registryproof.GenesisParentEligible(3, ir, s0, s), registryproof.ErrParentNotGenesis,
		"an executed block must not become an eligible genesis parent by editing a copy of its values")
	require.False(t, s.Genesis())
	require.Equal(t, uint64(2), s.Number())
	require.Equal(t, b2.Hash, s.ParentHash())
	require.Equal(t, uint64(6), s.LastAppliedRootRound())
	require.Equal(t, uint64(2), s.Fields().RoundAuthorized)
	require.Equal(t, uint64(1), s.Fields().CertifiedRound)
}

// Edits to a copy of the snapshot's values, or to a copied Snapshot's values, change nothing the
// snapshot reports.
func TestSnapshotCopiesDoNotShareState(t *testing.T) {
	ctx, genesis, _, b2 := registryproof.FixtureChain(t)
	s, err := registryproof.Verify(ctx, b2.Hash, b2.Evidence)
	require.NoError(t, err)
	want := s.Fields()

	copied := s
	f := copied.Fields()
	f.ParentHash, f.Number, f.StateRoot, f.Genesis = genesis.Hash, 0, common.Hash{1}, true
	f.ClockRootRound, f.RoundAuthorized, f.CertifiedRound, f.OutcomesCommitment = 0, 0, 0, common.Hash{}
	f.CertifiedBlockHash[0] ^= 0xff

	require.Equal(t, want, s.Fields())
	require.Equal(t, want, copied.Fields())
	require.Equal(t, s, copied)
}

func TestZeroSnapshotIsNotAParent(t *testing.T) {
	s0 := registryproof.GenesisState()
	var zero registryproof.Snapshot
	require.False(t, zero.Valid())
	require.Equal(t, registryproof.Fields{}, zero.Fields())
	err := registryproof.GenesisParentEligible(2, &bfttypes.InputRecord{PreviousHash: s0, Hash: s0}, s0, zero)
	require.ErrorIs(t, err, registryproof.ErrParentNotGenesis)
	require.ErrorContains(t, err, "not produced by Verify", "refused as unverified, not by reading zero values")
}

// Snapshot exposes no field, and Fields holds no reference type, so neither a Snapshot nor a Fields copy
// can reach the verified record's memory.
func TestSnapshotHasNoExportedOrReferenceState(t *testing.T) {
	st := reflect.TypeOf(registryproof.Snapshot{})
	for i := 0; i < st.NumField(); i++ {
		require.False(t, st.Field(i).IsExported(), "Snapshot field %s is exported", st.Field(i).Name)
	}

	ft := reflect.TypeOf(registryproof.Fields{})
	require.Positive(t, ft.NumField())
	for i := 0; i < ft.NumField(); i++ {
		switch k := ft.Field(i).Type.Kind(); k {
		case reflect.Array:
			require.Equal(t, reflect.Uint8, ft.Field(i).Type.Elem().Kind(), ft.Field(i).Name)
		case reflect.Uint64, reflect.Bool:
		default:
			t.Fatalf("Fields.%s has kind %s, which a copy could share", ft.Field(i).Name, k)
		}
	}
}
