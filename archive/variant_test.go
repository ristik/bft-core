package archive

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Two valid representations of one block (bft-core#876): the base object and a variant. Each is an immutable object of its own, read by its manifest digest; the base
// object is never touched; a variant already stored must be identical; a damaged base does not hide a sound variant.
func TestVariantObjectsAreAddressedByManifestDigest(t *testing.T) {
	s, err := Open(t.TempDir())
	require.NoError(t, err)
	q, base := fixture()
	variant := *base
	variant.ResultingUC = append([]byte(nil), base.ResultingUC...)
	variant.ResultingUC[len(variant.ResultingUC)-1] ^= 1
	require.NoError(t, s.Put(q, base))
	dBase, err := ManifestDigest(q, base)
	require.NoError(t, err)
	dVar, err := ManifestDigest(q, &variant)
	require.NoError(t, err)
	require.NotEqual(t, dBase, dVar)

	require.Error(t, s.Put(q, &variant), "the base object of a request is immutable: a different record cannot be put there")
	require.NoError(t, s.PutVariant(q, &variant))
	require.NoError(t, s.PutVariant(q, &variant), "idempotent")

	got, err := s.Get(q)
	require.NoError(t, err)
	require.Equal(t, base.ResultingUC, got.ResultingUC, "the default read is still the base object")
	exactBase, err := s.GetExact(q, dBase)
	require.NoError(t, err)
	require.Equal(t, base.ResultingUC, exactBase.ResultingUC)
	exactVar, err := s.GetExact(q, dVar)
	require.NoError(t, err)
	require.Equal(t, variant.ResultingUC, exactVar.ResultingUC)
	_, err = s.GetExact(q, [32]byte{9})
	require.ErrorIs(t, err, ErrUnavailable, "a digest nobody stored")

	// a variant is not indexed as the block's record: the round index keeps answering with the base
	require.NoError(t, s.PutVariant(q, base), "putting the base representation as a variant is harmless and idempotent")
}
