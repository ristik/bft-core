package trustbase

import (
	"crypto"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

func threeEpochStore(t *testing.T) *TrustBaseStore {
	t.Helper()
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	store, err := NewTrustBaseStore(memorydb.New(), logger.New(t))
	require.NoError(t, err)
	var prev *types.RootTrustBaseV1
	for epoch := uint64(1); epoch <= 3; epoch++ {
		opts := []types.Option{types.WithEpoch(epoch), types.WithEpochStart(epoch * 10)}
		if prev != nil {
			h, err := prev.Hash(crypto.SHA256)
			require.NoError(t, err)
			opts = append(opts, types.WithPreviousTrustBaseHash(h))
		}
		tb, err := types.NewTrustBase(5, []*types.NodeInfo{trustbase.NewNodeInfoFromVerifier(t, "n", verifier)}, opts...)
		require.NoError(t, err)
		require.NoError(t, tb.Sign("n", signer))
		require.NoError(t, store.Store(tb))
		prev = tb
	}
	return store
}

func cfg2() votesig.Config {
	return votesig.Config{Scheme: votesig.SchemeDomainBound, Network: 5, Genesis: sha256.Sum256([]byte("g"))}
}

func TestSigningConfigIsAPropertyOfTheEpoch(t *testing.T) {
	s := threeEpochStore(t)
	// nothing is activated: every installed epoch is scheme 1, and nothing in production installs an activation
	for epoch := uint64(1); epoch <= 3; epoch++ {
		c, err := s.SigningConfig(epoch)
		require.NoError(t, err)
		require.EqualValues(t, votesig.SchemeLegacy, c.Scheme)
		require.EqualValues(t, 5, c.Network)
	}
	require.NoError(t, s.ActivateSigning(2, cfg2()))
	c, err := s.SigningConfig(1)
	require.NoError(t, err)
	require.EqualValues(t, votesig.SchemeLegacy, c.Scheme, "before the boundary")
	for _, epoch := range []uint64{2, 3} {
		c, err = s.SigningConfig(epoch)
		require.NoError(t, err)
		require.Equal(t, cfg2(), c, "at and after the boundary")
	}
}

func TestMissingHistoryIsAnErrorNotAnImplicitLegacyChoice(t *testing.T) {
	s := threeEpochStore(t)
	_, err := s.SigningConfig(4)
	require.ErrorIs(t, err, ErrSigningHistory)
	require.ErrorIs(t, s.ActivateSigning(4, cfg2()), ErrSigningHistory, "an activation needs the epoch's trust base")
}

func TestActivationIsRefusedWhenItDoesNotFitTheHistory(t *testing.T) {
	s := threeEpochStore(t)
	require.ErrorIs(t, s.ActivateSigning(2, votesig.Config{Scheme: votesig.SchemeLegacy, Network: 5}), ErrSigningHistory, "scheme 1 is not an activation")
	require.ErrorIs(t, s.ActivateSigning(2, votesig.Config{Scheme: 2, Network: 5}), votesig.ErrConfig, "no genesis identity")
	require.ErrorIs(t, s.ActivateSigning(2, votesig.Config{Scheme: 3, Network: 5}), ErrSigningHistory)
	other := cfg2()
	other.Network = 6
	require.ErrorIs(t, s.ActivateSigning(2, other), ErrSigningHistory, "another network than the trust base's")

	require.NoError(t, s.ActivateSigning(3, cfg2()))
	require.NoError(t, s.ActivateSigning(3, cfg2()), "the same record again is a no-op")
	changed := cfg2()
	changed.Genesis[0] ^= 1
	require.ErrorIs(t, s.ActivateSigning(3, changed), ErrSigningHistory, "another record for the same epoch")
	require.ErrorIs(t, s.ActivateSigning(2, cfg2()), ErrSigningHistory, "an activation below a recorded one: the scheme never goes back")
	c, err := s.SigningConfig(2)
	require.NoError(t, err)
	require.EqualValues(t, votesig.SchemeLegacy, c.Scheme, "the refused activation changed nothing")
}
