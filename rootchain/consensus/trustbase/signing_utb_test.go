package trustbase

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// Without a verified history a UTB deployment's epochs are UTB epochs from the first, in the legacy scheme; a plain deployment's are not.
func TestUTBProfileMakesTheFallbackConfigurationAUTBEpoch(t *testing.T) {
	s := threeEpochStore(t)
	cfg, err := s.SigningConfig(1)
	require.NoError(t, err)
	require.False(t, cfg.UTB)

	s.EnableUTBProfile()
	for epoch := uint64(1); epoch <= 3; epoch++ {
		cfg, err = s.SigningConfig(epoch)
		require.NoError(t, err)
		require.True(t, cfg.UTB, "epoch %d", epoch)
		require.EqualValues(t, votesig.SchemeLegacy, cfg.Scheme)
	}
	_, err = s.SigningConfig(9)
	require.Error(t, err, "an epoch without an installed trust base is still no implicit configuration")
}
