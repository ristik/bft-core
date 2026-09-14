package f4aregistry

import (
	"encoding/hex"
	"maps"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReview153SelfConsistentWrongGenesisContext(t *testing.T) {
	g, _, full, _ := build(t, vectorConfig())
	g.NetworkID++
	c, err := g.commitment()
	require.NoError(t, err)
	altered := *full
	altered.PartitionParams = maps.Clone(full.PartitionParams)
	altered.PartitionParams[genesisParam] = hex.EncodeToString(c)
	_, err = verifyConfiguredGenesis(&altered, g)
	require.Error(t, err, "G names another network than the configuration, despite self-consistent hashes")
}
