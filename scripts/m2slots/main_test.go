package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/registryproof"
)

func TestLaneSlotsMatchReviewedRegistry(t *testing.T) {
	require.Equal(t, registryproof.SlotKey(4).Hex(), slot("assignment.rootEpoch"))
	require.Equal(t, registryproof.SlotKey(20).Hex(), slot("transition.cursor"))
}
