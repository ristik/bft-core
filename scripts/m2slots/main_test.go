package main

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/registryproof"
)

func TestLaneSlotsMatchReviewedRegistry(t *testing.T) {
	require.Equal(t, registryproof.SlotKey(4).Hex(), slot("assignment.rootEpoch"))
	require.Equal(t, registryproof.SlotKey(20).Hex(), slot("transition.cursor"))
}

// The fresh-B1 registry names its slots under another prefix; the same field is another key, and the layout switch is the only difference.
func TestTheB1LayoutNamesItsSlotsUnderItsOwnPrefix(t *testing.T) {
	require.Equal(t, crypto.Keccak256Hash([]byte("unicity.seal-registry/assignment.rootEpoch")).Hex(), slotUnder("3", "assignment.rootEpoch"))
	require.Equal(t, slot("assignment.rootEpoch"), slotUnder("", "assignment.rootEpoch"), "no layout selected is layout 2")
	require.NotEqual(t, slotUnder("", "assignment.rootEpoch"), slotUnder("3", "assignment.rootEpoch"))
}
