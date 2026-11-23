package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestLastSignedUCRequiresNamedValidatorsSignature(t *testing.T) {
	seal := types.NewUnicitySeal()
	seal.Epoch = 1
	seal.RootChainRoundNumber = 2
	seal.Timestamp = types.GenesisTime
	seal.Hash = make([]byte, 32)
	var members []*types.NodeInfo
	for _, id := range []string{"one", "two", "three", "named"} {
		signer, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		verifier, err := signer.Verifier()
		require.NoError(t, err)
		key, err := verifier.MarshalPublicKey()
		require.NoError(t, err)
		members = append(members, &types.NodeInfo{NodeID: id, SigKey: key, Stake: 1})
		require.NoError(t, seal.Sign(id, signer))
	}
	trust, err := types.NewTrustBase(3, members)
	require.NoError(t, err)
	require.NoError(t, seal.Verify(trust))
	require.True(t, sealSignedBy(seal, trust, "named"))
	seal.Signatures["named"] = seal.Signatures["one"]
	require.NoError(t, seal.Verify(trust), "the other three roots still form quorum")
	require.False(t, sealSignedBy(seal, trust, "named"))
	require.True(t, sealSignedBy(seal, trust, "one"))
	require.True(t, sealSignedBy(seal, trust, ""))
	require.False(t, sealSignedBy(seal, trust, "absent"))
}
