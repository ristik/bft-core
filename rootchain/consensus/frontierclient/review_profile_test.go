package frontierclient_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontierclient"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestReviewCollectorRequiresTheFixedTrustProfile(t *testing.T) {
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	key, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	profile := func() frontierclient.Profile {
		return frontierclient.Profile{
			TrustBase: &types.RootTrustBaseV1{
				Version: 1, NetworkID: 5, Epoch: 1, QuorumThreshold: 1,
				RootNodes: []*types.NodeInfo{{NodeID: "root", SigKey: bytes.Clone(key), Stake: 1}},
			},
			NetworkID: 5, PartitionID: 1, RootEpoch: 1,
			FullShardConfHash:     bytes.Repeat([]byte{1}, 32),
			GenesisOriginIdentity: bytes.Repeat([]byte{2}, 32),
			Nonce:                 bytes.Repeat([]byte{3}, 32),
		}
	}
	_, err = frontierclient.NewCollector(profile())
	require.NoError(t, err)
	cases := []struct {
		name   string
		change func(*frontierclient.Profile)
	}{
		{"nil trust", func(p *frontierclient.Profile) { p.TrustBase = nil }},
		{"nil root before sort", func(p *frontierclient.Profile) { p.TrustBase.RootNodes = append(p.TrustBase.RootNodes, nil) }},
		{"unspecified version", func(p *frontierclient.Profile) { p.TrustBase.Version = 0 }},
		{"another version", func(p *frontierclient.Profile) { p.TrustBase.Version = 2 }},
		{"weighted root", func(p *frontierclient.Profile) { p.TrustBase.RootNodes[0].Stake = 2 }},
		{"no quorum", func(p *frontierclient.Profile) { p.TrustBase.QuorumThreshold = 0 }},
		{"impossible quorum", func(p *frontierclient.Profile) { p.TrustBase.QuorumThreshold = 2 }},
		{"duplicate identity", func(p *frontierclient.Profile) {
			p.TrustBase.RootNodes = append(p.TrustBase.RootNodes, &types.NodeInfo{NodeID: "root", SigKey: bytes.Clone(key), Stake: 1})
			p.TrustBase.QuorumThreshold = 2
		}},
		{"oversized key", func(p *frontierclient.Profile) { p.TrustBase.RootNodes[0].SigKey = make([]byte, 257) }},
		{"invalid key", func(p *frontierclient.Profile) { p.TrustBase.RootNodes[0].SigKey = make([]byte, 33) }},
		{"wrong trust network", func(p *frontierclient.Profile) { p.TrustBase.NetworkID++ }},
		{"wrong trust epoch", func(p *frontierclient.Profile) { p.TrustBase.Epoch++ }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := profile()
			tc.change(&p)
			require.NotPanics(t, func() {
				got, err := frontierclient.NewCollector(p)
				require.ErrorIs(t, err, frontierclient.ErrProfile)
				require.Nil(t, got)
			})
		})
	}
}
