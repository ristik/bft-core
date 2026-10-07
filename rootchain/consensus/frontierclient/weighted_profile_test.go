package frontierclient

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

func weightedProfile(t *testing.T) Profile {
	t.Helper()
	trust := &types.RootTrustBaseV1{Version: 1, NetworkID: 5, Epoch: 2, QuorumThreshold: 7}
	for _, n := range []struct {
		id    string
		stake uint64
	}{{"a-heavy", 6}, {"b", 1}, {"c", 1}, {"d", 1}} {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		key, err := v.MarshalPublicKey()
		require.NoError(t, err)
		trust.RootNodes = append(trust.RootNodes, &types.NodeInfo{NodeID: n.id, SigKey: bytes.Clone(key), Stake: n.stake})
	}
	return Profile{TrustBase: trust, NetworkID: 5, PartitionID: 1, RootEpoch: 2, FullShardConfHash: bytes.Repeat([]byte{1}, 32),
		GenesisOriginIdentity: bytes.Repeat([]byte{2}, 32), Nonce: bytes.Repeat([]byte{3}, 32), Mode: weightvalidation.ModeWeighted}
}

// A weighted committee is a profile only of a verified Q3 epoch (Mode weighted), with the exact weighted threshold; the quorum
// over replies is then a weight: the heavy member and one light member reach 7 of 9, three light members do not.
func TestWeightedProfileIsExplicitAndCountsByWeight(t *testing.T) {
	c, err := NewCollector(weightedProfile(t))
	require.NoError(t, err, "acceptance control")
	heavy, ok := c.stakeOf("a-heavy")
	require.True(t, ok)
	light, _ := c.stakeOf("b")
	require.EqualValues(t, 6, heavy)
	require.EqualValues(t, 1, light)
	require.False(t, quorumweight.Reached(heavy, c.quorum), "the heavy member alone is 6 of 7")
	require.True(t, quorumweight.Reached(heavy+light, c.quorum))
	require.False(t, quorumweight.Reached(3*light, c.quorum), "three light members are 3 of 7")

	for name, change := range map[string]func(*Profile){
		"the unit profile refuses weights":  func(p *Profile) { p.Mode = weightvalidation.ModeUnit },
		"an unset mode is the unit profile": func(p *Profile) { p.Mode = 0 },
		"a threshold below the exact one":   func(p *Profile) { p.TrustBase.QuorumThreshold = 6 },
		"a threshold above the exact one":   func(p *Profile) { p.TrustBase.QuorumThreshold = 8 },
		"a weight above the member cap":     func(p *Profile) { p.TrustBase.RootNodes[0].Stake = 1<<40 + 1 },
		"a zero weight":                     func(p *Profile) { p.TrustBase.RootNodes[1].Stake = 0 },
		"a duplicated signing key":          func(p *Profile) { p.TrustBase.RootNodes[2].SigKey = bytes.Clone(p.TrustBase.RootNodes[1].SigKey) },
	} {
		t.Run(name, func(t *testing.T) {
			p := weightedProfile(t)
			change(&p)
			got, err := NewCollector(p)
			require.ErrorIs(t, err, ErrProfile)
			require.Nil(t, got)
		})
	}
}
