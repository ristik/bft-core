package b1registry_test

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1registry"
	"github.com/unicitynetwork/bft-core/b1state"
)

func profile(k uint64) b1state.Profile {
	p := b1state.Profile{Network: 5, RootGenesisID: [32]byte{1}, ExecutionChainID: 1337, RuntimeHash: [32]byte(common.HexToHash(b1registry.CodeHashHex)), CompilerHash: b1registry.CompilerHash(), WCert: k - 1, DeltaEV: k, DeltaHold: k + 1, RestGas: 1136500 + 1147500*k, CompanionBytes: 1 << 20, OtherCompanionBytes: 65536, OrdinaryCapacity: 7000000, GenesisUCTime: 1000}
	p.SystemGas, _ = p.RequiredSystemGas()
	p.MaxGas = p.SystemGas + p.OrdinaryCapacity
	return p
}
func TestMeasuredProfileBoundaries(t *testing.T) {
	for k := uint64(1); k <= 16; k++ {
		require.NoError(t, b1registry.ValidateProfile(profile(k)))
	}
	p := profile(17)
	require.ErrorIs(t, b1registry.ValidateProfile(p), b1registry.ErrArtifact)
	for _, tc := range []struct {
		name   string
		change func(*b1state.Profile)
		want   error
	}{
		{"runtime", func(p *b1state.Profile) { p.RuntimeHash[0] ^= 1 }, b1registry.ErrArtifact},
		{"compiler", func(p *b1state.Profile) { p.CompilerHash[0] ^= 1 }, b1registry.ErrArtifact},
		{"rest", func(p *b1state.Profile) { p.RestGas-- }, b1registry.ErrArtifact},
		{"system", func(p *b1state.Profile) { p.SystemGas--; p.MaxGas-- }, b1state.ErrProfile},
		{"ordinary", func(p *b1state.Profile) { p.OrdinaryCapacity-- }, b1state.ErrProfile},
		{"transport", func(p *b1state.Profile) {
			_, cap, _, _ := p.Bounds()
			p.CompanionBytes = cap + p.OtherCompanionBytes - 1
		}, b1state.ErrProfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := profile(16)
			tc.change(&p)
			require.ErrorIs(t, b1registry.ValidateProfile(p), tc.want)
		})
	}
}
