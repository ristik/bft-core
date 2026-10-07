package registrygenesis

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1registry"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/registryproof"
)

func TestFreshB1ArtifactGuards(t *testing.T) {
	p := b1state.Profile{Network: 5, RootGenesisID: [32]byte{1}, ExecutionChainID: 1337, RuntimeHash: [32]byte(common.HexToHash(b1registry.CodeHashHex)), CompilerHash: b1registry.CompilerHash(), WCert: 0, DeltaEV: 1, DeltaHold: 2, RestGas: 2238000, CompanionBytes: 1 << 20, OtherCompanionBytes: 65536, OrdinaryCapacity: 7000000}
	p.SystemGas, _ = p.RequiredSystemGas()
	p.MaxGas = p.SystemGas + p.OrdinaryCapacity
	code, err := b1registry.Runtime()
	require.NoError(t, err)
	a := Artifact{RuntimeCode: code, CodeHash: common.Hash(p.RuntimeHash), Layout: registryproof.FreshB1, b1: &b1GenesisConfig{profile: p}}
	require.NoError(t, a.check())
	t.Run("missing-config", func(t *testing.T) { b := a; b.b1 = nil; require.ErrorIs(t, b.check(), ErrArtifact) })
	t.Run("profile", func(t *testing.T) {
		b := a
		local := *a.b1
		b.b1 = &local
		b.b1.profile.SystemGas--
		require.ErrorIs(t, b.check(), b1state.ErrProfile)
	})
	t.Run("runtime", func(t *testing.T) {
		b := a
		b.RuntimeCode = []byte{0}
		b.CodeHash = crypto.Keccak256Hash(b.RuntimeCode)
		require.ErrorIs(t, b.check(), ErrArtifact)
	})
}
