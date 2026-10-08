package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/q4replay"
)

func bundle(t *testing.T, weight uint64) string {
	s, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	v, err := s.Verifier()
	require.NoError(t, err)
	pub, err := v.MarshalPublicKey()
	require.NoError(t, err)
	b := &q4replay.Bundle{Version: q4replay.Version, Scenario: "cli", Class: q4replay.InBound, Epochs: []q4replay.Epoch{{Epoch: 1, Scheme: 1, Total: 3, Quorum: 3, Members: []q4replay.Member{{Name: "a", ID: "a", PubKey: pub, Weight: weight}}}}}
	path := filepath.Join(t.TempDir(), "b.json")
	require.NoError(t, b.Save(path))
	return path
}

func TestCommandExitStatuses(t *testing.T) {
	out, err := os.Create(filepath.Join(t.TempDir(), "out"))
	require.NoError(t, err)
	defer out.Close()
	require.Equal(t, 0, run([]string{"check", bundle(t, 3)}, out, out))
	require.Equal(t, 1, run([]string{"check", bundle(t, 2)}, out, out), "claimed total differs from the weights")
	require.Equal(t, 1, run([]string{"check", "-equivocators", "a", bundle(t, 3)}, out, out), "no equivocator was found, the claim fails")
	require.Equal(t, 2, run([]string{"check", filepath.Join(t.TempDir(), "missing.json")}, out, out))
	require.Equal(t, 2, run(nil, out, out))
}
