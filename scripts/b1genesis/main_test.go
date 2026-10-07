package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/b1fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
)

func TestOfflineExportBindsFreshAllocationAndRefusesOverwrite(t *testing.T) {
	f := b1fixture.New(t, 0)
	dir := t.TempDir()
	write := func(name string, v any) string {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, raw, 0600))
		return path
	}
	oldArgs, oldFlags := os.Args, flag.CommandLine
	t.Cleanup(func() { os.Args, flag.CommandLine = oldArgs, oldFlags })
	out := filepath.Join(dir, "export")
	os.Args = []string{"b1genesis", "--profile", write("profile.json", f.Pair.Profile), "--root-genesis", write("root.json", f.Chain.TrustBase), "--shard-conf", write("shard.json", certifiedchain.Config(5)), "--out", out}
	flag.CommandLine = flag.NewFlagSet("b1genesis", flag.ContinueOnError)
	require.NoError(t, run())
	raw, err := os.ReadFile(filepath.Join(out, "genesis.json"))
	require.NoError(t, err)
	require.JSONEq(t, string(f.Genesis.GenesisJSON()), string(raw))
	raw, err = os.ReadFile(filepath.Join(out, "manifest.json"))
	require.NoError(t, err)
	var manifest struct {
		Active               bool              `json:"active"`
		StorageWords         map[string]string `json:"storageWords"`
		ExecutionGenesisHash string            `json:"executionGenesisHash"`
	}
	require.NoError(t, json.Unmarshal(raw, &manifest))
	require.False(t, manifest.Active)
	require.Equal(t, f.Genesis.EVMGenesisHash().Hex(), manifest.ExecutionGenesisHash)
	require.Len(t, manifest.StorageWords, len(f.Genesis.B1Words()))
	for key, value := range f.Genesis.B1Words() {
		require.Equal(t, value.Hex(), manifest.StorageWords[key.Hex()])
	}
	flag.CommandLine = flag.NewFlagSet("b1genesis", flag.ContinueOnError)
	require.ErrorIs(t, run(), os.ErrExist)
}
