package main

import (
	"encoding/json"
	"flag"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"os"
	"path/filepath"
	"strings"
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

// mutateRegistry edits the registry account of a genesis JSON: each case changes exactly one thing.
func mutateRegistry(t *testing.T, genesis []byte, edit func(code *string, storage map[string]string, acct map[string]any)) []byte {
	t.Helper()
	var spec map[string]any
	require.NoError(t, json.Unmarshal(genesis, &spec))
	alloc := spec["alloc"].(map[string]any)
	for k, v := range alloc {
		if strings.EqualFold(strings.TrimPrefix(k, "0x"), "ff00000000000000000000000000000000000002") {
			acct := v.(map[string]any)
			code := acct["code"].(string)
			raw := acct["storage"].(map[string]any)
			storage := map[string]string{}
			for sk, sv := range raw {
				storage[sk] = sv.(string)
			}
			edit(&code, storage, acct)
			acct["code"] = code
			out := map[string]any{}
			for sk, sv := range storage {
				out[sk] = sv
			}
			acct["storage"] = out
			alloc[k] = acct
		}
	}
	out, err := json.Marshal(spec)
	require.NoError(t, err)
	return out
}

// The deployed registry account is compared with an independent regeneration, code and storage: the unchanged genesis passes, and each single
// change to the deployed account (a code byte, a word, an extra word, a missing word, a nonce, an absent account) is refused by its own sentinel.
func TestVerifyComparesTheDeployedRegistryAccountWithTheRegeneration(t *testing.T) {
	f := b1fixture.New(t, 0)
	genesis := f.Genesis.GenesisJSON()
	words, err := verifyDeployed(f.Genesis, f.Pair.Profile.RuntimeHash, genesis)
	require.NoError(t, err)
	require.Positive(t, words)

	flipLast := func(s string) string {
		b := []byte(s)
		if b[len(b)-1] == '0' {
			b[len(b)-1] = '1'
		} else {
			b[len(b)-1] = '0'
		}
		return string(b)
	}
	cases := []struct {
		name string
		edit func(code *string, storage map[string]string, acct map[string]any)
		want error
	}{
		{"a code byte", func(code *string, _ map[string]string, _ map[string]any) { *code = flipLast(*code) }, ErrDeployedCode},
		{"truncated code", func(code *string, _ map[string]string, _ map[string]any) { *code = (*code)[:len(*code)-2] }, ErrDeployedCode},
		{"a storage word's value", func(_ *string, s map[string]string, _ map[string]any) {
			for k, v := range s {
				if v != "0x0000000000000000000000000000000000000000000000000000000000000000" {
					s[k] = flipLast(v)
					return
				}
			}
		}, ErrDeployedStorage},
		{"an extra storage word", func(_ *string, s map[string]string, _ map[string]any) {
			s["0x"+strings.Repeat("ab", 32)] = "0x" + strings.Repeat("00", 31) + "07"
		}, ErrDeployedStorage},
		{"a missing storage word", func(_ *string, s map[string]string, _ map[string]any) {
			for k, v := range s {
				if v != "0x0000000000000000000000000000000000000000000000000000000000000000" {
					delete(s, k)
					return
				}
			}
		}, ErrDeployedStorage},
		{"a nonce on the account", func(_ *string, _ map[string]string, a map[string]any) { a["nonce"] = "0x1" }, ErrDeployedAccount},
		{"a balance on the account", func(_ *string, _ map[string]string, a map[string]any) { a["balance"] = "0x5" }, ErrDeployedAccount},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := verifyDeployed(f.Genesis, f.Pair.Profile.RuntimeHash, mutateRegistry(t, genesis, c.edit))
			require.ErrorIs(t, err, c.want)
		})
	}
	// two keys that resolve to the registry address, the second tampered: refused every time (the result must not depend on map order)
	t.Run("the registry address allocated under two keys", func(t *testing.T) {
		var spec map[string]any
		require.NoError(t, json.Unmarshal(genesis, &spec))
		alloc := spec["alloc"].(map[string]any)
		for k, v := range alloc {
			if strings.EqualFold(strings.TrimPrefix(k, "0x"), "ff00000000000000000000000000000000000002") {
				tampered := map[string]any{}
				for ak, av := range v.(map[string]any) {
					tampered[ak] = av
				}
				tampered["code"] = "0x00"
				alloc["0x"+strings.ToUpper(strings.TrimPrefix(k, "0x"))] = tampered
				break
			}
		}
		raw, err := json.Marshal(spec)
		require.NoError(t, err)
		for i := 0; i < 200; i++ {
			_, err = verifyDeployed(f.Genesis, f.Pair.Profile.RuntimeHash, raw)
			require.ErrorIs(t, err, ErrDeployedAliased)
		}
	})
	t.Run("the registry account absent", func(t *testing.T) {
		var spec map[string]any
		require.NoError(t, json.Unmarshal(genesis, &spec))
		spec["alloc"] = map[string]any{}
		raw, err := json.Marshal(spec)
		require.NoError(t, err)
		_, err = verifyDeployed(f.Genesis, f.Pair.Profile.RuntimeHash, raw)
		require.ErrorIs(t, err, ErrDeployedAbsent)
	})
	t.Run("not a genesis", func(t *testing.T) {
		_, err := verifyDeployed(f.Genesis, f.Pair.Profile.RuntimeHash, []byte("not json"))
		require.ErrorIs(t, err, ErrDeployedGenesis)
	})
	t.Run("a profile that commits to another runtime", func(t *testing.T) {
		other := f.Pair.Profile.RuntimeHash
		other[0] ^= 1
		_, err := verifyDeployed(f.Genesis, other, genesis)
		require.ErrorIs(t, err, ErrRegeneratedCode)
	})
}

// --verify through the command: the deployed genesis the lane's clients run is checked against the inputs the chain was made from.
func TestVerifyFlagThroughTheCommand(t *testing.T) {
	f := b1fixture.New(t, 0)
	dir := t.TempDir()
	write := func(name string, v any) string {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, raw, 0600))
		return path
	}
	full, err := f.Genesis.FullConfig()
	require.NoError(t, err)
	profile, root, shard := write("profile.json", f.Pair.Profile), write("root.json", f.Chain.TrustBase), write("shard.json", full)
	good := filepath.Join(dir, "genesis.json")
	require.NoError(t, os.WriteFile(good, f.Genesis.GenesisJSON(), 0600))
	bad := filepath.Join(dir, "bad-genesis.json")
	require.NoError(t, os.WriteFile(bad, mutateRegistry(t, f.Genesis.GenesisJSON(), func(code *string, _ map[string]string, _ map[string]any) { *code = (*code)[:len(*code)-2] + "ff" }), 0600))
	oldArgs, oldFlags := os.Args, flag.CommandLine
	t.Cleanup(func() { os.Args, flag.CommandLine = oldArgs, oldFlags })
	invoke := func(args ...string) error {
		os.Args = append([]string{"b1genesis"}, args...)
		flag.CommandLine = flag.NewFlagSet("b1genesis", flag.ContinueOnError)
		return run()
	}
	require.NoError(t, invoke("--profile", profile, "--root-genesis", root, "--shard-conf", shard, "--verify", good))
	require.ErrorIs(t, invoke("--profile", profile, "--root-genesis", root, "--shard-conf", shard, "--verify", bad), ErrDeployedCode)
	// the supplied full configuration's genesis commitment must be the regenerated one (it hashes the record, which includes the B1 profile hash, not the genesis bytes)
	wrong := *full
	wrong.PartitionParams = map[string]string{}
	for k, v := range full.PartitionParams {
		wrong.PartitionParams[k] = v
	}
	wrong.PartitionParams[registrygenesis.GenesisParam] = strings.Repeat("ab", 32)
	require.ErrorIs(t, invoke("--profile", profile, "--root-genesis", root, "--shard-conf", write("wrong-commitment.json", wrong), "--verify", good), ErrCommitment)
	require.Error(t, invoke("--profile", profile, "--root-genesis", root, "--shard-conf", shard), "neither --out nor --verify")
	require.Error(t, invoke("--profile", profile, "--root-genesis", root, "--shard-conf", shard, "--verify", good, "--out", filepath.Join(dir, "x")), "both")
}
