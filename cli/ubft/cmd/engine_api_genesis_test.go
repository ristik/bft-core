package cmd

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	testobserve "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
)

// finalizedGenesis is the part of the emitted JSON these tests read.
type finalizedGenesis struct {
	Alloc map[string]struct {
		Balance string            `json:"balance"`
		Code    string            `json:"code"`
		Storage map[string]string `json:"storage"`
	} `json:"alloc"`
}

func writeGenesisShardConf(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shard-conf.json")
	require.NoError(t, util.WriteJsonFile(path, certifiedchain.Config(3)))
	return path
}

// runEngineAPIGenesis runs the command and returns its combined stdout and the error.
func runEngineAPIGenesis(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := New(testobserve.NewFactory(t))
	cmd.baseCmd.SetOut(&out)
	cmd.baseCmd.SetArgs(append([]string{"engine-api", "genesis"}, args...))
	err := cmd.Execute(context.Background())
	return out.String(), err
}

func readFinalizedGenesis(t *testing.T, path string) finalizedGenesis {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc finalizedGenesis
	require.NoError(t, json.Unmarshal(raw, &doc))
	return doc
}

func registryAllocKey() string { return strings.ToLower(registryproof.RegistryAddress.Hex()) }

// TestEngineAPIGenesis_CarriesThePinnedRegistryAccount is the unit's whole point: the generated
// artifact allocates a_sr with the pinned runtime code and the initialized registry storage, instead
// of the empty alloc the command used to write.
func TestEngineAPIGenesis_CarriesThePinnedRegistryAccount(t *testing.T) {
	shardConf := writeGenesisShardConf(t)
	out := filepath.Join(t.TempDir(), "genesis.json")

	stdout, err := runEngineAPIGenesis(t, "--shard-conf", shardConf, "--out", out)
	require.NoError(t, err)

	art, err := registrygenesis.PinnedArtifact()
	require.NoError(t, err)

	doc := readFinalizedGenesis(t, out)
	account, ok := doc.Alloc[registryAllocKey()]
	require.True(t, ok, "finalized genesis must allocate a_sr %s", registryproof.RegistryAddress)
	require.Equal(t, hexutil.Encode(art.RuntimeCode), account.Code, "a_sr must carry the pinned runtime code")
	require.NotEmpty(t, account.Storage, "a_sr must carry the initialized registry storage")
	for key := range account.Storage {
		require.Contains(t, slotKeySet(), common.HexToHash(key), "a_sr storage key %s is not one of the pinned 22 slots", key)
	}

	// The identities are printed, not written beside the artifact.
	for _, label := range []string{
		"full shard conf hash:", "state root:", "block hash:", "execution config identity:", "origin identity:",
	} {
		require.Contains(t, stdout, label)
	}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if i := strings.Index(line, "identity:"); i >= 0 {
			require.Regexp(t, `0x[0-9a-f]{64}$`, strings.TrimSpace(line[i+len("identity:"):]))
		}
	}
}

// TestEngineAPIGenesis_Deterministic proves the same inputs produce byte-identical output, which the
// printed identities and any later distribution digest depend on.
func TestEngineAPIGenesis_Deterministic(t *testing.T) {
	shardConf := writeGenesisShardConf(t)
	first := filepath.Join(t.TempDir(), "first.json")
	second := filepath.Join(t.TempDir(), "second.json")

	_, err := runEngineAPIGenesis(t, "--shard-conf", shardConf, "--out", first)
	require.NoError(t, err)
	_, err = runEngineAPIGenesis(t, "--shard-conf", shardConf, "--out", second)
	require.NoError(t, err)

	firstBytes, err := os.ReadFile(first)
	require.NoError(t, err)
	secondBytes, err := os.ReadFile(second)
	require.NoError(t, err)
	require.Equal(t, firstBytes, secondBytes)
}

// TestEngineAPIGenesis_RefusesRootEpochZero pins the refusal the v2 observation profile requires.
func TestEngineAPIGenesis_RefusesRootEpochZero(t *testing.T) {
	shardConf := writeGenesisShardConf(t)
	out := filepath.Join(t.TempDir(), "genesis.json")

	_, err := runEngineAPIGenesis(t, "--shard-conf", shardConf, "--out", out, "--root-epoch", "0")
	require.ErrorContains(t, err, "must be non-zero")
	require.NoFileExists(t, out)
}

// TestEngineAPIGenesis_RefusesAllocSourceCombinedWithTemplateFlags is the conflict rule: the file and
// a template-shaping flag must not silently fight over the same genesis field.
func TestEngineAPIGenesis_RefusesAllocSourceCombinedWithTemplateFlags(t *testing.T) {
	shardConf := writeGenesisShardConf(t)
	source := writeGenesisSource(t, 1337, map[string]any{
		"0x1000000000000000000000000000000000000001": map[string]any{"balance": "0x1"},
	})
	out := filepath.Join(t.TempDir(), "genesis.json")

	_, err := runEngineAPIGenesis(t, "--shard-conf", shardConf, "--out", out, "--alloc-source", source, "--gas-limit", "1")
	require.ErrorContains(t, err, "--alloc-source")
	require.ErrorContains(t, err, "--gas-limit")
	require.NoFileExists(t, out)
}

// TestEngineAPIGenesis_AllocSourceIsUsedVerbatim proves --alloc-source replaces the built-in template
// and that the operator's own allocation survives preparation.
func TestEngineAPIGenesis_AllocSourceIsUsedVerbatim(t *testing.T) {
	shardConf := writeGenesisShardConf(t)
	const funded = "0x1000000000000000000000000000000000000001"
	source := writeGenesisSource(t, 1337, map[string]any{
		funded: map[string]any{"balance": "0xde0b6b3a7640000"},
	})
	out := filepath.Join(t.TempDir(), "genesis.json")

	_, err := runEngineAPIGenesis(t, "--shard-conf", shardConf, "--out", out, "--alloc-source", source)
	require.NoError(t, err)

	doc := readFinalizedGenesis(t, out)
	require.Contains(t, doc.Alloc, strings.ToLower(funded), "the operator's funded account must survive preparation")
	require.Equal(t, "0xde0b6b3a7640000", doc.Alloc[strings.ToLower(funded)].Balance)
	require.Contains(t, doc.Alloc, registryAllocKey(), "the pinned registry account must still be inserted")
}

func TestEngineAPIGenesis_ManifestCompilesIntoStandardPipeline(t *testing.T) {
	shardConf := writeGenesisShardConf(t)
	manifestPath := filepath.Join(t.TempDir(), "allocation-build.json")
	baseManifest, err := os.ReadFile(filepath.Join("..", "..", "..", "registrygenesis", "testdata", "allocation-build-v1.example.json"))
	require.NoError(t, err)
	manifestBytes, err := registrygenesis.ExportAllocationManifest(baseManifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, manifestBytes, 0o600))
	out := filepath.Join(t.TempDir(), "genesis.json")
	_, err = runEngineAPIGenesis(t, "--shard-conf", shardConf, "--out", out, "--manifest", manifestPath)
	require.NoError(t, err)
	doc := readFinalizedGenesis(t, out)
	funded := "0x1000000000000000000000000000000000000001"
	expectedFunded, ok := new(big.Int).SetString("400000000000000000000000000", 10)
	require.True(t, ok)
	require.Equal(t, hexutil.EncodeBig(expectedFunded), doc.Alloc[funded].Balance)
	collector := "0x9b137463d4e7986d7f535f9b79e28b4ef1938e9b"
	require.NotEmpty(t, doc.Alloc[collector].Code, "fee beneficiary must retain exported FeeCollector code")
	require.Contains(t, doc.Alloc, registryAllocKey())

	_, err = runEngineAPIGenesis(t, "--shard-conf", shardConf, "--out", filepath.Join(t.TempDir(), "conflict.json"), "--manifest", manifestPath, "--alloc-source", manifestPath)
	require.ErrorContains(t, err, "mutually exclusive")
}

// TestEngineAPIGenesis_WritesTheFullShardConf is the other half of F4f section 2's output: the full
// shard configuration (the base conf plus seal_registry_genesis), whose hash is the fullShardConfHash
// an observation's ShardConfHash must equal. A node handed only the base conf can never satisfy that
// check, so this artifact is required, not cosmetic.
func TestEngineAPIGenesis_WritesTheFullShardConf(t *testing.T) {
	shardConfPath := writeGenesisShardConf(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "genesis.json")

	stdout, err := runEngineAPIGenesis(t, "--shard-conf", shardConfPath, "--out", out)
	require.NoError(t, err)

	// Defaulted beside --out.
	fullPath := filepath.Join(dir, "genesis-full-shard-conf.json")
	require.FileExists(t, fullPath)
	require.Contains(t, stdout, "wrote "+fullPath+" (full shard configuration)")

	// It loads through the CLI's ordinary shard-conf path: util.ReadJsonFile is the same call
	// baseFlags.loadConf makes for --shard-conf.
	var full types.PartitionDescriptionRecord
	_, err = util.ReadJsonFile(fullPath, &full)
	require.NoError(t, err)
	finalized, err := os.ReadFile(out)
	require.NoError(t, err)
	art, err := registrygenesis.PinnedArtifact()
	require.NoError(t, err)
	pins := registrygenesis.Pins{
		RootEpoch: 1, RegistryCodeHash: art.CodeHash,
		SystemAddress: registrygenesis.SystemAddress, RegistryAddress: registryproof.RegistryAddress,
	}
	origin, err := registrygenesis.ValidateFinalizedGenesisJSON(&full, pins, art, finalized, nil, registrygenesis.DefaultGenesisJSONLimits())
	require.NoError(t, err, "the emitted genesis must validate against the emitted full configuration")
	require.True(t, origin.Valid())

	// Its hash is the full shard conf hash the command printed.
	h, err := full.Hash(crypto.SHA256)
	require.NoError(t, err)
	require.Contains(t, stdout, "full shard conf hash:       "+common.BytesToHash(h).Hex())

	// It differs from the input base conf only by seal_registry_genesis.
	var base types.PartitionDescriptionRecord
	_, err = util.ReadJsonFile(shardConfPath, &base)
	require.NoError(t, err)
	require.NotContains(t, base.PartitionParams, registrygenesis.GenesisParam)
	commitment, ok := full.PartitionParams[registrygenesis.GenesisParam]
	require.True(t, ok, "the full conf must carry %s", registrygenesis.GenesisParam)
	require.Len(t, commitment, 64)
	delete(full.PartitionParams, registrygenesis.GenesisParam)
	require.Equal(t, base, full)

	// An explicit path is honored.
	explicit := filepath.Join(dir, "explicit-full.json")
	_, err = runEngineAPIGenesis(t, "--shard-conf", shardConfPath, "--out", filepath.Join(dir, "genesis2.json"), "--full-shard-conf", explicit)
	require.NoError(t, err)
	require.FileExists(t, explicit)
}

func TestEngineAPIGenesis_RejectsOverlappingOrIncompleteOutputs(t *testing.T) {
	shardConf := writeGenesisShardConf(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "genesis.json")

	_, err := runEngineAPIGenesis(t, "--shard-conf", shardConf, "--out", out,
		"--full-shard-conf", filepath.Join(dir, ".", "genesis.json"))
	require.ErrorContains(t, err, "must name different files")
	require.NoFileExists(t, out)

	_, err = runEngineAPIGenesis(t, "--shard-conf", shardConf, "--out", out,
		"--full-shard-conf", filepath.Join(dir, "missing", "full.json"))
	require.ErrorContains(t, err, "staging the full shard configuration")
	require.NoFileExists(t, out, "a failed second stage must not publish the genesis")
}

func slotKeySet() map[common.Hash]struct{} {
	out := make(map[common.Hash]struct{}, registryproof.FieldCount)
	for i := 0; i < registryproof.FieldCount; i++ {
		out[registryproof.SlotKey(i)] = struct{}{}
	}
	return out
}

func writeGenesisSource(t *testing.T, chainID uint64, alloc map[string]any) string {
	t.Helper()
	doc := map[string]any{
		"config": map[string]any{
			"chainId":        chainID,
			"homesteadBlock": 0, "eip150Block": 0, "eip155Block": 0, "eip158Block": 0,
			"byzantiumBlock": 0, "constantinopleBlock": 0, "petersburgBlock": 0,
			"istanbulBlock": 0, "berlinBlock": 0, "londonBlock": 0, "mergeNetsplitBlock": 0,
			"shanghaiTime": 0, "cancunTime": 0,
			"terminalTotalDifficulty": 0, "terminalTotalDifficultyPassed": true,
		},
		"nonce": "0x0", "timestamp": "0x0", "extraData": "0x",
		"gasLimit": "0x1c9c380", "difficulty": "0x0",
		"mixHash": common.Hash{}.Hex(), "coinbase": common.Address{}.Hex(),
		"alloc": alloc, "baseFeePerGas": "0x3b9aca00",
	}
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "source.json")
	require.NoError(t, os.WriteFile(path, raw, 0600))
	return path
}

// The launch genesis (registry layout 2) always sets validator_coupling=true in the exported EVM configuration, so every root
// validator refuses an uncoupled committee change; layout 1 keeps its legacy configuration.
func TestEngineAPIGenesis_Layout2ExportsTheCouplingParameter(t *testing.T) {
	shardConfPath := writeGenesisShardConf(t)
	dir := t.TempDir()
	exportFull := func(t *testing.T, conf string, extra ...string) (types.PartitionDescriptionRecord, error) {
		t.Helper()
		full := filepath.Join(dir, "full-"+filepath.Base(t.Name())+".json")
		args := append([]string{"--shard-conf", conf, "--out", filepath.Join(dir, "g-"+filepath.Base(t.Name())+".json"), "--full-shard-conf", full}, extra...)
		if _, err := runEngineAPIGenesis(t, args...); err != nil {
			return types.PartitionDescriptionRecord{}, err
		}
		var out types.PartitionDescriptionRecord
		_, err := util.ReadJsonFile(full, &out)
		return out, err
	}
	t.Run("layout 2 carries it and the hash commits to it", func(t *testing.T) {
		full, err := exportFull(t, shardConfPath, "--registry-layout", "2")
		require.NoError(t, err)
		require.Equal(t, "true", full.PartitionParams[evmassign.CouplingParam])
		require.True(t, evmassign.CouplingRequired(&full))
		without := full
		without.PartitionParams = map[string]string{}
		for k, v := range full.PartitionParams {
			if k != evmassign.CouplingParam {
				without.PartitionParams[k] = v
			}
		}
		a, err := full.Hash(crypto.SHA256)
		require.NoError(t, err)
		b, err := without.Hash(crypto.SHA256)
		require.NoError(t, err)
		require.NotEqual(t, a, b, "the full configuration hash commits to the parameter")
	})
	t.Run("layout 1 is unchanged", func(t *testing.T) {
		full, err := exportFull(t, shardConfPath)
		require.NoError(t, err)
		require.NotContains(t, full.PartitionParams, evmassign.CouplingParam)
	})
	t.Run("an explicit opt-out is refused", func(t *testing.T) {
		var base types.PartitionDescriptionRecord
		_, err := util.ReadJsonFile(shardConfPath, &base)
		require.NoError(t, err)
		base.PartitionParams = map[string]string{"chain_id": base.PartitionParams["chain_id"], evmassign.CouplingParam: "false"}
		optOut := filepath.Join(t.TempDir(), "optout.json")
		require.NoError(t, util.WriteJsonFile(optOut, &base))
		_, err = exportFull(t, optOut, "--registry-layout", "2")
		require.ErrorContains(t, err, "requires validator_coupling=true")
	})
}
