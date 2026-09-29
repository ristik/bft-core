package registrygenesis

import (
	"bytes"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/registryproof"
)

func syntheticManifest() AllocationManifest {
	collector := "0x3000000000000000000000000000000000000001"
	wuct := "0x3000000000000000000000000000000000000002"
	treasury := "0x3000000000000000000000000000000000000003"
	return AllocationManifest{
		Version:      AllocationManifestVersion,
		NativeSupply: "1000000",
		Chain: ManifestChain{ChainID: 1337, Forks: ManifestForks{
			TerminalTotalDifficulty: "0", TerminalTotalDifficultyPassed: true,
		}},
		Genesis: ManifestGenesis{GasLimit: 30_000_000, BaseFeePerGas: "1000000000"},
		Addresses: ManifestAddresses{
			System: SystemAddress.Hex(), Registry: registryproof.RegistryAddress.Hex(),
			FeeCollector: collector, WUCT: wuct, Treasury: treasury,
			TeamVesting: "0x3000000000000000000000000000000000000004", EcosystemVesting: "0x3000000000000000000000000000000000000005",
		},
		FeeBeneficiary: collector,
		FeeSplit:       ManifestFeeSplit{TreasuryBps: 10_000},
		Allocations: []ManifestAllocation{
			{Purpose: "test_eoa", Recipient: "0x1000000000000000000000000000000000000001", Kind: "eoa", Amount: "700000"},
			{Purpose: "test_collector", Recipient: collector, Kind: "contract_pot", Amount: "300000"},
		},
		BootstrapGasBudgets: []ManifestGasBudget{{Recipient: "0x1000000000000000000000000000000000000001", Gas: 250_000}},
		Contracts: []ManifestContract{
			{Name: "feeCollector", Address: collector, Artifact: "synthetic/fee-collector.json#/runtime", SHA256: strings.Repeat("a", 64)},
			{Name: "wuct", Address: wuct, Artifact: "synthetic/wuct.json#/runtime", SHA256: strings.Repeat("b", 64)},
			{Name: "teamVesting", Address: "0x3000000000000000000000000000000000000004", Artifact: "synthetic/team-vault.json#/runtime", SHA256: strings.Repeat("c", 64)},
			{Name: "ecosystemVesting", Address: "0x3000000000000000000000000000000000000005", Artifact: "synthetic/ecosystem-vault.json#/runtime", SHA256: strings.Repeat("d", 64)},
		},
	}
}

func manifestBytes(t *testing.T, m AllocationManifest) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return b
}

func TestCompileAllocationManifestIntoExistingGenesisPipeline(t *testing.T) {
	m := syntheticManifest()
	input := manifestBytes(t, m)
	one, err := CompileAllocationManifest(input, 1337)
	require.NoError(t, err)
	two, err := CompileAllocationManifest(input, 1337)
	require.NoError(t, err)
	require.Equal(t, one, two, "two builds from the same manifest are byte-identical")

	prepared, err := PrepareGenesisJSON(vectorConfig(), vectorPins(pinnedArtifact(t)), pinnedArtifact(t), one, GenesisJSONLimits{})
	require.NoError(t, err)
	var finalized map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(prepared.GenesisJSON(), &finalized))
	var alloc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(finalized["alloc"], &alloc))
	require.Contains(t, alloc, common.HexToAddress(m.Addresses.FeeCollector).Hex())
	require.Contains(t, alloc, registryproof.RegistryAddress.Hex(), "existing preparation adds the registry predeploy")
	require.True(t, prepared.Origin().Valid())
}

func TestOwnerDirectionExampleManifest(t *testing.T) {
	path := filepath.Join("testdata", "allocation-build-v1.example.json")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	m, err := DecodeAllocationManifest(raw)
	require.NoError(t, err)
	require.Equal(t, "1000000000000000000000000000", m.NativeSupply)
	require.Equal(t, ManifestFeeSplit{TreasuryBps: 10_000}, m.FeeSplit)
	require.Len(t, m.Allocations, 6) // four allocation classes, with the gas class split across three EOAs
	compiled, err := CompileAllocationManifest(raw, 1337)
	require.NoError(t, err)
	prepared, err := PrepareGenesisJSON(vectorConfig(), vectorPins(pinnedArtifact(t)), pinnedArtifact(t), compiled, GenesisJSONLimits{})
	require.NoError(t, err)
	require.True(t, prepared.Origin().Valid())
}

func TestAllocationManifestCanonicalOrderingAndFormatting(t *testing.T) {
	m := syntheticManifest()
	canonical, err := CompileAllocationManifest(manifestBytes(t, m), 1337)
	require.NoError(t, err)

	// Recipient ordering and JSON whitespace/key formatting are not semantic inputs.
	m.Allocations[0], m.Allocations[1] = m.Allocations[1], m.Allocations[0]
	compact, err := json.Marshal(m)
	require.NoError(t, err)
	var generic any
	require.NoError(t, json.Unmarshal(compact, &generic))
	formatted, err := json.MarshalIndent(generic, "", "    ")
	require.NoError(t, err)
	compiled, err := CompileAllocationManifest(formatted, 1337)
	require.NoError(t, err)
	require.Equal(t, canonical, compiled)
}

func TestAllocationManifestExactSupplyAndOffByOne(t *testing.T) {
	m := syntheticManifest()
	require.NoError(t, validateAllocationManifest(m))
	m.Allocations[0].Amount = "699999"
	err := validateAllocationManifest(m)
	require.ErrorIs(t, err, ErrAllocationManifest)
	require.ErrorContains(t, err, "does not equal nativeSupply")
	m = syntheticManifest()
	m.Allocations[0].Amount = "700001"
	err = validateAllocationManifest(m)
	require.ErrorIs(t, err, ErrAllocationManifest)
	require.ErrorContains(t, err, "does not equal nativeSupply")
}

func TestAllocationManifestRejectsDuplicateRecipientAndReservedCollisions(t *testing.T) {
	t.Run("duplicate recipient", func(t *testing.T) {
		m := syntheticManifest()
		m.Allocations = append(m.Allocations, ManifestAllocation{Purpose: "duplicate", Recipient: m.Allocations[0].Recipient, Kind: "eoa", Amount: "0"})
		require.ErrorIs(t, validateAllocationManifest(m), ErrAllocationManifest)
	})
	t.Run("system address", func(t *testing.T) {
		m := syntheticManifest()
		m.Allocations[0].Recipient = m.Addresses.System
		require.ErrorIs(t, validateAllocationManifest(m), ErrAllocationManifest)
	})
	t.Run("registry address", func(t *testing.T) {
		m := syntheticManifest()
		m.Allocations[0].Recipient = m.Addresses.Registry
		require.ErrorIs(t, validateAllocationManifest(m), ErrAllocationManifest)
	})
	t.Run("precompile address", func(t *testing.T) {
		m := syntheticManifest()
		m.Allocations[0].Recipient = "0x0000000000000000000000000000000000000001"
		require.ErrorIs(t, validateAllocationManifest(m), ErrAllocationManifest)
	})
	t.Run("gas budget precompile", func(t *testing.T) {
		m := syntheticManifest()
		m.BootstrapGasBudgets[0].Recipient = "0x0000000000000000000000000000000000000001"
		require.ErrorIs(t, validateAllocationManifest(m), ErrAllocationManifest)
	})
	t.Run("fixed contract precompile", func(t *testing.T) {
		m := syntheticManifest()
		m.Addresses.WUCT = "0x000000000000000000000000000000000000000a"
		m.Contracts[1].Address = m.Addresses.WUCT
		require.ErrorIs(t, validateAllocationManifest(m), ErrAllocationManifest)
	})
}

func TestAllocationManifestRejectsBeneficiaryAndChainMismatch(t *testing.T) {
	m := syntheticManifest()
	m.FeeBeneficiary = "0x4000000000000000000000000000000000000001"
	require.ErrorIs(t, validateAllocationManifest(m), ErrAllocationManifest)
	require.ErrorIs(t, func() error {
		_, err := CompileAllocationManifest(manifestBytes(t, syntheticManifest()), 1338)
		return err
	}(), ErrAllocationManifest)
}

func TestDecodeAllocationManifestIsStrict(t *testing.T) {
	valid := manifestBytes(t, syntheticManifest())
	var doc map[string]any
	require.NoError(t, json.Unmarshal(valid, &doc))
	doc["unknown"] = true
	unknown, err := json.Marshal(doc)
	require.NoError(t, err)
	_, err = DecodeAllocationManifest(unknown)
	require.ErrorIs(t, err, ErrAllocationManifest)

	duplicate := bytes.Replace(valid, []byte(`"version":`), []byte(`"version":"unicity/allocation-build/v1","version":`), 1)
	_, err = DecodeAllocationManifest(duplicate)
	require.ErrorIs(t, err, ErrAllocationManifest)
	_, err = DecodeAllocationManifest(append(valid, []byte(` {}`)...))
	require.ErrorIs(t, err, ErrAllocationManifest)
	var missing map[string]any
	require.NoError(t, json.Unmarshal(valid, &missing))
	delete(missing["chain"].(map[string]any)["forks"].(map[string]any), "londonBlock")
	withoutFork, err := json.Marshal(missing)
	require.NoError(t, err)
	_, err = DecodeAllocationManifest(withoutFork)
	require.ErrorIs(t, err, ErrAllocationManifest)
}

func TestAllocationManifestAmountsUseExactIntegers(t *testing.T) {
	m := syntheticManifest()
	m.NativeSupply = "01000000"
	require.ErrorIs(t, validateAllocationManifest(m), ErrAllocationManifest)
	m = syntheticManifest()
	m.Allocations[0].Amount = "1e6"
	require.ErrorIs(t, validateAllocationManifest(m), ErrAllocationManifest)
	m = syntheticManifest()
	m.NativeSupply = new(big.Int).Add(big.NewInt(1_000_000), big.NewInt(1)).String()
	require.ErrorIs(t, validateAllocationManifest(m), ErrAllocationManifest)
}
