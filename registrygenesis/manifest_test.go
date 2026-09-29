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
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
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
		Genesis:    ManifestGenesis{GasLimit: 30_000_000, BaseFeePerGas: "1000000000"},
		Deployment: ManifestDeployment{Deployer: "0x000000000000000000000000000000000000dEaD"},
		Addresses: ManifestAddresses{
			System: SystemAddress.Hex(), Registry: registryproof.RegistryAddress.Hex(),
			FeeCollector: collector, WUCT: wuct, Treasury: treasury,
			TeamVesting: "0x3000000000000000000000000000000000000004", EcosystemVesting: "0x3000000000000000000000000000000000000005",
		},
		FeeBeneficiary: collector,
		FeeSplit:       ManifestFeeSplit{TreasuryBps: 10_000},
		Allocations: []ManifestAllocation{
			{Purpose: "test_eoa", Recipient: "0x1000000000000000000000000000000000000001", Kind: "eoa", Amount: "700000"},
			{Purpose: "test_collector", Recipient: collector, Kind: "contract_pot", Amount: "300000", State: &ManifestAccountState{Code: "0x", CodeHash: crypto.Keccak256Hash(nil).Hex(), Storage: map[string]string{}}},
		},
		BootstrapGasBudgets: []ManifestGasBudget{{Recipient: "0x1000000000000000000000000000000000000001", Gas: 250_000}},
		Contracts: []ManifestContract{
			{Name: "feeCollector", Address: collector, Artifact: "synthetic/fee-collector.json#/runtime", SHA256: strings.Repeat("a", 64), SourceCommit: strings.Repeat("a", 40)},
			{Name: "wuct", Address: wuct, Artifact: "synthetic/wuct.json#/runtime", SHA256: strings.Repeat("b", 64), SourceCommit: strings.Repeat("b", 40)},
			{Name: "teamVesting", Address: "0x3000000000000000000000000000000000000004", Artifact: "synthetic/team-vault.json#/runtime", SHA256: strings.Repeat("c", 64), SourceCommit: strings.Repeat("c", 40)},
			{Name: "ecosystemVesting", Address: "0x3000000000000000000000000000000000000005", Artifact: "synthetic/ecosystem-vault.json#/runtime", SHA256: strings.Repeat("d", 64), SourceCommit: strings.Repeat("d", 40)},
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
	require.Len(t, m.Allocations, 8) // includes zero-supply contract accounts
	exported, err := ExportAllocationManifest(raw)
	require.NoError(t, err)
	compiled, err := CompileAllocationManifest(exported, 1337)
	require.NoError(t, err)
	prepared, err := PrepareGenesisJSON(vectorConfig(), vectorPins(pinnedArtifact(t)), pinnedArtifact(t), compiled, GenesisJSONLimits{})
	require.NoError(t, err)
	require.True(t, prepared.Origin().Valid())
}

func TestConstructorExportIsDeterministicAndComplete(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "allocation-build-v1.example.json"))
	require.NoError(t, err)
	one, err := ExportAllocationManifest(raw)
	require.NoError(t, err)
	two, err := ExportAllocationManifest(raw)
	require.NoError(t, err)
	require.Equal(t, one, two, "constructor execution and serialization are byte stable")

	exported, err := DecodeAllocationManifest(one)
	require.NoError(t, err)
	require.Equal(t, exported.Addresses.FeeCollector, exported.FeeBeneficiary)
	total := new(big.Int)
	for _, allocation := range exported.Allocations {
		amount, ok := new(big.Int).SetString(allocation.Amount, 10)
		require.True(t, ok)
		total.Add(total, amount)
		if allocation.Schedule != nil {
			require.NotNil(t, allocation.State)
			statusSlot := common.BigToHash(big.NewInt(0))
			require.Equal(t, common.BigToHash(big.NewInt(1)).Hex(), allocation.State.Storage[statusSlot.Hex()], "ReentrancyGuard slot 0 retains the constructor value")
			require.Equal(t, crypto.Keccak256Hash(common.FromHex(allocation.State.Code)).Hex(), allocation.State.CodeHash)
		}
	}
	require.Equal(t, exported.NativeSupply, total.String())
	compiled, err := CompileAllocationManifest(one, 1337)
	require.NoError(t, err)
	var genesis struct {
		Alloc map[string]struct {
			Balance string            `json:"balance"`
			Code    string            `json:"code"`
			Storage map[string]string `json:"storage"`
		} `json:"alloc"`
	}
	require.NoError(t, json.Unmarshal(compiled, &genesis))
	for _, allocation := range exported.Allocations {
		if allocation.Schedule == nil {
			continue
		}
		account := genesis.Alloc[common.HexToAddress(allocation.Recipient).Hex()]
		principal, _ := new(big.Int).SetString(allocation.Amount, 10)
		require.Equal(t, hexutil.EncodeBig(principal), account.Balance, "vault balance equals principal exactly")
		require.Equal(t, allocation.State.Code, account.Code)
		require.Equal(t, allocation.State.Storage, account.Storage)
	}
}

func TestConstructorExportRejectsUnreceivableVestingBeneficiary(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "allocation-build-v1.example.json"))
	require.NoError(t, err)
	var m AllocationManifest
	require.NoError(t, json.Unmarshal(raw, &m))
	for i := range m.Allocations {
		if m.Allocations[i].Schedule != nil {
			m.Allocations[i].BeneficiaryKind = "contract_receiver"
			m.Allocations[i].Beneficiary = m.Addresses.Treasury
			break
		}
	}
	_, err = ExportAllocationManifest(manifestBytes(t, m))
	require.ErrorIs(t, err, ErrAllocationManifest)
}

func TestConstructorExportAcceptsPayableContractBeneficiary(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "allocation-build-v1.example.json"))
	require.NoError(t, err)
	var m AllocationManifest
	require.NoError(t, json.Unmarshal(raw, &m))
	for i := range m.Allocations {
		if m.Allocations[i].Schedule != nil {
			m.Allocations[i].BeneficiaryKind = "contract_receiver"
			m.Allocations[i].Beneficiary = m.Addresses.FeeCollector
			break
		}
	}
	_, err = ExportAllocationManifest(manifestBytes(t, m))
	require.NoError(t, err, "FeeCollector has a payable receive function and accepts a one-wei probe transfer")
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
	require.ErrorIs(t, err, ErrManifestSupplySum)
	require.ErrorContains(t, err, "does not equal nativeSupply")
	m = syntheticManifest()
	m.Allocations[0].Amount = "700001"
	err = validateAllocationManifest(m)
	require.ErrorIs(t, err, ErrAllocationManifest)
	require.ErrorIs(t, err, ErrManifestSupplySum)
	require.ErrorContains(t, err, "does not equal nativeSupply")
}

func TestAllocationManifestRejectsDuplicateRecipientAndReservedCollisions(t *testing.T) {
	t.Run("duplicate recipient", func(t *testing.T) {
		m := syntheticManifest()
		m.Allocations = append(m.Allocations, ManifestAllocation{Purpose: "duplicate", Recipient: m.Allocations[0].Recipient, Kind: "eoa", Amount: "0"})
		err := validateAllocationManifest(m)
		require.ErrorIs(t, err, ErrAllocationManifest)
		require.ErrorIs(t, err, ErrManifestDuplicateRecipient)
	})
	t.Run("system address", func(t *testing.T) {
		m := syntheticManifest()
		m.Allocations[0].Recipient = m.Addresses.System
		err := validateAllocationManifest(m)
		require.ErrorIs(t, err, ErrAllocationManifest)
		require.ErrorIs(t, err, ErrManifestAddressCollision)
	})
	t.Run("registry address", func(t *testing.T) {
		m := syntheticManifest()
		m.Allocations[0].Recipient = m.Addresses.Registry
		err := validateAllocationManifest(m)
		require.ErrorIs(t, err, ErrAllocationManifest)
		require.ErrorIs(t, err, ErrManifestAddressCollision)
	})
	t.Run("precompile address", func(t *testing.T) {
		m := syntheticManifest()
		m.Allocations[0].Recipient = "0x0000000000000000000000000000000000000001"
		err := validateAllocationManifest(m)
		require.ErrorIs(t, err, ErrAllocationManifest)
		require.ErrorIs(t, err, ErrManifestAddressCollision)
	})
	t.Run("gas budget precompile", func(t *testing.T) {
		m := syntheticManifest()
		m.BootstrapGasBudgets[0].Recipient = "0x0000000000000000000000000000000000000001"
		err := validateAllocationManifest(m)
		require.ErrorIs(t, err, ErrAllocationManifest)
		require.ErrorIs(t, err, ErrManifestAddressCollision)
	})
	t.Run("fixed contract precompile", func(t *testing.T) {
		m := syntheticManifest()
		m.Addresses.WUCT = "0x000000000000000000000000000000000000000a"
		m.Contracts[1].Address = m.Addresses.WUCT
		err := validateAllocationManifest(m)
		require.ErrorIs(t, err, ErrAllocationManifest)
		require.ErrorIs(t, err, ErrManifestAddressCollision)
	})
}

func TestAllocationManifestRejectsBeneficiaryAndChainMismatch(t *testing.T) {
	m := syntheticManifest()
	m.FeeBeneficiary = "0x4000000000000000000000000000000000000001"
	err := validateAllocationManifest(m)
	require.ErrorIs(t, err, ErrAllocationManifest)
	require.ErrorIs(t, err, ErrManifestFeeBeneficiary)
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
	require.ErrorIs(t, err, ErrManifestStrictDecode)

	duplicate := bytes.Replace(valid, []byte(`"version":`), []byte(`"version":"unicity/allocation-build/v1","version":`), 1)
	_, err = DecodeAllocationManifest(duplicate)
	require.ErrorIs(t, err, ErrAllocationManifest)
	require.ErrorIs(t, err, ErrManifestStrictDecode)
	_, err = DecodeAllocationManifest(append(valid, []byte(` {}`)...))
	require.ErrorIs(t, err, ErrAllocationManifest)
	require.ErrorIs(t, err, ErrManifestStrictDecode)
	var missing map[string]any
	require.NoError(t, json.Unmarshal(valid, &missing))
	delete(missing["chain"].(map[string]any)["forks"].(map[string]any), "londonBlock")
	withoutFork, err := json.Marshal(missing)
	require.NoError(t, err)
	_, err = DecodeAllocationManifest(withoutFork)
	require.ErrorIs(t, err, ErrAllocationManifest)
	require.ErrorIs(t, err, ErrManifestStrictDecode)
}

func TestDecodeAllocationManifestRequiresSupportedVersion(t *testing.T) {
	valid := manifestBytes(t, syntheticManifest())
	var missing map[string]any
	require.NoError(t, json.Unmarshal(valid, &missing))
	delete(missing, "version")
	withoutVersion, err := json.Marshal(missing)
	require.NoError(t, err)
	_, err = DecodeAllocationManifest(withoutVersion)
	require.ErrorIs(t, err, ErrAllocationManifest)
	require.ErrorIs(t, err, ErrManifestVersion)

	var wrong map[string]any
	require.NoError(t, json.Unmarshal(valid, &wrong))
	wrong["version"] = "unicity/allocation-build/v999"
	wrongVersion, err := json.Marshal(wrong)
	require.NoError(t, err)
	_, err = DecodeAllocationManifest(wrongVersion)
	require.ErrorIs(t, err, ErrAllocationManifest)
	require.ErrorIs(t, err, ErrManifestVersion)
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
