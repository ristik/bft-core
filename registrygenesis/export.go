package registrygenesis

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

//go:embed testdata/t1-artifacts/*.json
var pinnedGenesisArtifacts embed.FS

const GenesisContractsCommit = "e7eb3216549b772a9e1df2b1214976d7dd9e6e62"

var (
	ErrGenesisExport           = errors.New("registrygenesis: constructor export failed")
	ErrGenesisPrincipalBalance = errors.New("registrygenesis: vault balance must equal principal")
)

type compilerArtifact struct {
	ABI                 json.RawMessage `json:"abi"`
	Bytecode            string          `json:"bytecode"`
	Runtime             string          `json:"runtime"`
	ImmutableReferences map[string][]struct {
		Start  int `json:"start"`
		Length int `json:"length"`
	} `json:"immutableReferences"`
	StorageLayout struct {
		Storage []struct {
			Label string `json:"label"`
			Slot  string `json:"slot"`
		} `json:"storage"`
	} `json:"storageLayout"`
}

// ExportAllocationManifest executes every pinned constructor in a local EVM and attaches each
// contract's constructor-executed account state to its allocation. Embedded compiler artifacts
// are content-hash checked against the manifest, so export is offline and deterministic.
func ExportAllocationManifest(data []byte) ([]byte, error) {
	return exportAllocationManifest(data, nil)
}

// exportAllocationManifest keeps the constructor export path testable against execution-state
// mismatches. afterFunding is nil in production and only allows same-package fixtures to model a
// genesis allocation/funding mismatch before the invariant is checked.
func exportAllocationManifest(data []byte, afterFunding func(*state.StateDB, common.Address)) ([]byte, error) {
	m, err := DecodeAllocationManifest(data)
	if err != nil {
		return nil, err
	}
	artifacts := make(map[string]compilerArtifact, 3)
	for _, c := range m.Contracts {
		if c.SourceCommit != GenesisContractsCommit {
			return nil, fmt.Errorf("%w: contract %s sourceCommit must be pinned to %s", ErrGenesisExport, c.Name, GenesisContractsCommit)
		}
		name := artifactName(c.Name)
		raw, err := pinnedGenesisArtifacts.ReadFile("testdata/t1-artifacts/" + name + ".json")
		if err != nil {
			return nil, fmt.Errorf("%w: unsupported embedded artifact %q", ErrGenesisExport, c.Artifact)
		}
		if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != c.SHA256 {
			return nil, fmt.Errorf("%w: artifact %s sha256 mismatch", ErrGenesisExport, c.Name)
		}
		if _, ok := artifacts[name]; ok {
			// Each declaration pins the artifact independently. In particular, both vault
			// entries must be checked even though they share the same compiler artifact.
			continue
		}
		var a compilerArtifact
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, fmt.Errorf("%w: decode artifact %s: %v", ErrGenesisExport, c.Name, err)
		}
		artifacts[name] = a
	}
	st, err := state.New(common.Hash{}, state.NewDatabaseForTesting())
	if err != nil {
		return nil, fmt.Errorf("%w: create state: %v", ErrGenesisExport, err)
	}
	deployer := common.HexToAddress(m.Deployment.Deployer)
	st.SetNonce(deployer, m.Deployment.FirstNonce)
	st.SetBalance(deployer, uint256.NewInt(0), 0)
	chain := *params.AllDevChainProtocolChanges
	chain.ChainID = new(big.Int).SetUint64(m.Chain.ChainID)
	zeroTime := uint64(0)
	chain.ShanghaiTime = &zeroTime
	chain.CancunTime = &zeroTime
	chain.PragueTime = nil
	chain.TerminalTotalDifficultyPassed = true
	baseFee, _ := new(big.Int).SetString(m.Genesis.BaseFeePerGas, 10)
	cfg := &runtime.Config{ChainConfig: &chain, Origin: deployer, Coinbase: common.HexToAddress(m.FeeBeneficiary), BlockNumber: new(big.Int).SetUint64(m.Deployment.BlockNumber), Time: m.Deployment.Timestamp, GasLimit: m.Genesis.GasLimit, BaseFee: baseFee, GasPrice: baseFee, State: st, Random: ptrHash(common.Hash{})}

	contracts := make(map[string]ManifestContract, len(m.Contracts))
	for _, c := range m.Contracts {
		contracts[c.Name] = c
	}
	order := []string{"feeCollector", "wuct", "teamVesting", "ecosystemVesting"}
	for i, name := range order {
		c := contracts[name]
		want := crypto.CreateAddress(deployer, m.Deployment.FirstNonce+uint64(i))
		if common.HexToAddress(c.Address) != want {
			return nil, fmt.Errorf("%w: %s address %s does not match deterministic CREATE address %s", ErrGenesisExport, name, c.Address, want)
		}
		artifact := artifacts[artifactName(name)]
		creation, err := hex.DecodeString(strings.TrimPrefix(artifact.Bytecode, "0x"))
		if err != nil {
			return nil, fmt.Errorf("%w: bad creation bytecode: %v", ErrGenesisExport, err)
		}
		parsed, err := abi.JSON(bytes.NewReader(artifact.ABI))
		if err != nil {
			return nil, fmt.Errorf("%w: bad ABI: %v", ErrGenesisExport, err)
		}
		var args []any
		switch name {
		case "feeCollector":
			args, err = feeCollectorArgs(m)
		case "wuct":
			args = nil
		case "teamVesting", "ecosystemVesting":
			var allocation *ManifestAllocation
			for j := range m.Allocations {
				if common.HexToAddress(m.Allocations[j].Recipient) == want {
					allocation = &m.Allocations[j]
					break
				}
			}
			if allocation == nil || allocation.Schedule == nil {
				return nil, fmt.Errorf("%w: %s has no vesting allocation and schedule", ErrGenesisExport, name)
			}
			beneficiary := common.HexToAddress(allocation.Beneficiary)
			if allocation.BeneficiaryKind != "eoa" && allocation.BeneficiaryKind != "contract_receiver" {
				return nil, fmt.Errorf("%w: %s beneficiaryKind must be eoa or contract_receiver", ErrGenesisExport, name)
			}
			if allocation.BeneficiaryKind == "eoa" && len(st.GetCode(beneficiary)) != 0 {
				return nil, fmt.Errorf("%w: EOA beneficiary %s has contract code", ErrGenesisExport, beneficiary)
			}
			amount, _ := new(big.Int).SetString(allocation.Amount, 10)
			args = []any{beneficiary, amount, allocation.Schedule.Start, allocation.Schedule.Cliff, allocation.Schedule.Duration}
		}
		if err != nil {
			return nil, fmt.Errorf("%w: constructor args %s: %v", ErrGenesisExport, name, err)
		}
		packed, err := parsed.Constructor.Inputs.Pack(args...)
		if err != nil {
			return nil, fmt.Errorf("%w: pack %s constructor: %v", ErrGenesisExport, name, err)
		}
		code, deployed, _, err := runtime.Create(append(creation, packed...), cfg)
		if err != nil {
			return nil, fmt.Errorf("%w: execute %s constructor: %v", ErrGenesisExport, name, err)
		}
		if deployed != want {
			return nil, fmt.Errorf("%w: %s deployed at unexpected address %s", ErrGenesisExport, name, deployed)
		}
		if err := compareRuntime(name, code, artifact); err != nil {
			return nil, err
		}
	}
	if err := validateVestingReceivers(m, artifacts, cfg); err != nil {
		return nil, err
	}
	for i := range m.Allocations {
		a := &m.Allocations[i]
		addr := common.HexToAddress(a.Recipient)
		if a.Kind == "contract_pot" {
			if existing := st.GetBalance(addr); existing.Sign() != 0 {
				return nil, fmt.Errorf("%w: contract %s constructor retained unexpected balance", ErrGenesisExport, a.Purpose)
			}
			amount, _ := new(big.Int).SetString(a.Amount, 10)
			st.SetBalance(addr, uint256.MustFromBig(amount), 0)
			if afterFunding != nil {
				afterFunding(st, addr)
			}
			if err := requirePrincipalBalance(addr, st.GetBalance(addr).ToBig(), amount); err != nil {
				return nil, fmt.Errorf("%w: %s: %w", ErrGenesisExport, a.Purpose, err)
			}
			artifact := artifacts[artifactName(contractNameForAddress(m, addr))]
			if len(artifact.StorageLayout.Storage) == 0 {
				return nil, fmt.Errorf("%w: storage layout absent for %s", ErrGenesisExport, a.Purpose)
			}
			storage := make(map[string]string)
			for _, item := range artifact.StorageLayout.Storage {
				slot, ok := new(big.Int).SetString(item.Slot, 10)
				if !ok {
					return nil, fmt.Errorf("%w: invalid storage slot %q", ErrGenesisExport, item.Slot)
				}
				key := common.BigToHash(slot)
				value := st.GetState(addr, key)
				if value != (common.Hash{}) || slot.Sign() == 0 {
					storage[key.Hex()] = value.Hex()
				}
			}
			a.State = &ManifestAccountState{Nonce: st.GetNonce(addr), Code: "0x" + hex.EncodeToString(st.GetCode(addr)), CodeHash: crypto.Keccak256Hash(st.GetCode(addr)).Hex(), Storage: storage}
		}
	}
	// The exporter only publishes manifest allocations: deployer setup balances and other EVM
	// implementation accounts cannot leak into the genesis allocation.
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrGenesisExport, err)
	}
	return append(out, '\n'), nil
}

func requirePrincipalBalance(address common.Address, balance, principal *big.Int) error {
	if balance.Cmp(principal) != 0 {
		return fmt.Errorf("%w: address %s balance %s principal %s", ErrGenesisPrincipalBalance, address, balance, principal)
	}
	return nil
}

func validateVestingReceivers(m AllocationManifest, artifacts map[string]compilerArtifact, cfg *runtime.Config) error {
	for _, allocation := range m.Allocations {
		if allocation.Schedule == nil {
			continue
		}
		beneficiary := common.HexToAddress(allocation.Beneficiary)
		if allocation.BeneficiaryKind == "eoa" {
			if len(cfg.State.GetCode(beneficiary)) != 0 {
				return fmt.Errorf("%w: EOA vesting beneficiary %s has contract code", ErrGenesisExport, beneficiary)
			}
			continue
		}
		name := contractNameForAddress(m, beneficiary)
		if name == "" {
			return fmt.Errorf("%w: contract vesting beneficiary %s is not in the deployment recipe", ErrGenesisExport, beneficiary)
		}
		artifact := artifacts[artifactName(name)]
		payable := false
		var entries []struct {
			Type            string `json:"type"`
			StateMutability string `json:"stateMutability"`
		}
		if err := json.Unmarshal(artifact.ABI, &entries); err != nil {
			return fmt.Errorf("%w: parse receiver ABI: %v", ErrGenesisExport, err)
		}
		for _, entry := range entries {
			if (entry.Type == "receive" || entry.Type == "fallback") && entry.StateMutability == "payable" {
				payable = true
			}
		}
		if !payable {
			return fmt.Errorf("%w: vesting beneficiary %s has no payable receive or fallback", ErrGenesisExport, beneficiary)
		}
		probe := cfg.State.Copy()
		caller := common.HexToAddress(m.Deployment.Deployer)
		probe.SetBalance(caller, uint256.NewInt(1), 0)
		probeCfg := *cfg
		probeCfg.State = probe
		probeCfg.Value = big.NewInt(1)
		if _, _, err := runtime.Call(beneficiary, nil, &probeCfg); err != nil {
			return fmt.Errorf("%w: vesting beneficiary %s rejects native value: %v", ErrGenesisExport, beneficiary, err)
		}
	}
	return nil
}

func artifactName(contract string) string {
	if contract == "feeCollector" {
		return "fee-collector"
	}
	if contract == "wuct" {
		return "wuct"
	}
	return "vesting"
}
func contractNameForAddress(m AllocationManifest, addr common.Address) string {
	for _, c := range m.Contracts {
		if common.HexToAddress(c.Address) == addr {
			return c.Name
		}
	}
	return ""
}
func ptrHash(h common.Hash) *common.Hash { return &h }
func feeCollectorArgs(m AllocationManifest) ([]any, error) {
	return []any{common.HexToAddress(m.Addresses.Treasury), m.FeeSplit.TreasuryBps}, nil
}
func compareRuntime(name string, code []byte, artifact compilerArtifact) error {
	expected, err := hex.DecodeString(strings.TrimPrefix(artifact.Runtime, "0x"))
	if err != nil {
		return fmt.Errorf("%w: invalid runtime template %s", ErrGenesisExport, name)
	}
	masked := make([]bool, len(expected))
	for _, refs := range artifact.ImmutableReferences {
		for _, ref := range refs {
			if ref.Start < 0 || ref.Length < 0 || ref.Start+ref.Length > len(expected) {
				return fmt.Errorf("%w: invalid immutable reference", ErrGenesisExport)
			}
			for i := ref.Start; i < ref.Start+ref.Length; i++ {
				masked[i] = true
			}
		}
	}
	if len(code) != len(expected) {
		return fmt.Errorf("%w: %s runtime size mismatch", ErrGenesisExport, name)
	}
	for i := range code {
		if !masked[i] && code[i] != expected[i] {
			return fmt.Errorf("%w: %s runtime differs from pinned artifact at byte %d", ErrGenesisExport, name, i)
		}
	}
	return nil
}
