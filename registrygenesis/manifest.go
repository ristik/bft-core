package registrygenesis

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-core/registryproof"
)

const (
	AllocationManifestVersion = "unicity/allocation-build/v1"
	maxAllocationManifestSize = 1 << 20
)

var (
	ErrAllocationManifest         = errors.New("registrygenesis: allocation manifest invalid")
	ErrManifestVersion            = errors.New("registrygenesis: allocation manifest version invalid")
	ErrManifestStrictDecode       = errors.New("registrygenesis: allocation manifest strict decoding failed")
	ErrManifestSupplySum          = errors.New("registrygenesis: allocation sum does not equal native supply")
	ErrManifestDuplicateRecipient = errors.New("registrygenesis: duplicate allocation recipient")
	ErrManifestAddressCollision   = errors.New("registrygenesis: reserved or system address collision")
	ErrManifestFeeBeneficiary     = errors.New("registrygenesis: fee beneficiary mismatch")
	ErrManifestUnverifiedContract = errors.New("registrygenesis: contract state is not verified constructor export")
	ErrManifestFeeCollectorCode   = errors.New("registrygenesis: fee beneficiary has no exported collector code")
	ErrManifestVaultBeneficiary   = errors.New("registrygenesis: vault beneficiary cannot receive or claim native value")
)

// AllocationManifest is the versioned build input for funded genesis. Contract code and
// initialized storage are added only by ExportAllocationManifest and verified again at compile.
type AllocationManifest struct {
	Version             string               `json:"version"`
	NativeSupply        string               `json:"nativeSupply"`
	Chain               ManifestChain        `json:"chain"`
	Genesis             ManifestGenesis      `json:"genesis"`
	Deployment          ManifestDeployment   `json:"deployment"`
	Addresses           ManifestAddresses    `json:"addresses"`
	FeeBeneficiary      string               `json:"feeBeneficiary"`
	FeeSplit            ManifestFeeSplit     `json:"feeSplit"`
	Allocations         []ManifestAllocation `json:"allocations"`
	BootstrapGasBudgets []ManifestGasBudget  `json:"bootstrapGasBudgets"`
	Contracts           []ManifestContract   `json:"contracts"`
}

type ManifestChain struct {
	ChainID uint64        `json:"chainId"`
	Forks   ManifestForks `json:"forks"`
}

// ManifestForks spells the complete supported standard-JSON schedule. This profile activates the
// V3-compatible Cancun schedule at genesis; unsupported future forks cannot be silently added.
type ManifestForks struct {
	HomesteadBlock                uint64 `json:"homesteadBlock"`
	EIP150Block                   uint64 `json:"eip150Block"`
	EIP155Block                   uint64 `json:"eip155Block"`
	EIP158Block                   uint64 `json:"eip158Block"`
	ByzantiumBlock                uint64 `json:"byzantiumBlock"`
	ConstantinopleBlock           uint64 `json:"constantinopleBlock"`
	PetersburgBlock               uint64 `json:"petersburgBlock"`
	IstanbulBlock                 uint64 `json:"istanbulBlock"`
	BerlinBlock                   uint64 `json:"berlinBlock"`
	LondonBlock                   uint64 `json:"londonBlock"`
	MergeNetsplitBlock            uint64 `json:"mergeNetsplitBlock"`
	ShanghaiTime                  uint64 `json:"shanghaiTime"`
	CancunTime                    uint64 `json:"cancunTime"`
	TerminalTotalDifficulty       string `json:"terminalTotalDifficulty"`
	TerminalTotalDifficultyPassed bool   `json:"terminalTotalDifficultyPassed"`
}

type ManifestGenesis struct {
	GasLimit      uint64 `json:"gasLimit"`
	BaseFeePerGas string `json:"baseFeePerGas"`
}

type ManifestDeployment struct {
	Deployer    string `json:"deployer"`
	FirstNonce  uint64 `json:"firstNonce"`
	BlockNumber uint64 `json:"blockNumber"`
	Timestamp   uint64 `json:"timestamp"`
}

type ManifestAddresses struct {
	System           string `json:"system"`
	Registry         string `json:"registry"`
	FeeCollector     string `json:"feeCollector"`
	WUCT             string `json:"wuct"`
	Treasury         string `json:"treasury"`
	TeamVesting      string `json:"teamVesting"`
	EcosystemVesting string `json:"ecosystemVesting"`
}

type ManifestFeeSplit struct {
	TreasuryBps uint16 `json:"treasuryBps"`
	RewardBps   uint16 `json:"rewardBps"`
}

type ManifestAllocation struct {
	Purpose         string                   `json:"purpose"`
	Recipient       string                   `json:"recipient"`
	Kind            string                   `json:"kind"` // "eoa" or "contract_pot"
	Amount          string                   `json:"amount"`
	Beneficiary     string                   `json:"beneficiary,omitempty"`
	BeneficiaryKind string                   `json:"beneficiaryKind,omitempty"` // "eoa" or "contract_receiver"
	Schedule        *ManifestVestingSchedule `json:"schedule,omitempty"`
	State           *ManifestAccountState    `json:"state,omitempty"`
}

type ManifestAccountState struct {
	Nonce    uint64            `json:"nonce"`
	Code     string            `json:"code"`
	CodeHash string            `json:"codeHash"`
	Storage  map[string]string `json:"storage"`
}

type ManifestVestingSchedule struct {
	Start    uint64 `json:"start"`
	Cliff    uint64 `json:"cliff"`
	Duration uint64 `json:"duration"`
}

type ManifestGasBudget struct {
	Recipient string `json:"recipient"`
	Gas       uint64 `json:"gas"`
}

type ManifestContract struct {
	Name         string `json:"name"`
	Address      string `json:"address"`
	Artifact     string `json:"artifact"`
	SHA256       string `json:"sha256"`
	SourceCommit string `json:"sourceCommit"`
}

// DecodeAllocationManifest strictly decodes one versioned manifest. Unknown and duplicate fields,
// trailing values, oversized documents, and unsupported versions are refused.
func DecodeAllocationManifest(data []byte) (AllocationManifest, error) {
	var m AllocationManifest
	if len(data) == 0 || len(data) > maxAllocationManifestSize {
		return m, manifestError(ErrManifestStrictDecode, "document size must be 1..%d bytes", maxAllocationManifestSize)
	}
	if err := scanJSON(data, 32); err != nil {
		return m, manifestError(ErrManifestStrictDecode, "%v", err)
	}
	if err := requireManifestFields(data); err != nil {
		return m, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, manifestError(ErrManifestStrictDecode, "%v", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return m, manifestError(ErrManifestStrictDecode, "trailing JSON value")
	}
	if m.Version != AllocationManifestVersion {
		return m, manifestError(ErrManifestVersion, "version must be %q", AllocationManifestVersion)
	}
	if err := validateAllocationManifest(m); err != nil {
		return m, err
	}
	return m, nil
}

func manifestError(check error, format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrAllocationManifest, check, fmt.Sprintf(format, args...))
}

// CompileAllocationManifest compiles validated allocation data into the standard geth/reth
// genesis-JSON source accepted by PrepareGenesisJSON. The caller then uses that existing pipeline
// to insert the registry and derive canonical identities.
func CompileAllocationManifest(data []byte, expectedChainID uint64) ([]byte, error) {
	m, err := DecodeAllocationManifest(data)
	if err != nil {
		return nil, err
	}
	if expectedChainID == 0 || m.Chain.ChainID != expectedChainID {
		return nil, fmt.Errorf("%w: manifest chain id %d does not match shard chain id %d", ErrAllocationManifest, m.Chain.ChainID, expectedChainID)
	}
	if err := verifyConstructorExport(data, m); err != nil {
		return nil, err
	}
	baseFee, ok := new(big.Int).SetString(m.Genesis.BaseFeePerGas, 10)
	if !ok || baseFee.Sign() < 0 || baseFee.BitLen() > 64 {
		return nil, fmt.Errorf("%w: baseFeePerGas must be an unsigned uint64 decimal string", ErrAllocationManifest)
	}
	type standardAccount struct {
		Balance string            `json:"balance"`
		Code    string            `json:"code,omitempty"`
		Nonce   string            `json:"nonce,omitempty"`
		Storage map[string]string `json:"storage,omitempty"`
	}
	alloc := make(map[string]standardAccount, len(m.Allocations))
	ordered := append([]ManifestAllocation(nil), m.Allocations...)
	sort.Slice(ordered, func(i, j int) bool {
		return strings.ToLower(ordered[i].Recipient) < strings.ToLower(ordered[j].Recipient)
	})
	for _, a := range ordered {
		addr := common.HexToAddress(a.Recipient)
		amount, _ := new(big.Int).SetString(a.Amount, 10) // validated below
		entry := standardAccount{Balance: hexutil.EncodeBig(amount)}
		if a.Kind == "contract_pot" {
			if a.State == nil {
				return nil, fmt.Errorf("%w: contract pot %s has no constructor-exported state", ErrAllocationManifest, addr)
			}
			code, e := hexutil.Decode(a.State.Code)
			if e != nil {
				return nil, fmt.Errorf("%w: contract pot %s has invalid code", ErrAllocationManifest, addr)
			}
			codeHash := crypto.Keccak256Hash(code)
			if !strings.EqualFold(a.State.CodeHash, codeHash.Hex()) {
				return nil, fmt.Errorf("%w: contract pot %s code hash mismatch", ErrAllocationManifest, addr)
			}
			entry.Code = a.State.Code
			entry.Nonce = hexutil.EncodeUint64(a.State.Nonce)
			entry.Storage = a.State.Storage
		}
		alloc[addr.Hex()] = entry
	}

	// Field names/order intentionally mirror the existing engine-api standard-JSON template.
	type standardForks struct {
		ChainID                       uint64 `json:"chainId"`
		HomesteadBlock                uint64 `json:"homesteadBlock"`
		EIP150Block                   uint64 `json:"eip150Block"`
		EIP155Block                   uint64 `json:"eip155Block"`
		EIP158Block                   uint64 `json:"eip158Block"`
		ByzantiumBlock                uint64 `json:"byzantiumBlock"`
		ConstantinopleBlock           uint64 `json:"constantinopleBlock"`
		PetersburgBlock               uint64 `json:"petersburgBlock"`
		IstanbulBlock                 uint64 `json:"istanbulBlock"`
		BerlinBlock                   uint64 `json:"berlinBlock"`
		LondonBlock                   uint64 `json:"londonBlock"`
		MergeNetsplitBlock            uint64 `json:"mergeNetsplitBlock"`
		ShanghaiTime                  uint64 `json:"shanghaiTime"`
		CancunTime                    uint64 `json:"cancunTime"`
		TerminalTotalDifficulty       string `json:"terminalTotalDifficulty"`
		TerminalTotalDifficultyPassed bool   `json:"terminalTotalDifficultyPassed"`
	}
	type standardGenesis struct {
		Config     standardForks              `json:"config"`
		Nonce      string                     `json:"nonce"`
		Timestamp  string                     `json:"timestamp"`
		ExtraData  string                     `json:"extraData"`
		GasLimit   string                     `json:"gasLimit"`
		Difficulty string                     `json:"difficulty"`
		MixHash    string                     `json:"mixHash"`
		Coinbase   string                     `json:"coinbase"`
		Alloc      map[string]standardAccount `json:"alloc"`
		BaseFee    string                     `json:"baseFeePerGas"`
	}
	f := m.Chain.Forks
	compiled := standardGenesis{
		Config: standardForks{m.Chain.ChainID, f.HomesteadBlock, f.EIP150Block, f.EIP155Block,
			f.EIP158Block, f.ByzantiumBlock, f.ConstantinopleBlock, f.PetersburgBlock, f.IstanbulBlock,
			f.BerlinBlock, f.LondonBlock, f.MergeNetsplitBlock, f.ShanghaiTime, f.CancunTime,
			f.TerminalTotalDifficulty, f.TerminalTotalDifficultyPassed},
		Nonce: "0x0", Timestamp: "0x0", ExtraData: "0x", GasLimit: hexutil.EncodeUint64(m.Genesis.GasLimit),
		Difficulty: "0x0", MixHash: common.Hash{}.Hex(), Coinbase: common.HexToAddress(m.FeeBeneficiary).Hex(),
		Alloc: alloc, BaseFee: hexutil.EncodeUint64(baseFee.Uint64()),
	}
	out, err := json.MarshalIndent(compiled, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: encoding standard genesis JSON: %v", ErrAllocationManifest, err)
	}
	return append(out, '\n'), nil
}

// verifyConstructorExport reruns the pinned constructors from the manifest's deterministic
// deployment recipe and requires every declared contract allocation to match that result.
// This prevents callers from supplying arbitrary runtime code/storage with a self-consistent
// code hash. The exporter itself is intentionally one-way and does not call the compiler.
func verifyConstructorExport(data []byte, m AllocationManifest) error {
	allocations := make(map[common.Address]ManifestAllocation, len(m.Allocations))
	for _, allocation := range m.Allocations {
		allocations[common.HexToAddress(allocation.Recipient)] = allocation
	}
	if err := requireFeeCollectorCode(m); err != nil {
		return err
	}
	for _, contract := range m.Contracts {
		address := common.HexToAddress(contract.Address)
		allocation, ok := allocations[address]
		if !ok || allocation.Kind != "contract_pot" || allocation.State == nil {
			if contract.Name == "feeCollector" {
				return manifestError(ErrManifestFeeCollectorCode, "fee beneficiary %s must have an exported FeeCollector allocation", address)
			}
			return manifestError(ErrManifestUnverifiedContract, "contract %s must have an exported contract-pot allocation", contract.Name)
		}
		code, err := hexutil.Decode(allocation.State.Code)
		if err != nil || len(code) == 0 {
			if contract.Name == "feeCollector" {
				return manifestError(ErrManifestFeeCollectorCode, "fee beneficiary %s must contain FeeCollector runtime code", address)
			}
			return manifestError(ErrManifestUnverifiedContract, "contract %s has invalid or empty runtime code", contract.Name)
		}
	}

	exportedJSON, err := ExportAllocationManifest(data)
	if err != nil {
		return fmt.Errorf("%w: verify constructor export: %w", ErrManifestUnverifiedContract, err)
	}
	exported, err := DecodeAllocationManifest(exportedJSON)
	if err != nil {
		return fmt.Errorf("%w: decode verified constructor export: %w", ErrManifestUnverifiedContract, err)
	}
	verified := make(map[common.Address]ManifestAllocation, len(exported.Allocations))
	for _, allocation := range exported.Allocations {
		verified[common.HexToAddress(allocation.Recipient)] = allocation
	}
	for _, contract := range m.Contracts {
		address := common.HexToAddress(contract.Address)
		actual := allocations[address]
		want, ok := verified[address]
		if !ok || want.State == nil || !reflect.DeepEqual(actual.State, want.State) {
			if contract.Name == "feeCollector" {
				return manifestError(ErrManifestFeeCollectorCode, "fee beneficiary %s does not contain the verified FeeCollector constructor state", address)
			}
			return manifestError(ErrManifestUnverifiedContract, "contract %s state differs from verified constructor export", contract.Name)
		}
	}
	return nil
}

func requireFeeCollectorCode(m AllocationManifest) error {
	feeAddress := common.HexToAddress(m.FeeBeneficiary)
	for _, allocation := range m.Allocations {
		if common.HexToAddress(allocation.Recipient) != feeAddress {
			continue
		}
		if allocation.Kind != "contract_pot" || allocation.State == nil {
			break
		}
		code, err := hexutil.Decode(allocation.State.Code)
		if err == nil && len(code) > 0 {
			return nil
		}
		break
	}
	return manifestError(ErrManifestFeeCollectorCode, "fee beneficiary %s must have exported FeeCollector runtime code", feeAddress)
}

func validateAllocationManifest(m AllocationManifest) error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrAllocationManifest, fmt.Sprintf(format, args...))
	}
	if m.Chain.ChainID == 0 {
		return fail("chain.chainId must be non-zero")
	}
	f := m.Chain.Forks
	if f.HomesteadBlock != 0 || f.EIP150Block != 0 || f.EIP155Block != 0 || f.EIP158Block != 0 ||
		f.ByzantiumBlock != 0 || f.ConstantinopleBlock != 0 || f.PetersburgBlock != 0 ||
		f.IstanbulBlock != 0 || f.BerlinBlock != 0 || f.LondonBlock != 0 || f.MergeNetsplitBlock != 0 ||
		f.ShanghaiTime != 0 || f.CancunTime != 0 || f.TerminalTotalDifficulty != "0" || !f.TerminalTotalDifficultyPassed {
		return fail("chain.forks must match the supported Cancun-at-genesis standard-JSON profile")
	}
	if m.Genesis.GasLimit == 0 {
		return fail("genesis.gasLimit must be non-zero")
	}
	if _, err := manifestAddress(m.Deployment.Deployer, "deployment.deployer"); err != nil {
		return err
	}
	if n, ok := new(big.Int).SetString(m.Genesis.BaseFeePerGas, 10); !ok || n.Sign() < 0 || n.BitLen() > 64 {
		return fail("genesis.baseFeePerGas must be an unsigned uint64 decimal string")
	}
	supply, ok := parseCanonicalUint(m.NativeSupply)
	if !ok {
		return fail("nativeSupply must be a canonical unsigned decimal integer")
	}
	addresses, err := validateManifestAddresses(m.Addresses)
	if err != nil {
		return err
	}
	beneficiary, err := manifestAddress(m.FeeBeneficiary, "feeBeneficiary")
	if err != nil {
		return err
	}
	if beneficiary != addresses["feeCollector"] {
		return manifestError(ErrManifestFeeBeneficiary, "feeBeneficiary must equal addresses.feeCollector")
	}
	if uint32(m.FeeSplit.TreasuryBps)+uint32(m.FeeSplit.RewardBps) != 10_000 {
		return fail("feeSplit treasuryBps plus rewardBps must equal 10000")
	}
	contracts := make(map[string]common.Address, len(m.Contracts))
	for _, c := range m.Contracts {
		if _, exists := contracts[c.Name]; exists {
			return fail("duplicate contract name %q", c.Name)
		}
		addr, e := manifestAddress(c.Address, "contracts.address")
		if e != nil {
			return e
		}
		if c.Name != "feeCollector" && c.Name != "wuct" && c.Name != "teamVesting" && c.Name != "ecosystemVesting" {
			return fail("unsupported contract name %q", c.Name)
		}
		if addr != addresses[c.Name] {
			return fail("contract %q address differs from fixed address", c.Name)
		}
		if strings.TrimSpace(c.Artifact) == "" || strings.ContainsAny(c.Artifact, "\x00\n\r") {
			return fail("contract %q artifact reference is empty or invalid", c.Name)
		}
		if sourceCommit, e := hex.DecodeString(c.SourceCommit); e != nil || len(sourceCommit) != 20 {
			return fail("contract %q sourceCommit must be a 40-character hexadecimal commit", c.Name)
		}
		hash, e := hex.DecodeString(c.SHA256)
		if e != nil || len(hash) != 32 {
			return fail("contract %q sha256 must be 64 hexadecimal characters", c.Name)
		}
		contracts[c.Name] = addr
	}
	if len(contracts) != 4 || contracts["feeCollector"] == (common.Address{}) || contracts["wuct"] == (common.Address{}) || contracts["teamVesting"] == (common.Address{}) || contracts["ecosystemVesting"] == (common.Address{}) {
		return fail("contracts must declare feeCollector, wuct, teamVesting, and ecosystemVesting artifact references")
	}
	seen := make(map[common.Address]struct{}, len(m.Allocations))
	total := new(big.Int)
	for _, a := range m.Allocations {
		addr, e := manifestAddress(a.Recipient, "allocations.recipient")
		if e != nil {
			return e
		}
		if addr == addresses["system"] || addr == addresses["registry"] || isPrecompileAddress(addr) {
			return manifestError(ErrManifestAddressCollision, "allocation recipient %s collides with a reserved, system, or precompile address", addr)
		}
		if _, exists := seen[addr]; exists {
			return manifestError(ErrManifestDuplicateRecipient, "duplicate allocation recipient %s", addr)
		}
		seen[addr] = struct{}{}
		amount, ok := parseCanonicalUint(a.Amount)
		if !ok {
			return fail("allocation amount for %s must be a canonical unsigned decimal integer", addr)
		}
		switch a.Kind {
		case "eoa":
			if _, isContract := contractsByAddress(addresses, addr); isContract {
				return fail("EOA allocation collides with a declared contract at %s", addr)
			}
		case "contract_pot":
			if _, isContract := contractsByAddress(addresses, addr); !isContract {
				return fail("contract_pot allocation %s has no matching declared contract", addr)
			}
		default:
			return fail("allocation kind %q is not eoa or contract_pot", a.Kind)
		}
		if strings.TrimSpace(a.Purpose) == "" {
			return fail("allocation purpose for %s is empty", addr)
		}
		if a.Schedule != nil && (a.Kind != "contract_pot" || a.Schedule.Duration == 0 || a.Schedule.Cliff > a.Schedule.Duration) {
			return fail("vesting schedule for %s requires a contract pot, positive duration, and cliff no longer than duration", addr)
		}
		if (addr == addresses["teamVesting"] || addr == addresses["ecosystemVesting"]) && a.Kind == "contract_pot" && a.Schedule == nil {
			return fail("vesting pot allocation for %s must declare its constructor schedule", addr)
		}
		if (addr == addresses["teamVesting"] || addr == addresses["ecosystemVesting"]) && a.Kind == "contract_pot" {
			beneficiary, e := manifestAddress(a.Beneficiary, "allocations.beneficiary")
			if e != nil {
				return e
			}
			if beneficiary == (common.Address{}) || beneficiary == addresses["system"] || beneficiary == addresses["registry"] || isPrecompileAddress(beneficiary) {
				return fail("vesting beneficiary %s collides with zero, a reserved/system address, or a precompile", beneficiary)
			}
			if a.BeneficiaryKind != "eoa" && a.BeneficiaryKind != "contract_receiver" {
				return fail("vesting beneficiaryKind must be eoa or contract_receiver")
			}
			if a.BeneficiaryKind == "contract_receiver" {
				name, declared := contractsByAddress(addresses, beneficiary)
				if !declared || name != "feeCollector" {
					return manifestError(ErrManifestVaultBeneficiary, "contract vesting beneficiary %s must be the payable FeeCollector", beneficiary)
				}
			}
		}
		total.Add(total, amount)
	}
	if len(m.Allocations) == 0 || total.Cmp(supply) != 0 {
		return manifestError(ErrManifestSupplySum, "allocation sum %s does not equal nativeSupply %s", total, supply)
	}
	gasRecipients := make(map[common.Address]struct{}, len(m.BootstrapGasBudgets))
	allocationKinds := make(map[common.Address]string, len(m.Allocations))
	for _, a := range m.Allocations {
		allocationKinds[common.HexToAddress(a.Recipient)] = a.Kind
	}
	for _, b := range m.BootstrapGasBudgets {
		addr, e := manifestAddress(b.Recipient, "bootstrapGasBudgets.recipient")
		if e != nil {
			return e
		}
		if addr == addresses["system"] || addr == addresses["registry"] || isPrecompileAddress(addr) {
			return manifestError(ErrManifestAddressCollision, "bootstrap gas recipient %s collides with a reserved, system, or precompile address", addr)
		}
		if b.Gas == 0 {
			return fail("bootstrap gas budget for %s must be non-zero", addr)
		}
		if allocationKinds[addr] != "eoa" {
			return fail("bootstrap gas recipient %s must have an EOA allocation", addr)
		}
		if _, exists := gasRecipients[addr]; exists {
			return fail("duplicate bootstrap gas recipient %s", addr)
		}
		gasRecipients[addr] = struct{}{}
	}
	return nil
}

func validateManifestAddresses(a ManifestAddresses) (map[string]common.Address, error) {
	fail := func(format string, args ...any) (map[string]common.Address, error) {
		return nil, fmt.Errorf("%w: %s", ErrAllocationManifest, fmt.Sprintf(format, args...))
	}
	system, err := manifestAddress(a.System, "addresses.system")
	if err != nil {
		return nil, err
	}
	registry, err := manifestAddress(a.Registry, "addresses.registry")
	if err != nil {
		return nil, err
	}
	if system != SystemAddress || registry != registryproof.RegistryAddress {
		return nil, manifestError(ErrManifestAddressCollision, "system and registry addresses must match the pinned reserved addresses")
	}
	addresses := map[string]common.Address{"system": system, "registry": registry}
	for key, text := range map[string]string{
		"feeCollector": a.FeeCollector, "wuct": a.WUCT, "treasury": a.Treasury,
		"teamVesting": a.TeamVesting, "ecosystemVesting": a.EcosystemVesting,
	} {
		addr, e := manifestAddress(text, "addresses."+key)
		if e != nil {
			return nil, e
		}
		if addr == (common.Address{}) || addr == system || addr == registry || isPrecompileAddress(addr) {
			return nil, manifestError(ErrManifestAddressCollision, "%s address %s collides with zero, a reserved/system address, or an EVM precompile", key, addr)
		}
		addresses[key] = addr
	}
	seen := make(map[common.Address]string, 5)
	for _, name := range []string{"feeCollector", "wuct", "treasury", "teamVesting", "ecosystemVesting"} {
		if other, exists := seen[addresses[name]]; exists {
			return fail("fixed %s and %s addresses must be distinct", other, name)
		}
		seen[addresses[name]] = name
	}
	return addresses, nil
}

func contractsByAddress(addresses map[string]common.Address, target common.Address) (string, bool) {
	for _, name := range []string{"feeCollector", "wuct", "teamVesting", "ecosystemVesting"} {
		if addresses[name] == target {
			return name, true
		}
	}
	return "", false
}

func isPrecompileAddress(addr common.Address) bool {
	for i := byte(1); i <= 10; i++ {
		var reserved common.Address
		reserved[19] = i
		if addr == reserved {
			return true
		}
	}
	return false
}

func manifestAddress(text, field string) (common.Address, error) {
	if len(text) != 42 || !strings.HasPrefix(text, "0x") || !common.IsHexAddress(text) {
		return common.Address{}, fmt.Errorf("%w: %s must be a 0x-prefixed 20-byte address", ErrAllocationManifest, field)
	}
	return common.HexToAddress(text), nil
}

func parseCanonicalUint(text string) (*big.Int, bool) {
	if text == "" || (len(text) > 1 && text[0] == '0') {
		return nil, false
	}
	for _, r := range text {
		if r < '0' || r > '9' {
			return nil, false
		}
	}
	n, ok := new(big.Int).SetString(text, 10)
	return n, ok && n.BitLen() <= 256
}

func requireManifestFields(data []byte) error {
	require := func(raw json.RawMessage, context string, fields ...string) (map[string]json.RawMessage, error) {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || object == nil {
			return nil, manifestError(ErrManifestStrictDecode, "%s must be an object", context)
		}
		for _, field := range fields {
			if _, ok := object[field]; !ok {
				return nil, manifestError(ErrManifestStrictDecode, "%s missing %s", context, field)
			}
		}
		return object, nil
	}
	root, err := require(data, "manifest", "nativeSupply", "chain", "genesis", "deployment", "addresses", "feeBeneficiary", "allocations", "bootstrapGasBudgets", "contracts")
	if err != nil {
		return err
	}
	if _, exists := root["version"]; !exists {
		return manifestError(ErrManifestVersion, "missing version")
	}
	chain, err := require(root["chain"], "chain", "chainId", "forks")
	if err != nil {
		return err
	}
	if _, err = require(chain["forks"], "chain.forks", "homesteadBlock", "eip150Block", "eip155Block", "eip158Block", "byzantiumBlock", "constantinopleBlock", "petersburgBlock", "istanbulBlock", "berlinBlock", "londonBlock", "mergeNetsplitBlock", "shanghaiTime", "cancunTime", "terminalTotalDifficulty", "terminalTotalDifficultyPassed"); err != nil {
		return err
	}
	if _, err = require(root["genesis"], "genesis", "gasLimit", "baseFeePerGas"); err != nil {
		return err
	}
	if _, err = require(root["deployment"], "deployment", "deployer", "firstNonce", "blockNumber", "timestamp"); err != nil {
		return err
	}
	if _, err = require(root["addresses"], "addresses", "system", "registry", "feeCollector", "wuct", "treasury", "teamVesting", "ecosystemVesting"); err != nil {
		return err
	}
	if _, err = require(root["feeSplit"], "feeSplit", "treasuryBps", "rewardBps"); err != nil {
		return err
	}
	for _, item := range []struct {
		field    string
		required []string
	}{{"allocations", []string{"purpose", "recipient", "kind", "amount"}}, {"bootstrapGasBudgets", []string{"recipient", "gas"}}, {"contracts", []string{"name", "address", "artifact", "sha256", "sourceCommit"}}} {
		var list []json.RawMessage
		if err := json.Unmarshal(root[item.field], &list); err != nil || list == nil {
			return manifestError(ErrManifestStrictDecode, "%s must be an array", item.field)
		}
		for i, entry := range list {
			if _, err := require(entry, fmt.Sprintf("%s[%d]", item.field, i), item.required...); err != nil {
				return err
			}
		}
	}
	return nil
}
