// Package supplyaudit checks native supply and contract custody from a complete,
// operator-exported state snapshot and its block accounting history.
package supplyaudit

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

const (
	SnapshotVersion     = "unicity/supply-audit-snapshot/v1"
	ResultVersion       = "unicity/supply-audit-result/v1"
	ContractsCommit     = "e7eb3216549b772a9e1df2b1214976d7dd9e6e62"
	wuctSupplySlot      = 2
	collectorCreditSlot = 1
	collectorRewardSlot = 2
	vaultReleasedSlot   = 1
)

var ErrInput = errors.New("supplyaudit: invalid input")

// Genesis is the ordinary geth/reth standard genesis JSON.
type Genesis struct {
	Difficulty string `json:"difficulty"`
	Config     struct {
		TerminalTotalDifficultyPassed bool `json:"terminalTotalDifficultyPassed"`
	} `json:"config"`
	Alloc map[string]GenesisAccount `json:"alloc"`
}

type GenesisAccount struct {
	Balance string `json:"balance"`
	Code    string `json:"code"`
}

// Snapshot is an offline state dump plus the accounting facts needed to reconcile it.
// FullState and each block's trace-coverage declaration are source assertions; this tool
// checks their consistency but does not authenticate a certificate or trace provider.
type Snapshot struct {
	Version         string             `json:"version"`
	ContractsCommit string             `json:"contractsCommit"`
	GenesisHash     string             `json:"genesisHash"`
	CertifiedBlock  CertifiedBlock     `json:"certifiedBlock"`
	FullState       bool               `json:"fullState"`
	Addresses       Addresses          `json:"addresses"`
	Accounts        map[string]Account `json:"accounts"`
	Blocks          []BlockAccounting  `json:"blocks"`
}

type CertifiedBlock struct {
	Number    uint64 `json:"number"`
	Hash      string `json:"hash"`
	Certified bool   `json:"certified"`
}
type Addresses struct {
	WUCT          string   `json:"wuct"`
	FeeCollector  string   `json:"feeCollector"`
	VestingVaults []string `json:"vestingVaults"`
}
type Account struct {
	Balance string            `json:"balance"`
	Code    string            `json:"code"`
	Storage map[string]string `json:"storage"`
}
type BlockAccounting struct {
	Number                     uint64              `json:"number"`
	Hash                       string              `json:"hash"`
	ParentHash                 string              `json:"parentHash"`
	Difficulty                 string              `json:"difficulty"`
	BaseFeePerGas              string              `json:"baseFeePerGas"`
	GasUsed                    string              `json:"gasUsed"`
	BlobGasUsed                *string             `json:"blobGasUsed"`
	WithdrawalsCount           *uint64             `json:"withdrawalsCount"`
	SelfDestructTracesComplete *bool               `json:"selfdestructTracesComplete"`
	SelfDestructs              []SelfDestructTrace `json:"selfdestructs"`
}
type SelfDestructTrace struct {
	TransactionHash          string `json:"transactionHash"`
	Contract                 string `json:"contract"`
	Beneficiary              string `json:"beneficiary"`
	CreatedInSameTransaction bool   `json:"createdInSameTransaction"`
	Opcode                   string `json:"opcode"`
	BurnedAmount             string `json:"burnedAmount"`
}

type Violation struct {
	Check    string `json:"check"`
	Message  string `json:"message"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
}
type Result struct {
	Version         string           `json:"version"`
	ContractsCommit string           `json:"contractsCommit"`
	Status          string           `json:"status"`
	CertifiedBlock  CertifiedBlock   `json:"certifiedBlock"`
	Coverage        Coverage         `json:"coverage"`
	Native          NativeMetrics    `json:"nativeSupply"`
	WUCT            TokenMetrics     `json:"wuct"`
	Vesting         []VaultMetrics   `json:"vestingVaults"`
	FeeCollector    LiabilityMetrics `json:"feeCollector"`
	Violations      []Violation      `json:"violations"`
}
type Coverage struct {
	FullState                  bool     `json:"fullState"`
	TraceComplete              bool     `json:"selfdestructTracesComplete"`
	UncoveredBlocks            []uint64 `json:"uncoveredSelfdestructTraceBlocks"`
	CertificationAuthenticated bool     `json:"certificationAuthenticated"`
}
type NativeMetrics struct {
	GenesisSupply             string `json:"genesisSupply"`
	BaseFeeBurn               string `json:"baseFeeBurn"`
	SelfDestructBurn          string `json:"selfdestructBurnObserved"`
	ExpectedFromObservedBurns string `json:"expectedFromObservedBurns"`
	Actual                    string `json:"actual"`
	Matches                   *bool  `json:"matches,omitempty"`
}
type TokenMetrics struct {
	TotalSupply   string `json:"totalSupply"`
	NativeBalance string `json:"nativeBalance"`
	Covered       bool   `json:"covered"`
}
type VaultMetrics struct {
	Address             string `json:"address"`
	Principal           string `json:"principal"`
	Released            string `json:"released"`
	NativeBalance       string `json:"nativeBalance"`
	UnreleasedPrincipal string `json:"unreleasedPrincipal"`
	Covered             bool   `json:"covered"`
}
type LiabilityMetrics struct {
	Address          string `json:"address"`
	TreasuryCredit   string `json:"treasuryCredit"`
	RewardPot        string `json:"rewardPot"`
	TotalLiabilities string `json:"totalLiabilities"`
	NativeBalance    string `json:"nativeBalance"`
	Covered          bool   `json:"covered"`
}

// Audit evaluates the snapshot. Input/schema errors are returned; accounting violations and
// incomplete trace coverage are represented in the machine-readable Result.
func Audit(genesisJSON, snapshotJSON []byte) (Result, error) {
	var result Result
	var genesis Genesis
	if err := json.Unmarshal(genesisJSON, &genesis); err != nil {
		return result, inputError("decode genesis: %v", err)
	}
	var snapshot Snapshot
	if err := strictDecode(snapshotJSON, &snapshot); err != nil {
		return result, inputError("decode snapshot: %v", err)
	}
	if snapshot.Version != SnapshotVersion {
		return result, inputError("snapshot version must be %q", SnapshotVersion)
	}
	if snapshot.ContractsCommit != ContractsCommit {
		return result, inputError("contractsCommit must be pinned to %s", ContractsCommit)
	}
	if !snapshot.FullState {
		return result, inputError("snapshot must assert fullState=true")
	}
	if !snapshot.CertifiedBlock.Certified {
		return result, inputError("snapshot block must be marked certified")
	}
	if !isHash(snapshot.CertifiedBlock.Hash) || !isHash(snapshot.GenesisHash) {
		return result, inputError("snapshot genesisHash and certifiedBlock.hash must be 32-byte hashes")
	}
	if !genesis.Config.TerminalTotalDifficultyPassed || parseZero(genesis.Difficulty) != nil {
		return result, inputError("genesis must be post-merge with zero difficulty and terminal total difficulty passed")
	}
	if len(genesis.Alloc) == 0 || len(snapshot.Accounts) == 0 {
		return result, inputError("genesis alloc and full-state accounts must be non-empty")
	}
	addresses := []string{snapshot.Addresses.WUCT, snapshot.Addresses.FeeCollector}
	addresses = append(addresses, snapshot.Addresses.VestingVaults...)
	seenContracts := make(map[common.Address]struct{}, len(addresses))
	for _, text := range addresses {
		if !common.IsHexAddress(text) || common.HexToAddress(text) == (common.Address{}) {
			return result, inputError("invalid or zero contract address %q", text)
		}
		address := common.HexToAddress(text)
		if _, exists := seenContracts[address]; exists {
			return result, inputError("duplicate contract address %s", address)
		}
		seenContracts[address] = struct{}{}
	}
	if len(snapshot.Addresses.VestingVaults) == 0 {
		return result, inputError("snapshot must list at least one vesting vault")
	}

	genesisSupply := new(big.Int)
	for address, account := range genesis.Alloc {
		if !common.IsHexAddress(address) {
			return result, inputError("invalid genesis allocation address %q", address)
		}
		balance, err := quantity(account.Balance)
		if err != nil {
			return result, inputError("invalid genesis balance for %s: %v", address, err)
		}
		genesisSupply.Add(genesisSupply, balance)
	}
	actualSupply := new(big.Int)
	stateAccounts := make(map[common.Address]Account, len(snapshot.Accounts))
	for text, account := range snapshot.Accounts {
		if !common.IsHexAddress(text) {
			return result, inputError("invalid state address %q", text)
		}
		address := common.HexToAddress(text)
		if _, exists := stateAccounts[address]; exists {
			return result, inputError("duplicate normalized state address %s", address)
		}
		balance, err := quantity(account.Balance)
		if err != nil {
			return result, inputError("invalid state balance for %s: %v", text, err)
		}
		actualSupply.Add(actualSupply, balance)
		stateAccounts[address] = account
	}
	result = Result{Version: ResultVersion, ContractsCommit: ContractsCommit, Status: "pass", CertifiedBlock: snapshot.CertifiedBlock, Coverage: Coverage{FullState: true, CertificationAuthenticated: false}}
	genesisAccounts := make(map[common.Address]GenesisAccount, len(genesis.Alloc))
	for text, account := range genesis.Alloc {
		genesisAccounts[common.HexToAddress(text)] = account
	}
	accountFor := func(text string) (common.Address, Account, *big.Int, error) {
		address := common.HexToAddress(text)
		account, ok := stateAccounts[address]
		if !ok {
			return address, Account{}, nil, inputError("full-state snapshot is missing account %s", address)
		}
		genesisAccount, exists := genesisAccounts[address]
		if !exists {
			return address, Account{}, nil, inputError("genesis allocation is missing contract %s", address)
		}
		genesisCode, err := decodeHex(genesisAccount.Code)
		if err != nil {
			return address, Account{}, nil, inputError("genesis code for %s: %v", address, err)
		}
		stateCode, err := decodeHex(account.Code)
		if err != nil {
			return address, Account{}, nil, inputError("state code for %s: %v", address, err)
		}
		if !bytes.Equal(genesisCode, stateCode) {
			return address, Account{}, nil, inputError("code for %s differs from genesis contract code", address)
		}
		if len(genesisCode) == 0 {
			return address, Account{}, nil, inputError("genesis contract %s has no code", address)
		}
		balance, err := quantity(account.Balance)
		return address, account, balance, err
	}

	if len(snapshot.Blocks) != int(snapshot.CertifiedBlock.Number) {
		return result, inputError("need exactly one accounting record for every block 1..%d", snapshot.CertifiedBlock.Number)
	}
	baseFeeBurn, selfDestructBurn := new(big.Int), new(big.Int)
	traceComplete := true
	uncovered := make([]uint64, 0)
	previousHash := strings.ToLower(snapshot.GenesisHash)
	for i, block := range snapshot.Blocks {
		wantNumber := uint64(i + 1)
		if block.Number != wantNumber {
			return result, inputError("block accounting must be contiguous at %d, got %d", wantNumber, block.Number)
		}
		if !isHash(block.Hash) || !isHash(block.ParentHash) || strings.ToLower(block.ParentHash) != previousHash {
			return result, inputError("block %d hash chain is invalid", block.Number)
		}
		difficulty, err := quantity(block.Difficulty)
		if err != nil {
			return result, inputError("block %d invalid difficulty: %v", block.Number, err)
		}
		if difficulty.Sign() != 0 {
			result.addViolation("issuance_disabled", fmt.Sprintf("block %d difficulty must be zero", block.Number), "0", block.Difficulty)
		}
		baseFee, err := quantity(block.BaseFeePerGas)
		if err != nil {
			return result, inputError("block %d invalid baseFeePerGas: %v", block.Number, err)
		}
		gasUsed, err := quantity(block.GasUsed)
		if err != nil {
			return result, inputError("block %d invalid gasUsed: %v", block.Number, err)
		}
		baseFeeBurn.Add(baseFeeBurn, new(big.Int).Mul(baseFee, gasUsed))
		if block.BlobGasUsed == nil {
			return result, inputError("block %d is missing blobGasUsed", block.Number)
		}
		blobGas, err := quantity(*block.BlobGasUsed)
		if err != nil {
			return result, inputError("block %d invalid blobGasUsed: %v", block.Number, err)
		}
		if blobGas.Sign() != 0 {
			result.addViolation("blob_rules_disabled", fmt.Sprintf("block %d has non-zero blobGasUsed", block.Number), "0", blobGas.String())
		}
		if block.WithdrawalsCount == nil {
			return result, inputError("block %d is missing withdrawalsCount", block.Number)
		}
		if *block.WithdrawalsCount != 0 {
			result.addViolation("withdrawals_disabled", fmt.Sprintf("block %d has withdrawals", block.Number), "0", fmt.Sprint(*block.WithdrawalsCount))
		}
		if block.SelfDestructTracesComplete == nil {
			return result, inputError("block %d is missing selfdestructTracesComplete", block.Number)
		}
		if block.SelfDestructs == nil {
			return result, inputError("block %d is missing selfdestructs array", block.Number)
		}
		if !*block.SelfDestructTracesComplete {
			traceComplete = false
			uncovered = append(uncovered, block.Number)
		}
		seenTrace := make(map[string]struct{})
		for _, trace := range block.SelfDestructs {
			if trace.Opcode != "SELFDESTRUCT" || !isHash(trace.TransactionHash) || !common.IsHexAddress(trace.Contract) || !common.IsHexAddress(trace.Beneficiary) {
				return result, inputError("block %d contains a malformed SELFDESTRUCT trace", block.Number)
			}
			key := strings.ToLower(trace.TransactionHash) + ":" + strings.ToLower(trace.Contract)
			if _, exists := seenTrace[key]; exists {
				return result, inputError("block %d contains duplicate SELFDESTRUCT trace %s", block.Number, key)
			}
			seenTrace[key] = struct{}{}
			if trace.CreatedInSameTransaction && common.HexToAddress(trace.Beneficiary) == common.HexToAddress(trace.Contract) {
				burn, err := quantity(trace.BurnedAmount)
				if err != nil {
					return result, inputError("block %d invalid selfdestruct burn amount: %v", block.Number, err)
				}
				selfDestructBurn.Add(selfDestructBurn, burn)
			} else if trace.BurnedAmount != "0x0" && trace.BurnedAmount != "0" && trace.BurnedAmount != "" {
				burn, err := quantity(trace.BurnedAmount)
				if err != nil {
					return result, inputError("block %d invalid trace burn amount: %v", block.Number, err)
				}
				if burn.Sign() != 0 {
					return result, inputError("block %d reports a burn outside Cancun's permitted SELFDESTRUCT case", block.Number)
				}
			}
		}
		previousHash = strings.ToLower(block.Hash)
	}
	if snapshot.CertifiedBlock.Number > 0 && strings.ToLower(snapshot.Blocks[len(snapshot.Blocks)-1].Hash) != strings.ToLower(snapshot.CertifiedBlock.Hash) {
		return result, inputError("certified block hash does not match final history header")
	}
	if snapshot.CertifiedBlock.Number == 0 && strings.ToLower(snapshot.GenesisHash) != strings.ToLower(snapshot.CertifiedBlock.Hash) {
		return result, inputError("genesis snapshot hash does not match certified block")
	}

	expectedSupply := new(big.Int).Sub(genesisSupply, baseFeeBurn)
	expectedSupply.Sub(expectedSupply, selfDestructBurn)
	result.Coverage.TraceComplete = traceComplete
	result.Coverage.UncoveredBlocks = uncovered
	result.Native = NativeMetrics{GenesisSupply: genesisSupply.String(), BaseFeeBurn: baseFeeBurn.String(), SelfDestructBurn: selfDestructBurn.String(), ExpectedFromObservedBurns: expectedSupply.String(), Actual: actualSupply.String()}
	if expectedSupply.Sign() < 0 {
		result.addViolation("native_supply_formula", "observed burns exceed genesis supply", "non-negative", expectedSupply.String())
	}
	if traceComplete {
		match := expectedSupply.Cmp(actualSupply) == 0
		result.Native.Matches = &match
		if !match {
			result.addViolation("native_supply_mismatch", "full-state native supply differs from genesis less base-fee and permitted SELFDESTRUCT burns", expectedSupply.String(), actualSupply.String())
		}
	} else {
		// Unseen permitted SELFDESTRUCT burns can only lower the expected result. A higher
		// observed balance is still a definite unexplained mint; a lower balance is inconclusive.
		if actualSupply.Cmp(expectedSupply) > 0 {
			result.addViolation("native_supply_mismatch", "native supply exceeds the maximum allowed after observed burns", "<= "+expectedSupply.String(), actualSupply.String())
		}
		result.Status = "inconclusive"
	}

	_, wuctAccount, wuctBalance, err := accountFor(snapshot.Addresses.WUCT)
	if err != nil {
		return result, err
	}
	wuctSupply, err := readStorage(wuctAccount, wuctSupplySlot)
	if err != nil {
		return result, inputError("read WUCT totalSupply: %v", err)
	}
	result.WUCT = TokenMetrics{TotalSupply: wuctSupply.String(), NativeBalance: wuctBalance.String(), Covered: true}
	if wuctSupply.Cmp(wuctBalance) > 0 {
		result.addViolation("wuct_native_custody", "WUCT totalSupply exceeds native balance held by WUCT", wuctSupply.String(), wuctBalance.String())
	}
	for _, vaultText := range snapshot.Addresses.VestingVaults {
		vaultAddress, account, balance, err := accountFor(vaultText)
		if err != nil {
			return result, err
		}
		code, err := decodeHex(account.Code)
		if err != nil {
			return result, inputError("vault %s code: %v", vaultAddress, err)
		}
		principal, err := readVaultPrincipal(code)
		if err != nil {
			return result, inputError("vault %s principal: %v", vaultAddress, err)
		}
		released, err := readStorage(account, vaultReleasedSlot)
		if err != nil {
			return result, inputError("vault %s released storage: %v", vaultAddress, err)
		}
		unreleased := new(big.Int).Sub(new(big.Int).Set(principal), released)
		metrics := VaultMetrics{Address: vaultAddress.Hex(), Principal: principal.String(), Released: released.String(), NativeBalance: balance.String(), Covered: true}
		if unreleased.Sign() < 0 {
			result.addViolation("vesting_released_exceeds_principal", "vault released exceeds immutable principal", principal.String(), released.String())
			unreleased.SetInt64(0)
		}
		metrics.UnreleasedPrincipal = unreleased.String()
		if balance.Cmp(unreleased) < 0 {
			result.addViolation("vesting_underfunded", "vault balance is below unreleased principal", unreleased.String(), balance.String())
		}
		result.Vesting = append(result.Vesting, metrics)
	}
	collectorAddress, collectorAccount, collectorBalance, err := accountFor(snapshot.Addresses.FeeCollector)
	if err != nil {
		return result, err
	}
	credit, err := readStorage(collectorAccount, collectorCreditSlot)
	if err != nil {
		return result, inputError("FeeCollector treasuryCredit storage: %v", err)
	}
	reward, err := readStorage(collectorAccount, collectorRewardSlot)
	if err != nil {
		return result, inputError("FeeCollector rewardPot storage: %v", err)
	}
	liabilities := new(big.Int).Add(credit, reward)
	result.FeeCollector = LiabilityMetrics{Address: collectorAddress.Hex(), TreasuryCredit: credit.String(), RewardPot: reward.String(), TotalLiabilities: liabilities.String(), NativeBalance: collectorBalance.String(), Covered: true}
	if liabilities.Cmp(collectorBalance) > 0 {
		result.addViolation("fee_collector_liabilities", "FeeCollector liabilities exceed native balance", liabilities.String(), collectorBalance.String())
	}
	if len(result.Violations) > 0 {
		result.Status = "fail"
	}
	sort.Slice(result.Violations, func(i, j int) bool { return result.Violations[i].Check < result.Violations[j].Check })
	return result, nil
}

func (r *Result) addViolation(check, message, expected, actual string) {
	r.Violations = append(r.Violations, Violation{Check: check, Message: message, Expected: expected, Actual: actual})
	r.Status = "fail"
}
func inputError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInput, fmt.Sprintf(format, args...))
}
func strictDecode(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}
func isHash(value string) bool {
	if len(value) != 66 || !strings.HasPrefix(value, "0x") {
		return false
	}
	_, err := hex.DecodeString(value[2:])
	return err == nil
}
func quantity(value string) (*big.Int, error) {
	if value == "" {
		return nil, errors.New("empty quantity")
	}
	base := 10
	text := value
	if strings.HasPrefix(value, "0x") {
		base = 16
		text = value[2:]
	}
	if text == "" {
		return nil, errors.New("empty quantity")
	}
	n, ok := new(big.Int).SetString(text, base)
	if !ok || n.Sign() < 0 || n.BitLen() > 256 {
		return nil, errors.New("quantity must be an unsigned 256-bit integer")
	}
	return n, nil
}
func parseZero(value string) error {
	n, err := quantity(value)
	if err != nil {
		return err
	}
	if n.Sign() != 0 {
		return fmt.Errorf("expected zero, got %s", n)
	}
	return nil
}
func decodeHex(value string) ([]byte, error) {
	if !strings.HasPrefix(value, "0x") {
		return nil, errors.New("hex value must have 0x prefix")
	}
	return hex.DecodeString(value[2:])
}
func readStorage(account Account, slot uint64) (*big.Int, error) {
	key := common.BigToHash(new(big.Int).SetUint64(slot)).Hex()
	value, ok := account.Storage[strings.ToLower(key)]
	if !ok {
		for k, v := range account.Storage {
			if strings.EqualFold(k, key) {
				value, ok = v, true
				break
			}
		}
	}
	if !ok {
		return nil, fmt.Errorf("missing storage slot %s", key)
	}
	n, err := quantity(value)
	if err != nil {
		return nil, err
	}
	if n.BitLen() > 256 {
		return nil, errors.New("storage word exceeds 256 bits")
	}
	return n, nil
}
func readVaultPrincipal(code []byte) (*big.Int, error) {
	// solc 0.8.37 / Cancun / via-IR artifact at ContractsCommit. Principal is the
	// immutable with two runtime references at byte offsets 487 and 1142.
	const first, second = 487, 1142
	if len(code) < second+32 {
		return nil, fmt.Errorf("runtime code too short for pinned immutable layout")
	}
	a := new(big.Int).SetBytes(code[first : first+32])
	b := new(big.Int).SetBytes(code[second : second+32])
	if a.Cmp(b) != 0 {
		return nil, errors.New("principal immutable references disagree")
	}
	return a, nil
}
