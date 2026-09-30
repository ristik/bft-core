package supplyaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/registrygenesis"
)

const (
	addrEOA       = "0x1000000000000000000000000000000000000001"
	addrWUCT      = "0x2000000000000000000000000000000000000001"
	addrVault     = "0x3000000000000000000000000000000000000001"
	addrCollector = "0x4000000000000000000000000000000000000001"
	genesisHash   = "0x0000000000000000000000000000000000000000000000000000000000000000"
	blockHash     = "0x1111111111111111111111111111111111111111111111111111111111111111"
	txHash        = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func artifactStorageSlotFromPinned(label string) (common.Hash, error) {
	fields, err := pinnedVestingStorageLayout()
	if err != nil {
		return common.Hash{}, err
	}
	return artifactStorageSlot(fields, label)
}

func TestPinnedVestingLayoutMatchesContractsArtifact(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "registrygenesis", "testdata", "t1-artifacts", "vesting.json"))
	require.NoError(t, err)
	hash := sha256.Sum256(raw)
	require.Equal(t, pinnedVestingArtifactSHA256, hex.EncodeToString(hash[:]))
	var source struct {
		StorageLayout struct {
			Storage []artifactStorageField `json:"storage"`
		} `json:"storageLayout"`
	}
	require.NoError(t, json.Unmarshal(raw, &source))
	embedded, err := pinnedVestingStorageLayout()
	require.NoError(t, err)
	require.Equal(t, source.StorageLayout.Storage, embedded)
}

func fixture(t *testing.T) ([]byte, []byte, Snapshot) {
	t.Helper()
	vaultCode := "0x6000"
	genesis := map[string]any{"difficulty": "0x0", "config": map[string]any{"terminalTotalDifficultyPassed": true}, "alloc": map[string]any{
		addrEOA: map[string]any{"balance": "0x4b0"}, addrWUCT: map[string]any{"balance": "0x64", "code": "0x6000"}, addrVault: map[string]any{"balance": "0x96", "code": vaultCode}, addrCollector: map[string]any{"balance": "0x32", "code": "0x6001"},
	}}
	genesisJSON, err := json.Marshal(genesis)
	if err != nil {
		t.Fatal(err)
	}
	blob, withdrawals, complete := "0x0", uint64(0), true
	word := func(n int64) string { return common.BigToHash(big.NewInt(n)).Hex() }
	releasedSlot, err := artifactStorageSlotFromPinned("released")
	if err != nil {
		t.Fatal(err)
	}
	txCount := uint64(1)
	snapshot := Snapshot{Version: SnapshotVersion, ContractsCommit: ContractsCommit, GenesisHash: genesisHash, CertifiedBlock: CertifiedBlock{Number: 1, Hash: blockHash, Certified: true}, FullState: true, Addresses: Addresses{WUCT: addrWUCT, FeeCollector: addrCollector, VestingVaults: []string{addrVault}}, Accounts: map[string]Account{
		addrEOA:       {Balance: "0x4c9", Code: "0x", Storage: map[string]string{}},
		addrWUCT:      {Balance: "0x64", Code: "0x6000", Storage: map[string]string{common.BigToHash(big.NewInt(wuctSupplySlot)).Hex(): word(80)}},
		addrVault:     {Balance: "0x64", Code: vaultCode, Storage: map[string]string{releasedSlot.Hex(): word(50), common.Hash{}.Hex(): word(1)}},
		addrCollector: {Balance: "0x32", Code: "0x6001", Storage: map[string]string{common.BigToHash(big.NewInt(collectorCreditSlot)).Hex(): word(10), common.BigToHash(big.NewInt(collectorRewardSlot)).Hex(): word(5)}},
	}, Blocks: []BlockAccounting{{Number: 1, Hash: blockHash, ParentHash: genesisHash, Difficulty: "0x0", BaseFeePerGas: "0xa", GasUsed: "0x2", TransactionCount: &txCount, FeeReceipts: []FeeReceipt{{TransactionHash: txHash, GasUsed: "0x2", EffectiveGasPrice: "0xc", PriorityFeePerGas: "0x2"}}, BlobGasUsed: &blob, WithdrawalsCount: &withdrawals, SelfDestructTracesComplete: &complete, SelfDestructs: []SelfDestructTrace{{TransactionHash: txHash, Contract: "0x5000000000000000000000000000000000000001", Beneficiary: "0x5000000000000000000000000000000000000001", CreatedInSameTransaction: true, Opcode: "SELFDESTRUCT", BurnedAmount: "0x5"}}}}}
	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return genesisJSON, snapshotJSON, snapshot
}

func TestAuditSyntheticStatePassesAllInvariants(t *testing.T) {
	g, s, _ := fixture(t)
	result, err := Audit(g, s)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "pass" {
		t.Fatalf("status=%s violations=%+v", result.Status, result.Violations)
	}
	if result.Native.GenesisSupply != "1500" || result.Native.BaseFeeBurn != "20" || result.Native.OrdinaryGasUsed != "2" || result.Native.SelfDestructBurn != "5" || result.Native.ExpectedFromObservedBurns != "1475" || result.Native.Actual != "1475" {
		t.Fatalf("unexpected supply audit: %+v", result.Native)
	}
	if !result.Coverage.TraceComplete || result.Coverage.CertificationAuthenticated {
		t.Fatalf("coverage must expose source assertions: %+v", result.Coverage)
	}
}

func TestAuditUsesRealExportedGenesisVestingStorage(t *testing.T) {
	manifestInput, err := os.ReadFile(filepath.Join("..", "registrygenesis", "testdata", "allocation-build-v1.example.json"))
	require.NoError(t, err)
	exported, err := registrygenesis.ExportAllocationManifest(manifestInput)
	require.NoError(t, err)
	manifest, err := registrygenesis.DecodeAllocationManifest(exported)
	require.NoError(t, err)
	genesisJSON, err := registrygenesis.CompileAllocationManifest(exported, 1337)
	require.NoError(t, err)

	var genesis Genesis
	require.NoError(t, json.Unmarshal(genesisJSON, &genesis))
	accounts := make(map[string]Account, len(genesis.Alloc))
	for address, account := range genesis.Alloc {
		storage := make(map[string]string, len(account.Storage))
		for key, value := range account.Storage {
			storage[key] = value
		}
		accounts[address] = Account{Balance: account.Balance, Code: account.Code, Storage: storage}
	}
	fields, err := pinnedVestingStorageLayout()
	require.NoError(t, err)
	releasedSlot, err := artifactStorageSlot(fields, "released")
	require.NoError(t, err)
	statusSlot, err := artifactStorageSlot(fields, "_status")
	require.NoError(t, err)
	word := func(n int64) string { return common.BigToHash(big.NewInt(n)).Hex() }
	setStorage := func(address string, slot common.Hash, value string) {
		key := common.HexToAddress(address).Hex()
		account := accounts[key]
		if account.Storage == nil {
			account.Storage = make(map[string]string)
		}
		account.Storage[slot.Hex()] = value
		accounts[key] = account
	}
	setStorage(manifest.Addresses.WUCT, common.BigToHash(big.NewInt(wuctSupplySlot)), word(0))
	setStorage(manifest.Addresses.FeeCollector, common.BigToHash(big.NewInt(collectorCreditSlot)), word(0))
	setStorage(manifest.Addresses.FeeCollector, common.BigToHash(big.NewInt(collectorRewardSlot)), word(0))
	for _, vault := range []string{manifest.Addresses.TeamVesting, manifest.Addresses.EcosystemVesting} {
		key := common.HexToAddress(vault).Hex()
		genesisVault := genesis.Alloc[key]
		require.NotEmpty(t, genesisVault.Code, "test uses constructor-exported vault runtime")
		status, err := readStorageAt(Account{Storage: genesisVault.Storage}, statusSlot)
		require.NoError(t, err)
		require.Equal(t, big.NewInt(1), status, "constructor-exported ReentrancyGuard slot 0 is retained")
		// Export omits zero-valued released storage; the RPC state capture still supplies it.
		setStorage(vault, releasedSlot, word(0))
	}

	blob, withdrawals, complete := "0x0", uint64(0), true
	transactionCount := uint64(0)
	snapshot := Snapshot{
		Version: SnapshotVersion, ContractsCommit: ContractsCommit, GenesisHash: genesisHash,
		CertifiedBlock: CertifiedBlock{Number: 1, Hash: blockHash, Certified: true}, FullState: true,
		Addresses: Addresses{WUCT: manifest.Addresses.WUCT, FeeCollector: manifest.Addresses.FeeCollector,
			VestingVaults: []string{manifest.Addresses.TeamVesting, manifest.Addresses.EcosystemVesting}},
		Accounts: accounts,
		Blocks: []BlockAccounting{{Number: 1, Hash: blockHash, ParentHash: genesisHash, Difficulty: "0x0",
			BaseFeePerGas: "0x1", GasUsed: "0x1", TransactionCount: &transactionCount,
			FeeReceipts: []FeeReceipt{}, BlobGasUsed: &blob, WithdrawalsCount: &withdrawals,
			SelfDestructTracesComplete: &complete, SelfDestructs: []SelfDestructTrace{}}},
	}
	snapshotJSON, err := json.Marshal(snapshot)
	require.NoError(t, err)
	result, err := Audit(genesisJSON, snapshotJSON)
	require.NoError(t, err)
	require.Equal(t, "pass", result.Status, "%+v", result.Violations)
	require.Equal(t, "0", result.Native.BaseFeeBurn, "system-only header gas is not paid transaction gas")
	require.Equal(t, "0", result.Native.OrdinaryGasUsed)
	require.Equal(t, "200000000000000000000000000", result.Vesting[0].Principal)
	require.Equal(t, "300000000000000000000000000", result.Vesting[1].Principal)
}

func TestUrethT4LaneReceiptBurnExcludesSystemPrefix(t *testing.T) {
	// Captured from live T4 block 3 in briefs/devnet-runs/t4-incremental-20260930T081700Z.
	// Its header includes 111003 reserved system gas plus this paid type-2 claim receipt.
	transactionCount := uint64(1)
	block := BlockAccounting{
		Number: 3, Hash: "0xa06e7f5b4e5277c04d5b21e1350dbcf48b3fe1894a3fd281c7e22a7cee73c145",
		BaseFeePerGas: "0x27f4c49c", GasUsed: "0x2f1cb", TransactionCount: &transactionCount,
		FeeReceipts: []FeeReceipt{{TransactionHash: "0xdc6ac0387de6596127d3d7939d9a634d94662a7e7065202b498f07efae563648",
			GasUsed: "0x14030", EffectiveGasPrice: "0x638f8e9c", PriorityFeePerGas: "0x3b9aca00"}},
	}
	baseFee, err := quantity(block.BaseFeePerGas)
	require.NoError(t, err)
	headerGas, err := quantity(block.GasUsed)
	require.NoError(t, err)
	burn, ordinaryGas, err := baseFeeBurnForBlock(block, baseFee, headerGas)
	require.NoError(t, err)
	require.Equal(t, int64(81968), ordinaryGas.Int64())
	require.Equal(t, int64(111003), new(big.Int).Sub(headerGas, ordinaryGas).Int64())
	require.Equal(t, "54947456998720", burn.String())

	// The recorded FeeCollector balance delta is the ordinary priority fee. Removing it
	// from the effective transaction fee leaves exactly the base fee burned above.
	effective, _ := quantity("0x638f8e9c")
	tip, _ := quantity("0x3b9aca00")
	totalEffectiveFee := new(big.Int).Mul(effective, ordinaryGas)
	priorityCredit := new(big.Int).Mul(tip, ordinaryGas)
	collectorBefore, _ := quantity("0x394c549ef000")
	collectorAfter, _ := quantity("0x83d8fe24d000")
	require.Equal(t, priorityCredit, new(big.Int).Sub(collectorAfter, collectorBefore))
	require.Equal(t, burn, new(big.Int).Sub(totalEffectiveFee, priorityCredit))
}

func TestAuditRejectsMissingOrMismatchedFeeReceiptCoverage(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*BlockAccounting)
	}{
		{"missing receipts", func(b *BlockAccounting) { b.FeeReceipts = nil }},
		{"receipt count mismatch", func(b *BlockAccounting) { count := uint64(2); b.TransactionCount = &count }},
		{"priority fee mismatch", func(b *BlockAccounting) { b.FeeReceipts[0].PriorityFeePerGas = "0x1" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			g, _, snapshot := fixture(t)
			test.mutate(&snapshot.Blocks[0])
			raw, err := json.Marshal(snapshot)
			require.NoError(t, err)
			_, err = Audit(g, raw)
			require.ErrorIs(t, err, ErrInput)
		})
	}
}

func TestAuditDetectsEveryInvariantViolation(t *testing.T) {
	tests := []struct {
		name, check string
		mutate      func(*Snapshot)
	}{
		{"native mint", "native_supply_mismatch", func(s *Snapshot) { a := s.Accounts[addrEOA]; a.Balance = "0x4ca"; s.Accounts[addrEOA] = a }},
		{"unexpected native burn", "native_supply_mismatch", func(s *Snapshot) { a := s.Accounts[addrEOA]; a.Balance = "0x4c8"; s.Accounts[addrEOA] = a }},
		{"WUCT custody", "wuct_native_custody", func(s *Snapshot) {
			a := s.Accounts[addrWUCT]
			a.Storage[common.BigToHash(big.NewInt(wuctSupplySlot)).Hex()] = common.BigToHash(big.NewInt(101)).Hex()
			s.Accounts[addrWUCT] = a
		}},
		{"vault underfunding", "vesting_underfunded", func(s *Snapshot) {
			a := s.Accounts[addrVault]
			a.Balance = "0x63"
			s.Accounts[addrVault] = a
			e := s.Accounts[addrEOA]
			e.Balance = "0x4ca"
			s.Accounts[addrEOA] = e
		}},
		{"released exceeds principal", "vesting_released_exceeds_principal", func(s *Snapshot) {
			a := s.Accounts[addrVault]
			releasedSlot, err := artifactStorageSlotFromPinned("released")
			if err != nil {
				t.Fatal(err)
			}
			a.Storage[releasedSlot.Hex()] = common.BigToHash(big.NewInt(151)).Hex()
			s.Accounts[addrVault] = a
		}},
		{"collector liabilities", "fee_collector_liabilities", func(s *Snapshot) {
			a := s.Accounts[addrCollector]
			a.Storage[common.BigToHash(big.NewInt(collectorRewardSlot)).Hex()] = common.BigToHash(big.NewInt(51)).Hex()
			s.Accounts[addrCollector] = a
		}},
		{"blob gas", "blob_rules_disabled", func(s *Snapshot) { v := "0x1"; s.Blocks[0].BlobGasUsed = &v }},
		{"withdrawals", "withdrawals_disabled", func(s *Snapshot) { v := uint64(1); s.Blocks[0].WithdrawalsCount = &v }},
		{"issuance", "issuance_disabled", func(s *Snapshot) { s.Blocks[0].Difficulty = "0x1" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			g, _, s := fixture(t)
			test.mutate(&s)
			raw, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			result, err := Audit(g, raw)
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != "fail" {
				t.Fatalf("status=%s", result.Status)
			}
			for _, v := range result.Violations {
				if v.Check == test.check {
					return
				}
			}
			t.Fatalf("missing violation %q: %+v", test.check, result.Violations)
		})
	}
}

func TestAuditReportsIncompleteTraceCoverage(t *testing.T) {
	g, _, s := fixture(t)
	complete := false
	s.Blocks[0].SelfDestructTracesComplete = &complete
	raw, _ := json.Marshal(s)
	result, err := Audit(g, raw)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "inconclusive" || result.Coverage.TraceComplete || len(result.Coverage.UncoveredBlocks) != 1 || result.Native.Matches != nil {
		t.Fatalf("incomplete traces were not surfaced: %+v", result)
	}
}

func TestAuditDoesNotCountNonPermittedSelfDestructAsBurn(t *testing.T) {
	g, _, s := fixture(t)
	s.Blocks[0].SelfDestructs[0].CreatedInSameTransaction = false
	s.Blocks[0].SelfDestructs[0].BurnedAmount = "0x0"
	a := s.Accounts[addrEOA]
	a.Balance = "0x4ce"
	s.Accounts[addrEOA] = a
	raw, _ := json.Marshal(s)
	result, err := Audit(g, raw)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "pass" || result.Native.SelfDestructBurn != "0" || result.Native.ExpectedFromObservedBurns != "1480" {
		t.Fatalf("non-permitted SELFDESTRUCT counted as burn: %+v", result)
	}
}

func TestAuditRejectsUnauthenticatedOrPartialInputs(t *testing.T) {
	g, _, snap := fixture(t)
	snap.FullState = false
	raw, _ := json.Marshal(snap)
	if _, err := Audit(g, raw); err == nil {
		t.Fatal("partial account state accepted")
	}
	_, _, snap = fixture(t)
	snap.CertifiedBlock.Certified = false
	raw, _ = json.Marshal(snap)
	if _, err := Audit(g, raw); err == nil {
		t.Fatal("uncertified block accepted")
	}
}
