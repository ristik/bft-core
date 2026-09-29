package supplyaudit

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
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

func fixture(t *testing.T) ([]byte, []byte, Snapshot) {
	t.Helper()
	code := make([]byte, 1180)
	principal := make([]byte, 32)
	big.NewInt(150).FillBytes(principal)
	copy(code[487:], principal)
	copy(code[1142:], principal)
	vaultCode := "0x" + hex.EncodeToString(code)
	genesis := map[string]any{"difficulty": "0x0", "config": map[string]any{"terminalTotalDifficultyPassed": true}, "alloc": map[string]any{
		addrEOA: map[string]any{"balance": "0x4b0"}, addrWUCT: map[string]any{"balance": "0x64", "code": "0x6000"}, addrVault: map[string]any{"balance": "0x96", "code": vaultCode}, addrCollector: map[string]any{"balance": "0x32", "code": "0x6001"},
	}}
	genesisJSON, err := json.Marshal(genesis)
	if err != nil {
		t.Fatal(err)
	}
	blob, withdrawals, complete := "0x0", uint64(0), true
	word := func(n int64) string { return common.BigToHash(big.NewInt(n)).Hex() }
	snapshot := Snapshot{Version: SnapshotVersion, ContractsCommit: ContractsCommit, GenesisHash: genesisHash, CertifiedBlock: CertifiedBlock{Number: 1, Hash: blockHash, Certified: true}, FullState: true, Addresses: Addresses{WUCT: addrWUCT, FeeCollector: addrCollector, VestingVaults: []string{addrVault}}, Accounts: map[string]Account{
		addrEOA:       {Balance: "0x4c9", Code: "0x", Storage: map[string]string{}},
		addrWUCT:      {Balance: "0x64", Code: "0x6000", Storage: map[string]string{common.BigToHash(big.NewInt(wuctSupplySlot)).Hex(): word(80)}},
		addrVault:     {Balance: "0x64", Code: vaultCode, Storage: map[string]string{common.BigToHash(big.NewInt(vaultReleasedSlot)).Hex(): word(50), common.Hash{}.Hex(): word(1)}},
		addrCollector: {Balance: "0x32", Code: "0x6001", Storage: map[string]string{common.BigToHash(big.NewInt(collectorCreditSlot)).Hex(): word(10), common.BigToHash(big.NewInt(collectorRewardSlot)).Hex(): word(5)}},
	}, Blocks: []BlockAccounting{{Number: 1, Hash: blockHash, ParentHash: genesisHash, Difficulty: "0x0", BaseFeePerGas: "0xa", GasUsed: "0x2", BlobGasUsed: &blob, WithdrawalsCount: &withdrawals, SelfDestructTracesComplete: &complete, SelfDestructs: []SelfDestructTrace{{TransactionHash: txHash, Contract: "0x5000000000000000000000000000000000000001", Beneficiary: "0x5000000000000000000000000000000000000001", CreatedInSameTransaction: true, Opcode: "SELFDESTRUCT", BurnedAmount: "0x5"}}}}}
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
	if result.Native.GenesisSupply != "1500" || result.Native.BaseFeeBurn != "20" || result.Native.SelfDestructBurn != "5" || result.Native.ExpectedFromObservedBurns != "1475" || result.Native.Actual != "1475" {
		t.Fatalf("unexpected supply audit: %+v", result.Native)
	}
	if !result.Coverage.TraceComplete || result.Coverage.CertificationAuthenticated {
		t.Fatalf("coverage must expose source assertions: %+v", result.Coverage)
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
			a.Storage[common.BigToHash(big.NewInt(vaultReleasedSlot)).Hex()] = common.BigToHash(big.NewInt(151)).Hex()
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
