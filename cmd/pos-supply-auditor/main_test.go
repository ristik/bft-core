package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unicitynetwork/bft-core/supplyaudit"
)

func TestRunEmitsMachineResultAndNonzeroOnViolation(t *testing.T) {
	genesisPath, snapshotPath, snapshot := writeT4AuditFixture(t)
	var stdout, stderr bytes.Buffer
	codeExit := run([]string{"--genesis", genesisPath, "--state-dump", snapshotPath}, &stdout, &stderr)
	if codeExit != 0 {
		t.Fatalf("valid audit exit=%d stderr=%s stdout=%s", codeExit, stderr.String(), stdout.String())
	}
	var result supplyaudit.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if result.Status != "pass" {
		t.Fatalf("status=%s", result.Status)
	}
	a := snapshot.Accounts["0x1000000000000000000000000000000000000001"]
	a.Balance = "0x4ca"
	snapshot.Accounts["0x1000000000000000000000000000000000000001"] = a
	snapshotJSON, _ := json.Marshal(snapshot)
	if err := os.WriteFile(snapshotPath, snapshotJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	codeExit = run([]string{"--genesis", genesisPath, "--state-dump", snapshotPath}, &stdout, &stderr)
	if codeExit == 0 {
		t.Fatal("supply violation exited successfully")
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("violation output is not JSON: %v", err)
	}
	if result.Status != "fail" {
		t.Fatalf("status=%s", result.Status)
	}
}

func TestRunMissingHeaderReceiptOrTraceIsInconclusiveExitTwo(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*supplyaudit.Snapshot)
	}{
		{"missing header", func(s *supplyaudit.Snapshot) { s.Blocks[0].Hash = "" }},
		{"missing receipt", func(s *supplyaudit.Snapshot) { s.Blocks[0].FeeReceipts = nil }},
		{"missing trace", func(s *supplyaudit.Snapshot) {
			s.Blocks[0].SelfDestructTracesComplete = nil
			s.Blocks[0].SelfDestructs = nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			genesisPath, snapshotPath, snapshot := writeT4AuditFixture(t)
			test.mutate(&snapshot)
			snapshotJSON, err := json.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(snapshotPath, snapshotJSON, 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			codeExit := run([]string{"--genesis", genesisPath, "--state-dump", snapshotPath}, &stdout, &stderr)
			if codeExit != 2 {
				t.Fatalf("incomplete audit exit=%d, want 2; stderr=%s stdout=%s", codeExit, stderr.String(), stdout.String())
			}
			var result supplyaudit.Result
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatalf("inconclusive output is not JSON: %v", err)
			}
			if result.Status != "inconclusive" {
				t.Fatalf("status=%q, want inconclusive", result.Status)
			}
			if len(result.Coverage.IncompleteReasons) == 0 {
				t.Fatal("inconclusive result omitted its coverage reason")
			}
		})
	}
}

func writeT4AuditFixture(t *testing.T) (string, string, supplyaudit.Snapshot) {
	t.Helper()
	code := make([]byte, 1180)
	principal := make([]byte, 32)
	big.NewInt(150).FillBytes(principal)
	copy(code[487:], principal)
	copy(code[1142:], principal)
	genesis := map[string]any{"difficulty": "0x0", "config": map[string]any{"terminalTotalDifficultyPassed": true}, "alloc": map[string]any{
		"0x1000000000000000000000000000000000000001": map[string]any{"balance": "0x4b0"},
		"0x2000000000000000000000000000000000000001": map[string]any{"balance": "0x64", "code": "0x6000"},
		"0x3000000000000000000000000000000000000001": map[string]any{"balance": "0x96", "code": "0x" + hex.EncodeToString(code)},
		"0x4000000000000000000000000000000000000001": map[string]any{"balance": "0x32", "code": "0x6001"},
	}}
	word := func(n int64) string { return common.BigToHash(big.NewInt(n)).Hex() }
	blob, withdrawals, traceComplete, transactionCount := "0x0", uint64(0), true, uint64(1)
	snapshot := supplyaudit.Snapshot{Version: supplyaudit.SnapshotVersion, ContractsCommit: supplyaudit.ContractsCommit, GenesisHash: "0x0000000000000000000000000000000000000000000000000000000000000000", CertifiedBlock: supplyaudit.CertifiedBlock{Number: 1, Hash: "0x1111111111111111111111111111111111111111111111111111111111111111", Certified: true}, FullState: true, Addresses: supplyaudit.Addresses{WUCT: "0x2000000000000000000000000000000000000001", FeeCollector: "0x4000000000000000000000000000000000000001", VestingVaults: []string{"0x3000000000000000000000000000000000000001"}}, Accounts: map[string]supplyaudit.Account{
		"0x1000000000000000000000000000000000000001": {Balance: "0x4c9", Code: "0x", Storage: map[string]string{}},
		"0x2000000000000000000000000000000000000001": {Balance: "0x64", Code: "0x6000", Storage: map[string]string{common.BigToHash(big.NewInt(2)).Hex(): word(80)}},
		"0x3000000000000000000000000000000000000001": {Balance: "0x64", Code: "0x" + hex.EncodeToString(code), Storage: map[string]string{common.BigToHash(big.NewInt(1)).Hex(): word(50)}},
		"0x4000000000000000000000000000000000000001": {Balance: "0x32", Code: "0x6001", Storage: map[string]string{common.BigToHash(big.NewInt(1)).Hex(): word(10), common.BigToHash(big.NewInt(2)).Hex(): word(5)}},
	}, Blocks: []supplyaudit.BlockAccounting{{Number: 1, Hash: "0x1111111111111111111111111111111111111111111111111111111111111111", ParentHash: "0x0000000000000000000000000000000000000000000000000000000000000000", Difficulty: "0x0", BaseFeePerGas: "0xa", GasUsed: "0x2", TransactionCount: &transactionCount, FeeReceipts: []supplyaudit.FeeReceipt{{TransactionHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", GasUsed: "0x2", EffectiveGasPrice: "0xc", PriorityFeePerGas: "0x2"}}, BlobGasUsed: &blob, WithdrawalsCount: &withdrawals, SelfDestructTracesComplete: &traceComplete, SelfDestructs: []supplyaudit.SelfDestructTrace{{TransactionHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Contract: "0x5000000000000000000000000000000000000001", Beneficiary: "0x5000000000000000000000000000000000000001", CreatedInSameTransaction: true, Opcode: "SELFDESTRUCT", BurnedAmount: "0x5"}}}}}
	genesisJSON, _ := json.Marshal(genesis)
	snapshotJSON, _ := json.Marshal(snapshot)
	dir := t.TempDir()
	genesisPath, snapshotPath := filepath.Join(dir, "genesis.json"), filepath.Join(dir, "state.json")
	if err := os.WriteFile(genesisPath, genesisJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapshotPath, snapshotJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	return genesisPath, snapshotPath, snapshot
}
