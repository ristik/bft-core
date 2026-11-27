package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

// The owner keys are read by `ubft pos-relayer tx ... --sender-key`, which accepts 0x-prefixed hex only (found by the container rehearsal).
func TestOwnerKeysAre0xPrefixedHex(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	owners(dir, "2")
	for _, id := range []string{"identity-1", "identity-2"} {
		for _, role := range []string{"owner", "withdrawal", "payee"} {
			raw, err := os.ReadFile(filepath.Join(dir, id, role+".key"))
			if err != nil {
				t.Fatal(err)
			}
			key, err := hexutil.Decode(strings.TrimSpace(string(raw)))
			if err != nil || len(key) != 32 {
				t.Fatalf("%s/%s: %v (%d bytes)", id, role, err, len(key))
			}
		}
	}
}

// The faucet's genesis balance is the caller's (generate.py --faucet-balance), in wei; a malformed one makes no key.
func TestFaucetBalance(t *testing.T) {
	for _, balance := range []string{DefaultFaucetBalanceWei, "1", "200000000000000000000"} {
		var out bytes.Buffer
		dir := filepath.Join(t.TempDir(), "faucet")
		if err := faucet(dir, balance, &out); err != nil {
			t.Fatal(err)
		}
		var alloc map[string]map[string]string
		if err := json.Unmarshal(out.Bytes(), &alloc); err != nil || len(alloc) != 1 {
			t.Fatalf("alloc %q: %v", out.String(), err)
		}
		for _, account := range alloc {
			if account["balance"] != balance {
				t.Fatalf("balance %q, want %q", account["balance"], balance)
			}
		}
		for _, name := range []string{"keystore.json", "password"} {
			if info, err := os.Stat(filepath.Join(dir, name)); err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("%s: %v", name, err)
			}
		}
	}
	for _, bad := range []string{"", "0", "-1", "1e21", "0x10", "1.5", " 1", "01"} {
		dir := filepath.Join(t.TempDir(), "faucet")
		if err := faucet(dir, bad, io.Discard); err == nil {
			t.Fatalf("balance %q accepted", bad)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("balance %q: the directory was made", bad)
		}
	}
	if DefaultFaucetBalanceWei != "50000000000000000000000" {
		t.Fatal("the default is 50,000 UCT")
	}
}
