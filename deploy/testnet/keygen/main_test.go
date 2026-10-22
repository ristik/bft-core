package main

import (
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
