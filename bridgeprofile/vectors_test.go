package bridgeprofile

import (
	"bytes"
	"encoding/hex"
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const goldenPath = "testdata/bridge-pr1-vectors-v1.json"

var update = flag.Bool("update", false, "rewrite the golden vector manifest")

func TestGoldenManifest(t *testing.T) {
	m, err := BuildManifest()
	require.NoError(t, err)
	got, err := m.JSON()
	require.NoError(t, err)
	if *update {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(goldenPath, got, 0o644))
	}
	want, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "go test ./bridgeprofile -update")
	require.True(t, bytes.Equal(want, got), "golden manifest differs; rerun with -update and review the diff")
}

// TestVectorsReplay re-executes every vector through the oracle's public API
// and compares with the manifest's expected outcome, so a stale expectation
// cannot hide behind the generator.
func TestVectorsReplay(t *testing.T) {
	m, err := BuildManifest()
	require.NoError(t, err)
	f := NewFixture(31337, 11, H([]byte("fixture-agg-conf")))
	seen := map[string]bool{}
	for _, v := range m.Vectors {
		require.False(t, seen[v.ID], "duplicate vector id %s", v.ID)
		seen[v.ID] = true
		in, _ := hex.DecodeString(v.Input)
		var res *Result
		var err error
		switch v.Op {
		case "mint":
			res, err = VerifyMint(f.Cfg, in)
		case "return":
			res, err = VerifyReturn(f.Cfg, in)
		default:
			continue // covered by the family tests
		}
		got := expectFor(res, err)
		require.Equal(t, v.Expected, got, v.ID)
	}
	// Every sentinel the manifest names must exist and every family appears.
	fam := map[string]bool{}
	for _, v := range m.Vectors {
		fam[v.Family] = true
	}
	for _, f := range []string{"derivation", "unlock", "policy", "envelope", "prepare", "history", "wire"} {
		require.True(t, fam[f], f)
	}
}
