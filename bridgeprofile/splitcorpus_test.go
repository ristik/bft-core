package bridgeprofile

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const splitCorpusDir = "testdata/split-corpus"

// The checked-in split corpus is the generator's output; BRIDGEPROFILE_UPDATE_SPLIT_CORPUS=1 rewrites it.
func TestSplitCorpusIsCurrentAndDeterministic(t *testing.T) {
	a, err := BuildSplitCorpus()
	require.NoError(t, err)
	b, err := BuildSplitCorpus()
	require.NoError(t, err)
	require.Equal(t, a.Digest(), b.Digest(), "the generator is deterministic")
	if os.Getenv("BRIDGEPROFILE_UPDATE_SPLIT_CORPUS") != "" {
		for name, bs := range a.Files {
			p := filepath.Join(splitCorpusDir, name)
			require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
			require.NoError(t, os.WriteFile(p, bs, 0o644))
		}
	}
	for name, bs := range a.Files {
		got, err := os.ReadFile(filepath.Join(splitCorpusDir, name))
		require.NoError(t, err, "run with BRIDGEPROFILE_UPDATE_SPLIT_CORPUS=1: %s", name)
		require.Equal(t, bs, got, name)
	}
}

// Replay reproduces every expectation from the case and the fixture set alone.
func TestSplitCorpusReplay(t *testing.T) {
	c, err := BuildSplitCorpus()
	require.NoError(t, err)
	n := 0
	for _, fam := range splitFamilies {
		for _, cs := range c.Cases[fam] {
			require.Equal(t, cs.Expected, ReplaySplit(c.Set, cs), cs.ID)
			n++
		}
	}
	require.Greater(t, n, 80)
}

func TestSplitMutationFileReplays(t *testing.T) {
	c, err := BuildSplitCorpus()
	require.NoError(t, err)
	var mf MutationFile
	require.NoError(t, json.Unmarshal(c.Files["mutation/cases.json"], &mf))
	base, err := hex.DecodeString(mf.Base)
	require.NoError(t, err)
	statuses := map[string]int{}
	for _, m := range mf.Cases {
		require.Equal(t, m.Expected, ReplayMutation(base, mf.Claims, m.Patch), m.ID)
		statuses[m.Expected.Values["statusName"]+m.Expected.Values["halt"]]++
	}
	require.Len(t, mf.Cases, 400)
	require.Greater(t, statuses["ErrCertScan"], 0)
	t.Logf("statuses over %d mutations: %v", len(mf.Cases), statuses)
}
