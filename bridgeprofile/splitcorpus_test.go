package bridgeprofile

import (
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
