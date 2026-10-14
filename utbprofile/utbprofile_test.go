package utbprofile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func write(t *testing.T, path string, n int) string {
	require.NoError(t, os.WriteFile(path, make([]byte, n), 0o644))
	return path
}

func TestFreshDeploymentPasses(t *testing.T) {
	d := t.TempDir()
	in := Inputs{Role: Root, GenesisFile: write(t, filepath.Join(d, "g.cbor"), 10), GenesisID: "0x01", EntriesDB: filepath.Join(d, "utb.db"),
		LegacyDBs: []string{filepath.Join(d, "rootchain.db")}, Profile2: true}
	require.NoError(t, Check(in))
	require.NoError(t, Check(Inputs{Role: Shard, EntriesDB: filepath.Join(d, "none.db")}), "a plain node with no entry store is not the profile's business")
}

func TestRefusals(t *testing.T) {
	d := t.TempDir()
	genesis := write(t, filepath.Join(d, "g.cbor"), 10)
	utbDB := filepath.Join(d, "utb.db")
	legacy := write(t, filepath.Join(d, "rootchain.db"), 100)
	base := Inputs{Role: Root, GenesisFile: genesis, GenesisID: "0x01", EntriesDB: utbDB, Profile2: true}

	for name, tc := range map[string]struct {
		mut  func(in *Inputs)
		want string
	}{
		"a pin without a genesis entry": {func(in *Inputs) { in.GenesisFile = "" }, "go together"},
		"a genesis entry without a pin": {func(in *Inputs) { in.GenesisID = "" }, "go together"},
		"a root without profile 2":      {func(in *Inputs) { in.Profile2 = false }, "profile 2"},
		"a missing genesis file":        {func(in *Inputs) { in.GenesisFile = filepath.Join(d, "missing") }, "missing or empty"},
		"an empty genesis file":         {func(in *Inputs) { in.GenesisFile = write(t, filepath.Join(d, "empty"), 0) }, "missing or empty"},
		"a legacy database":             {func(in *Inputs) { in.LegacyDBs = []string{legacy} }, "no approved migration"},
		"an unwritable entry store":     {func(in *Inputs) { in.EntriesDB = filepath.Join(genesis, "x", "utb.db") }, "cannot be persisted"},
	} {
		t.Run(name, func(t *testing.T) {
			in := base
			tc.mut(&in)
			err := Check(in)
			require.ErrorIs(t, err, ErrRefused)
			require.ErrorContains(t, err, tc.want)
		})
	}

	t.Run("a legacy database next to an existing entry store is a continuation, not a migration", func(t *testing.T) {
		in := base
		in.LegacyDBs = []string{legacy}
		in.EntriesDB = write(t, filepath.Join(d, "existing-utb.db"), 50)
		require.NoError(t, Check(in))
	})
	t.Run("entries on disk but the profile off", func(t *testing.T) {
		err := Check(Inputs{Role: Shard, EntriesDB: write(t, filepath.Join(d, "shard-utb.db"), 50)})
		require.ErrorIs(t, err, ErrRefused)
		require.ErrorContains(t, err, "profile is off")
	})
	t.Run("every finding is reported", func(t *testing.T) {
		in := base
		in.GenesisID, in.Profile2, in.LegacyDBs = "", false, []string{legacy}
		err := Check(in)
		require.ErrorContains(t, err, "go together")
		require.ErrorContains(t, err, "profile 2")
		require.ErrorContains(t, err, "no approved migration")
	})
}
