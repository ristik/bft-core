// Package m2archive tests the shell helper that archives a root's stores at a successor install.
package m2archive

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The root's block and record store (rootchain.db) holds the durable control cuts and the record log that the shard nodes' restart admission
// needs after an install (#488): the install step archives a copy and leaves it in place. The trust and orchestration stores are moved aside.
func TestInstallArchiveKeepsTheRootStoreInPlace(t *testing.T) {
	lib, err := filepath.Abs("../lib/m2-handoff-lib.sh")
	require.NoError(t, err)
	run := func(t *testing.T, env ...string) string {
		t.Helper()
		dir := t.TempDir()
		root := filepath.Join(dir, "test-nodes", "root1")
		require.NoError(t, os.MkdirAll(root, 0o755))
		for _, f := range []string{"rootchain.db", "trustbase.db", "root-trust-history.db", "orchestration.db"} {
			require.NoError(t, os.WriteFile(filepath.Join(root, f), []byte("old "+f), 0o644))
		}
		cmd := exec.Command("bash", "-c", "source "+lib+"; m2_archive_root_state 1 2")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		return root
	}
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }

	t.Run("by default", func(t *testing.T) {
		root := run(t)
		archive := filepath.Join(root, "pre-epoch-2-state")
		got, err := os.ReadFile(filepath.Join(root, "rootchain.db"))
		require.NoError(t, err, "rootchain.db stays in place")
		require.Equal(t, "old rootchain.db", string(got))
		copied, err := os.ReadFile(filepath.Join(archive, "rootchain.db"))
		require.NoError(t, err, "and a copy is archived")
		require.Equal(t, "old rootchain.db", string(copied))
		for _, f := range []string{"trustbase.db", "root-trust-history.db", "orchestration.db"} {
			require.False(t, exists(filepath.Join(root, f)), "%s is moved aside", f)
			require.True(t, exists(filepath.Join(archive, f)), "%s is archived", f)
		}
	})
	t.Run("the old behaviour is an explicit choice", func(t *testing.T) {
		root := run(t, "M2_ARCHIVE_MOVE_ROOT_DB=1")
		require.False(t, exists(filepath.Join(root, "rootchain.db")))
		require.True(t, exists(filepath.Join(root, "pre-epoch-2-state", "rootchain.db")))
	})
}
