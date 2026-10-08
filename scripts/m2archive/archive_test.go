// Package m2archive tests the shell helper that archives a root's stores at a successor install.
package m2archive

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The root's stores are one consistent set: the block store (rootchain.db: committed blocks, durable control cuts, the record log of #488) is checked at
// start against the configurations the orchestration store derived from the committed handoffs, and the trust stores hold the installed epochs. The install
// step archives a copy of every store and leaves them all in place; only an explicit opt-out moves them.
func TestInstallArchiveKeepsEveryRootStoreInPlace(t *testing.T) {
	lib, err := filepath.Abs("../lib/m2-handoff-lib.sh")
	require.NoError(t, err)
	stores := []string{"rootchain.db", "trustbase.db", "root-trust-history.db", "orchestration.db"}
	run := func(t *testing.T, env ...string) string {
		t.Helper()
		dir := t.TempDir()
		root := filepath.Join(dir, "test-nodes", "root1")
		require.NoError(t, os.MkdirAll(root, 0o755))
		for _, f := range stores {
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

	t.Run("by default every store stays and a copy is archived", func(t *testing.T) {
		root := run(t)
		archive := filepath.Join(root, "pre-epoch-2-state")
		for _, f := range stores {
			got, err := os.ReadFile(filepath.Join(root, f))
			require.NoError(t, err, "%s stays in place", f)
			require.Equal(t, "old "+f, string(got))
			copied, err := os.ReadFile(filepath.Join(archive, f))
			require.NoError(t, err, "%s is archived", f)
			require.Equal(t, "old "+f, string(copied))
		}
	})
	t.Run("the old behaviour is an explicit choice", func(t *testing.T) {
		root := run(t, "M2_ARCHIVE_MOVE_STATE=1")
		for _, f := range stores {
			require.False(t, exists(filepath.Join(root, f)), "%s is moved aside", f)
			require.True(t, exists(filepath.Join(root, "pre-epoch-2-state", f)), "%s is archived", f)
		}
	})
}
