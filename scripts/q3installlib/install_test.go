// Package q3installlib tests the lanes' installation barrier (scripts/lib/q3-flow-lib.sh q3_install_roots) against roots that switch into the epoch in
// process (bft-core#1086): a switched root is installed and not restarted, any other root is restarted after the check that it holds no certificate of the
// new epoch, and an unavailable or incomplete status is never evidence of an install.
package q3installlib

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// root is one stubbed root: its q3/status answers in turn (the last repeats; "" is unavailable) and its q3/signers answer ("" is a refusal: 422 or down).
type root struct {
	statuses []string
	signers  string
}

const (
	published  = `{"activeEpoch":3,"switch":{"phase":"running","epoch":3,"target":3,"tookMs":40}}`
	following  = `{"activeEpoch":3,"follower":true,"switch":{"phase":"following","epoch":3,"target":3}}`
	switching  = `{"activeEpoch":3,"switch":{"phase":"switching","epoch":2,"target":3}}`
	faulted    = `{"activeEpoch":3,"switch":{"phase":"faulted","epoch":2,"target":3}}`
	declined   = `{"activeEpoch":2,"switch":{"phase":"running","epoch":2,"declined":3,"declinedReason":"leaving"}}`
	undecided  = `{"activeEpoch":2,"switch":{"phase":"running","epoch":2}}`
	olderImage = `{"activeEpoch":2}`
	oldCert    = `{"epoch":2,"round":40}`
	newCert    = `{"epoch":3,"round":41}`
)

// install runs q3_install_roots 3 over the stubbed roots and returns its output, the restart call (roots and boot root) and its error.
func install(t *testing.T, roots map[string]root) (string, string, error) {
	t.Helper()
	lib, err := filepath.Abs("../lib/q3-flow-lib.sh")
	require.NoError(t, err)
	dir := t.TempDir()
	var ids []string
	for id, r := range roots {
		ids = append(ids, id)
		for i, s := range r.statuses {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "status-"+id+"-"+string(rune('a'+i))), []byte(s), 0o644))
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, "count-"+id), []byte(string(rune('a'+len(r.statuses)-1))), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "signers-"+id), []byte(r.signers), 0o644))
	}
	script := `
source "` + lib + `"
sleep() { command sleep 0.01; }
q3_status_of() {   # the stubbed root's next answer; an empty one is unavailable
  local n=$(cat "count-$1") seen=$(cat "seen-$1" 2>/dev/null || echo a) s
  s=$(cat "status-$1-$seen")
  [ "$seen" = "$n" ] || printf '%s' "$(printf '%s' "$seen" | tr 'a-y' 'b-z')" >"seen-$1"
  [ -n "$s" ] || return 22
  printf '%s' "$s"
}
q3_signers_of() { local s; s=$(cat "signers-$1"); [ -n "$s" ] || return 22; printf '%s' "$s"; }
h3_restart_roots() { echo "restart roots=[$H3_ROOTS] epoch=$1 boot=[${H3_BOOT_ROOT:-}]" >restart.txt; }
Q3_SWITCH_WAIT=1 H3_ROOTS="` + strings.Join(sortStrings(ids), " ") + `" q3_install_roots 3
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	restart, _ := os.ReadFile(filepath.Join(dir, "restart.txt"))
	return string(out), strings.TrimSpace(string(restart)), err
}

func sortStrings(s []string) []string {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
	return s
}

func TestTheInstallBarrierWithInProcessSwitches(t *testing.T) {
	t.Run("staying roots that switched are installed, the leaver is restarted", func(t *testing.T) {
		out, restart, err := install(t, map[string]root{
			"1": {statuses: []string{published}}, "2": {statuses: []string{published}}, "3": {statuses: []string{published}},
			"4": {statuses: []string{published}}, "5": {statuses: []string{declined}, signers: oldCert}})
		require.NoError(t, err, out)
		require.Contains(t, out, "switched in process: 1 2 3 4; restarted: 5")
		require.Equal(t, "restart roots=[5] epoch=3 boot=[1]", restart, "the leaver bootstraps to a switched root")
	})
	t.Run("every root switched: nothing is restarted", func(t *testing.T) {
		out, restart, err := install(t, map[string]root{"1": {statuses: []string{published}}, "2": {statuses: []string{following}}})
		require.NoError(t, err, out)
		require.Empty(t, restart)
	})
	t.Run("an unavailable or switching status is no evidence: asked again until published", func(t *testing.T) {
		out, restart, err := install(t, map[string]root{"1": {statuses: []string{"", switching, "", published}}})
		require.NoError(t, err, out)
		require.Contains(t, out, "switched in process: 1; restarted: none")
		require.Empty(t, restart)
	})
	t.Run("a root that never answers its status is restarted after the wait", func(t *testing.T) {
		out, restart, err := install(t, map[string]root{"1": {statuses: []string{published}}, "2": {statuses: []string{""}, signers: oldCert}})
		require.NoError(t, err, out)
		require.Equal(t, "restart roots=[2] epoch=3 boot=[1]", restart)
	})
	t.Run("switching throughout, undecided and older images are restarted", func(t *testing.T) {
		out, restart, err := install(t, map[string]root{
			"1": {statuses: []string{switching}, signers: oldCert}, "2": {statuses: []string{undecided}, signers: oldCert},
			"3": {statuses: []string{olderImage}, signers: oldCert}})
		require.NoError(t, err, out)
		require.Equal(t, "restart roots=[3 1 2] epoch=3 boot=[]", restart)
	})
	t.Run("a faulted root is restarted, also while it is down", func(t *testing.T) {
		out, restart, err := install(t, map[string]root{"1": {statuses: []string{published}}, "2": {statuses: []string{faulted}}})
		require.NoError(t, err, out)
		require.Equal(t, "restart roots=[2] epoch=3 boot=[1]", restart)
	})
	t.Run("a root to restart that holds a certificate of the new epoch breaks the barrier", func(t *testing.T) {
		out, restart, err := install(t, map[string]root{"1": {statuses: []string{olderImage}, signers: newCert}})
		require.Error(t, err)
		require.Contains(t, out, "root 1 reports a certificate of epoch 3 before its install restart into 3")
		require.Empty(t, restart, "nothing is restarted")
	})
}
