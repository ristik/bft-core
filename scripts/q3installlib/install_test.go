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
	// a joiner (a follower of epoch 2) whose image acquires the activation from a root peer, before it switched
	joinerWaiting = `{"activeEpoch":2,"follower":true,"switch":{"phase":"running","epoch":2,"acquires":true}}`
	oldCert       = `{"epoch":2,"round":40}`
	newCert       = `{"epoch":3,"round":41}`
)

// install runs q3_install_roots 3 over the stubbed roots and returns its output, the restart call (roots and boot root) and its error.
func install(t *testing.T, roots map[string]root, env ...string) (string, string, error) {
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
h3_restart_roots() { echo "restart roots=[$H3_ROOTS] epoch=$1 boot=[${H3_BOOT_ROOT:-}] wait=[${H3_WAIT_ROOT:-}]" >restart.txt; }
# bash's SECONDS counts whole seconds, so a wait of N lasts between N-1 and N seconds: a wait of 1 could expire within milliseconds and restart a root
# whose stubbed status sequence had not reached "published" yet (a CI flake). 3 leaves at least 2 s for the cases that must not reach the deadline.
Q3_SWITCH_WAIT=3 H3_ROOTS="` + strings.Join(sortStrings(ids), " ") + `" q3_install_roots 3
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
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
		require.Equal(t, "restart roots=[5] epoch=3 boot=[1] wait=[1]", restart, "the leaver bootstraps to a switched root, and the restart waits on that member")
	})
	t.Run("a joiner that acquires the activation is waited for until it switched (bft-core#1086 PR 2)", func(t *testing.T) {
		out, restart, err := install(t, map[string]root{"1": {statuses: []string{published}},
			"5": {statuses: []string{joinerWaiting, joinerWaiting, published}, signers: oldCert}}, "Q3_EXPECT_SWITCHED=1 5")
		require.NoError(t, err, out)
		require.Contains(t, out, "switched in process: 1 5; restarted: none")
		require.Empty(t, restart)
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
		require.Equal(t, "restart roots=[2] epoch=3 boot=[1] wait=[1]", restart)
	})
	t.Run("switching throughout, undecided and older images are restarted", func(t *testing.T) {
		out, restart, err := install(t, map[string]root{
			"1": {statuses: []string{switching}, signers: oldCert}, "2": {statuses: []string{undecided}, signers: oldCert},
			"3": {statuses: []string{olderImage}, signers: oldCert}})
		require.NoError(t, err, out)
		require.Equal(t, "restart roots=[3 1 2] epoch=3 boot=[] wait=[]", restart)
	})
	t.Run("a faulted root is restarted, also while it is down", func(t *testing.T) {
		out, restart, err := install(t, map[string]root{"1": {statuses: []string{published}}, "2": {statuses: []string{faulted}}})
		require.NoError(t, err, out)
		require.Equal(t, "restart roots=[2] epoch=3 boot=[1] wait=[1]", restart)
	})
	t.Run("a root to restart that holds a certificate of the new epoch breaks the barrier", func(t *testing.T) {
		out, restart, err := install(t, map[string]root{"1": {statuses: []string{olderImage}, signers: newCert}})
		require.Error(t, err)
		require.Contains(t, out, "root 1 reports a certificate of epoch 3 before its install restart into 3")
		require.Empty(t, restart, "nothing is restarted")
	})
	t.Run("an expected switch that did not happen fails the step", func(t *testing.T) {
		roots := map[string]root{"1": {statuses: []string{published}}, "2": {statuses: []string{declined}, signers: oldCert}}
		out, restart, err := install(t, roots, "Q3_EXPECT_SWITCHED=1 2")
		require.Error(t, err)
		require.Contains(t, out, "root 2 was expected to switch into epoch 3 in process, but is restarted")
		require.Empty(t, restart)
		out, _, err = install(t, roots, "Q3_EXPECT_SWITCHED=1")
		require.NoError(t, err, out)
	})
}

// h3_restart_roots with only some roots to restart (bft-core#1086): each bootstraps to H3_BOOT_ROOT (a root that switched in process, still running), in both
// the one-by-one and the together form, and the restart waits on H3_WAIT_ROOT; without them the form of before (a root of the set, the first root).
func TestRestartOfSomeRootsBootstrapsToTheSwitchedRoot(t *testing.T) {
	lib, err := filepath.Abs("../lib/h3-lib.sh")
	require.NoError(t, err)
	run := func(t *testing.T, env ...string) string {
		t.Helper()
		dir := t.TempDir()
		script := `
source "` + lib + `"
mkdir test-nodes
marker=test-nodes/.stall-watch-pause
stop_pidfile() { [ -f "$marker" ]; }; lsof() { return 1; }; m2_archive_root_state() { :; }; m2_rpc_port() { echo 1; }
m2_root_addr() { echo "addr$1"; }
m2_start_root() { [ -f "$marker" ] && echo "start $1 epoch=$2 boot=[$3]" >>calls.txt; }
m2_wait_root_epoch() { [ -f "$marker" ] && echo "wait $1 epoch=$2" >>calls.txt; }
h3_restart_roots 3 || exit 1
[ ! -e "$marker" ] || exit 1
cat calls.txt`
		cmd := exec.Command("bash", "-c", script)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), env...)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		require.NoError(t, err, stderr.String())
		return strings.TrimSpace(string(out))
	}
	t.Run("one by one", func(t *testing.T) {
		require.Equal(t, "start 5 epoch=3 boot=[addr1]\nwait 1 epoch=3", run(t, "H3_ROOTS=5", "H3_BOOT_ROOT=1", "H3_WAIT_ROOT=1"))
		require.Equal(t, "start 1 epoch=3 boot=[addr2]\nstart 2 epoch=3 boot=[addr1]\nwait 1 epoch=3", run(t, "H3_ROOTS=1 2"), "as before")
	})
	t.Run("together", func(t *testing.T) {
		out := run(t, "H3_ROOTS=4 5", "H3_BOOT_ROOT=1", "H3_WAIT_ROOT=1", "H3_RESTART_TOGETHER=1")
		require.Contains(t, out, "start 4 epoch=3 boot=[addr1]")
		require.Contains(t, out, "start 5 epoch=3 boot=[addr4]")
		require.Contains(t, out, "wait 1 epoch=3")
		require.Contains(t, run(t, "H3_ROOTS=1 2", "H3_RESTART_TOGETHER=1"), "start 1 epoch=3 boot=[]", "as before: the first root has no bootnode")
	})
}

func TestM2InstallPausesRootWatchdogThroughEpochReadiness(t *testing.T) {
	lib, err := filepath.Abs("../lib/m2-handoff-lib.sh")
	require.NoError(t, err)
	script := `
set -eu
source "$1"
mkdir test-nodes
marker=test-nodes/.stall-watch-pause
stop_pidfile() { [ -f "$marker" ]; }
lsof() { return 1; }
m2_root_addr() { echo "addr$1"; }
m2_archive_root_state() { [ -f "$marker" ]; }
m2_start_root() { [ -f "$marker" ]; }
m2_wait_root_epoch() { [ -f "$marker" ] || exit 2; [ "$2" = 2 ]; }
m2_online_validators() { :; }
m2_advance_authorities() { [ ! -e "$marker" ]; }
m2_send_paid() { :; }
m2_measure_pause() { :; }

m2_install_epoch 2 "1 2"
[ ! -e "$marker" ]

if m2_install_epoch 3 "1 2"; then
  echo "install succeeded despite failed epoch readiness" >&2
  exit 1
fi
[ -f "$marker" ]`
	cmd := exec.Command("bash", "-c", script, "m2-install-watchdog-fixture", lib)
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}
