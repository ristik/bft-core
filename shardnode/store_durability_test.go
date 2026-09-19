package shardnode

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/types"
)

/*
Fault injection for the certificate checkpoint store, in the shape certifiedstore/fault_test.go and
certifiedstore/kill_test.go established: a checkpoint table, an injectable hook, an in-process
failure test, and a SIGKILL child-process test that reopens the real file.

The save that matters is durable, not merely atomic. A rename can never leave a half-written
checkpoint, but without the file sync the entry can name data the device has not written, and without
the directory sync the entry itself can be lost. The second failure is the dangerous one: an absent
file is a clean fresh start to LoadLUC, so a lost entry restarts a long-running validator from
genesis. These tests cover both the error path (in-process) and the lost-write path (SIGKILL), which
are different evidence.
*/

// saveCheckpoints are the points SaveLUC passes exactly once. The names are the fault-injection
// contract: a test or a child process names one and takes control there.
var saveCheckpoints = []string{
	"before-write",
	"after-write",
	"after-file-sync",
	"after-close",
	"after-rename",
	"after-dir-sync",
}

// savedAt reports whether the rename that names the new certificate has happened by this checkpoint.
// The rename is the point at which a reader of the path sees the new file; the directory sync is the
// point at which that entry survives a power loss. Both in-process and after SIGKILL the entry is
// already visible at "after-rename".
func savedAt(name string) bool {
	return name == "after-rename" || name == "after-dir-sync"
}

var errInjected = errors.New("shardnode test: injected checkpoint failure")

// failAt fails SaveLUC at the named checkpoint.
func failAt(name string) func(string) error {
	return func(got string) error {
		if got == name {
			return errInjected
		}
		return nil
	}
}

// killAt ends the process at the named checkpoint, so no deferred function runs.
func killAt(name string) func(string) error {
	return func(got string) error {
		if got == name {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {} // SIGKILL is delivered asynchronously; never return into SaveLUC
		}
		return nil
	}
}

// durabilityUC is a certificate whose round identifies it. The durability tests only compare which
// certificate LoadLUC returned, so these need to survive a marshaling round trip, not to verify as a
// real certificate; SaveLUC and LoadLUC do no signature work.
func durabilityUC(round uint64) *types.UnicityCertificate {
	return &types.UnicityCertificate{
		Version:     1,
		InputRecord: &types.InputRecord{Version: 1, RoundNumber: round, Hash: []byte{byte(round)}, SummaryValue: []byte{}},
		UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: round, Timestamp: round},
	}
}

// writePrior leaves the certificate whose round is 1 at path, so a failed save has a prior state to
// fall back to or replace.
func writePrior(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, NewFileStore(path).SaveLUC(durabilityUC(1)))
}

// requirePriorOrNew loads path and requires the prior certificate (round 1) or the new one (round
// 2), never an error and never a damaged file.
func requirePriorOrNew(t *testing.T, path string, wantNew bool) {
	t.Helper()
	uc, err := NewFileStore(path).LoadLUC()
	require.NoError(t, err, "a failed save must leave a readable prior or new certificate, never damage")
	require.NotNil(t, uc)
	if wantNew {
		require.Equal(t, uint64(2), uc.InputRecord.RoundNumber, "the new certificate")
		return
	}
	require.Equal(t, uint64(1), uc.InputRecord.RoundNumber, "the prior certificate")
}

// tempFiles lists the temporary checkpoints left in dir. SaveLUC's deferred remove should clear them
// on every in-process path; a SIGKILL before the rename cannot run that deferred remove, which is
// why the process-kill test does not assert this.
func tempFiles(t *testing.T, dir string) []string {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, ".luc-*.tmp"))
	require.NoError(t, err)
	return names
}

// TestSaveLUCSyncsTheFileAndTheDirectory: an ordinary save syncs the temporary file and then the
// directory, and the checkpoints fall on the correct sides of both. The event list is the whole
// assertion: a missing sync, a sync in the wrong order relative to the rename, or a synced file
// after the rename would all change it.
func TestSaveLUCSyncsTheFileAndTheDirectory(t *testing.T) {
	var events []string

	origFile, origDir := syncFile, syncDirectory
	syncFile = func(f *os.File) error {
		events = append(events, "file-sync")
		return origFile(f)
	}
	syncDirectory = func(dir string) error {
		events = append(events, "dir-sync")
		return origDir(dir)
	}
	t.Cleanup(func() { syncFile, syncDirectory = origFile, origDir })

	store := NewFileStore(filepath.Join(t.TempDir(), "luc.cbor"))
	store.checkpoint = func(name string) error {
		events = append(events, name)
		return nil
	}
	require.NoError(t, store.SaveLUC(durabilityUC(2)))

	require.Equal(t, []string{
		"before-write",
		"after-write",
		"file-sync",
		"after-file-sync",
		"after-close",
		"after-rename",
		"dir-sync",
		"after-dir-sync",
	}, events, "both syncs happen, in the order the write sequence requires")
}

// TestSaveLUCFailuresLeavePriorOrNewState: every checkpoint fails in turn. The prior or the new
// certificate loads afterwards, never an error and never a damaged file, and no temporary file
// survives the deferred remove.
func TestSaveLUCFailuresLeavePriorOrNewState(t *testing.T) {
	for _, name := range saveCheckpoints {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "luc.cbor")
			writePrior(t, path)

			store := NewFileStore(path)
			store.checkpoint = failAt(name)
			err := store.SaveLUC(durabilityUC(2))
			require.ErrorIs(t, err, errInjected, "the checkpoint failure is reported")

			requirePriorOrNew(t, path, savedAt(name))
			require.Empty(t, tempFiles(t, dir), "the deferred remove clears the temporary file")
		})
	}
}

const (
	childStoreEnv      = "SHARDNODE_CHILD_STORE"
	childCheckpointEnv = "SHARDNODE_CHILD_CHECKPOINT"
)

// TestChildProcessSavesUntilKilled runs only as the child of TestSaveLUCProcessKilledAtEachCheckpoint.
func TestChildProcessSavesUntilKilled(t *testing.T) {
	path := os.Getenv(childStoreEnv)
	if path == "" {
		t.Skip("child process of TestSaveLUCProcessKilledAtEachCheckpoint")
	}
	store := NewFileStore(path)
	store.checkpoint = killAt(os.Getenv(childCheckpointEnv))
	_ = store.SaveLUC(durabilityUC(2))
	t.Fatalf("checkpoint %s was not reached", os.Getenv(childCheckpointEnv))
}

// TestSaveLUCProcessKilledAtEachCheckpoint: a child process is SIGKILLed at each checkpoint, so no
// deferred remove or close runs, and the parent reopens the real file. This is the only one of the
// two classes that exercises a lost write rather than a returned error. After the rename the new
// certificate is what the parent sees; before it, the prior one.
func TestSaveLUCProcessKilledAtEachCheckpoint(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses SIGKILL")
	}
	for _, name := range saveCheckpoints {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "luc.cbor")
			writePrior(t, path)

			cmd := exec.Command(os.Args[0], "-test.run=^TestChildProcessSavesUntilKilled$", "-test.count=1")
			cmd.Env = append(os.Environ(), childStoreEnv+"="+path, childCheckpointEnv+"="+name)
			out, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			require.True(t, errors.As(err, &exitErr), "the child must not exit normally: %v\n%s", err, out)
			status, ok := exitErr.Sys().(syscall.WaitStatus)
			require.True(t, ok)
			require.True(t, status.Signaled() && status.Signal() == syscall.SIGKILL, "the child died by SIGKILL at %s:\n%s", name, out)

			requirePriorOrNew(t, path, savedAt(name))
		})
	}
}

// TestSaveLUCFailedSyncIsAnError: a failing sync fails the save instead of being ignored. The two
// syncs are on different sides of the rename, so they leave different states.
func TestSaveLUCFailedSyncIsAnError(t *testing.T) {
	t.Run("a failing file sync fails before the rename and leaves the prior certificate", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "luc.cbor")
		writePrior(t, path)

		orig := syncFile
		syncFile = func(*os.File) error { return errors.New("file sync failed") }
		t.Cleanup(func() { syncFile = orig })

		err := NewFileStore(path).SaveLUC(durabilityUC(2))
		require.ErrorContains(t, err, "syncing temp file")
		requirePriorOrNew(t, path, false)
		require.Empty(t, tempFiles(t, dir), "the temporary file is cleared")
	})

	t.Run("a failing directory sync fails after the rename replaced the file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "luc.cbor")
		writePrior(t, path)

		orig := syncDirectory
		syncDirectory = func(string) error { return errors.New("directory sync failed") }
		t.Cleanup(func() { syncDirectory = orig })

		err := NewFileStore(path).SaveLUC(durabilityUC(2))
		require.ErrorContains(t, err, "syncing store directory")
		// The rename has happened by the time the directory is synced, so the new certificate is
		// what a reader sees. The prior file cannot be intact at this step, and the error says
		// only that the new entry's durability was not confirmed. This is the one place the spec's
		// short phrase "the prior file is intact" does not describe what the code can do.
		requirePriorOrNew(t, path, true)
		require.Empty(t, tempFiles(t, dir), "the renamed temporary file no longer exists")
	})
}

// TestSaveLUCLeavesNoTemporaryFileBehind: the ordinary save and every in-process failure path clear
// the temporary file. A SIGKILL before the rename cannot, which is why this test is the in-process
// class only.
func TestSaveLUCLeavesNoTemporaryFileBehind(t *testing.T) {
	t.Run("the ordinary save", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, NewFileStore(filepath.Join(dir, "luc.cbor")).SaveLUC(durabilityUC(2)))
		require.Empty(t, tempFiles(t, dir))
	})

	for _, name := range saveCheckpoints {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "luc.cbor")
			writePrior(t, path)

			store := NewFileStore(path)
			store.checkpoint = failAt(name)
			require.ErrorIs(t, store.SaveLUC(durabilityUC(2)), errInjected)
			require.Empty(t, tempFiles(t, dir), "the deferred remove clears the temporary file")
		})
	}
}
