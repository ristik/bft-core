package certifiedstore

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

/*
Process termination at every named point of Publish. A child process (this test binary, re-executed) opens
the prepared store and publishes block 4; at the chosen checkpoint it sends itself SIGKILL, so no deferred
function, rollback call or Close runs. The parent confirms the child died by that signal, reopens the real
bbolt file, and requires the complete prior state or, for a kill after commit returned, the complete new
state.

This is evidence about PROCESS termination. The operating system keeps the file's written pages, so it
exercises bbolt's commit ordering and meta-page selection on reopen; it does not model power loss, a lost
device write cache, or a filesystem that does not honour sync (docs/design/f6b-certified-record-store.md).
*/

const (
	childDBEnv         = "CERTIFIEDSTORE_CHILD_DB"
	childCheckpointEnv = "CERTIFIEDSTORE_CHILD_CHECKPOINT"
	childOccurrenceEnv = "CERTIFIEDSTORE_CHILD_OCCURRENCE"
)

// TestChildProcessPublishesUntilKilled runs only as the child of TestProcessKilledAtEachCheckpoint.
func TestChildProcessPublishesUntilKilled(t *testing.T) {
	path := os.Getenv(childDBEnv)
	if path == "" {
		t.Skip("child process of TestProcessKilledAtEachCheckpoint")
	}
	occurrence, err := strconv.Atoi(os.Getenv(childOccurrenceEnv))
	require.NoError(t, err)
	c := checkpointCase{name: os.Getenv(childCheckpointEnv), occurrence: occurrence}

	f := newFixture(t, 4)
	s, err := Open(path, Settings{Retain: 1})
	require.NoError(t, err)
	s.checkpoint = failAt(c, func() {
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		select {} // SIGKILL is delivered asynchronously; never return into Publish
	})
	_ = s.Publish(context.Background(), f.ctx, f.record(4))
	t.Fatalf("checkpoint %s was not reached", c)
}

func TestProcessKilledAtEachCheckpoint(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses SIGKILL")
	}
	f := newFixture(t, 4)
	after := expectedAfter(t, f)

	for _, c := range publishCheckpoints {
		t.Run(c.String(), func(t *testing.T) {
			path := tempDB(t)
			before := prepared(t, f, path)

			cmd := exec.Command(os.Args[0], "-test.run=^TestChildProcessPublishesUntilKilled$", "-test.count=1")
			cmd.Env = append(os.Environ(), childDBEnv+"="+path, childCheckpointEnv+"="+c.name, childOccurrenceEnv+"="+strconv.Itoa(c.occurrence))
			out, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			require.True(t, errors.As(err, &exitErr), "the child must not exit normally: %v\n%s", err, out)
			status, ok := exitErr.Sys().(syscall.WaitStatus)
			require.True(t, ok)
			require.True(t, status.Signaled() && status.Signal() == syscall.SIGKILL, "the child died by SIGKILL at %s:\n%s", c, out)

			s := f.open(path, 1)
			assertPriorOrNew(t, f, s, before, after, c.name == "after-commit")
		})
	}
}
