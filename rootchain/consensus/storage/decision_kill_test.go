package storage

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

/*
H6 (#23), process termination around the root's safety writes. A child process (this test binary, re-executed) opens a production
store (sync on) and, for round after round, does what MakeVote does before it releases a vote: RecordSignedDecision, then
SetHighestQcRound. Only after both returned does it print the round, standing for the release. The parent sends SIGKILL after a varying
number of released rounds (so the kill lands at a different point of the next round's writes), reopens the real bbolt file and
requires: every released round's decision is on disk with its exact statement and message, the safety floor is at least the last
released round, and a round beyond it is either absent or complete (never torn), with no floor below a recorded decision.

This is evidence about PROCESS termination: the operating system keeps the written pages, so it exercises bbolt's commit ordering and
meta-page selection on reopen. It does not model power loss, a lost device write cache or a filesystem that does not honour fsync;
those are documented limits (docs/operations/h6/authority-loss.md).
*/

const (
	decisionChildDBEnv = "ROOT_DECISION_CHILD_DB"
	decisionChildMax   = 100_000
)

func killStatement(r uint64) []byte { return []byte(fmt.Sprintf("statement/%d", r)) }
func killMessage(r uint64) []byte {
	return bytes.Repeat([]byte(fmt.Sprintf("signed-vote/%d/", r)), 64) // a few KiB, so a write spans pages
}

// TestChildRecordsRootDecisionsUntilKilled runs only as the child of TestRootDecisionsSurviveSIGKILL.
func TestChildRecordsRootDecisionsUntilKilled(t *testing.T) {
	path := os.Getenv(decisionChildDBEnv)
	if path == "" {
		t.Skip("child process of TestRootDecisionsSurviveSIGKILL")
	}
	db, err := NewBoltStorage(path)
	require.NoError(t, err)
	for r := uint64(1); r <= decisionChildMax; r++ {
		require.NoError(t, db.RecordSignedDecision(DecisionVote, 1, r, killStatement(r), killMessage(r)))
		require.NoError(t, db.SetHighestQcRound(r-1, r))
		fmt.Fprintf(os.Stdout, "released %d\n", r)
	}
	t.Fatal("never killed")
}

func TestRootDecisionsSurviveSIGKILL(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses SIGKILL")
	}
	for i, after := range []uint64{1, 2, 3, 5, 8, 13, 21, 34} {
		t.Run(strconv.FormatUint(after, 10), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rootchain.db")
			cmd := exec.Command(os.Args[0], "-test.run=^TestChildRecordsRootDecisionsUntilKilled$", "-test.count=1", "-test.v")
			cmd.Env = append(os.Environ(), decisionChildDBEnv+"="+path)
			out, err := cmd.StdoutPipe()
			require.NoError(t, err)
			require.NoError(t, cmd.Start())
			released := uint64(0)
			sc := bufio.NewScanner(out)
			for sc.Scan() {
				if n, ok := strings.CutPrefix(sc.Text(), "released "); ok {
					released, err = strconv.ParseUint(n, 10, 64)
					require.NoError(t, err)
					if released >= after {
						// land the kill at a varying point of the next round's writes
						time.Sleep(time.Duration(i*137) * time.Microsecond)
						require.NoError(t, cmd.Process.Signal(syscall.SIGKILL))
						break
					}
				}
			}
			err = cmd.Wait()
			var exitErr *exec.ExitError
			require.True(t, errors.As(err, &exitErr), "the child must not exit normally: %v", err)
			status, ok := exitErr.Sys().(syscall.WaitStatus)
			require.True(t, ok)
			require.True(t, status.Signaled() && status.Signal() == syscall.SIGKILL)
			require.GreaterOrEqual(t, released, after)

			db, err := NewBoltStorage(path)
			require.NoError(t, err)
			defer func() { require.NoError(t, db.db.Close()) }()
			snap, err := db.ReadSafetySnapshot()
			require.NoError(t, err, "the safety state reads back coherently")
			require.GreaterOrEqual(t, snap.HighestVotedRound, released, "no released vote is below the floor")
			for r := uint64(1); r <= released; r++ {
				s, m, err := db.SignedDecision(DecisionVote, 1, r)
				require.NoError(t, err)
				require.Equal(t, killStatement(r), s, "round %d", r)
				require.Equal(t, killMessage(r), m, "round %d", r)
			}
			// a round written but not released is complete or absent, never torn; and it is never above the floor + 1
			for r := released + 1; r <= released+2; r++ {
				s, m, err := db.SignedDecision(DecisionVote, 1, r)
				require.NoError(t, err)
				if s != nil {
					require.Equal(t, killStatement(r), s)
					require.Equal(t, killMessage(r), m)
					require.GreaterOrEqual(t, snap.HighestVotedRound+1, r, "a decision beyond the next round cannot exist")
				}
			}
		})
	}
}
