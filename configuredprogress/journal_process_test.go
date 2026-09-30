package configuredprogress

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	journalCrashChildEnv = "D2_JOURNAL_CRASH_CHILD"
	journalCrashPointEnv = "D2_JOURNAL_CRASH_POINT"
	journalCrashDBEnv    = "D2_JOURNAL_CRASH_DB"
)

// TestJournalCrashProcess is run in a child process and killed from the storage
// checkpoint hook. If a checkpoint is removed or moved outside its transaction,
// the parent observes a normal exit or a partial journal and fails.
func TestJournalCrashProcess(t *testing.T) {
	if os.Getenv(journalCrashChildEnv) != "1" {
		return
	}
	point := os.Getenv(journalCrashPointEnv)
	f := newFixture(t, 2)
	s, err := OpenConfiguredV2(os.Getenv(journalCrashDBEnv), Settings{Retain: 3})
	require.NoError(t, err)
	require.NoError(t, s.EnableJournal(context.Background(), f.ctx, testJournalLimits))
	s.checkpoint = func(name string) error {
		if name == point {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
		return nil
	}

	bootstrap := f.bootstrap(1, 4)
	if point == "before-candidate-put" || point == "before-candidate-commit" {
		require.NoError(t, s.PutJournalCandidate(context.Background(), f.ctx, testJournalLimits, candidateB1(f, bootstrap)))
	} else {
		prepared, _, err := s.PrepareObservation(context.Background(), f.ctx, f.first(1, 2, 5))
		require.NoError(t, err)
		_, _, err = s.CommitObservation(prepared)
		require.NoError(t, err)
	}
	t.Fatal("named journal SIGKILL checkpoint was not reached")
}

func TestJournalSIGKILLWriteAndCertificationTransactionsRecoverExactAssociation(t *testing.T) {
	points := []string{
		"before-candidate-put",
		"before-candidate-commit",
		"before-journal-observation-put",
		"before-journal-observation-commit",
		"before-observation-commit",
	}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t, 2)
			s, path := openJournal(t, f, testJournalLimits)
			bootstrap := f.bootstrap(1, 4)
			admitJournal(t, s, f, bootstrap)
			if point != "before-candidate-put" && point != "before-candidate-commit" {
				require.NoError(t, s.PutJournalCandidate(context.Background(), f.ctx, testJournalLimits, candidateB1(f, bootstrap)))
			}
			require.NoError(t, s.Close())

			cmd := exec.Command(os.Args[0], "-test.run=^TestJournalCrashProcess$")
			cmd.Env = append(os.Environ(), journalCrashChildEnv+"=1", journalCrashPointEnv+"="+point, journalCrashDBEnv+"="+path)
			err := cmd.Run()
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit)
			waitStatus, ok := exit.ProcessState.Sys().(syscall.WaitStatus)
			require.True(t, ok)
			require.True(t, waitStatus.Signaled())
			require.Equal(t, syscall.SIGKILL, waitStatus.Signal())

			reopened, err := OpenConfiguredV2(path, Settings{Retain: 3})
			require.NoError(t, err)
			defer reopened.Close()
			require.NoError(t, reopened.EnableJournal(context.Background(), f.ctx, testJournalLimits))
			image, err := reopened.LoadJournal(context.Background(), f.ctx, testJournalLimits)
			require.NoError(t, err)
			require.Len(t, image.Observations, 1, "only the bootstrap observation may survive an uncommitted admission")
			if point == "before-candidate-put" || point == "before-candidate-commit" {
				require.Empty(t, image.Candidates)
			} else {
				require.Len(t, image.Candidates, 1)
				require.False(t, image.Candidates[0].Certified, "a crash before certification commit cannot publish a partial association")
				admitJournal(t, reopened, f, f.first(1, 2, 5))
				image, err = reopened.LoadJournal(context.Background(), f.ctx, testJournalLimits)
				require.NoError(t, err)
				require.True(t, image.Candidates[0].Certified, "the exact candidate can be certified after recovery")
			}
		})
	}
}
