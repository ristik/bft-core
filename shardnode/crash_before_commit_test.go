package shardnode

/*
F6i section 2: a fault before the execution commit (#14 position 5).

The distinction from position 6 is stated in the code below rather than implied. There, a Commit
reached the executor and its answer was lost, so the executor had already moved. Here, the fault is
intercepted before the executor is commanded at all: the executor's own Commit is never issued and
its head never moves, which is the state a process that dies between observing a certificate and
issuing the commit leaves behind. A second process over the same, still-unmoved executor must
reconcile forward and sign nothing.

The fixture follows restart_boundaries_test.go's two-process-over-one-executor pattern, because the
second process's job is exactly to build the executor state the first process could not. The two
subtests cover the two ways the round can name the block it must reach: a certificate that names it
(the ordinary anchor path) and a quiet tail that does not (the #92 recovery path).
*/

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// commitFaultingExecutor intercepts the first Commit and returns an error WITHOUT calling the
// underlying executor. The executor's own Commit is therefore never issued, which is what makes this
// position 5 rather than position 6: the call was not in flight with a lost answer, it never reached
// the executor. The remaining calls pass through.
type commitFaultingExecutor struct {
	*restartExecutor
	mu       sync.Mutex
	failures int
}

func (e *commitFaultingExecutor) Commit(ctx context.Context, hash Hash) (Status, error) {
	e.mu.Lock()
	if e.failures > 0 {
		e.failures--
		e.mu.Unlock()
		return StatusSyncing, errors.New("the process died before the executor was commanded")
	}
	e.mu.Unlock()
	return e.restartExecutor.Commit(ctx, hash)
}

// TestCrashBeforeExecutionCommitReconcilesWithoutVoting: process A is driven to the recovery commit,
// which faults before reaching the executor, so the executor is left behind and unmoved. Process B,
// a fresh process over the same executor, reconciles forward to the certified block and signs
// nothing on the uncommitted state.
func TestCrashBeforeExecutionCommitReconcilesWithoutVoting(t *testing.T) {
	t.Run("the certificate in hand names the block", func(t *testing.T) {
		// The ordinary anchor path: the certificate names the block, so reconcile targets it
		// directly and the fault lands on that Commit.
		s := newRestartScenario(t)
		exec := &commitFaultingExecutor{restartExecutor: s.newExecutor(s.behind), failures: 1}

		roundA, _, subA, stopA := s.newProcess(t, exec)
		require.Error(t, roundA.HandleCertificate(context.Background(), s.source.UC, s.source.Technical),
			"the faulted commit leaves the round unable to prove its identity")
		require.Empty(t, exec.commitTargets(), "the executor's own Commit was never issued")
		require.Equal(t, Hash(s.blockA), exec.currentHead().Hash, "and the head never moved")
		require.Empty(t, subA.rounds(), "nothing was signed before the fault either")
		stopA()

		roundB, _, subB, _ := s.newProcess(t, exec)
		s.restore(t, roundB, s.older)
		require.NoError(t, roundB.HandleCertificate(context.Background(), s.source.UC, s.source.Technical),
			"the second process reconciles through the ordinary commit path")

		require.Equal(t, Hash(s.blockB), exec.currentHead().Hash, "the executor reached the certified block")
		targets := exec.commitTargets()
		require.Len(t, targets, 1, "exactly one Commit reached the executor, and it is the certified block")
		require.Equal(t, Hash(s.blockB), targets[0])
		require.Empty(t, subB.rounds(), "the restored process signs nothing on the uncommitted state")
		s.requireNoRollback(t, exec.restartExecutor, 0)
	})

	t.Run("the certificate in hand does not name the block", func(t *testing.T) {
		// The #92 recovery path: the held certificate is quiet, so the block has to come from
		// authenticated evidence, and the fault lands on the applier's Commit.
		s := newRestartScenario(t)
		exec := &commitFaultingExecutor{restartExecutor: s.newExecutor(s.behind), failures: 1}

		roundA, stackA, subA, stopA := s.newProcess(t, exec)
		s.restore(t, roundA, s.older)
		require.Error(t, s.deliver(t, roundA, 0), "no anchor yet, so it refuses and asks for evidence")
		stA := waitRecovered(t, stackA.Requester)
		require.Equal(t, RecoveryReady, stA.State, "err: %v", stA.LastErr)
		require.Error(t, s.deliver(t, roundA, 1), "the faulted commit leaves the round unable to prove its identity")
		require.Equal(t, ApplyExecutorUnreachable, stackA.Applier.Status().Last,
			"an executor that said nothing leaves the target retained and the outcome retryable, not a fault")
		require.Empty(t, exec.commitTargets(), "the executor's own Commit was never issued")
		require.Equal(t, Hash(s.blockA), exec.currentHead().Hash, "and the head never moved")
		require.Empty(t, subA.rounds(), "nothing was signed before the fault either")
		stopA()

		roundB, stackB, subB, _ := s.newProcess(t, exec)
		s.restore(t, roundB, s.older)
		require.Error(t, s.deliver(t, roundB, 0), "a fresh process starts with no anchor too")
		stB := waitRecovered(t, stackB.Requester)
		require.Equal(t, RecoveryReady, stB.State, "err: %v", stB.LastErr)
		require.NoError(t, s.deliver(t, roundB, 1), "with the target re-derived, the round completes")

		require.Equal(t, Hash(s.blockB), exec.currentHead().Hash, "the executor reached the certified block")
		targets := exec.commitTargets()
		require.Len(t, targets, 1, "exactly one Commit reached the executor, and it is the certified block")
		require.Equal(t, Hash(s.blockB), targets[0])
		require.Empty(t, subB.rounds(), "the restored process signs nothing on the uncommitted state")
		require.False(t, roundB.health.Snapshot().Voting)
		s.requireNoRollback(t, exec.restartExecutor, 0)
	})
}
