package archivewiring

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/shardnode"
)

// stoppingExecutor runs the wrapped executor until the nth call of one method, where it cancels the restore context and fails
// the way a stopped RPC does: returning the context's error.
type stoppingExecutor struct {
	RestoreExecutor
	method string
	nth    int
	cancel context.CancelFunc
	mu     sync.Mutex
	calls  map[string]int
	hit    bool
}

func (s *stoppingExecutor) stop(ctx context.Context, method string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls == nil {
		s.calls = make(map[string]int)
	}
	s.calls[method]++
	if method != s.method || s.calls[method] != s.nth {
		return nil
	}
	s.hit = true
	s.cancel()
	return ctx.Err()
}

func (s *stoppingExecutor) Head(ctx context.Context) (shardnode.BlockRef, error) {
	if err := s.stop(ctx, "Head"); err != nil {
		return shardnode.BlockRef{}, err
	}
	return s.RestoreExecutor.Head(ctx)
}

func (s *stoppingExecutor) Finalized(ctx context.Context) (shardnode.BlockRef, error) {
	if err := s.stop(ctx, "Finalized"); err != nil {
		return shardnode.BlockRef{}, err
	}
	return s.RestoreExecutor.Finalized(ctx)
}

func (s *stoppingExecutor) Verify(ctx context.Context, b shardnode.Block, p shardnode.RoundParams) (shardnode.Status, error) {
	if err := s.stop(ctx, "Verify"); err != nil {
		return shardnode.StatusInvalid, err
	}
	return s.RestoreExecutor.Verify(ctx, b, p)
}

func (s *stoppingExecutor) RecoveryForkchoice(ctx context.Context, h, f shardnode.Hash) (shardnode.Status, error) {
	if err := s.stop(ctx, "RecoveryForkchoice"); err != nil {
		return shardnode.StatusInvalid, err
	}
	return s.RestoreExecutor.RecoveryForkchoice(ctx, h, f)
}

func (s *stoppingExecutor) Commit(ctx context.Context, h shardnode.Hash) (shardnode.Status, error) {
	if err := s.stop(ctx, "Commit"); err != nil {
		return shardnode.StatusInvalid, err
	}
	return s.RestoreExecutor.Commit(ctx, h)
}

// A restore stopped while the paired EL import, the replay forkchoice, finality or any executor read is in flight stays an
// ErrRestore refusal and is still a stopped context to errors.Is: shutdown classification must not depend on which stage was
// running (the fetch stage already behaved this way). Head/Finalized are called first by the empty-disk preconditions and again
// by the final reads after finality.
func TestArchiveRestoreKeepsTheContextCauseWhenTheExecutorIsStopped(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		method string
		nth    int
		retry  bool
	}{
		{"genesis head precondition", "Head", 1, false},
		{"genesis finality precondition", "Finalized", 1, false},
		{"paired seal import", "Verify", 1, false},
		{"replay forkchoice", "RecoveryForkchoice", 1, false},
		{"finality", "Commit", 1, false},
		{"final head read", "Head", 2, false},
		{"final finality read", "Finalized", 2, false},
		{"retry head read", "Head", 1, true},
		{"retry finality read", "Finalized", 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fx := newRetryRestoreFixture(t, 0, FetchRetry{Initial: time.Millisecond, Max: 5 * time.Millisecond, Total: 20 * time.Second})
			if tc.retry {
				// A completed restore leaves the durable pin; running it again takes the retry branch.
				require.NoError(t, fx.restore.Restore(context.Background()))
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stopper := &stoppingExecutor{RestoreExecutor: fx.restore.Adapter, method: tc.method, nth: tc.nth, cancel: cancel}
			fx.restore.Adapter = stopper
			err := fx.restore.Restore(ctx)
			require.True(t, stopper.hit, "the executor was stopped at the intended call")
			require.Error(t, err)
			require.ErrorIs(t, err, ErrRestore)
			require.ErrorIs(t, err, context.Canceled)
			require.NotErrorIs(t, err, context.DeadlineExceeded)
			require.False(t, errors.Is(err, ErrBinding), "a stop is not a binding refusal")
		})
	}
}

// A deadline is kept the same way, and a refusal that has no executor cause (the value mismatch) still reads as ErrRestore alone
// with its unchanged message.
func TestRestoreCauseKeepsTheMessageAndOnlyWrapsARealCause(t *testing.T) {
	t.Parallel()
	err := restoreCause(context.DeadlineExceeded, "advancing replay head %d returned %s: %v", 3, shardnode.StatusInvalid, context.DeadlineExceeded)
	require.ErrorIs(t, err, ErrRestore)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.EqualError(t, err, ErrRestore.Error()+": advancing replay head 3 returned "+shardnode.StatusInvalid.String()+": context deadline exceeded")

	mismatch := restoreCause(nil, "EL head differs from replay target: %v", nil)
	require.ErrorIs(t, mismatch, ErrRestore)
	require.NotErrorIs(t, mismatch, context.Canceled)
	require.EqualError(t, mismatch, ErrRestore.Error()+": EL head differs from replay target: <nil>")
}
