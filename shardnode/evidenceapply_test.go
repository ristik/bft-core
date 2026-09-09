package shardnode

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

/*
Fixtures for the target applier (docs/design/f6b-quiet-tail-anchor-recovery.md §6.4).

The executor is a stub with function fields, because what is under test is the POLICY: which of the
executor's three possible answers this node treats as a wait, which as a fault, and which as knowing
nothing at all. A real executor would make those answers harder to produce and no more convincing.
*/

// --- harness -----------------------------------------------------------------------------------

type stubExecutor struct {
	commit  func(ctx context.Context, hash Hash) (Status, error)
	head    func(ctx context.Context) (BlockRef, error)
	genesis func(ctx context.Context) (BlockRef, error)

	commits  []Hash
	heads    int
	geneses  int
	blocking chan struct{}
}

func (e *stubExecutor) Commit(ctx context.Context, hash Hash) (Status, error) {
	e.commits = append(e.commits, Hash(append([]byte(nil), hash...)))
	if e.commit != nil {
		return e.commit(ctx, hash)
	}
	return StatusValid, nil
}

func (e *stubExecutor) Head(ctx context.Context) (BlockRef, error) {
	e.heads++
	if e.head != nil {
		return e.head(ctx)
	}
	return BlockRef{}, nil
}

func (e *stubExecutor) GenesisBlock(ctx context.Context) (BlockRef, error) {
	e.geneses++
	if e.genesis != nil {
		return e.genesis(ctx)
	}
	return BlockRef{}, nil
}

func (e *stubExecutor) Build(context.Context, RoundParams) (BuildID, error) {
	return "", errors.New("not used")
}
func (e *stubExecutor) Seal(context.Context, BuildID) (Block, error) {
	return Block{}, errors.New("not used")
}
func (e *stubExecutor) Verify(context.Context, Block, RoundParams) (Status, error) {
	return StatusInvalid, errors.New("not used")
}

// stubTarget is the requester's half, reduced to what the applier is allowed to use: it holds a
// target and answers for it. It cannot be asked to fetch anything, which is the point.
type stubTarget struct {
	anchor *ExecutionAnchor
	// shared makes Target hand out the record itself rather than a copy. EvidenceRequester does
	// copy, but the applier must not DEPEND on that: it takes a TargetSource, and a source that
	// returns its own record is the naive implementation of one.
	shared bool
}

func (s *stubTarget) Target() (*ExecutionAnchor, bool) {
	if s.anchor == nil {
		return nil, false
	}
	if s.shared {
		return s.anchor, true
	}
	return copyAnchor(s.anchor), true
}

type applyFixture struct {
	applier *TargetApplier
	ex      *stubExecutor
	src     *stubTarget
	clock   *testClock
}

func newApplyFixture(t *testing.T, budget ApplyBudget, ex *stubExecutor, anchor *ExecutionAnchor) *applyFixture {
	t.Helper()
	clock := &testClock{at: time.Unix(1_700_000_000, 0)}
	src := &stubTarget{anchor: anchor}
	a, err := NewTargetApplier(ApplyConfig{Executor: ex, Source: src, Budget: budget, Now: clock.now})
	require.NoError(t, err)
	return &applyFixture{applier: a, ex: ex, src: src, clock: clock}
}

func testApplyBudget() ApplyBudget {
	return ApplyBudget{MaxAttempts: 3, Backoff: time.Second, Timeout: 2 * time.Second}
}

// The recovered situation: block bb produced state 0b in round 10, the shard has been quiet since,
// and this node's executor is a block behind at state 0a.
func recoveredAnchor() *ExecutionAnchor {
	return &ExecutionAnchor{BlockHash: Hash(h32(0xbb)), StateRoot: Hash(h32(0x0b)), Round: 10}
}

func behindHead() BlockRef {
	return BlockRef{Number: 4, Hash: Hash(h32(0xaa)), StateRoot: Hash(h32(0x0a))}
}

func recoveredHead() BlockRef {
	return BlockRef{Number: 5, Hash: Hash(h32(0xbb)), StateRoot: Hash(h32(0x0b))}
}

// --- the ordinary case -------------------------------------------------------------------------

func TestTargetApplier_CommitsTheCertifiedBlock(t *testing.T) {
	ex := &stubExecutor{head: func(context.Context) (BlockRef, error) { return recoveredHead(), nil }}
	f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

	res := f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead())

	require.Equal(t, ApplyApplied, res.Outcome, "err: %v", res.Err)
	require.NoError(t, res.Err)
	require.Equal(t, recoveredHead(), res.Head)
	require.Len(t, ex.commits, 1)
	require.Equal(t, Hash(h32(0xbb)), ex.commits[0], "Commit is keyed by block hash, never by state root")
	require.Zero(t, ex.geneses, "the genesis exception is not consulted for an ordinary anchor")

	st := f.applier.Status()
	require.Equal(t, 1, st.Applied)
	require.Zero(t, st.Attempts, "a successful apply leaves no attempt debt behind")
}

// --- the recheck -------------------------------------------------------------------------------

/*
The gate that keeps §5's cursors apart: a verified target is not a licence to commit, it is an answer
to one question. The question is "what block produced the state THIS round builds on", and a target
about another state is not an answer to it — matching hashes would be the only argument for treating
it as one, and §3.3.1 is the counterexample to that argument.
*/
func TestTargetApplier_RechecksTheCertificateBeforeCommitting(t *testing.T) {
	t.Run("a target for another state is never sent to the executor", func(t *testing.T) {
		ex := &stubExecutor{}
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

		res := f.applier.Apply(context.Background(), Hash(h32(0x0c)), behindHead())

		require.Equal(t, ApplyStaleTarget, res.Outcome)
		require.ErrorIs(t, res.Err, ErrApplyStaleTarget)
		require.Empty(t, ex.commits, "nothing was sent to the executor")
		require.False(t, res.Outcome.Retryable(), "another attempt at the same question changes nothing")
	})

	t.Run("no verified target is its own answer", func(t *testing.T) {
		ex := &stubExecutor{}
		f := newApplyFixture(t, testApplyBudget(), ex, nil)

		res := f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead())

		require.Equal(t, ApplyNoTarget, res.Outcome)
		require.ErrorIs(t, res.Err, ErrApplyNoTarget)
		require.Empty(t, ex.commits)
	})

	t.Run("the head reported back is the one the caller had", func(t *testing.T) {
		ex := &stubExecutor{}
		f := newApplyFixture(t, testApplyBudget(), ex, nil)
		res := f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead())
		require.Equal(t, behindHead(), res.Head, "an attempt that read no head does not invent one")
		require.Zero(t, ex.heads)
	})
}

// --- the three executor situations ---------------------------------------------------------------

/*
The taxonomy this file exists for. All three arrive as "the node did not recover", and all three call
for different operator responses, so none of them may be reported as another.
*/
func TestTargetApplier_TheThreeExecutorSituationsStayApart(t *testing.T) {
	t.Run("unreachable: nothing at all is known", func(t *testing.T) {
		ex := &stubExecutor{commit: func(context.Context, Hash) (Status, error) {
			return StatusValid, errors.New("dial tcp 127.0.0.1:8551: connection refused")
		}}
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

		res := f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead())

		require.Equal(t, ApplyExecutorUnreachable, res.Outcome)
		require.ErrorIs(t, res.Err, ErrApplyExecutorUnreachable)
		require.NotErrorIs(t, res.Err, ErrApplyPayloadUnavailable, "an RPC failure is not an answer about the payload")
		require.NotErrorIs(t, res.Err, ErrApplyPayloadInvalid)
		require.True(t, res.Outcome.Retryable())
		require.NotNil(t, res.Target, "the target is kept: the authority to retry is what dropping it would lose")
		require.Zero(t, ex.heads, "no head is read after a commit that did not report")
	})

	for _, status := range []Status{StatusSyncing, StatusAccepted} {
		t.Run("unavailable: the executor answered, and does not have it ("+status.String()+")", func(t *testing.T) {
			ex := &stubExecutor{commit: func(context.Context, Hash) (Status, error) { return status, nil }}
			f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

			res := f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead())

			require.Equal(t, ApplyPayloadUnavailable, res.Outcome)
			require.ErrorIs(t, res.Err, ErrApplyPayloadUnavailable)
			require.NotErrorIs(t, res.Err, ErrApplyExecutorUnreachable)
			require.NotErrorIs(t, res.Err, ErrApplyPayloadInvalid)
			require.True(t, res.Outcome.Retryable(), "the ordinary state after an execution-client restart")
			require.NotNil(t, res.Target)
		})
	}

	t.Run("invalid: the executor rejected it, and that is a fault", func(t *testing.T) {
		ex := &stubExecutor{commit: func(context.Context, Hash) (Status, error) { return StatusInvalid, nil }}
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

		res := f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead())

		require.Equal(t, ApplyPayloadInvalid, res.Outcome)
		require.ErrorIs(t, res.Err, ErrApplyPayloadInvalid)
		require.NotErrorIs(t, res.Err, ErrApplyPayloadUnavailable)
		require.False(t, res.Outcome.Retryable(), "no number of attempts makes a rejected payload valid")

		// Terminal for THIS block, and the executor is not asked again about it.
		again := f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead())
		require.Equal(t, ApplyPayloadInvalid, again.Outcome)
		require.Len(t, ex.commits, 1, "a fault is not re-litigated against the executor")

		// A DIFFERENT block for the same state is a different claim — §3.3.1's whole point — and
		// gets its own attempt.
		f.src.anchor = &ExecutionAnchor{BlockHash: Hash(h32(0xee)), StateRoot: Hash(h32(0x0b)), Round: 12}
		ex.commit = func(context.Context, Hash) (Status, error) { return StatusValid, nil }
		ex.head = func(context.Context) (BlockRef, error) {
			return BlockRef{Number: 6, Hash: Hash(h32(0xee)), StateRoot: Hash(h32(0x0b))}, nil
		}
		third := f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead())
		require.Equal(t, ApplyApplied, third.Outcome, "err: %v", third.Err)
		require.Len(t, ex.commits, 2)
	})

	t.Run("unreachable again: the commit reported and the head could not be read", func(t *testing.T) {
		ex := &stubExecutor{head: func(context.Context) (BlockRef, error) {
			return BlockRef{}, errors.New("connection reset by peer")
		}}
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

		res := f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead())

		require.Equal(t, ApplyExecutorUnreachable, res.Outcome)
		require.True(t, res.Outcome.Retryable(), "whether this node recovered is unknown, and unknown is retryable")
		require.Equal(t, behindHead(), res.Head)
	})
}

// --- P-id ----------------------------------------------------------------------------------------

/*
A commit that reports success while the head is somewhere else is exactly what P-id exists to catch,
and it is a fault rather than something to wait through: the executor has answered, and its answer
contradicts the certificate.
*/
func TestTargetApplier_EnforcesHeadIdentityAfterAValidCommit(t *testing.T) {
	t.Run("the head is another block", func(t *testing.T) {
		ex := &stubExecutor{head: func(context.Context) (BlockRef, error) {
			return BlockRef{Number: 5, Hash: Hash(h32(0xcc)), StateRoot: Hash(h32(0x0b))}, nil
		}}
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

		res := f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead())

		require.Equal(t, ApplyHeadMismatch, res.Outcome)
		require.ErrorIs(t, res.Err, ErrApplyHeadMismatch)
		require.False(t, res.Outcome.Retryable())
	})

	t.Run("the head is the certified block at another state", func(t *testing.T) {
		ex := &stubExecutor{head: func(context.Context) (BlockRef, error) {
			return BlockRef{Number: 5, Hash: Hash(h32(0xbb)), StateRoot: Hash(h32(0x0c))}, nil
		}}
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

		res := f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead())

		require.Equal(t, ApplyHeadMismatch, res.Outcome)
		require.ErrorContains(t, res.Err, "is at state 0c0c")
	})

	/*
	   Row 13's exception, and nothing wider. The shard's first certified round carries a block hash
	   the executor may never have made canonical, so for THAT anchor the comparison is against the
	   executor's own block zero, in full. It is read only when the exception could apply.
	*/
	t.Run("the genesis round compares against the executor's own block zero", func(t *testing.T) {
		genesis := BlockRef{Number: 0, Hash: Hash(h32(0x01)), StateRoot: Hash(h32(0x0b))}
		ex := &stubExecutor{
			head:    func(context.Context) (BlockRef, error) { return genesis, nil },
			genesis: func(context.Context) (BlockRef, error) { return genesis, nil },
		}
		f := newApplyFixture(t, testApplyBudget(), ex, &ExecutionAnchor{
			BlockHash: Hash(h32(0xbb)), StateRoot: Hash(h32(0x0b)), Round: 1, fromGenesisRound: true,
		})

		res := f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead())
		require.Equal(t, ApplyApplied, res.Outcome, "err: %v", res.Err)
		require.Equal(t, 1, ex.geneses)
	})

	t.Run("a head that is not the executor's block zero is still refused", func(t *testing.T) {
		genesis := BlockRef{Number: 0, Hash: Hash(h32(0x01)), StateRoot: Hash(h32(0x0b))}
		ex := &stubExecutor{
			// An executor presenting a tip as though it were genesis.
			head: func(context.Context) (BlockRef, error) {
				return BlockRef{Number: 9, Hash: Hash(h32(0x09)), StateRoot: Hash(h32(0x0b))}, nil
			},
			genesis: func(context.Context) (BlockRef, error) { return genesis, nil },
		}
		f := newApplyFixture(t, testApplyBudget(), ex, &ExecutionAnchor{
			BlockHash: Hash(h32(0xbb)), StateRoot: Hash(h32(0x0b)), Round: 1, fromGenesisRound: true,
		})

		res := f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead())
		require.Equal(t, ApplyHeadMismatch, res.Outcome)
	})

	t.Run("an executor that cannot answer for its own block zero does not widen the check", func(t *testing.T) {
		ex := &stubExecutor{
			head: func(context.Context) (BlockRef, error) {
				return BlockRef{Number: 0, Hash: Hash(h32(0x01)), StateRoot: Hash(h32(0x0b))}, nil
			},
			genesis: func(context.Context) (BlockRef, error) {
				return BlockRef{}, errors.New("eth_getBlockByNumber: timeout")
			},
		}
		f := newApplyFixture(t, testApplyBudget(), ex, &ExecutionAnchor{
			BlockHash: Hash(h32(0xbb)), StateRoot: Hash(h32(0x0b)), Round: 1, fromGenesisRound: true,
		})

		res := f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead())
		require.Equal(t, ApplyExecutorUnreachable, res.Outcome)
		require.True(t, res.Outcome.Retryable())
	})
}

// --- the bounds ------------------------------------------------------------------------------------

func TestTargetApplier_AttemptsAreBoundedAndSpaced(t *testing.T) {
	unavailable := func() *stubExecutor {
		return &stubExecutor{commit: func(context.Context, Hash) (Status, error) { return StatusSyncing, nil }}
	}

	t.Run("attempts within one certified state are spaced by the backoff", func(t *testing.T) {
		ex := unavailable()
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

		require.Equal(t, ApplyPayloadUnavailable, f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead()).Outcome)
		res := f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead())
		require.Equal(t, ApplyBackoff, res.Outcome)
		require.ErrorIs(t, res.Err, ErrApplyBackoff)
		require.Len(t, ex.commits, 1, "the backoff is a refusal to ask, not a quieter way of asking")

		f.clock.advance(2 * time.Second)
		require.Equal(t, ApplyPayloadUnavailable, f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead()).Outcome)
		require.Len(t, ex.commits, 2)
	})

	t.Run("one certified state gets a bounded number of attempts", func(t *testing.T) {
		ex := unavailable()
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

		for i := 0; i < testApplyBudget().MaxAttempts; i++ {
			require.Equal(t, ApplyPayloadUnavailable, f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead()).Outcome, "attempt %d", i)
			f.clock.advance(2 * time.Second)
		}
		res := f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead())
		require.Equal(t, ApplyExhausted, res.Outcome)
		require.ErrorIs(t, res.Err, ErrApplyExhausted)
		require.Len(t, ex.commits, testApplyBudget().MaxAttempts)
	})

	/*
	   And exhaustion is not a permanent stop. An unavailable payload is the expected state after an
	   execution-client restart, so a node that stopped trying for good would have turned a
	   recoverable situation into a permanent one. The shard advancing is what supplies the next
	   attempts — the same rhythm the live path already has.
	*/
	t.Run("the next certified state brings a fresh budget", func(t *testing.T) {
		ex := unavailable()
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())
		for i := 0; i < testApplyBudget().MaxAttempts; i++ {
			f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead())
			f.clock.advance(2 * time.Second)
		}
		require.Equal(t, ApplyExhausted, f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead()).Outcome)

		// The shard certified a state-changing round; the requester verified a target for it.
		f.src.anchor = &ExecutionAnchor{BlockHash: Hash(h32(0xee)), StateRoot: Hash(h32(0x0c)), Round: 12}
		res := f.applier.Apply(context.Background(), Hash(h32(0x0c)), behindHead())
		require.Equal(t, ApplyPayloadUnavailable, res.Outcome, "err: %v", res.Err)
		require.Len(t, ex.commits, testApplyBudget().MaxAttempts+1)
	})

	t.Run("one executor call cannot hold the caller", func(t *testing.T) {
		budget := testApplyBudget()
		budget.Timeout = 50 * time.Millisecond
		ex := &stubExecutor{commit: func(ctx context.Context, _ Hash) (Status, error) {
			<-ctx.Done() // an executor that never answers
			return StatusValid, ctx.Err()
		}}
		f := newApplyFixture(t, budget, ex, recoveredAnchor())

		started := time.Now()
		res := f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead())
		require.Less(t, time.Since(started), 2*time.Second)
		require.Equal(t, ApplyExecutorUnreachable, res.Outcome)
		require.ErrorIs(t, res.Err, context.DeadlineExceeded)
	})

	t.Run("a cancelled caller is not held either", func(t *testing.T) {
		ex := &stubExecutor{commit: func(ctx context.Context, _ Hash) (Status, error) {
			<-ctx.Done()
			return StatusValid, ctx.Err()
		}}
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		res := f.applier.Apply(ctx, Hash(h32(0x0b)), behindHead())
		require.Equal(t, ApplyExecutorUnreachable, res.Outcome)
		require.ErrorIs(t, res.Err, context.Canceled)
	})
}

func TestTargetApplier_RefusesAnUnusableConfiguration(t *testing.T) {
	ok := ApplyConfig{Executor: &stubExecutor{}, Source: &stubTarget{}, Budget: testApplyBudget()}
	for _, tc := range []struct {
		name   string
		broken func(*ApplyConfig)
		want   error
	}{
		{"no executor", func(c *ApplyConfig) { c.Executor = nil }, ErrApplyBudgetInvalid},
		{"no target source", func(c *ApplyConfig) { c.Source = nil }, ErrApplyBudgetInvalid},
		{"no attempt bound", func(c *ApplyConfig) { c.Budget.MaxAttempts = 0 }, ErrApplyBudgetInvalid},
		{"no per-call bound", func(c *ApplyConfig) { c.Budget.Timeout = 0 }, ErrApplyBudgetInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ok
			tc.broken(&cfg)
			_, err := NewTargetApplier(cfg)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

// What a caller is handed is its own, here as everywhere else in this path: ExecutionAnchor's hashes
// are byte slices, and the result carries one.
func TestTargetApplier_ReturnedTargetDoesNotAliasTheSource(t *testing.T) {
	ex := &stubExecutor{head: func(context.Context) (BlockRef, error) { return recoveredHead(), nil }}
	anchor := recoveredAnchor()
	f := newApplyFixture(t, testApplyBudget(), ex, anchor)
	f.src.shared = true // a source that hands out its own record, which the applier may not rely on

	res := f.applier.Apply(context.Background(), Hash(h32(0x0b)), behindHead())
	require.Equal(t, ApplyApplied, res.Outcome)
	res.Target.BlockHash[0] ^= 0xff
	res.Target.StateRoot[0] ^= 0xff

	require.Equal(t, Hash(h32(0xbb)), anchor.BlockHash, "the source's record is not the caller's to edit")
	require.Equal(t, Hash(h32(0x0b)), anchor.StateRoot)
}
