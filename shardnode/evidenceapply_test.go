package shardnode

import (
	"context"
	"errors"
	"fmt"
	"sync"
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
	mu     sync.Mutex
	anchor *ExecutionAnchor
	// verifiedFor is the certificate the anchor was verified against. It travels with the anchor
	// because the applier compares bindings, never state roots.
	verifiedFor CertificateBinding
	// shared makes Target hand out the record itself rather than a copy. EvidenceRequester does
	// copy, but the applier must not DEPEND on that: it takes a TargetSource, and a source that
	// returns its own record is the naive implementation of one.
	shared bool
}

func (s *stubTarget) Target() (VerifiedTarget, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.anchor == nil {
		return VerifiedTarget{}, false
	}
	if s.shared {
		return VerifiedTarget{Anchor: s.anchor, For: s.verifiedFor}, true
	}
	return VerifiedTarget{Anchor: copyAnchor(s.anchor), For: s.verifiedFor.clone()}, true
}

func (s *stubTarget) set(anchor *ExecutionAnchor, for_ CertificateBinding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.anchor, s.verifiedFor = anchor, for_
}

// bind names a certificate the way the applier is given one. Identities are synthetic here and real
// in TestBindingFor; what matters to these fixtures is that two certificates of a quiet tail differ
// in their rounds while sharing a state root, which is exactly what defeats a state-keyed rule.
func bind(round, rootRound uint64, state []byte) CertificateBinding {
	return CertificateBinding{
		Round:     round,
		RootRound: rootRound,
		Identity:  []byte(fmt.Sprintf("ir(round=%d,state=%x)", round, state)),
		State:     Hash(state),
	}
}

// heldBinding is the certificate this node holds throughout: round 16, quiet at state 0b.
func heldBinding() CertificateBinding { return bind(16, 120, h32(0x0b)) }

type applyFixture struct {
	applier *TargetApplier
	ex      *stubExecutor
	src     *stubTarget
	clock   *testClock
}

func newApplyFixture(t *testing.T, budget ApplyBudget, ex *stubExecutor, anchor *ExecutionAnchor) *applyFixture {
	t.Helper()
	clock := &testClock{at: time.Unix(1_700_000_000, 0)}
	src := &stubTarget{anchor: anchor, verifiedFor: heldBinding()}
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

	res := f.applier.Apply(context.Background(), heldBinding(), behindHead())

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
	/*
	   The reproduction review published: a state root cannot bind an anchor to a certificate. Rounds
	   12 and 16 of a quiet tail carry the SAME state root — that is what quiet means — so a target
	   verified against round 12 passes any state comparison for round 16 while being an answer about
	   a certificate this node has moved past. What separates them is the certificate itself.
	*/
	t.Run("a target verified against an earlier certificate at the same state is refused", func(t *testing.T) {
		ex := &stubExecutor{}
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())
		f.src.set(recoveredAnchor(), bind(12, 110, h32(0x0b))) // same state, earlier certificate

		res := f.applier.Apply(context.Background(), heldBinding(), behindHead())

		require.Equal(t, ApplyStaleTarget, res.Outcome)
		require.ErrorIs(t, res.Err, ErrApplyStaleTarget)
		require.ErrorContains(t, res.Err, "verified against round 12")
		require.Empty(t, ex.commits, "nothing was sent to the executor")
	})

	t.Run("a repeat of the held round is a different certificate", func(t *testing.T) {
		ex := &stubExecutor{}
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())
		// Same partition round and the same input record, certified at a LATER root round. The
		// requester carries a target across it; until it has, this is not the same question.
		res := f.applier.Apply(context.Background(), bind(16, 130, h32(0x0b)), behindHead())

		require.Equal(t, ApplyStaleTarget, res.Outcome)
		require.Empty(t, ex.commits)
	})

	t.Run("a target for another state is never sent to the executor", func(t *testing.T) {
		ex := &stubExecutor{}
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())
		// The binding matches and the anchor disagrees with it about the state: a bug on this node
		// rather than anything a peer did, and named separately from staleness.
		f.src.set(&ExecutionAnchor{BlockHash: Hash(h32(0xbb)), StateRoot: Hash(h32(0x0c)), Round: 10}, heldBinding())

		res := f.applier.Apply(context.Background(), heldBinding(), behindHead())

		require.Equal(t, ApplyStaleTarget, res.Outcome)
		require.ErrorContains(t, res.Err, "the certificate for that round builds on 0b0b")
		require.Empty(t, ex.commits, "nothing was sent to the executor")
	})

	t.Run("no certificate named is refused before the source is consulted", func(t *testing.T) {
		ex := &stubExecutor{}
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())
		res := f.applier.Apply(context.Background(), CertificateBinding{}, behindHead())
		require.Equal(t, ApplyNoTarget, res.Outcome)
		require.Empty(t, ex.commits)
	})

	t.Run("no verified target is its own answer", func(t *testing.T) {
		ex := &stubExecutor{}
		f := newApplyFixture(t, testApplyBudget(), ex, nil)

		res := f.applier.Apply(context.Background(), heldBinding(), behindHead())

		require.Equal(t, ApplyNoTarget, res.Outcome)
		require.ErrorIs(t, res.Err, ErrApplyNoTarget)
		require.Empty(t, ex.commits)
	})

	t.Run("the head reported back is the one the caller had", func(t *testing.T) {
		ex := &stubExecutor{}
		f := newApplyFixture(t, testApplyBudget(), ex, nil)
		res := f.applier.Apply(context.Background(), heldBinding(), behindHead())
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

		res := f.applier.Apply(context.Background(), heldBinding(), behindHead())

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

			res := f.applier.Apply(context.Background(), heldBinding(), behindHead())

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

		res := f.applier.Apply(context.Background(), heldBinding(), behindHead())

		require.Equal(t, ApplyPayloadInvalid, res.Outcome)
		require.ErrorIs(t, res.Err, ErrApplyPayloadInvalid)
		require.NotErrorIs(t, res.Err, ErrApplyPayloadUnavailable)
		require.False(t, res.Outcome.Retryable(), "no number of attempts makes a rejected payload valid")

		// Terminal for THIS block, and the executor is not asked again about it.
		again := f.applier.Apply(context.Background(), heldBinding(), behindHead())
		require.Equal(t, ApplyPayloadInvalid, again.Outcome)
		require.Len(t, ex.commits, 1, "a fault is not re-litigated against the executor")

		// A DIFFERENT block for the same state is a different claim — §3.3.1's whole point — and
		// gets its own attempt.
		f.src.set(&ExecutionAnchor{BlockHash: Hash(h32(0xee)), StateRoot: Hash(h32(0x0b)), Round: 12}, heldBinding())
		ex.commit = func(context.Context, Hash) (Status, error) { return StatusValid, nil }
		ex.head = func(context.Context) (BlockRef, error) {
			return BlockRef{Number: 6, Hash: Hash(h32(0xee)), StateRoot: Hash(h32(0x0b))}, nil
		}
		third := f.applier.Apply(context.Background(), heldBinding(), behindHead())
		require.Equal(t, ApplyApplied, third.Outcome, "err: %v", third.Err)
		require.Len(t, ex.commits, 2)
	})

	t.Run("unreachable again: the commit reported and the head could not be read", func(t *testing.T) {
		ex := &stubExecutor{head: func(context.Context) (BlockRef, error) {
			return BlockRef{}, errors.New("connection reset by peer")
		}}
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

		res := f.applier.Apply(context.Background(), heldBinding(), behindHead())

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

		res := f.applier.Apply(context.Background(), heldBinding(), behindHead())

		require.Equal(t, ApplyHeadMismatch, res.Outcome)
		require.ErrorIs(t, res.Err, ErrApplyHeadMismatch)
		require.False(t, res.Outcome.Retryable())
	})

	t.Run("the head is the certified block at another state", func(t *testing.T) {
		ex := &stubExecutor{head: func(context.Context) (BlockRef, error) {
			return BlockRef{Number: 5, Hash: Hash(h32(0xbb)), StateRoot: Hash(h32(0x0c))}, nil
		}}
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

		res := f.applier.Apply(context.Background(), heldBinding(), behindHead())

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

		res := f.applier.Apply(context.Background(), heldBinding(), behindHead())
		require.Equal(t, ApplyApplied, res.Outcome, "err: %v", res.Err)
		require.Equal(t, 1, ex.geneses, "block zero is configuration: read once, not once per question")
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

		res := f.applier.Apply(context.Background(), heldBinding(), behindHead())
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

		res := f.applier.Apply(context.Background(), heldBinding(), behindHead())
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

		require.Equal(t, ApplyPayloadUnavailable, f.applier.Apply(context.Background(), heldBinding(), behindHead()).Outcome)
		res := f.applier.Apply(context.Background(), heldBinding(), behindHead())
		require.Equal(t, ApplyBackoff, res.Outcome)
		require.ErrorIs(t, res.Err, ErrApplyBackoff)
		require.Len(t, ex.commits, 1, "the backoff is a refusal to ask, not a quieter way of asking")

		f.clock.advance(2 * time.Second)
		require.Equal(t, ApplyPayloadUnavailable, f.applier.Apply(context.Background(), heldBinding(), behindHead()).Outcome)
		require.Len(t, ex.commits, 2)
	})

	t.Run("one certified state gets a bounded number of attempts", func(t *testing.T) {
		ex := unavailable()
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

		for i := 0; i < testApplyBudget().MaxAttempts; i++ {
			require.Equal(t, ApplyPayloadUnavailable, f.applier.Apply(context.Background(), heldBinding(), behindHead()).Outcome, "attempt %d", i)
			f.clock.advance(2 * time.Second)
		}
		res := f.applier.Apply(context.Background(), heldBinding(), behindHead())
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
	t.Run("the next certificate brings a fresh budget, even a quiet one", func(t *testing.T) {
		ex := unavailable()
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())
		for i := 0; i < testApplyBudget().MaxAttempts; i++ {
			f.applier.Apply(context.Background(), heldBinding(), behindHead())
			f.clock.advance(2 * time.Second)
		}
		require.Equal(t, ApplyExhausted, f.applier.Apply(context.Background(), heldBinding(), behindHead()).Outcome)

		// The shard certified another QUIET round: same state root, a new certificate. This is the
		// case review reproduced — a state-keyed budget never renews here, and the node that most
		// needs to retry is the one that can no longer.
		quiet := bind(19, 130, h32(0x0b))
		f.src.set(recoveredAnchor(), quiet)
		res := f.applier.Apply(context.Background(), quiet, behindHead())
		require.Equal(t, ApplyPayloadUnavailable, res.Outcome, "err: %v", res.Err)
		require.Len(t, ex.commits, testApplyBudget().MaxAttempts+1,
			"a quiet certificate is a new opportunity, and the state root never changes across one")
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
		res := f.applier.Apply(context.Background(), heldBinding(), behindHead())
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
		res := f.applier.Apply(ctx, heldBinding(), behindHead())
		require.Equal(t, ApplyExecutorUnreachable, res.Outcome)
		require.ErrorIs(t, res.Err, context.Canceled)
	})
}

/*
A commit is not a read. Two attempts inside the executor at once make "what did the executor do"
unanswerable, and the head read afterwards belongs to neither of them — so a second caller is turned
away rather than admitted alongside the first.
*/
func TestTargetApplier_OneAttemptIsInsideTheExecutorAtATime(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	ex := &stubExecutor{
		commit: func(ctx context.Context, _ Hash) (Status, error) {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return StatusValid, ctx.Err()
			}
			return StatusValid, nil
		},
		head: func(context.Context) (BlockRef, error) { return recoveredHead(), nil },
	}
	f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

	first := make(chan ApplyResult, 1)
	go func() { first <- f.applier.Apply(context.Background(), heldBinding(), behindHead()) }()
	<-entered

	second := f.applier.Apply(context.Background(), heldBinding(), behindHead())
	require.Equal(t, ApplyInFlight, second.Outcome)
	require.ErrorIs(t, second.Err, ErrApplyInFlight)
	require.True(t, second.Outcome.Retryable())
	require.True(t, f.applier.Status().InFlight)

	close(release)
	select {
	case res := <-first:
		require.Equal(t, ApplyApplied, res.Outcome, "err: %v", res.Err)
	case <-time.After(5 * time.Second):
		t.Fatal("the first attempt never finished")
	}
	require.Len(t, ex.commits, 1, "two callers, one commit")
	require.False(t, f.applier.Status().InFlight, "the slot is released on every exit")

	// And the slot is released after a refusal too, not only after a success.
	ex.commit = func(context.Context, Hash) (Status, error) { return StatusInvalid, nil }
	f.src.set(&ExecutionAnchor{BlockHash: Hash(h32(0xee)), StateRoot: Hash(h32(0x0b)), Round: 12}, heldBinding())
	f.applier.Apply(context.Background(), heldBinding(), behindHead())
	require.False(t, f.applier.Status().InFlight)
}

/*
A commit takes time, and the requester's ordinary behaviour across a quiet tail is to install a
target for a newer certificate while one is in flight. Committing was still correct if the target
still names the same block; what must not happen is reporting this node RECOVERED for a question the
answer was never about.
*/
func TestTargetApplier_NoticesTheTargetMovingUnderTheCommit(t *testing.T) {
	t.Run("a different block arrives while the commit is in the executor", func(t *testing.T) {
		var f *applyFixture
		ex := &stubExecutor{head: func(context.Context) (BlockRef, error) { return recoveredHead(), nil }}
		ex.commit = func(context.Context, Hash) (Status, error) {
			// The shard certified a state-changing round; the requester verified a new target.
			f.src.set(&ExecutionAnchor{BlockHash: Hash(h32(0xee)), StateRoot: Hash(h32(0x0c)), Round: 21}, bind(21, 140, h32(0x0c)))
			return StatusValid, nil
		}
		f = newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

		res := f.applier.Apply(context.Background(), heldBinding(), behindHead())

		require.Equal(t, ApplyTargetMoved, res.Outcome)
		require.ErrorIs(t, res.Err, ErrApplyTargetMoved)
		require.True(t, res.Outcome.Retryable(), "the next attempt names the certificate now held")
		require.Zero(t, f.applier.Status().Applied, "nothing was recovered for the round that was asked about")
	})

	t.Run("the same block carried onto a later certificate is still an application", func(t *testing.T) {
		var f *applyFixture
		ex := &stubExecutor{head: func(context.Context) (BlockRef, error) { return recoveredHead(), nil }}
		ex.commit = func(context.Context, Hash) (Status, error) {
			// A quiet round: the requester carried the SAME anchor onto the newer certificate.
			f.src.set(recoveredAnchor(), bind(19, 130, h32(0x0b)))
			return StatusValid, nil
		}
		f = newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

		res := f.applier.Apply(context.Background(), heldBinding(), behindHead())
		require.Equal(t, ApplyApplied, res.Outcome, "err: %v", res.Err)
		require.Equal(t, 1, f.applier.Status().Applied)
	})
}

/*
A node already on the certified block needs no finality-changing call at all: adopting a verified
statement is not the same as changing what the executor considers canonical.

The second case is the one the real-reth acceptance run found, and it is not a corner: the shard's
first certified round is non-quiet by convention, so it names a block a client builds and discards,
and against an executor with no block identity at genesis BlockHashOrFallback puts the STATE ROOT in
the certificate's block-hash field. On a shard with no transactions that is the only anchor there is.
Committing it asked reth to make the empty-trie state root canonical, which it answered SYNCING —
correctly, for ever — while the executor was already exactly where the certificate said.
*/
func TestTargetApplier_AdoptsWithoutCommittingWhenTheExecutorIsAlreadyThere(t *testing.T) {
	t.Run("an ordinary anchor the executor already holds", func(t *testing.T) {
		ex := &stubExecutor{}
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

		res := f.applier.Apply(context.Background(), heldBinding(), recoveredHead())

		require.Equal(t, ApplyApplied, res.Outcome, "err: %v", res.Err)
		require.Empty(t, ex.commits, "nothing needed to change, so nothing was changed")
		require.Zero(t, ex.heads, "and the head the caller already read was enough")
		require.Equal(t, 1, f.applier.Status().Applied)
	})

	t.Run("the genesis-round anchor, whose block hash is a state root", func(t *testing.T) {
		// Exactly the shape measured against reth: the certificate names 0x56e8… (a state root via
		// BlockHashOrFallback), and the executor sits at its own genesis block, at that state.
		stateRoot := h32(0x0b)
		genesis := BlockRef{Number: 0, Hash: Hash(h32(0x59)), StateRoot: Hash(stateRoot)}
		ex := &stubExecutor{genesis: func(context.Context) (BlockRef, error) { return genesis, nil }}
		anchor := &ExecutionAnchor{
			BlockHash: Hash(stateRoot), StateRoot: Hash(stateRoot), Round: 1, fromGenesisRound: true,
		}
		f := newApplyFixture(t, testApplyBudget(), ex, anchor)

		res := f.applier.Apply(context.Background(), heldBinding(), genesis)

		require.Equal(t, ApplyApplied, res.Outcome, "err: %v", res.Err)
		require.Empty(t, ex.commits,
			"committing a state root as though it were a block is what reth answered SYNCING to, for ever")
		require.Equal(t, 1, ex.geneses, "block zero is read once, for the row-13 exception")
	})

	t.Run("the right block at the wrong state is not already there", func(t *testing.T) {
		// Both halves of P-id, in the pre-check as everywhere else: the same block hash at another
		// state would mean the executor and the certificate disagree about what that block produced,
		// and adopting it would claim an execution identity the executor does not have.
		wrongState := BlockRef{Number: 5, Hash: Hash(h32(0xbb)), StateRoot: Hash(h32(0x0c))}
		ex := &stubExecutor{head: func(context.Context) (BlockRef, error) { return wrongState, nil }}
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

		res := f.applier.Apply(context.Background(), heldBinding(), wrongState)

		require.NotEqual(t, ApplyApplied, res.Outcome, "the state must be checked, not just the block")
		require.Equal(t, ApplyHeadMismatch, res.Outcome)
		require.Zero(t, f.applier.Status().Applied)
	})

	t.Run("and it still commits when the executor is NOT already there", func(t *testing.T) {
		ex := &stubExecutor{head: func(context.Context) (BlockRef, error) { return recoveredHead(), nil }}
		f := newApplyFixture(t, testApplyBudget(), ex, recoveredAnchor())

		res := f.applier.Apply(context.Background(), heldBinding(), behindHead())

		require.Equal(t, ApplyApplied, res.Outcome, "err: %v", res.Err)
		require.Len(t, ex.commits, 1, "a node behind the certified block still has to be moved to it")
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

	res := f.applier.Apply(context.Background(), heldBinding(), behindHead())
	require.Equal(t, ApplyApplied, res.Outcome)
	res.Target.BlockHash[0] ^= 0xff
	res.Target.StateRoot[0] ^= 0xff

	require.Equal(t, Hash(h32(0xbb)), anchor.BlockHash, "the source's record is not the caller's to edit")
	require.Equal(t, Hash(h32(0x0b)), anchor.StateRoot)
}
