package shardnode

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/types"
)

/*
The finality gate (finality.go).

What it is for is easy to state and easy to lose: `Round.mu` used to serialize every
finality-changing executor call by accident, being held across the whole of HandleCertificate. It is
a ROUND lock, and the accident stopped holding the moment a second thing — evidence recovery — could
commit. These fixtures pin the two properties that replace it: exclusion, and the two different
answers a waiter and a non-waiter get.
*/
func TestFinalityGate(t *testing.T) {
	t.Run("one holder at a time, and the holder is named", func(t *testing.T) {
		g := NewFinalityGate()
		_, _, held := g.Holder()
		require.False(t, held)

		release, err := g.acquire(context.Background(), "round-commit")
		require.NoError(t, err)
		who, _, held := g.Holder()
		require.True(t, held)
		require.Equal(t, "round-commit", who)

		_, err = g.tryAcquire("recovery-apply")
		require.ErrorIs(t, err, ErrFinalityBusy)
		require.ErrorContains(t, err, `"round-commit"`, "the refusal says who is inside the executor")

		release()
		_, _, held = g.Holder()
		require.False(t, held)

		again, err := g.tryAcquire("recovery-apply")
		require.NoError(t, err)
		again()
	})

	t.Run("release is idempotent", func(t *testing.T) {
		// Every caller defers its release, and some paths return through more than one of them.
		// A second release must not hand the gate to two holders at once.
		g := NewFinalityGate()
		release, err := g.acquire(context.Background(), "a")
		require.NoError(t, err)
		release()
		release()

		first, err := g.tryAcquire("b")
		require.NoError(t, err)
		defer first()
		_, err = g.tryAcquire("c")
		require.ErrorIs(t, err, ErrFinalityBusy, "the gate was not left open by the double release")
	})

	t.Run("a waiter proceeds when the holder releases", func(t *testing.T) {
		g := NewFinalityGate()
		release, err := g.acquire(context.Background(), "holder")
		require.NoError(t, err)

		got := make(chan error, 1)
		go func() {
			r, err := g.acquire(context.Background(), "waiter")
			if r != nil {
				r()
			}
			got <- err
		}()

		select {
		case <-got:
			t.Fatal("the waiter did not wait")
		case <-time.After(50 * time.Millisecond):
		}
		release()
		select {
		case err := <-got:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("the waiter was never woken")
		}
	})

	t.Run("a waiter's context ends its wait, and says who it was waiting for", func(t *testing.T) {
		g := NewFinalityGate()
		release, err := g.acquire(context.Background(), "a-slow-commit")
		require.NoError(t, err)
		defer release()

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err = g.acquire(ctx, "round-commit")
		require.ErrorIs(t, err, ErrFinalityBusy)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.ErrorContains(t, err, "a-slow-commit")
	})

	t.Run("many waiters are all woken and none is lost", func(t *testing.T) {
		// The wake channel is closed and replaced rather than sent on, so a waiter that has not yet
		// reached its select still learns. With a send, one of these would block forever.
		g := NewFinalityGate()
		release, err := g.acquire(context.Background(), "holder")
		require.NoError(t, err)

		const waiters = 8
		done := make(chan struct{}, waiters)
		for i := 0; i < waiters; i++ {
			go func() {
				r, err := g.acquire(context.Background(), "waiter")
				if err == nil {
					r()
				}
				done <- struct{}{}
			}()
		}
		// Every one of them must really be parked before the holder releases. Without this the
		// goroutines mostly find the gate already free and never wait at all, and the fixture then
		// establishes nothing about waking them — a send-instead-of-close would leave seven blocked
		// forever and the test would still pass.
		require.Eventually(t, func() bool { return g.Waiting() == waiters }, 5*time.Second, time.Millisecond,
			"the waiters never parked")
		release()
		for i := 0; i < waiters; i++ {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("waiter %d was never woken", i)
			}
		}
	})
}

// The applier does not queue behind the round. Its whole contract is one bounded attempt with an
// answer, and the caller is a round loop — so a gate it cannot have is reported, not waited for.
func TestTargetApplier_DoesNotWaitForTheRoundsOwnCommit(t *testing.T) {
	gate := NewFinalityGate()
	ex := &stubExecutor{head: func(context.Context) (BlockRef, error) { return recoveredHead(), nil }}
	clock := &testClock{at: time.Unix(1_700_000_000, 0)}
	src := &stubTarget{anchor: recoveredAnchor(), verifiedFor: heldBinding()}
	a, err := NewTargetApplier(ApplyConfig{Executor: ex, Source: src, Budget: testApplyBudget(), Gate: gate, Now: clock.now})
	require.NoError(t, err)

	release, err := gate.acquire(context.Background(), "round-commit")
	require.NoError(t, err)

	started := time.Now()
	res := a.Apply(context.Background(), heldBinding(), behindHead())
	require.Less(t, time.Since(started), 2*time.Second, "it did not wait")
	require.Equal(t, ApplyBusy, res.Outcome)
	require.ErrorIs(t, res.Err, ErrApplyBusy)
	require.ErrorIs(t, res.Err, ErrFinalityBusy)
	require.True(t, res.Outcome.Retryable(), "the next certificate is the next opportunity")
	require.Empty(t, ex.commits, "and nothing reached the executor")

	release()
	clock.advance(2 * time.Second)
	res = a.Apply(context.Background(), heldBinding(), behindHead())
	require.Equal(t, ApplyApplied, res.Outcome, "err: %v", res.Err)
	require.Len(t, ex.commits, 1)
}

/*
Round's own finality-changing calls take the gate. Asserted through the gate rather than through a
mock executor, because what matters is the mutual exclusion with recovery, not the call itself.
*/
func TestRound_TakesTheFinalityGateForItsOwnCommits(t *testing.T) {
	f := newEvidenceFixture(t)
	stateA, stateB, blockB := h32(0x0a), h32(0x0b), h32(0xbb)
	source := f.cert(10, 100, stateA, stateB, blockB, 12)

	gate := NewFinalityGate()
	inside := make(chan struct{})
	release := make(chan struct{})
	genesis := BlockRef{Number: 0, Hash: Hash(h32(0x01)), StateRoot: Hash(h32(0x02))}
	exec := newTrackingExecutor(BlockRef{Number: 4, Hash: Hash(h32(0xaa)), StateRoot: Hash(stateA)}, genesis)
	exec.blocks[string(blockB)] = BlockRef{Number: 5, Hash: Hash(blockB), StateRoot: Hash(stateB)}
	exec.onCommit = func() {
		close(inside)
		<-release
	}

	r := NewRound("gated", evidencePartitionID, types.ShardID{}, exec, NewLoopbackDisseminator(), nil, nil, nil)
	r.SetAwaitTimeout(50 * time.Millisecond)
	r.finality = gate

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.HandleCertificate(context.Background(), source.UC, source.Technical)
	}()

	<-inside
	who, _, held := gate.Holder()
	require.True(t, held, "the round holds the gate while it is inside the executor")
	require.Equal(t, "reconcile", who)
	_, err := gate.tryAcquire("recovery-apply")
	require.ErrorIs(t, err, ErrFinalityBusy, "recovery cannot commit alongside the round")

	close(release)
	<-done
	_, _, held = gate.Holder()
	require.False(t, held, "and the round released it")
}

// Build sets head, safe and finalized on the parent before any payload exists, so it changes
// finality even though it reads as "start a block".
func TestRound_TakesTheFinalityGateForBuild(t *testing.T) {
	gate := NewFinalityGate()
	exec := newTrackingExecutor(BlockRef{}, BlockRef{})
	r := NewRound("gated", evidencePartitionID, types.ShardID{}, exec, NewLoopbackDisseminator(), nil, nil, nil)
	r.finality = gate

	release, err := gate.acquire(context.Background(), "recovery-apply")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = r.buildFinal(ctx, RoundParams{})
	require.ErrorIs(t, err, ErrFinalityBusy)
	require.ErrorContains(t, err, "recovery-apply")
	release()

	_, err = r.buildFinal(context.Background(), RoundParams{})
	require.ErrorContains(t, err, "not a leader in this test", "the gate was free and Build was reached")
}

// Defence in depth: an anchor with no block hash would make Commit(nil) reachable, which every other
// layer is built to prevent. installVerified is the newest way in, so it refuses one too.
func TestContinuityState_InstallVerifiedRefusesAnAnchorWithNoBlock(t *testing.T) {
	var c continuityState
	c.installVerified(nil, 16, 19)
	require.Nil(t, c.anchor)

	c.installVerified(&ExecutionAnchor{StateRoot: Hash(h32(0x0b)), Round: 10}, 16, 19)
	require.Nil(t, c.anchor, "an anchor that names no block is not an anchor")
	require.Zero(t, c.through)

	// The realistic starting point: this node HELD an anchor and lost the thread of evidence for it
	// (row 10). Evidence repairs exactly that, so the interval must stop being broken.
	c.invalidate()
	require.True(t, c.broken)
	c.installVerified(&ExecutionAnchor{BlockHash: Hash(h32(0xbb)), StateRoot: Hash(h32(0x0b)), Round: 10}, 16, 19)
	require.NotNil(t, c.anchor)
	require.EqualValues(t, 16, c.through)
	require.EqualValues(t, 19, c.expectedNext, "the assignment comes from the technical record, never round+1")
	require.False(t, c.broken)
}

/*
The leader path takes the gate too. Build sets head, safe and finalized on the parent before any
payload exists, so a recovery commit interleaved with it would move finality under a block being
constructed on top of it.
*/
func TestRound_LeaderBuildIsGated(t *testing.T) {
	f := newEvidenceFixture(t)
	stateA, stateB, blockB := h32(0x0a), h32(0x0b), h32(0xbb)
	// "leader" is the leader the fixture's technical records name.
	source := f.cert(10, 100, stateA, stateB, blockB, 12)

	gate := NewFinalityGate()
	genesis := BlockRef{Number: 0, Hash: Hash(h32(0x01)), StateRoot: Hash(h32(0x02))}
	// Already at the certified block, so nothing reconciles and the round goes straight to Build.
	exec := newTrackingExecutor(BlockRef{Number: 5, Hash: Hash(blockB), StateRoot: Hash(stateB)}, genesis)

	r := NewRound("leader", evidencePartitionID, types.ShardID{}, exec, NewLoopbackDisseminator(), nil, nil, nil)
	r.SetAwaitTimeout(50 * time.Millisecond)
	r.finality = gate

	release, err := gate.acquire(context.Background(), "recovery-apply")
	require.NoError(t, err)

	// The round WAITS for the gate — it must proceed — so it is the caller's context that bounds
	// the wait. In production the only other holder is the applier, which holds it for exactly one
	// Commit under its own per-call timeout, so the wait is bounded by that.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err = r.HandleCertificate(ctx, source.UC, source.Technical)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrFinalityBusy, "the leader waited for the gate and its context ran out")
	require.ErrorContains(t, err, "recovery-apply")
	release()
}

/*
The gate covers the whole commit-and-confirm sequence, not just the commit.

Held for the Commit alone and released before the head was read, the confirmation was meaningless in
the one case it exists for: the round could commit something of its own in between, the head would
then be that other block, and a head that is not the committed block is recorded as a FAULT and never
retried. Interference by a correct round permanently refused a target that was correct too.
*/
func TestTargetApplier_HoldsTheGateThroughTheConfirmation(t *testing.T) {
	gate := NewFinalityGate()
	var duringCommit, duringHead, duringGenesis string
	ex := &stubExecutor{
		commit: func(context.Context, Hash) (Status, error) {
			duringCommit, _, _ = gate.Holder()
			return StatusValid, nil
		},
		head: func(context.Context) (BlockRef, error) {
			duringHead, _, _ = gate.Holder()
			return BlockRef{Number: 0, Hash: Hash(h32(0x01)), StateRoot: Hash(h32(0x0b))}, nil
		},
		genesis: func(context.Context) (BlockRef, error) {
			duringGenesis, _, _ = gate.Holder()
			return BlockRef{Number: 0, Hash: Hash(h32(0x01)), StateRoot: Hash(h32(0x0b))}, nil
		},
	}
	clock := &testClock{at: time.Unix(1_700_000_000, 0)}
	// A genesis-round anchor, so the genesis read the row-13 exception needs happens too.
	anchor := &ExecutionAnchor{BlockHash: Hash(h32(0xbb)), StateRoot: Hash(h32(0x0b)), Round: 1, fromGenesisRound: true}
	src := &stubTarget{anchor: anchor, verifiedFor: heldBinding()}
	a, err := NewTargetApplier(ApplyConfig{Executor: ex, Source: src, Budget: testApplyBudget(), Gate: gate, Now: clock.now})
	require.NoError(t, err)

	res := a.Apply(context.Background(), heldBinding(), behindHead())
	require.Equal(t, ApplyApplied, res.Outcome, "err: %v", res.Err)

	require.Equal(t, "recovery-apply", duringCommit, "held for the commit")
	require.Equal(t, "recovery-apply", duringHead, "and still held when the head that confirms it is read")
	// The executor's block zero is immutable configuration, read once and cached, so it is asked for
	// before the gate is taken and never again — the gate covers what can CHANGE under the
	// confirmation, and configuration cannot.
	require.Equal(t, "", duringGenesis)
	require.Equal(t, 1, ex.geneses)

	_, _, stillHeld := gate.Holder()
	require.False(t, stillHeld, "and released once the answer is known")
}
