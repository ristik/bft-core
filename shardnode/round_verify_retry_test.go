package shardnode_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
)

type transientVerifyFault struct{ error }

func (transientVerifyFault) TransientVerify() bool { return true }

type transientThenValid struct {
	*executortest.Fake
	calls  atomic.Int32
	always bool
}

func (p *transientThenValid) Verify(ctx context.Context, b shardnode.Block, params shardnode.RoundParams) (shardnode.Status, error) {
	if p.calls.Add(1) == 1 || p.always {
		return shardnode.StatusSyncing, transientVerifyFault{errors.New("local proof unavailable")}
	}
	return p.Fake.Verify(ctx, b, params)
}

func TestRound_RetriesTransientWitnessOnceThenSubmits(t *testing.T) {
	exec := &transientThenValid{Fake: executortest.New()}
	sub := &recordingSubmitter{}
	r, nodeID := newTestRound(t, exec, sub)
	r.SetAwaitTimeout(2 * time.Second)
	start := time.Now()
	require.NoError(t, r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, nodeID)))
	require.Len(t, sub.got, 1)
	require.EqualValues(t, 2, exec.calls.Load())
	require.GreaterOrEqual(t, time.Since(start), 500*time.Millisecond)
}

func TestRound_AbstainsAfterTwoTransientWitnessEpisodes(t *testing.T) {
	exec := &transientThenValid{Fake: executortest.New(), always: true}
	sub := &recordingSubmitter{}
	r, nodeID := newTestRound(t, exec, sub)
	r.SetAwaitTimeout(2 * time.Second)
	require.NoError(t, r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, nodeID)))
	require.Empty(t, sub.got)
	require.EqualValues(t, 2, exec.calls.Load(), "no replenished proof episode on every 100 ms poll")
}

type deadlineVerify struct{ *executortest.Fake }

func (p *deadlineVerify) Verify(ctx context.Context, _ shardnode.Block, _ shardnode.RoundParams) (shardnode.Status, error) {
	<-ctx.Done()
	return shardnode.StatusSyncing, transientVerifyFault{ctx.Err()}
}

func TestRound_PassesDeadlineIntoTransientVerification(t *testing.T) {
	exec := &deadlineVerify{Fake: executortest.New()}
	sub := &recordingSubmitter{}
	r, nodeID := newTestRound(t, exec, sub)
	r.SetAwaitTimeout(120 * time.Millisecond)
	start := time.Now()
	require.NoError(t, r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, nodeID)))
	require.Empty(t, sub.got)
	require.Less(t, time.Since(start), 500*time.Millisecond)
}

type preparedBuildExecutor struct {
	*executortest.Fake
	prepared atomic.Bool
	built    atomic.Bool
}

func (p *preparedBuildExecutor) PrepareBuild(_ context.Context, params shardnode.RoundParams) (func(context.Context) (shardnode.BuildID, error), error) {
	p.prepared.Store(true)
	return func(ctx context.Context) (shardnode.BuildID, error) {
		p.built.Store(true)
		return p.Fake.Build(ctx, params)
	}, nil
}

func (p *preparedBuildExecutor) Build(context.Context, shardnode.RoundParams) (shardnode.BuildID, error) {
	panic("round bypassed the prepared build")
}

func TestRound_UsesPreparedBuildBeforeFinalityMutation(t *testing.T) {
	exec := &preparedBuildExecutor{Fake: executortest.New()}
	sub := &recordingSubmitter{}
	r, nodeID := newTestRound(t, exec, sub)
	require.NoError(t, r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, nodeID)))
	require.True(t, exec.prepared.Load())
	require.True(t, exec.built.Load())
	require.Len(t, sub.got, 1)
}

// pendingThenValid wraps a real Fake but overrides Verify to report
// StatusSyncing for the first n calls before delegating for real — proving
// verifyWithRetry actually polls rather than failing on the first
// non-Valid response (docs/engine-api-adapter-plan.md's status policy, C1.2).
type pendingThenValid struct {
	*executortest.Fake
	remaining atomic.Int32
}

func (p *pendingThenValid) Verify(ctx context.Context, b shardnode.Block, params shardnode.RoundParams) (shardnode.Status, error) {
	if p.remaining.Add(-1) >= 0 {
		return shardnode.StatusSyncing, nil
	}
	return p.Fake.Verify(ctx, b, params)
}

// alwaysPending reports StatusSyncing forever — proving the retry loop
// gives up at the deadline and the round abstains rather than hanging or
// erroring the whole certificate handler.
type alwaysPending struct {
	*executortest.Fake
}

func (p *alwaysPending) Verify(_ context.Context, _ shardnode.Block, _ shardnode.RoundParams) (shardnode.Status, error) {
	return shardnode.StatusSyncing, nil
}

func TestRound_VerifyRetriesOnSyncingUntilValid(t *testing.T) {
	ctx := context.Background()
	exec := &pendingThenValid{Fake: executortest.New()}
	exec.remaining.Store(2) // Syncing, Syncing, then real (Valid)

	sub := &recordingSubmitter{}
	r, nodeID := newTestRound(t, exec, sub)
	r.SetAwaitTimeout(2 * time.Second) // budget for the retries, not the test's own patience

	start := time.Now()
	err := r.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID))
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotEmpty(t, sub.got, "round should have been submitted once Verify finally returned Valid")
	require.GreaterOrEqual(t, elapsed, 200*time.Millisecond, "must have actually waited across at least two retry intervals, not returned instantly")
	require.Less(t, elapsed, 2*time.Second, "must not have waited for the full deadline once Verify resolved")
}

func TestRound_AbstainsAfterVerifyStaysPendingPastDeadline(t *testing.T) {
	ctx := context.Background()
	exec := &alwaysPending{Fake: executortest.New()}
	sub := &recordingSubmitter{}
	r, nodeID := newTestRound(t, exec, sub)
	r.SetAwaitTimeout(150 * time.Millisecond) // short, so the test doesn't wait long

	err := r.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID))
	require.NoError(t, err, "abstaining is not an error — it's a round with nothing submitted")
	require.Empty(t, sub.got, "nothing should be submitted for a round the executor never validated")
}
