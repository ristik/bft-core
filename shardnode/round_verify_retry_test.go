package shardnode_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
)

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
