package shardnode_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/shardnode/executortest"
)

// bft-core#728: a follower whose leader is down waits the full await budget for the leader's block and abstains. The same certificate reaches it again (several roots answer
// the same request, retransmissions); each delivery is handled in the single BFT client loop, so if every copy starts a new full await a newer certificate queues behind
// copies x budget (measured on the CI lane: median 3, up to 5 awaits of 5 s per dead-leader round). A re-delivery of the authorization it already gave up on must not wait again.
func TestRound_ARedeliveredAuthorizationIsNotAwaitedAgain(t *testing.T) {
	const budget = 400 * time.Millisecond
	exec := executortest.New()
	sub := &recordingSubmitter{}
	r, _ := newTestRound(t, exec, sub)
	r.SetAwaitTimeout(budget)

	uc, rec := genesisUC(1000), tr(1, 0, "node-of-a-leader-that-is-down")

	start := time.Now()
	err := r.HandleCertificate(context.Background(), uc, rec)
	first := time.Since(start)
	require.Error(t, err)
	require.ErrorContains(t, err, "awaiting round 1 block from leader")
	require.GreaterOrEqual(t, first, budget, "the first delivery waits the whole budget for a leader that never publishes")

	start = time.Now()
	err = r.HandleCertificate(context.Background(), uc, rec)
	second := time.Since(start)
	require.Less(t, second, budget/4, "the second delivery of the same authorization waited %s again", second)
	require.Empty(t, sub.got, "and nothing was submitted")
	_ = err
}

// The memo is per authorization: a different certificate (the repeat UC, a later root round) is a new attempt and waits again.
func TestRound_ANewAuthorizationIsAwaitedAfterAnAbstainedOne(t *testing.T) {
	const budget = 300 * time.Millisecond
	exec := executortest.New()
	r, _ := newTestRound(t, exec, &recordingSubmitter{})
	r.SetAwaitTimeout(budget)
	rec := tr(1, 0, "node-of-a-leader-that-is-down")

	_ = r.HandleCertificate(context.Background(), genesisUC(1000), rec)

	later := genesisUC(1000)
	later.UnicitySeal.RootChainRoundNumber = 2
	start := time.Now()
	err := r.HandleCertificate(context.Background(), later, rec)
	require.Error(t, err)
	require.GreaterOrEqual(t, time.Since(start), budget, "a certificate with a later root round is a fresh attempt")
}

// An abstain after the full budget is not a verdict on the round: if the leader's block arrives after it and the same certificate is delivered again, the block is
// picked up (a poll, not a wait) and the follower signs.
func TestRound_AReDeliveryPicksUpABlockThatArrivedAfterTheAbstain(t *testing.T) {
	ctx := context.Background()
	d := newBroadcastDisseminator()
	leader := newDeterminismValidator(t, d)
	follower := newDeterminismValidator(t, d)
	follower.round.SetAwaitTimeout(200 * time.Millisecond)

	uc, rec := genesisUC(1000), tr(1, 0, leader.nodeID)
	require.Error(t, follower.round.HandleCertificate(ctx, uc, rec), "the leader has not published: the follower abstains after its budget")
	require.Empty(t, follower.sub.got)

	require.NoError(t, leader.round.HandleCertificate(ctx, uc, rec), "the leader publishes late")

	start := time.Now()
	require.NoError(t, follower.round.HandleCertificate(ctx, uc, rec))
	require.Less(t, time.Since(start), 100*time.Millisecond, "the re-delivery polls instead of waiting")
	require.Len(t, follower.sub.got, 1, "and the follower signed the late block")
	require.Equal(t, leader.sub.last(t).InputRecord.BlockHash, follower.sub.last(t).InputRecord.BlockHash)
}
