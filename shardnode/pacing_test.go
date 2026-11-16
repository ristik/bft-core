package shardnode_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
)

// bft-core#1167: with a block interval the leader builds its next block no sooner than the interval after its previous one, and the
// paced request is byte-for-byte what an unpaced node submits for the same certificates: pacing is a delay, never a different block.
func TestPacing_LeaderDelaysTheNextBuildAndBuildsTheSameBlock(t *testing.T) {
	const interval = 300 * time.Millisecond
	ctx := context.Background()
	paced, plain := &recordingSubmitter{}, &recordingSubmitter{}
	rp, id := newTestRound(t, executortest.New(), paced)
	rp.SetBlockInterval(interval)
	ru, idu := newTestRound(t, executortest.New(), plain)

	start := time.Now()
	require.NoError(t, rp.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, id)))
	require.NoError(t, ru.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, idu)))
	require.Less(t, time.Since(start), interval, "the first block of a process is not delayed: there is no previous one")

	uc1 := certifyFrom(paced.last(t), 2, 1000)
	start = time.Now()
	require.NoError(t, rp.HandleCertificate(ctx, uc1, tr(2, 0, id)))
	waited := time.Since(start)
	require.GreaterOrEqual(t, waited, interval-50*time.Millisecond, "the second build waits for the interval")
	require.NoError(t, ru.HandleCertificate(ctx, certifyFrom(plain.last(t), 2, 1000), tr(2, 0, idu)))

	require.Len(t, paced.got, 2)
	require.Equal(t, plain.last(t).InputRecord, paced.last(t).InputRecord, "the paced input record is the unpaced one")
}

// Time already spent since the previous block counts: a certificate that arrives after the interval is built on at once.
func TestPacing_NoDelayOnceTheIntervalHasPassed(t *testing.T) {
	const interval = 150 * time.Millisecond
	ctx := context.Background()
	sub := &recordingSubmitter{}
	r, id := newTestRound(t, executortest.New(), sub)
	r.SetBlockInterval(interval)

	require.NoError(t, r.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, id)))
	time.Sleep(interval)
	start := time.Now()
	require.NoError(t, r.HandleCertificate(ctx, certifyFrom(sub.last(t), 2, 1000), tr(2, 0, id)))
	require.Less(t, time.Since(start), interval/2)
}

// Zero disables pacing (the code default): consecutive rounds run back to back.
func TestPacing_ZeroIntervalDoesNotDelay(t *testing.T) {
	ctx := context.Background()
	sub := &recordingSubmitter{}
	r, id := newTestRound(t, executortest.New(), sub)
	r.SetBlockInterval(0)
	start := time.Now()
	require.NoError(t, r.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, id)))
	for i := uint64(2); i <= 4; i++ {
		require.NoError(t, r.HandleCertificate(ctx, certifyFrom(sub.last(t), i, 1000), tr(i, 0, id)))
	}
	require.Less(t, time.Since(start), 200*time.Millisecond)
}

// A follower extends its wait for the leader's block by what remains of its own interval, so a paced leader is not mistaken for a silent
// one: with a 100 ms await budget and a 400 ms interval the follower takes a block that arrives 300 ms into the round and signs it.
func TestPacing_FollowerWaitCoversThePacedLeader(t *testing.T) {
	const interval, budget = 400 * time.Millisecond, 100 * time.Millisecond
	ctx := context.Background()
	d := newBroadcastDisseminator()
	leader := newDeterminismValidator(t, d)
	follower := newDeterminismValidator(t, d)
	for _, v := range []*determinismValidator{leader, follower} {
		v.round.SetBlockInterval(interval)
		v.round.SetAwaitTimeout(budget)
	}

	// Round 1: both take part at once (no previous block); the follower marks the time it received the leader's block.
	uc, rec := genesisUC(1000), tr(1, 0, leader.nodeID)
	require.NoError(t, leader.round.HandleCertificate(ctx, uc, rec))
	require.NoError(t, follower.round.HandleCertificate(ctx, uc, rec))
	require.Len(t, follower.sub.got, 1)

	// Round 2: the leader publishes 300 ms later, beyond the follower's budget but within its interval.
	uc2, rec2 := certifyFrom(leader.sub.last(t), 2, 1000), tr(2, 0, leader.nodeID)
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = leader.round.HandleCertificate(ctx, uc2, rec2)
	}()
	require.NoError(t, follower.round.HandleCertificate(ctx, uc2, rec2))
	require.Len(t, follower.sub.got, 2, "the follower signed the paced leader's block")
	require.Equal(t, leader.sub.last(t).InputRecord, follower.sub.last(t).InputRecord)
}

// Pacing is never a reason to keep a cancelled node waiting.
func TestPacing_LeaderWaitEndsWithTheContext(t *testing.T) {
	sub := &recordingSubmitter{}
	r, id := newTestRound(t, executortest.New(), sub)
	r.SetBlockInterval(time.Hour)
	require.NoError(t, r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, id)))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := r.HandleCertificate(ctx, certifyFrom(sub.last(t), 2, 1000), tr(2, 0, id))
	require.Error(t, err)
	require.True(t, errors.Is(err, context.DeadlineExceeded), "got %v", err)
	require.Less(t, time.Since(start), time.Second)
	require.Len(t, sub.got, 1, "nothing was built or submitted for the cancelled round")
}

func TestPacing_MinT2ForBlockInterval(t *testing.T) {
	const rbr = 900 * time.Millisecond
	require.Zero(t, shardnode.MinT2ForBlockInterval(0, rbr))
	// small intervals: the await budget is T2/2, so T2 >= 2*(interval + root round)
	require.Equal(t, 3800*time.Millisecond, shardnode.MinT2ForBlockInterval(time.Second, rbr))
	// large intervals: the await budget is capped at DefaultAwaitTimeout
	require.Equal(t, 10*time.Second+shardnode.DefaultAwaitTimeout+rbr, shardnode.MinT2ForBlockInterval(10*time.Second, rbr))

	for _, tc := range []struct {
		interval, t2 time.Duration
		ok           bool
	}{
		{0, 5 * time.Second, true},
		{time.Second, 5 * time.Second, true},
		{2 * time.Second, 5 * time.Second, false},
		{10 * time.Second, 5 * time.Second, false},
		{10 * time.Second, 15 * time.Second, false},
		{10 * time.Second, 20 * time.Second, true},
		{-time.Second, 20 * time.Second, false},
	} {
		err := shardnode.CheckBlockInterval(tc.interval, tc.t2, rbr)
		if tc.ok {
			require.NoError(t, err, "interval %s, T2 %s", tc.interval, tc.t2)
		} else {
			require.Error(t, err, "interval %s, T2 %s", tc.interval, tc.t2)
		}
		// the rule is self-consistent: the T2 it asks for satisfies the await budget derived from that T2
		if tc.interval > 0 {
			need := shardnode.MinT2ForBlockInterval(tc.interval, rbr)
			require.GreaterOrEqual(t, need, tc.interval+shardnode.AwaitTimeoutForT2(need)+rbr)
			require.NoError(t, shardnode.CheckBlockInterval(tc.interval, need, rbr))
		}
	}
}
