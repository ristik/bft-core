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
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

func pacingSigner(t *testing.T) abcrypto.Signer {
	t.Helper()
	s, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	return s
}

// countingBuilds counts the builds that reach the executor: a build is the first irreversible leader action (it moves forkchoice).
type countingBuilds struct {
	shardnode.Executor
	builds atomic.Int32
}

func (e *countingBuilds) Build(ctx context.Context, p shardnode.RoundParams) (shardnode.BuildID, error) {
	e.builds.Add(1)
	return e.Executor.Build(ctx, p)
}

// pacedLeader is a single-validator round that has led round 1 (so its pacing state is populated) and holds round 1's certificate.
func pacedLeader(t *testing.T, interval time.Duration) (*shardnode.Round, string, *countingBuilds, *recordingSubmitter, *types.UnicityCertificate) {
	t.Helper()
	exec := &countingBuilds{Executor: executortest.New()}
	sub := &recordingSubmitter{}
	r, id := newTestRound(t, exec, sub)
	r.SetBlockInterval(interval)
	require.NoError(t, r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, id)))
	require.EqualValues(t, 1, exec.builds.Load())
	return r, id, exec, sub, certifyFrom(sub.last(t), 2, 1000)
}

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

type pacingWaitObserver struct {
	*broadcastDisseminator
	roundTwoBudget chan time.Duration
}

func (d pacingWaitObserver) Await(ctx context.Context, round uint64) (shardnode.Block, error) {
	if round == 2 {
		deadline, _ := ctx.Deadline()
		d.roundTwoBudget <- time.Until(deadline)
	}
	return d.broadcastDisseminator.Await(ctx, round)
}

// The follower gives a paced leader time to produce round 2. Observe the actual
// await budget and release delivery after the follower starts waiting.
func TestPacing_FollowerWaitCoversThePacedLeader(t *testing.T) {
	const interval, budget = time.Hour, 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watchdog := time.AfterFunc(5*time.Second, cancel)
	defer watchdog.Stop()
	d := pacingWaitObserver{
		broadcastDisseminator: newBroadcastDisseminator(),
		roundTwoBudget:        make(chan time.Duration, 1),
	}
	leader := newDeterminismValidator(t, d)
	follower := newDeterminismValidator(t, d)
	follower.round.SetBlockInterval(interval)
	follower.round.SetAwaitTimeout(budget)

	uc, rec := genesisUC(1000), tr(1, 0, leader.nodeID)
	require.NoError(t, leader.round.HandleCertificate(ctx, uc, rec))
	require.NoError(t, follower.round.HandleCertificate(ctx, uc, rec))
	require.Len(t, follower.sub.got, 1)

	uc2, rec2 := certifyFrom(leader.sub.last(t), 2, 1000), tr(2, 0, leader.nodeID)
	followerDone := make(chan error, 1)
	go func() {
		followerDone <- follower.round.HandleCertificate(ctx, uc2, rec2)
	}()
	select {
	case wait := <-d.roundTwoBudget:
		require.Greater(t, wait, interval/2, "the follower adds the remaining block interval")
	case err := <-followerDone:
		t.Fatalf("follower returned before awaiting round 2: %v", err)
	case <-ctx.Done():
		t.Fatal("follower did not await round 2")
	}

	// The test releases the leader now that the follower is waiting. Awaiting
	// its handler also ensures the leader has submitted before comparing records.
	require.NoError(t, leader.round.HandleCertificate(ctx, uc2, rec2))
	require.NoError(t, <-followerDone)
	require.Len(t, follower.sub.got, 2, "the follower signed the leader's block")
	require.Len(t, leader.sub.got, 2)
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

// A repeat UC of the certificate a paced leader holds ends its wait at once (the authorization was replaced): nothing is built or sent for
// the replaced certificate, the round returns cleanly, and the repeat is then handled normally, still paced from the last real build.
func TestPacing_ARepeatUCEndsAPacedLeadersWait(t *testing.T) {
	const interval = 400 * time.Millisecond
	r, id, exec, sub, uc1 := pacedLeader(t, interval)
	var fired atomic.Bool
	r.SetSupersessionWatch(func(held *types.UnicityCertificate, cancel func()) func() {
		if held.GetRootRoundNumber() == uc1.GetRootRoundNumber() && fired.CompareAndSwap(false, true) {
			time.AfterFunc(50*time.Millisecond, cancel) // the repeat arrives while the leader waits
		}
		return func() {}
	})

	start := time.Now()
	require.NoError(t, r.HandleCertificate(context.Background(), uc1, tr(2, 0, id)), "a superseded wait is an abstention, not a failure")
	require.Less(t, time.Since(start), interval/2, "the wait ended with the repeat, not with the interval")
	require.True(t, fired.Load())
	require.EqualValues(t, 1, exec.builds.Load(), "nothing was built for the replaced certificate")
	require.Len(t, sub.got, 1, "and nothing was sent")

	repeat := certifyFrom(sub.got[0], 3, 1000) // same input record, a later root round
	start = time.Now()
	require.NoError(t, r.HandleCertificate(context.Background(), repeat, tr(2, 0, id)))
	require.GreaterOrEqual(t, time.Since(start), interval/2, "the repeat is paced from the last real build, which the abandoned wait did not move")
	require.EqualValues(t, 2, exec.builds.Load())
	require.Len(t, sub.got, 2)
	require.Equal(t, uint64(2), sub.last(t).InputRecord.RoundNumber)
}

// A role that ends while the leader waits (retired, or re-published under a new token) stops the round before the build: the lease is
// checked again after the wait, so a node that lost its role during the delay never moves forkchoice, signs or sends.
func TestPacing_ARoleEndingDuringTheWaitBuildsNothing(t *testing.T) {
	const interval = 300 * time.Millisecond
	for name, end := range map[string]func(*leaseRole){
		"retired":      func(l *leaseRole) { l.active.Store(false) },
		"re-published": func(l *leaseRole) { l.token.Add(1) },
	} {
		t.Run(name, func(t *testing.T) {
			role := &leaseRole{}
			role.active.Store(true)
			exec := &countingBuilds{Executor: executortest.New()}
			sub := &recordingSubmitter{}
			r, id := newTestRound(t, exec, sub)
			r.SetRole(role)
			r.SetBlockInterval(interval)
			require.NoError(t, r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, id)))
			uc1 := certifyFrom(sub.last(t), 2, 1000)

			time.AfterFunc(50*time.Millisecond, func() { end(role) })
			require.NoError(t, r.HandleCertificate(context.Background(), uc1, tr(2, 0, id)))
			require.EqualValues(t, 1, exec.builds.Load(), "no build after the role ended during the wait")
			require.Len(t, sub.got, 1, "no request either")
		})
	}
}

// Leadership rotates between rounds: the round-1 leader follows in round 2 and the round-1 follower leads it. The new leader paces from
// when it received round 1's block; the new follower extends its wait from when it built it. Both take part in round 2, though the paced
// block arrives well after the follower's own await budget.
func TestPacing_LeadershipChangeBetweenPacedRounds(t *testing.T) {
	const interval, budget = 400 * time.Millisecond, 100 * time.Millisecond
	ctx := context.Background()
	d := newBroadcastDisseminator()
	a, b := newDeterminismValidator(t, d), newDeterminismValidator(t, d)
	for _, v := range []*determinismValidator{a, b} {
		v.round.SetBlockInterval(interval)
		v.round.SetAwaitTimeout(budget)
	}
	uc, rec := genesisUC(1000), tr(1, 0, a.nodeID)
	require.NoError(t, a.round.HandleCertificate(ctx, uc, rec))
	require.NoError(t, b.round.HandleCertificate(ctx, uc, rec))

	uc2, rec2 := certifyFrom(a.sub.last(t), 2, 1000), tr(2, 0, b.nodeID)
	led := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		require.NoError(t, b.round.HandleCertificate(ctx, uc2, rec2))
		led <- time.Since(start)
	}()
	require.NoError(t, a.round.HandleCertificate(ctx, uc2, rec2), "the former leader waited for the paced block beyond its budget")
	require.GreaterOrEqual(t, <-led, interval-100*time.Millisecond, "the former follower paced its first build from the block it received")
	require.Len(t, a.sub.got, 2)
	require.Len(t, b.sub.got, 2)
	require.Equal(t, b.sub.last(t).InputRecord, a.sub.last(t).InputRecord)
}

// Pacing state is per process and never persisted: after a restart the first block is not delayed. The same certificate (a repeat at a
// later root round, as after a lost round) is paced by the process that built recently, and built at once by a restarted one.
func TestPacing_ARestartedProcessStartsUnpaced(t *testing.T) {
	const interval = 300 * time.Millisecond
	ctx := context.Background()
	r, id, _, sub, _ := pacedLeader(t, interval)
	repeat := genesisUC(1000)
	repeat.UnicitySeal.RootChainRoundNumber = 2

	start := time.Now()
	require.NoError(t, r.HandleCertificate(ctx, repeat, tr(1, 0, id)))
	require.GreaterOrEqual(t, time.Since(start), interval-100*time.Millisecond, "the running process is paced: its state was populated")

	restartedSub := &recordingSubmitter{}
	restarted := shardnode.NewRound(id, types.PartitionID(8), types.ShardID{}, executortest.New(), shardnode.NewLoopbackDisseminator(), pacingSigner(t), restartedSub, nil)
	restarted.SetBlockInterval(interval)
	start = time.Now()
	require.NoError(t, restarted.HandleCertificate(ctx, repeat, tr(1, 0, id)))
	require.Less(t, time.Since(start), interval/2, "a restarted process has no previous block to pace from")
	require.Equal(t, sub.last(t).InputRecord, restartedSub.last(t).InputRecord, "and builds the same block")
}
