package shardnode_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
	"github.com/unicitynetwork/bft-go-base/types"
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

// supersessionProbe stands in for the BFT client's supersession registry: it records the registrations and lets a test fire the cancel.
type supersessionProbe struct {
	mu          sync.Mutex
	registered  int
	unregisters int
	cancel      func()
	fireOnArm   bool // the repeat UC arrived before the wait registered
	armed       chan struct{}
}

func newSupersessionProbe(fireOnArm bool) *supersessionProbe {
	return &supersessionProbe{fireOnArm: fireOnArm, armed: make(chan struct{}, 8)}
}

func (p *supersessionProbe) watch(_ *types.UnicityCertificate, cancel func()) func() {
	p.mu.Lock()
	p.registered++
	p.cancel = cancel
	fire := p.fireOnArm
	p.mu.Unlock()
	if fire {
		cancel()
	}
	p.armed <- struct{}{}
	return func() {
		p.mu.Lock()
		p.unregisters++
		p.mu.Unlock()
	}
}

func (p *supersessionProbe) waitArmed(t *testing.T) {
	t.Helper()
	select {
	case <-p.armed:
	case <-time.After(3 * time.Second):
		t.Fatal("the follower never armed its supersession watch")
	}
}

func (p *supersessionProbe) fire() {
	p.mu.Lock()
	cancel := p.cancel
	p.mu.Unlock()
	cancel()
}

func (p *supersessionProbe) counts() (registered, unregisters int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.registered, p.unregisters
}

// bft-core#728: a repeat UC that arrives while the follower waits for the leader's block ends that wait at once, instead of after the whole budget. The old wait signs nothing
// and the certificate counts as handled (the repeat UC is delivered next with its own budget).
func TestRound_ARepeatUCDuringTheWaitEndsItAndSignsNothing(t *testing.T) {
	const budget = 5 * time.Second
	sub := &recordingSubmitter{}
	r, _ := newTestRound(t, executortest.New(), sub)
	r.SetAwaitTimeout(budget)
	probe := newSupersessionProbe(false)
	r.SetSupersessionWatch(probe.watch)

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, "node-of-a-leader-that-is-down"))
	}()
	probe.waitArmed(t)
	select {
	case err := <-done:
		t.Fatalf("returned before the repeat UC arrived: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	probe.fire()
	require.NoError(t, <-done, "the abandoned wait is not a failure of the certified application")
	require.Less(t, time.Since(start), budget/4, "the wait ended on the repeat UC, not on the budget")
	require.Empty(t, sub.got, "nothing was signed for the superseded certificate")
	registered, unregisters := probe.counts()
	require.Equal(t, 1, registered)
	require.Equal(t, 1, unregisters, "the wait unregistered itself")
}

// Arrival before registration: the repeat UC reached the client just before the follower started waiting. The registration itself cancels, so the wait does not start.
func TestRound_ARepeatUCThatArrivedBeforeTheWaitCancelsItAtRegistration(t *testing.T) {
	const budget = 5 * time.Second
	sub := &recordingSubmitter{}
	r, _ := newTestRound(t, executortest.New(), sub)
	r.SetAwaitTimeout(budget)
	r.SetSupersessionWatch(newSupersessionProbe(true).watch)

	start := time.Now()
	require.NoError(t, r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, "node-of-a-leader-that-is-down")))
	require.Less(t, time.Since(start), budget/4)
	require.Empty(t, sub.got)
}

// The block is preferred: if the leader's block is already there when the wait is superseded, the follower takes it and signs, as without the signal.
func TestRound_ABlockThatIsThereWhenTheWaitIsSupersededIsStillTaken(t *testing.T) {
	ctx := context.Background()
	d := newBroadcastDisseminator()
	leader := newDeterminismValidator(t, d)
	follower := newDeterminismValidator(t, d)
	follower.round.SetAwaitTimeout(5 * time.Second)
	follower.round.SetSupersessionWatch(newSupersessionProbe(true).watch)

	uc, rec := genesisUC(1000), tr(1, 0, leader.nodeID)
	require.NoError(t, leader.round.HandleCertificate(ctx, uc, rec))
	require.NoError(t, follower.round.HandleCertificate(ctx, uc, rec))
	require.Len(t, follower.sub.got, 1, "the follower signed the leader's block")
	require.Equal(t, leader.sub.last(t).InputRecord.BlockHash, follower.sub.last(t).InputRecord.BlockHash)
}

// A late payload for the superseded certificate changes nothing; the repeat UC (a later root round) is a fresh attempt that takes the block once it is there and signs it.
func TestRound_ALateBlockAfterTheSupersededWaitIsSignedOnTheRepeatUC(t *testing.T) {
	ctx := context.Background()
	d := newBroadcastDisseminator()
	leader := newDeterminismValidator(t, d)
	follower := newDeterminismValidator(t, d)
	follower.round.SetAwaitTimeout(5 * time.Second)
	probe := newSupersessionProbe(false)
	follower.round.SetSupersessionWatch(probe.watch)

	uc, rec := genesisUC(1000), tr(1, 0, leader.nodeID)
	done := make(chan error, 1)
	go func() { done <- follower.round.HandleCertificate(ctx, uc, rec) }()
	probe.waitArmed(t)
	probe.fire()
	require.NoError(t, <-done)
	require.Empty(t, follower.sub.got)

	require.NoError(t, leader.round.HandleCertificate(ctx, uc, rec), "the leader publishes after the abandoned wait")
	require.Empty(t, follower.sub.got, "the block alone signs nothing")

	repeat := genesisUC(1000)
	repeat.UnicitySeal.RootChainRoundNumber = 2
	start := time.Now()
	require.NoError(t, follower.round.HandleCertificate(ctx, repeat, rec))
	require.Less(t, time.Since(start), time.Second)
	require.Len(t, follower.sub.got, 1, "the repeat UC took the block and the follower signed once")
	require.Equal(t, leader.sub.last(t).InputRecord.BlockHash, follower.sub.last(t).InputRecord.BlockHash)
}

// Supersession is remembered like an abstention: the same obsolete authorization delivered again (admission retry) does not start another wait and does not register one.
func TestRound_ASupersededAuthorizationIsNotWaitedOnAgainWhenRedelivered(t *testing.T) {
	const budget = 5 * time.Second
	sub := &recordingSubmitter{}
	r, _ := newTestRound(t, executortest.New(), sub)
	r.SetAwaitTimeout(budget)
	probe := newSupersessionProbe(true)
	r.SetSupersessionWatch(probe.watch)

	uc, rec := genesisUC(1000), tr(1, 0, "node-of-a-leader-that-is-down")
	require.NoError(t, r.HandleCertificate(context.Background(), uc, rec))
	start := time.Now()
	_ = r.HandleCertificate(context.Background(), uc, rec)
	require.Less(t, time.Since(start), budget/4, "the redelivery polled")
	registered, _ := probe.counts()
	require.Equal(t, 1, registered, "and did not arm a second wait")
	require.Empty(t, sub.got)
}

// Without a repeat UC nothing changes: the wait runs its whole budget and the abstention is still an error, so a retry is not mistaken for success.
func TestRound_AWaitWithNoRepeatUCStillTimesOutAsAnError(t *testing.T) {
	const budget = 300 * time.Millisecond
	r, _ := newTestRound(t, executortest.New(), &recordingSubmitter{})
	r.SetAwaitTimeout(budget)
	probe := newSupersessionProbe(false)
	r.SetSupersessionWatch(probe.watch)

	start := time.Now()
	err := r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, "node-of-a-leader-that-is-down"))
	require.Error(t, err)
	require.ErrorContains(t, err, "awaiting round 1 block from leader")
	require.GreaterOrEqual(t, time.Since(start), budget)
	_, unregisters := probe.counts()
	require.Equal(t, 1, unregisters)
}

// lateBlockDisseminator makes the first Await honour only its context (as when the wait is cancelled before the block shows), and later Awaits read the real one.
type lateBlockDisseminator struct {
	inner *broadcastDisseminator
	mu    sync.Mutex
	calls int
}

func (d *lateBlockDisseminator) Publish(ctx context.Context, round uint64, b shardnode.Block) error {
	return d.inner.Publish(ctx, round, b)
}

func (d *lateBlockDisseminator) Await(ctx context.Context, round uint64) (shardnode.Block, error) {
	d.mu.Lock()
	d.calls++
	first := d.calls == 1
	d.mu.Unlock()
	if first {
		<-ctx.Done()
		return shardnode.Block{}, ctx.Err()
	}
	return d.inner.Await(ctx, round)
}

// The block that lands in the same instant as the repeat UC is taken by the short poll after the cancelled wait, and signed.
func TestRound_ABlockThatLandsWithTheRepeatUCIsTakenByThePollAfterTheCancelledWait(t *testing.T) {
	ctx := context.Background()
	d := newBroadcastDisseminator()
	leader := newDeterminismValidator(t, d)
	follower := newDeterminismValidator(t, &lateBlockDisseminator{inner: d})
	follower.round.SetAwaitTimeout(5 * time.Second)
	follower.round.SetSupersessionWatch(newSupersessionProbe(true).watch)

	uc, rec := genesisUC(1000), tr(1, 0, leader.nodeID)
	require.NoError(t, leader.round.HandleCertificate(ctx, uc, rec))
	require.NoError(t, follower.round.HandleCertificate(ctx, uc, rec))
	require.Len(t, follower.sub.got, 1, "the follower signed the block the poll found")
}
