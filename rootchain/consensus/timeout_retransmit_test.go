package consensus

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-go-base/types"
)

const retxT = 10 * time.Second

func newFakeClock() *fakeClock           { return &fakeClock{t: time.Unix(1_000_000, 0)} }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }

func mult(r *timeoutRetx, d time.Duration) float64 { return float64(d) / float64(r.T) }

// The attempt times of arch's schedule: t0+T, t0+3T, t0+7T, t0+11T, t0+15T (intervals T, 2T, 4T, 4T, 4T), with C=4; T, 2T, 2T, ... with C=2.
func TestRetxAttemptTimes(t *testing.T) {
	for _, tc := range []struct {
		c    int64
		want []float64
	}{{4, []float64{1, 3, 7, 11, 15}}, {2, []float64{1, 3, 5, 7, 9}}, {8, []float64{1, 3, 7, 15, 23}}} {
		clk := newFakeClock()
		r := newTimeoutRetx(retxT, tc.c, clk.now)
		t0 := clk.now()
		r.firstSent(1, 5, false)
		var got []float64
		for step := 0; step < 1000 && len(got) < len(tc.want); step++ {
			clk.add(retxT / 20) // a fine clock: the attempt is made the moment it is due, not at a tick
			if r.due(1, 5) {
				got = append(got, mult(r, clk.now().Sub(t0)))
				r.scheduledSent(false)
			}
		}
		require.Equal(t, tc.want, got, "C=%d", tc.c)
	}
}

// The interval arithmetic saturates: a huge exponent and a huge C are bounded.
func TestRetxIntervalSaturates(t *testing.T) {
	r := newTimeoutRetx(retxT, 1<<40, newFakeClock().now)
	require.EqualValues(t, maxBackoffCap, r.C)
	require.Equal(t, maxBackoffCap*retxT, r.interval(1_000_000))
	require.Equal(t, retxT, newTimeoutRetx(retxT, 0, newFakeClock().now).interval(7), "C below 1 is 1: no spacing")
}

// A reset only brings the due attempt forward: the exponent starts over, an attempt due sooner keeps its time, and one never moves later.
func TestRetxResetNeverPostpones(t *testing.T) {
	clk := newFakeClock()
	r := newTimeoutRetx(retxT, 4, clk.now)
	t0 := clk.now()
	r.firstSent(1, 5, false)
	clk.add(retxT)
	require.True(t, r.due(1, 5))
	r.scheduledSent(false) // next at t0+3T
	require.Equal(t, t0.Add(3*retxT), r.next)

	clk.add(retxT / 5) // t0+1.2T: now+T = 2.2T is sooner than 3T
	r.registered(1, 5)
	require.Equal(t, t0.Add(22*retxT/10), r.next)
	require.Equal(t, 1, r.c.resetsForward)

	clk.add(retxT * 8 / 10) // t0+2.0T: now+T = 3.0T is later than the pending 2.2T
	r.registered(1, 5)
	require.Equal(t, t0.Add(22*retxT/10), r.next, "not postponed")
	require.Equal(t, 1, r.c.resetsNoEffect)

	// after the reset attempt the exponent restarted: the next interval is 2T, not 4T
	clk.add(retxT / 5)
	require.True(t, r.due(1, 5))
	r.scheduledSent(false)
	require.Equal(t, clk.now().Add(2*retxT), r.next)

	// a signer of another round or epoch is not a reset
	r.registered(1, 4)
	r.registered(2, 5)
	require.Equal(t, 1, r.c.resetsForward)
	require.Equal(t, 1, r.c.resetsNoEffect)
}

// A schedule belongs to its epoch and round: a firing for another one is stale and sends nothing, and retire drops it.
func TestRetxStaleAndRetire(t *testing.T) {
	clk := newFakeClock()
	r := newTimeoutRetx(retxT, 4, clk.now)
	r.firstSent(1, 5, false)
	clk.add(retxT)
	require.False(t, r.due(1, 6))
	require.False(t, r.due(2, 5))
	require.True(t, r.due(1, 5))
	r.retire(1, 5, true) // the same round: kept
	require.True(t, r.active)
	r.retire(1, 6, true)
	require.False(t, r.active)
	require.False(t, r.due(1, 5), "nothing is sent for a round that was dropped")
	r.firstSent(1, 7, false)
	r.retire(0, 0, false) // the pacemaker holds no vote any more (a recovery reset it)
	require.False(t, r.active)
}

// The timer is the scheduler's clock: it fires at the due time and is moved by a reset.
func TestRetxTimerFires(t *testing.T) {
	r := newTimeoutRetx(40*time.Millisecond, 4, time.Now)
	r.timer = time.NewTimer(time.Hour)
	r.timer.Stop()
	start := time.Now()
	r.firstSent(1, 5, false)
	select {
	case <-r.Chan():
		el := time.Since(start)
		require.GreaterOrEqual(t, el, 38*time.Millisecond)
		require.Less(t, el, 400*time.Millisecond)
	case <-time.After(2 * time.Second):
		t.Fatal("the timer did not fire")
	}
	require.True(t, r.due(1, 5))
	r.scheduledSent(false)
	r.registered(1, 5) // now+T is sooner than the 2T just scheduled
	start = time.Now()
	select {
	case <-r.Chan():
		require.Less(t, time.Since(start), 70*time.Millisecond+200*time.Millisecond)
	case <-time.After(2 * time.Second):
		t.Fatal("the moved timer did not fire")
	}
	var nilRetx *timeoutRetx
	require.Nil(t, nilRetx.Chan(), "off: the loop's case never fires")
}

// retxReplica is a replica of the 4-root anchor cluster whose manager runs the schedule with a fake clock (no timer: the test calls the timer's handler).
func retxReplica(t *testing.T, c int64) (*anchorReplica, *fakeClock, []*abdrc.TimeoutMsg) {
	t.Helper()
	receiver, votes := timeoutVotesOf(t)
	clk := newFakeClock()
	receiver.manager.retx = newTimeoutRetx(retxT, c, clk.now)
	return receiver, clk, votes
}

func timeoutSends(r *anchorReplica) []*abdrc.TimeoutMsg {
	var out []*abdrc.TimeoutMsg
	for _, m := range r.net.SentMessages(network.ProtocolRootTimeout) {
		out = append(out, m.Message.(*abdrc.TimeoutMsg))
	}
	return out
}

// The pacemaker ticker's repeats do not send while the round is scheduled; the timer's attempts fall at t0+T, 3T, 7T, 11T even though the first send
// was not at a tick (an early f+1 timeout), and every one is the byte-identical recorded vote to the whole committee.
func TestScheduledRetransmitsAreByteIdenticalAndTicksAreSilent(t *testing.T) {
	r, clk, _ := retxReplica(t, 4)
	ctx := context.Background()
	m := r.manager
	r.net.ResetSentMessages(network.ProtocolRootTimeout)

	clk.add(37 * time.Millisecond) // t0 is not a multiple of anything
	t0 := clk.now()
	m.onLocalTimeout(ctx)
	first := timeoutSends(r)
	require.Len(t, first, len(r.manager.Validators()), "the first send goes to every validator")
	want, err := types.Cbor.Marshal(first[0])
	require.NoError(t, err)

	var at []float64
	prev := len(first)
	for step := 0; step < 800 && len(at) < 4; step++ {
		clk.add(retxT / 20)
		if step%20 == 19 { // the ticker keeps firing every T, aligned to nothing in particular
			m.onLocalTimeout(ctx)
			require.Len(t, timeoutSends(r), prev, "a tick sends nothing while scheduled")
		}
		m.onRetransmitTimer(ctx)
		if n := len(timeoutSends(r)); n != prev {
			require.Equal(t, prev+len(m.Validators()), n)
			at = append(at, mult(m.retx, clk.now().Sub(t0)))
			prev = n
		}
	}
	require.Equal(t, []float64{1, 3, 7, 11}, at)
	for _, s := range timeoutSends(r) {
		got, err := types.Cbor.Marshal(s)
		require.NoError(t, err)
		require.Equal(t, want, got, "the recorded vote is resent unchanged")
	}
	require.Equal(t, 1, m.retx.c.firstSends)
	require.Equal(t, 4, m.retx.c.scheduledSends)
	require.Positive(t, m.retx.c.suppressedTicks)
}

// With the experiment off (the default) the ticker repeats exactly as before.
func TestWithoutTheBackoffTicksStillRepeat(t *testing.T) {
	receiver, _ := timeoutVotesOf(t)
	require.Nil(t, receiver.manager.retx)
	receiver.net.ResetSentMessages(network.ProtocolRootTimeout)
	for i := 1; i <= 3; i++ {
		receiver.manager.onLocalTimeout(context.Background())
		require.Len(t, timeoutSends(receiver), i*len(receiver.manager.Validators()))
	}
	receiver.manager.onRetransmitTimer(context.Background()) // a nil scheduler does nothing
	require.Len(t, timeoutSends(receiver), 3*len(receiver.manager.Validators()))
}

// Resets come only from a newly registered signer of the current round: a duplicate, an invalid or a stale message never moves the schedule; a
// new signer brings the due attempt forward; and a round that has moved on gets no old-round send.
func TestRetxResetOnlyOnNewlyRegisteredSigner(t *testing.T) {
	r, clk, votes := retxReplica(t, 4)
	require.Len(t, votes, 2)
	ctx := context.Background()
	m := r.manager
	t0 := clk.now()
	m.onLocalTimeout(ctx) // first send
	clk.add(retxT)
	m.onRetransmitTimer(ctx) // attempt at T; the next is due at 3T
	require.Equal(t, t0.Add(3*retxT), m.retx.next)
	clk.add(retxT / 5) // 1.2T

	// invalid: refused before registration
	require.Error(t, m.onTimeoutMsg(ctx, corrupted(t, votes[0])))
	require.Equal(t, t0.Add(3*retxT), m.retx.next, "an invalid message is no reset")
	// a stale one (older round)
	stale := recodeTimeout(t, votes[0])
	stale.Timeout.Round = m.pacemaker.GetCurrentRound() - 1
	require.Error(t, m.onTimeoutMsg(ctx, stale))
	require.Equal(t, t0.Add(3*retxT), m.retx.next, "an old-round message is no reset")
	require.Zero(t, m.retx.c.resetsForward+m.retx.c.resetsNoEffect)

	// a genuinely new signer
	require.NoError(t, m.onTimeoutMsg(ctx, votes[0]))
	require.Equal(t, t0.Add(22*retxT/10), m.retx.next, "now+T, sooner than 3T")
	require.Equal(t, 1, m.retx.c.resetsForward)
	// the same signer again: a duplicate, no reset
	require.ErrorIs(t, m.onTimeoutMsg(ctx, recodeTimeout(t, votes[0])), quorumweight.ErrDuplicateSigner)
	require.Equal(t, 1, m.retx.c.resetsForward)
	require.Zero(t, m.retx.c.resetsNoEffect)
	// a coalesced reset sends nothing by itself
	require.Len(t, timeoutSends(r), 3*len(m.Validators()), "(the helper's own timeout, the first send with the schedule, and the attempt at T)")

	// the second new signer: a reset with no effect (now+T is later than the pending attempt), not a postponement
	clk.add(retxT / 10)
	pending := m.retx.next
	require.NoError(t, m.onTimeoutMsg(ctx, votes[1]))
	require.Equal(t, pending, m.retx.next)
	require.Equal(t, 1, m.retx.c.resetsNoEffect)

	// the round moves on (a certificate, a proposal or a recovery starts a new one): the old round's schedule sends nothing more
	oldRound := m.pacemaker.GetCurrentRound()
	m.pacemaker.Reset(ctx, oldRound, nil, nil)
	require.Greater(t, m.pacemaker.GetCurrentRound(), oldRound)
	epoch, round, held := m.heldTimeoutVote()
	m.retx.retire(epoch, round, held)
	require.False(t, m.retx.active)
	sent := len(timeoutSends(r))
	clk.add(10 * retxT)
	m.onRetransmitTimer(ctx)
	require.Len(t, timeoutSends(r), sent, "no old-round send after the transition")
}

// A state installation or restart is a new first send at the base interval, with the same recorded vote.
func TestRetxRestartsAfterRecoveryReset(t *testing.T) {
	r, clk, _ := retxReplica(t, 4)
	ctx := context.Background()
	m := r.manager
	m.onLocalTimeout(ctx)
	clk.add(retxT)
	m.onRetransmitTimer(ctx)
	clk.add(3 * retxT)
	m.onRetransmitTimer(ctx) // interval now 4T
	require.Equal(t, 4*retxT, m.retx.sched)
	first := timeoutSends(r)[0]

	round := m.pacemaker.GetCurrentRound()
	m.pacemaker.Reset(ctx, round-1, m.pacemaker.LastRoundTC(), nil) // as a recovery does: same round, no held vote
	epoch, rd, held := m.heldTimeoutVote()
	require.False(t, held)
	m.retx.retire(epoch, rd, held)
	require.False(t, m.retx.active)

	r.net.ResetSentMessages(network.ProtocolRootTimeout)
	clk.add(retxT)
	m.onLocalTimeout(ctx) // the ticker's next repeat finds no vote held: signs/recovers the recorded one and sends it as a first send
	again := timeoutSends(r)
	require.Len(t, again, len(m.Validators()))
	a, _ := types.Cbor.Marshal(first)
	b, _ := types.Cbor.Marshal(again[0])
	require.Equal(t, a, b, "the recorded vote, unchanged")
	require.Equal(t, 2, m.retx.c.firstSends)
	require.Equal(t, retxT, m.retx.sched, "back at the base interval")
}

// A timeout vote that cannot be stored is not sent and creates no schedule; the ticker's next repeat tries again, and the schedule starts at the
// first send that did go out.
func TestRetxNoScheduleUntilFirstSendStored(t *testing.T) {
	fail, writes := &atomic.Bool{}, &atomic.Int64{}
	mockNet := testnetwork.NewRootMockNetwork()
	cm, _, _ := initConsensusManagerOver(t, mockNet, func(db storage.BoltDB) PersistentStore {
		return voteFailStore{BoltDB: db, fail: fail, writes: writes}
	})
	ctx := context.Background()
	cm.pacemaker.Reset(ctx, cm.blockStore.GetHighQc().GetRound(), nil, nil)
	t.Cleanup(cm.pacemaker.Stop)
	clk := newFakeClock()
	cm.retx = newTimeoutRetx(retxT, 4, clk.now)

	fail.Store(true)
	cm.onLocalTimeout(ctx)
	require.Zero(t, sentTimeouts(mockNet), "not stored, not sent")
	require.False(t, cm.retx.active, "and nothing is scheduled")
	clk.add(retxT)
	cm.onRetransmitTimer(ctx)
	require.Zero(t, sentTimeouts(mockNet))

	fail.Store(false)
	cm.onLocalTimeout(ctx) // the ticker's next repeat: bounded retry intact
	require.NotZero(t, sentTimeouts(mockNet))
	require.True(t, cm.retx.active)
	require.Equal(t, clk.now().Add(retxT), cm.retx.next)
}
