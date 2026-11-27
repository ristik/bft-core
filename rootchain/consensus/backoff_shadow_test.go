package consensus

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

const bt = 10 * time.Second

// From the first send at t0 the schedule allows attempts at t0+T, t0+3T, t0+7T, t0+11T, …; a real repeat every T is classified accordingly.
func TestBackoffShadowFollowsTheScheduleOfTheReview(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	b := newBackoffShadow(bt, 4, clk.now)
	b.attempt(7, false) // first send
	var allowed []int
	for n := 1; n <= 12; n++ {
		clk.t = clk.t.Add(bt)
		before := b.c.allowed
		b.attempt(7, true)
		if b.c.allowed > before {
			allowed = append(allowed, n)
		}
	}
	require.Equal(t, []int{1, 3, 7, 11}, allowed, "attempts at t0+T, t0+3T, t0+7T, t0+11T")
	require.Equal(t, 12, b.c.rebroadcasts)
	require.Equal(t, 8, b.c.suppressed)
	require.Equal(t, 1, b.c.firstSends)
}

func TestBackoffShadowCapFactorOneIsTheCurrentBehaviour(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	b := newBackoffShadow(bt, 1, clk.now)
	b.attempt(7, false)
	for n := 0; n < 8; n++ {
		clk.t = clk.t.Add(bt)
		b.attempt(7, true)
	}
	require.Equal(t, 8, b.c.allowed)
	require.Zero(t, b.c.suppressed)
}

// A newly registered signer resets the exponent and brings the next due attempt forward; it never postpones one that is due sooner.
func TestBackoffShadowResetBringsForwardAndNeverPostpones(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	b := newBackoffShadow(bt, 4, clk.now)
	b.attempt(7, false)
	clk.t = clk.t.Add(bt)
	b.attempt(7, true) // allowed at t0+T; next due t0+3T
	clk.t = clk.t.Add(bt / 2)
	b.registered(7) // at t0+1.5T: due moves to t0+2.5T
	require.Equal(t, 1, b.c.resetsApplied)
	clk.t = clk.t.Add(bt / 2) // t0+2T: still early
	b.attempt(7, true)
	require.Equal(t, 1, b.c.suppressed)
	clk.t = clk.t.Add(bt) // t0+3T: due
	b.attempt(7, true)
	require.Equal(t, 2, b.c.allowed)
	// a registration that would postpone: the next attempt is due at t0+3T+T (reset exponent), a registration now (due t0+4T) is not later than that
	before := b.rounds[7].next
	clk.t = clk.t.Add(bt / 4)
	b.registered(7)
	require.False(t, b.rounds[7].next.After(before), "never later than it was")
	require.Equal(t, 2, b.c.newSigners)
}

func TestBackoffShadowOtherRoundsAndNilAreInert(t *testing.T) {
	var nilModel *backoffShadow
	nilModel.attempt(1, true)
	nilModel.registered(1)
	clk := &fakeClock{t: time.Unix(1000, 0)}
	b := newBackoffShadow(bt, 4, clk.now)
	b.registered(9) // this node has not timed round 9 out
	require.Zero(t, b.c.newSigners)
	b.attempt(9, false)
	b.attempt(10, false) // a new round: its own schedule
	require.Equal(t, 2, b.c.firstSends)
	b.attempt(30, false)
	require.NotContains(t, b.rounds, uint64(9), "old rounds are dropped")
}
