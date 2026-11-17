package consensus

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/vradmit"
)

// The residence rule waits ceil(T(L, v) * 1000 * (1 + rho)) ms of this root's own monotonic clock from the first time it held the committed
// opening of view v, for HandoffView(I, v+1) only; it never applies to another view, and a re-observed opening keeps its first time.
func TestResidenceRuleWaitsFromTheFirstObservedOpening(t *testing.T) {
	start := time.Now()
	r := newVRResidence(start)
	s := vradmit.GenesisRootState(1, 4)
	intent := [32]byte{7}
	want, ok := vradmit.ResidenceWaitMillis(0, 0, 4)
	require.True(t, ok)

	w, ok := r.wait(s, intent, 1, start.Add(time.Second))
	require.True(t, ok)
	require.Equal(t, want, w, "view 0 opened when this root first held the attempt's state, here at its first observation")
	w, ok = r.wait(s, intent, 1, start.Add(time.Second+time.Duration(want-1)*time.Millisecond))
	require.True(t, ok)
	require.EqualValues(t, 1, w)
	w, ok = r.wait(s, intent, 1, start.Add(time.Second+time.Duration(want)*time.Millisecond))
	require.True(t, ok)
	require.Zero(t, w, "eligible")
	_, ok = r.wait(s, intent, 2, start.Add(time.Hour))
	require.False(t, ok, "view 2 is not the successor of the committed view 0")

	// view 1 commits: its wait starts when this root first holds that commit
	s.Backoff.Intent, s.Backoff.LastView, s.OpenUCTime = intent[:], 1, 1_000
	later := start.Add(time.Minute)
	w, ok = r.wait(s, intent, 2, later)
	require.True(t, ok)
	want1, _ := vradmit.ResidenceWaitMillis(0, 1, 4)
	require.Equal(t, want1, w)
	_, ok = r.wait(s, [32]byte{8}, 2, later)
	require.False(t, ok, "another intent")
	// a restart re-learns: a fresh tracker starts the wait at its own observation
	r2 := newVRResidence(later.Add(time.Hour))
	w, _ = r2.wait(s, intent, 2, later.Add(time.Hour))
	require.Equal(t, want1, w)
}

// VR-mode planning is aligned with the cooldown: no attempt is plannable between the lapse and the end of the cooldown, where the pre-VR
// planner already plans the next one.
func TestPlannedAttemptIsCooldownAlignedInVRMode(t *testing.T) {
	prepared := &evmroot.ControlState{Network: 5, Epoch: 1, PredecessorBodyID: make([]byte, 32), Phase: "prepared", Attempt: 3, OrderedRound: 100}
	k, err := plannedAttempt(prepared, 130)
	require.NoError(t, err, "the pre-VR planner plans past the lapse")
	require.EqualValues(t, 4, k)

	vr, err := vradmit.GenesisRootState(1, 4).Encode()
	require.NoError(t, err)
	prepared.VR = vr
	_, err = plannedAttempt(prepared, 130)
	require.True(t, errors.Is(err, ErrHandoffApproval), "lapsed but cooling down: no next attempt")
	_, err = plannedAttempt(prepared, 148)
	require.ErrorIs(t, err, ErrHandoffApproval)
	k, err = plannedAttempt(prepared, 149)
	require.NoError(t, err)
	require.EqualValues(t, 4, k)
	idle := &evmroot.ControlState{Phase: "idle", VR: vr}
	k, err = plannedAttempt(idle, 1)
	require.NoError(t, err)
	require.Zero(t, k)
	aborted := &evmroot.ControlState{Phase: "aborted", Attempt: ^uint64(0), VR: vr}
	_, err = plannedAttempt(aborted, 1)
	require.ErrorIs(t, err, ErrHandoffApproval, "attempt exhaustion")
}
