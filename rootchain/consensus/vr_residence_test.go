package consensus

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/vradmit"
)

// opening is a committed VR opening: the backoff at (1, 0) with lastView views of intent bound, at committed round, and the intent
// derivable over it with its anchor round.
func opening(intent [32]byte, lastView, committed, anchor uint64, derivable bool) storage.VROpening {
	s := vradmit.GenesisRootState(1, 4)
	if lastView != 0 {
		s.Backoff.Intent, s.Backoff.LastView, s.OpenUCTime = intent[:], lastView, 1_000
	}
	return storage.VROpening{State: s, CommittedRound: committed, Intent: storage.VRIntent{Digest: intent, AnchorRound: anchor}, IntentOK: derivable}
}

// The residence rule waits ceil(T(L, v) * 1000 * (1 + rho)) ms of this root's own monotonic clock from the first time it held the
// committed opening of view v, for HandoffView(I, v+1) of the same intent only; a re-observed opening keeps its first time.
func TestResidenceRuleWaitsFromTheFirstHeldOpening(t *testing.T) {
	start := time.Now()
	r := newVRResidence(start)
	intent := [32]byte{7}
	want, ok := vradmit.ResidenceWaitMillis(0, 0, 4)
	require.True(t, ok)

	o := opening(intent, 0, 20, 20, true) // the anchor block is committed
	r.observe(o, start)
	w, held, ok := r.wait(o, intent, 1, start.Add(time.Second))
	require.True(t, ok)
	require.True(t, held)
	require.Equal(t, want-1_000, w, "the wait runs from the first held opening, not from the proposal")
	w, _, _ = r.wait(o, intent, 1, start.Add(time.Duration(want)*time.Millisecond))
	require.Zero(t, w, "eligible")
	_, _, ok = r.wait(o, intent, 2, start.Add(time.Hour))
	require.False(t, ok, "view 2 is not the successor of the committed view 0")

	// view 1 commits: its wait starts when this root first holds that commit
	o1 := opening(intent, 1, 30, 20, false)
	later := start.Add(time.Minute)
	r.observe(o1, later)
	want1, _ := vradmit.ResidenceWaitMillis(0, 1, 4)
	w, held, ok = r.wait(o1, intent, 2, later.Add(time.Second))
	require.True(t, ok && held)
	require.Equal(t, want1-1_000, w)
	_, _, ok = r.wait(o1, [32]byte{8}, 2, later)
	require.False(t, ok, "another intent")
	// a restart re-learns: a fresh tracker starts the wait at its own observation
	r2 := newVRResidence(later.Add(time.Hour))
	w, _, _ = r2.wait(o1, intent, 2, later.Add(time.Hour))
	require.Equal(t, want1, w)
}

// #1177 review (astra 2): view 0's opening is the commit of the derived intent's anchor block. Before that commit is held nothing is eligible
// (the wait is never spent on the older, unbound committed attempt), and time held for one intent's anchor is never another intent's.
func TestResidenceViewZeroIsBoundToTheDerivedIntentsAnchorCommit(t *testing.T) {
	start := time.Now()
	r := newVRResidence(start)
	a, b := [32]byte{0xa}, [32]byte{0xb}
	want, _ := vradmit.ResidenceWaitMillis(0, 0, 4)

	early := opening(a, 0, 19, 20, true) // the anchor (round 20) is not committed yet
	r.observe(early, start)
	_, held, ok := r.wait(early, a, 1, start.Add(time.Hour))
	require.True(t, ok)
	require.False(t, held, "no eligibility before the anchor commit is held, however long the attempt has been open")
	notDerivable := opening(a, 0, 40, 20, false)
	_, held, _ = r.wait(notDerivable, a, 1, start.Add(time.Hour))
	require.False(t, held, "no derivable intent: no held opening")

	anchored := opening(a, 0, 20, 20, true)
	at := start.Add(2 * time.Hour)
	r.observe(anchored, at)
	w, held, ok := r.wait(anchored, a, 1, at.Add(time.Duration(want)*time.Millisecond))
	require.True(t, ok && held)
	require.Zero(t, w)
	_, _, ok = r.wait(anchored, b, 1, at.Add(time.Duration(want)*time.Millisecond))
	require.False(t, ok, "the held opening is A's anchor: another intent's view 1 is not eligible on it")

	// another attempt's anchor is another opening
	next := anchored
	next.State.Backoff.Attempt = 1
	r.observe(next, at.Add(time.Hour))
	w, _, _ = r.wait(next, a, 1, at.Add(time.Hour))
	require.Equal(t, want, w)
}

// #1177 review (sol): a root that has held the opening commit longer than the residence period votes at once when the next view's proposal
// arrives: the opening is observed when the commit is learned, not when the proposal arrives.
func TestResidenceAnAlreadyMatureCommitDoesNotRestartTheWait(t *testing.T) {
	x := newPlanFixture(t).cm
	head, err := x.blockStore().Block(x.blockStore().GetHighQc().GetRound())
	require.NoError(t, err)
	intent := [32]byte{7}
	s := vradmit.GenesisRootState(1, 4)
	s.Backoff.Intent, s.Backoff.LastView, s.OpenUCTime = intent[:], 1, 1_000
	raw, err := s.Encode()
	require.NoError(t, err)
	head.ShardState.Control.VR = raw

	now := time.Now()
	x.residence = &vrResidence{base: now, clock: func() time.Time { return now }}
	x.observeVR() // the commit is learned
	wait, ok := vradmit.ResidenceWaitMillis(0, 1, 4)
	require.True(t, ok)
	now = now.Add(time.Duration(wait+50) * time.Millisecond)
	block := &rctypes.BlockData{Epoch: 1, Round: 2, Payload: &rctypes.Payload{PosControls: []rctypes.PosControl{{Registry: true, Op: rctypes.OpHandoffView,
		View: &rctypes.ViewContext{IntentDigest: intent, View: 2}}}}}
	deferred, err := x.residenceDefers(block, nil)
	if x.deferred != nil {
		defer x.deferred.timer.Stop()
	}
	require.NoError(t, err)
	require.False(t, deferred, "the opening commit was already held longer than the residence period")

	// not yet mature: deferred for exactly the remainder
	x.residence = &vrResidence{base: now, clock: func() time.Time { return now }}
	x.observeVR()
	now = now.Add(time.Second)
	deferred, err = x.residenceDefers(block, nil)
	require.NoError(t, err)
	require.True(t, deferred)
	require.NotNil(t, x.deferred)
	x.deferred.timer.Stop()
}

// The deferred-vote lifecycle (sol's review checks): a stale round and an already voted round are dropped, a replacement stops the earlier
// timer, and an epoch reset stops the timer and forgets the tracker.
func TestResidenceDeferredVoteLifecycle(t *testing.T) {
	x := &ConsensusManager{pacemaker: &Pacemaker{}}
	x.pacemaker.currentRound.Store(10)
	x.deferred = &deferredVote{block: &rctypes.BlockData{Round: 9}}
	x.voteDeferred(context.Background())
	require.Nil(t, x.deferred, "stale round")

	x = &ConsensusManager{pacemaker: &Pacemaker{voteSent: &abdrc.VoteMsg{}}}
	x.pacemaker.currentRound.Store(10)
	x.deferred = &deferredVote{block: &rctypes.BlockData{Round: 10}}
	x.voteDeferred(context.Background())
	require.Nil(t, x.deferred, "already voted")

	x = &ConsensusManager{deferredReady: make(chan struct{}, 1)}
	x.deferVote(&rctypes.BlockData{Round: 9}, nil, 100)
	x.deferVote(&rctypes.BlockData{Round: 10}, nil, 500)
	select {
	case <-x.deferredReady:
		t.Fatal("the replaced timer fired")
	case <-time.After(200 * time.Millisecond):
	}
	select {
	case <-x.deferredReady:
	case <-time.After(time.Second):
		t.Fatal("the replacement never fired")
	}

	m, _, _ := initConsensusManager(t, testnetwork.NewRootMockNetwork())
	m.residence = newVRResidence(time.Now())
	m.deferVote(&rctypes.BlockData{Round: 10}, nil, 100)
	m.resetVolatile()
	require.Nil(t, m.deferred)
	require.Nil(t, m.residence)
	select {
	case <-m.deferredReady:
		t.Fatal("the timer survived the epoch reset")
	case <-time.After(200 * time.Millisecond):
	}
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
