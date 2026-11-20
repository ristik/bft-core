package vrrules

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/vrschema"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// scripted is a Source whose evidence and failure the test changes, counting reads.
type scripted struct {
	ev    Evidence
	fail  bool
	reads int
}

func (s *scripted) Read(context.Context) (Evidence, error) {
	s.reads++
	if s.fail {
		return Evidence{}, errors.New("rpc down")
	}
	return s.ev, nil
}

func TestGateFence(t *testing.T) {
	known, unk := vrschema.RuleID("known"), vrschema.RuleID("unknown")
	sched := []vrschema.Activation{
		{RuleID: unk, ReleaseDigest: vrschema.Word{1}, RootEpoch: 6, State: vrschema.ActSuperseded, ChangeID: 1},
		{RuleID: unk, ReleaseDigest: vrschema.Word{2}, RootEpoch: 9, State: vrschema.ActActive, ChangeID: 2},
		{RuleID: known, RootEpoch: 5, State: vrschema.ActLatched, ChangeID: 3},
	}
	g := NewGate(StaticSource{Entries: sched}, Set{known: "known"}, quiet())
	ctx := context.Background()
	require.NoError(t, g.Check(ctx, 8), "allowed before E; the superseded entry and the known rule never fence")
	for _, e := range []uint64{9, 10, 1000} {
		err := g.Check(ctx, e)
		require.ErrorIs(t, err, ErrUpgradeRequired, "refused at E and later")
		var u *UpgradeRequired
		require.True(t, errors.As(err, &u))
		require.Equal(t, vrschema.Word{2}, u.ReleaseDigest)
		require.EqualValues(t, 9, u.RootEpoch)
		require.Contains(t, err.Error(), "UpgradeRequired")
	}
	require.Len(t, g.Pending(), 1, "the warning state holds the entry before E")
}

// The test rule is known only in the default build profile: the expectation is explicit for each.
func TestGateTestRuleByBuildProfile(t *testing.T) {
	r := vrschema.RuleID(TestRuleName)
	g := NewGate(StaticSource{Entries: []vrschema.Activation{{RuleID: r, ReleaseDigest: vrschema.Word{4}, RootEpoch: 3, State: vrschema.ActActive, ChangeID: 1}}}, nil, quiet())
	err := g.Check(context.Background(), 50)
	if testRuleKnown {
		require.NoError(t, err)
		require.Empty(t, g.Pending())
	} else {
		require.ErrorIs(t, err, ErrUpgradeRequired)
		require.Len(t, g.Pending(), 1)
	}
}

func TestGateExplicitKnownRulePasses(t *testing.T) {
	r := vrschema.RuleID("any")
	g := NewGate(StaticSource{Entries: []vrschema.Activation{{RuleID: r, RootEpoch: 3, State: vrschema.ActActive, ChangeID: 1}}}, Set{r: "any"}, quiet())
	require.NoError(t, g.Check(context.Background(), 50))
}

func TestGateFailsClosedWithoutAdequateEvidence(t *testing.T) {
	ctx := context.Background()
	rule := vrschema.RuleID("new")
	src := &scripted{fail: true}
	g := NewGate(src, Set{}, quiet())
	require.Error(t, g.Check(ctx, 5), "no evidence at all")

	src.fail = false
	src.ev = Evidence{CoveredEpoch: 3, Schedule: []vrschema.Activation{{RuleID: rule, RootEpoch: 6, State: vrschema.ActActive, ChangeID: 1}}}
	// epoch 5 needs VR to know epoch 4: a state that knows 3 is behind, never passed
	err := g.Check(ctx, 5)
	require.ErrorIs(t, err, ErrNotCovered)
	require.NotErrorIs(t, err, ErrUpgradeRequired)
	// epoch 4 needs 3: covered, and E=6 is later
	require.NoError(t, g.Check(ctx, 4))

	// once VR caught up, the same retry decides: the new rule fences epoch 6, and the cached evidence serves lower epochs without a read
	src.ev.CoveredEpoch = 6
	require.ErrorIs(t, g.Check(ctx, 6), ErrUpgradeRequired)
	reads := src.reads
	src.fail = true
	require.ErrorIs(t, g.Check(ctx, 7), ErrUpgradeRequired, "evidence covering epoch 6 covers epoch 7")
	require.NoError(t, g.Check(ctx, 5), "an outage does not matter for an epoch the evidence covers")
	require.Error(t, g.Check(ctx, 9), "evidence that does not cover epoch 9 and a failing source: refuse")
	require.Equal(t, reads+1, src.reads, "only the uncovered epoch reads")
}

func TestGateReplayOfManyEpochsCostsOneRead(t *testing.T) {
	src := &scripted{ev: Evidence{CoveredEpoch: 100}}
	g := NewGate(src, Set{}, quiet())
	for e := uint64(1); e <= 101; e++ {
		require.NoError(t, g.Check(context.Background(), e))
	}
	require.Equal(t, 1, src.reads)
}

func TestGateRefusesEvidencePastVRBounds(t *testing.T) {
	g := NewGate(StaticSource{Entries: make([]vrschema.Activation, MaxActivations+1)}, Set{}, quiet())
	require.Error(t, g.Check(context.Background(), 3))
	g = NewGate(StaticSource{Pending: make([]PendingEntry, MaxPending+1)}, Set{}, quiet())
	require.Error(t, g.Poll(context.Background(), 1))
}

func TestPendingChangesWarnButNeverEnforce(t *testing.T) {
	rule := vrschema.RuleID("queued")
	src := StaticSource{Pending: []PendingEntry{{State: "Queued", Activation: vrschema.Activation{RuleID: rule, ReleaseDigest: vrschema.Word{5}, RootEpoch: 4}}}}
	g := NewGate(src, Set{}, quiet())
	require.NoError(t, g.Poll(context.Background(), 1))
	require.Len(t, g.Preview(), 1, "the Queued entry warns")
	require.Empty(t, g.Pending(), "and is not an effective entry")
	require.NoError(t, g.Check(context.Background(), 100), "enforcement stays on the committed schedule")
	// a supported rule warns nothing
	g = NewGate(src, Set{rule: "queued"}, quiet())
	require.NoError(t, g.Poll(context.Background(), 1))
	require.Empty(t, g.Preview())
}

func TestNoSourceIsNoFence(t *testing.T) {
	g := NewGate(nil, nil, quiet())
	require.Nil(t, g)
	require.NoError(t, g.Check(context.Background(), 1<<40))
	require.NoError(t, g.Poll(context.Background(), 1))
	require.Empty(t, g.Pending())
	require.Empty(t, g.Preview())
}

// Recovery from K to K+2 with VR still at K: the superseded primary at K+1 never gets its Boundary, so VR never knows epoch K+1. The
// authenticated checkpoint of the install decides, with no coverage to wait for; the endpoint (stale at K) is never asked.
func TestCheckpointDecidesAKToKPlus2Recovery(t *testing.T) {
	const k = 5
	stale := &scripted{ev: Evidence{CoveredEpoch: k}} // VR is still at K
	later := vrschema.RuleID("due-at-k2")
	entry := func(e uint64) []vrschema.Activation {
		return []vrschema.Activation{{RuleID: later, ReleaseDigest: vrschema.Word{8}, RootEpoch: e, State: vrschema.ActActive, ChangeID: 1}}
	}
	ctx := context.Background()

	// without the checkpoint the coverage rule would wait for epoch K+1: K+2 needs K+1
	g := NewGate(stale, Set{}, quiet())
	require.ErrorIs(t, g.Check(ctx, k+2), ErrNotCovered)
	stale.reads = 0

	// an empty schedule passes without stalling
	g = NewGate(stale, Set{}, quiet())
	require.NoError(t, g.CheckCheckpoint(k+2, nil))
	require.Zero(t, stale.reads)
	// a supported schedule passes
	g = NewGate(stale, Set{later: "due-at-k2"}, quiet())
	require.NoError(t, g.CheckCheckpoint(k+2, entry(k+2)))
	// an unknown rule due at K+2 is refused at K+2 (and later), allowed before
	g = NewGate(stale, Set{}, quiet())
	require.NoError(t, g.CheckCheckpoint(k+1, entry(k+2)), "K+1 is before E")
	require.ErrorIs(t, g.CheckCheckpoint(k+2, entry(k+2)), ErrUpgradeRequired)
	require.ErrorIs(t, g.CheckCheckpoint(k+3, entry(k+2)), ErrUpgradeRequired)
	// the checkpoint evidence of the install also serves the signer of that epoch without a read
	g = NewGate(stale, Set{}, quiet())
	require.NoError(t, g.CheckCheckpoint(k+2, nil))
	require.NoError(t, g.Check(ctx, k+2))
	require.Zero(t, stale.reads)
	require.Error(t, g.Check(ctx, k+4), "but not an epoch the checkpoint does not cover: the stale source is not enough")
}
