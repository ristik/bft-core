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

type flaky struct {
	entries []vrschema.Activation
	fail    bool
}

func (f *flaky) Schedule(context.Context) ([]vrschema.Activation, error) {
	if f.fail {
		return nil, errors.New("rpc down")
	}
	return f.entries, nil
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

func TestGateKnownRulePasses(t *testing.T) {
	r := vrschema.RuleID(TestRuleName)
	g := NewGate(StaticSource{Entries: []vrschema.Activation{{RuleID: r, RootEpoch: 3, State: vrschema.ActActive, ChangeID: 1}}}, nil, quiet())
	require.NoError(t, g.Check(context.Background(), 50))
	require.Empty(t, g.Pending())
}

func TestGateSourceErrorFailsClosedUnlessEpochKnown(t *testing.T) {
	src := &flaky{}
	g := NewGate(src, Set{}, quiet())
	ctx := context.Background()
	require.NoError(t, g.Check(ctx, 4))
	src.fail = true
	require.NoError(t, g.Check(ctx, 4), "the schedule last read for this epoch stands")
	err := g.Check(ctx, 5)
	require.Error(t, err, "no schedule known for this epoch: refuse, never pass silently")
	require.NotErrorIs(t, err, ErrUpgradeRequired)
	src.fail = false
	require.NoError(t, g.Check(ctx, 5), "retry succeeds once the source is back")
}

func TestGateCachedFallbackStillFences(t *testing.T) {
	r := vrschema.RuleID("new-rule")
	src := &flaky{entries: []vrschema.Activation{{RuleID: r, RootEpoch: 4, State: vrschema.ActActive, ChangeID: 1}}}
	g := NewGate(src, Set{}, quiet())
	require.ErrorIs(t, g.Check(context.Background(), 7), ErrUpgradeRequired)
	src.fail = true
	require.ErrorIs(t, g.Check(context.Background(), 7), ErrUpgradeRequired)
}

func TestGateCacheIsBounded(t *testing.T) {
	g := NewGate(StaticSource{}, Set{}, quiet())
	for e := uint64(0); e < 3*MaxCachedEpochs; e++ {
		require.NoError(t, g.Check(context.Background(), e))
	}
	require.LessOrEqual(t, len(g.cache), MaxCachedEpochs)
}

func TestNoSourceIsNoFence(t *testing.T) {
	g := NewGate(nil, nil, quiet())
	require.Nil(t, g)
	require.NoError(t, g.Check(context.Background(), 1<<40))
	require.NoError(t, g.Poll(context.Background(), 1))
	require.Empty(t, g.Pending())
}
