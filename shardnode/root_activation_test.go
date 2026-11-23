package shardnode

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestVerifiedActivationCancelsWorkBeforeAdmittingSuccessor(t *testing.T) {
	old := RootActivation{Epoch: 5, BodyID: [32]byte{1}}
	next := RootActivation{Epoch: 6, BodyID: [32]byte{2}}
	g := NewRootActivationGate(old)
	work, end, err := g.work(t.Context(), old.Epoch)
	require.NoError(t, err)
	defer end()
	require.Equal(t, old, rootActivationOf(work))
	require.NoError(t, g.Begin(next))
	select {
	case <-work.Done():
		require.ErrorIs(t, context.Cause(work), ErrRootActivationSuperseded)
	case <-time.After(time.Second):
		t.Fatal("verified handoff did not cancel old work")
	}
	require.Equal(t, old, g.Current())
	require.ErrorIs(t, underRootActivation(work, func() error { t.Fatal("old work escaped"); return nil }), ErrRootActivationSuperseded)
	_, _, err = g.work(t.Context(), next.Epoch)
	require.ErrorIs(t, err, ErrRootActivationSuperseded)
	require.ErrorIs(t, g.Install(RootActivation{Epoch: next.Epoch, BodyID: [32]byte{3}}), ErrRootActivationSuperseded)
	require.NoError(t, g.Install(next))
	fresh, done, err := g.work(t.Context(), next.Epoch)
	require.NoError(t, err)
	defer done()
	require.Equal(t, next, rootActivationOf(fresh))
	require.NoError(t, underRootActivation(fresh, func() error { return nil }))
}

type activationBuildProbe struct {
	Executor
	built chan RoundParams
}

func (p activationBuildProbe) Build(_ context.Context, params RoundParams) (BuildID, error) {
	p.built <- params
	return "", ErrBuildUnavailable
}

func TestVerifiedActivationCancelsPacedLeaderAndFirstSuccessorBuildsImmediately(t *testing.T) {
	g := NewRootActivationGate(RootActivation{Epoch: 1})
	exec := activationBuildProbe{built: make(chan RoundParams, 1)}
	round := &Round{nodeID: "leader", executor: exec, pacer: blockPacer{from: time.Now(), interval: time.Hour}}
	old, done, err := g.work(t.Context(), 1)
	require.NoError(t, err)
	defer done()
	returned := make(chan error, 1)
	go func() {
		_, _, err := round.produceBlock(old, BlockRef{}, Expectation{}, nil, "leader", nil, nil, nil)
		returned <- err
	}()
	next := RootActivation{Epoch: 2, BodyID: [32]byte{1}}
	require.NoError(t, g.Begin(next))
	select {
	case err := <-returned:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("obsolete leader pacing did not stop")
	}
	require.Empty(t, exec.built)
	require.NoError(t, g.Install(next))
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	fresh, end, err := g.work(ctx, 2)
	require.NoError(t, err)
	defer end()
	_, _, err = round.produceBlock(fresh, BlockRef{}, Expectation{}, nil, "leader", nil, nil, nil)
	require.ErrorIs(t, err, ErrBuildUnavailable)
	require.Equal(t, next, (<-exec.built).Activation)
}
