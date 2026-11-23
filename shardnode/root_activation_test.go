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
