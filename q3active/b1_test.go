package q3active_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
)

func TestB1RefusesIncompleteInterveningActivation(t *testing.T) {
	var absent *q3active.Runtime
	_, err := absent.B1History(0)
	require.ErrorIs(t, err, q3active.ErrHistory)
	_, err = new(q3active.Runtime).B1History(0)
	require.ErrorIs(t, err, q3active.ErrHistory)
	f := q3fixture.New(t, q3fixture.Options{})
	p := newProcess(t, f)
	rt := p.start()
	p.root.OnInstall = func(q3format.Entry) { _, err := rt.B1History(100); require.ErrorIs(t, err, q3active.ErrNotActive) }
	require.NoError(t, rt.Activate(ctx, p.bundle()))
	h, err := rt.B1History(100)
	require.NoError(t, err)
	require.EqualValues(t, 2, h.Tip().Epoch())
	// Later-tip knowledge cannot close the older origin's open epoch.
	h, err = rt.B1History(6)
	require.NoError(t, err)
	entries, err := h.B1Entries(6)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	restarted := p.start()
	_, err = restarted.B1History(100)
	require.ErrorIs(t, err, q3active.ErrNotActive)
	require.NoError(t, restarted.Recover(ctx))
	_, err = restarted.B1History(100)
	require.NoError(t, err)
}
