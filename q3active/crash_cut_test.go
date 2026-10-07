package q3active_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3install"
)

var errDoneWrite = errors.New("injected: the completion marker could not be written")

// failDone is the durable store whose only failing write is the journal's completion marker: the stage and every step marker are
// durable, the process then cannot finish.
type failDone struct{ keyvaluedb.KeyValueDB }

func (d failDone) Write(k []byte, v any) error {
	if bytes.HasSuffix(k, []byte("done")) {
		return errDoneWrite
	}
	return d.KeyValueDB.Write(k, v)
}

// TestNoActiveContextBeforeTheCompletionMarkerAndItsRecoveryAfterRestart is the crash cut after the snapshot step's marker and
// before the completion marker, with no marker or safety state erased: nothing is served while the journal is unfinished (the
// installer's provisional snapshot stays private), and a restart rebuilds the volatile snapshot and completes.
func TestNoActiveContextBeforeTheCompletionMarkerAndItsRecoveryAfterRestart(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	p := newProcess(t, f)

	rt, err := q3active.New(q3active.Config{DB: failDone{p.DB}, Genesis: f.Old})
	require.NoError(t, err)
	p.Attach(rt)
	require.ErrorIs(t, rt.Activate(ctx, p.bundle()), errDoneWrite)

	require.Nil(t, rt.Snapshot(), "the snapshot is not served although every step ran: the epoch is not complete")
	require.ErrorIs(t, rt.Admit(2), q3active.ErrNotActive)
	_, err = rt.Mode(2)
	require.ErrorIs(t, err, q3active.ErrNotActive)
	require.ErrorIs(t, rt.Gate(ctx, f.Claim), q3install.ErrIncomplete)

	// the process restarts over the same durable state; the volatile snapshot is gone
	rt2 := p.start()
	require.Nil(t, rt2.Snapshot(), "nothing is published before recovery")
	require.ErrorIs(t, rt2.Admit(2), q3active.ErrNotActive)
	require.NoError(t, rt2.Recover(ctx), "the marked snapshot step is rebuilt, not reported as unpublished")

	s := rt2.Snapshot()
	require.NotNil(t, s)
	require.EqualValues(t, 2, s.Epoch())
	require.EqualValues(t, 9, s.Total())
	require.EqualValues(t, 7, s.Threshold())
	require.NoError(t, rt2.Admit(2))
	require.NoError(t, rt2.Gate(ctx, f.Claim))
	require.Equal(t, 1, p.root.Installs, "the finished root step is not installed again")
}
