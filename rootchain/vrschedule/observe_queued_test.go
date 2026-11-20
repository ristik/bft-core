package vrschedule

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
)

type queuedFake struct{ queued []vrschema.Activation }

func (queuedFake) OpenOutput(context.Context, [32]byte, [32]byte) (*vrhandoff.Output, error) {
	return nil, nil // VR has no open output
}
func (f queuedFake) QueuedSchedules(context.Context, uint64) ([]vrschema.Activation, error) {
	return f.queued, nil
}

// Through the real observer path: with NO open output at all, a ScheduleActivation change VR still holds Queued is reported to the
// warning (design section 7.4, astra r3 item 3), and keeps being reported with every later observation until the next read says otherwise.
func TestObserverReportsAQueuedChangeWithNoOpenOutput(t *testing.T) {
	queued := vrschema.Activation{RuleID: vrschema.RuleID("unknown"), ReleaseDigest: vrschema.Word{1}, RootEpoch: 12, State: vrschema.ActActive, ChangeID: 3}
	var got [][]vrschema.Activation
	o := &Observer{Reader: queuedFake{queued: []vrschema.Activation{queued}}, Outputs: NewOutputs(), SyncQueued: true,
		OnPending: func(a []vrschema.Activation) { got = append(got, a) }}
	require.NoError(t, o.Observe(context.Background(), CertifiedEVM{BlockNumber: 7, StateRoot: [32]byte{1}, RootRound: 1}))
	require.NotEmpty(t, got)
	require.Equal(t, []vrschema.Activation{queued}, got[len(got)-1], "the queued change is reported although no output is open")
	// the next observed block (within QueuedEvery, so no new read) still carries it
	require.NoError(t, o.Observe(context.Background(), CertifiedEVM{BlockNumber: 8, StateRoot: [32]byte{2}, RootRound: 2, ParentRound: 1}))
	require.Equal(t, []vrschema.Activation{queued}, got[len(got)-1])
}
