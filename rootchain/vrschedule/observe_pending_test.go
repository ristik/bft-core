package vrschedule

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
)

func TestPendingSchedulesOfAnOutput(t *testing.T) {
	require.Nil(t, PendingSchedules(nil))
	p, err := vrschema.EncodeChange(vrschema.KindScheduleActivation, vrschema.RuleID("r"), vrschema.Word{1}, uint64(9), uint64(100), "l")
	require.NoError(t, err)
	out := &vrhandoff.Output{Changes: []vrschema.RegistryChange{
		{ID: 1, Kind: uint64(vrschema.KindCommitteeLimits)}, {ID: 2, Kind: uint64(vrschema.KindScheduleActivation), Payload: p}}}
	got := PendingSchedules(out)
	require.Len(t, got, 1)
	require.Equal(t, vrschema.RuleID("r"), got[0].RuleID)
	require.EqualValues(t, 9, got[0].RootEpoch)
	require.EqualValues(t, 2, got[0].ChangeID)
}
