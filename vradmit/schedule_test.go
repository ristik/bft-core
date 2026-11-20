package vradmit

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/vrschema"
)

func schedChange(t *testing.T, id uint64, rule string, release byte, epoch uint64) vrschema.RegistryChange {
	p, err := vrschema.EncodeChange(vrschema.KindScheduleActivation, vrschema.RuleID(rule), vrschema.Word{release}, epoch, uint64(5000), "x")
	require.NoError(t, err)
	return vrschema.RegistryChange{ID: id, Kind: uint64(vrschema.KindScheduleActivation), Payload: p}
}

// The root-history transitions of the activation schedule (design section 7.1): staged at the Freeze, committed at H, a postponement
// supersedes, the latch at the commit into E is permanent and survives the encoding, a recovery's second commit changes nothing, and the
// state round-trips canonically.
func TestRootScheduleStageCommitPostponeLatch(t *testing.T) {
	a := vrschema.RuleID("a")
	s := GenesisRootState(1, 4)
	s, err := s.StageSchedule([]vrschema.RegistryChange{schedChange(t, 1, "a", 1, 9), schedChange(t, 2, "b", 1, 9)}, []uint8{vrschema.VerdictAccepted, vrschema.VerdictPastCutoff})
	require.NoError(t, err)
	require.Len(t, s.StagedSchedule, 1, "only the Accepted entry")
	_, err = s.StageSchedule(nil, []uint8{1})
	require.Error(t, err)
	s.StagedBody, s.StagedResult = [32]byte{1}, vrschema.Word{1}
	raw, err := s.Encode()
	require.NoError(t, err)
	back, err := DecodeRootState(raw)
	require.NoError(t, err)
	require.Equal(t, s.StagedSchedule, back.StagedSchedule)

	s, err = s.CommitSchedule(2) // H into epoch 2
	require.NoError(t, err)
	require.Len(t, s.Schedule, 1)
	require.Equal(t, vrschema.ActActive, s.Schedule[0].State)
	again, err := s.CommitSchedule(2) // the recovery's second commit of the same result
	require.NoError(t, err)
	require.Equal(t, s.Schedule, again.Schedule, "idempotent by change id")

	// a postponement supersedes the effective entry
	s.StagedSchedule = nil
	s, err = s.StageSchedule([]vrschema.RegistryChange{schedChange(t, 7, "a", 2, 12)}, []uint8{vrschema.VerdictAccepted})
	require.NoError(t, err)
	s, err = s.CommitSchedule(5)
	require.NoError(t, err)
	eff := vrschema.Effective(s.Schedule)
	require.EqualValues(t, 12, eff[a].RootEpoch)
	require.Equal(t, vrschema.ActSuperseded, s.Schedule[0].State)

	// the commit into an epoch >= E latches, permanently; afterwards a postponement is refused by the fold
	s.StagedSchedule = nil
	s, err = s.CommitSchedule(12)
	require.NoError(t, err)
	require.Equal(t, vrschema.ActLatched, vrschema.Effective(s.Schedule)[a].State)
	require.Equal(t, vrschema.VerdictLatched, vrschema.ScheduleVerdict(vrschema.Schedule{RuleID: a, RootEpoch: 30}, 13, vrschema.Effective(s.Schedule)))
	raw, err = s.Encode()
	require.NoError(t, err)
	back, err = DecodeRootState(raw)
	require.NoError(t, err)
	require.Equal(t, s.Schedule, back.Schedule)

	// a staged schedule without a staged body is not a state
	bad := GenesisRootState(1, 4)
	bad.StagedSchedule = []vrschema.Activation{{RuleID: a, RootEpoch: 9, State: vrschema.ActActive, ChangeID: 1}}
	_, err = bad.Encode()
	require.ErrorIs(t, err, ErrRootState)
}
