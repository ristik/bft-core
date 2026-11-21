package storage_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/vrschema"
)

func schedulePayload(t *testing.T, rule string, epoch uint64) []byte {
	p, err := vrschema.EncodeChange(vrschema.KindScheduleActivation, vrschema.RuleID(rule), vrschema.Keccak([]byte("release")), epoch, uint64(10_000), "test")
	require.NoError(t, err)
	return p
}

// The activation schedule through the real executor (VT-07a, design section 7.1): an Accepted ScheduleActivation is staged by the Freeze,
// enters the committed root schedule when H commits (Active: its E is after the installed epoch), and the fold gives the next schedule
// of the rule its verdict from that committed schedule. A schedule past the cutoff (successor epoch 2 > E - 2) is Rejected and never staged.
func TestVRScheduleActivationIsStagedAtTheFreezeAndCommittedWithH(t *testing.T) {
	f := newVXFixture(t)
	f.extraChanges = append(f.extraChanges,
		vrschema.RegistryChange{ID: 5, Kind: uint64(vrschema.KindScheduleActivation), Payload: schedulePayload(t, "fork-a", 4), Verdict: uint64(vrschema.VerdictAccepted)},
		vrschema.RegistryChange{ID: 6, Kind: uint64(vrschema.KindScheduleActivation), Payload: schedulePayload(t, "fork-b", 3), Verdict: uint64(vrschema.VerdictPastCutoff)})
	f.build()
	g := f.genesis()
	require.Empty(t, rootState(t, g).Schedule)
	prep := f.must(g, f.block(g, 11, 1_010, [][]byte{f.record("prepare", 0, 11).Bytes()}))
	fz := f.must(prep, f.block(prep, 12, 1_020, [][]byte{f.record("freeze", 0, 12).Bytes(), f.freezeV5(0)}))
	s := rootState(t, fz)
	require.Empty(t, s.Schedule, "not committed before H")
	require.Len(t, s.StagedSchedule, 1, "only the Accepted change is staged")
	require.Equal(t, vrschema.RuleID("fork-a"), s.StagedSchedule[0].RuleID)
	require.EqualValues(t, 4, s.StagedSchedule[0].RootEpoch)
	require.EqualValues(t, 5, s.StagedSchedule[0].ChangeID)

	_, _, v5, _, ok := storage.VRRetainedForTest(fz)
	require.True(t, ok)
	f.candidates[string(s.StagedBody[:])] = v5
	commit := f.record("freeze", 0, 13)
	commit.Kind = "commit"
	tr, err := storage.ExpectedCommitTRForTest(f.candidates, commit, fz.ShardState.States[vxShard])
	require.NoError(t, err)
	commit.SuccessorTRHash = tr
	h := f.must(fz, f.block(fz, 13, 1_030, [][]byte{commit.Bytes()}))
	hs := rootState(t, h)
	require.Len(t, hs.Schedule, 1, "H commits the schedule")
	require.Equal(t, vrschema.ActActive, hs.Schedule[0].State, "E = 4 is after the installed epoch 2: not latched")
	require.EqualValues(t, 4, hs.Schedule[0].RootEpoch)

	// replay: the same blocks give the same state
	h2 := f.must(fz, f.block(fz, 13, 1_030, [][]byte{commit.Bytes()}))
	require.Equal(t, h.RootHash, h2.RootHash)
}
