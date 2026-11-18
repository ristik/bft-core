package consensus

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/vrhandofffix"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/vrschedule"
)

// The staged successor is written only for the intent that is active: a callback of a candidate whose intent was cleared or replaced cannot
// restore the cleared set or replace another intent's (and the intent worker caches a staging only once it is installed).
func TestAStagingWriteIsTiedToTheActiveIntent(t *testing.T) {
	var installed []uint64
	var failNext bool
	v := &vrHandoff{}
	v.stageIntent = func(epoch uint64, _ []evmassign.Identity, _ []evmroot.Member) error {
		if failNext && epoch != 0 {
			return errors.New("refused")
		}
		installed = append(installed, epoch)
		return nil
	}
	x := &ConsensusManager{vr: v}

	// a candidate of an intent that was never active, or whose intent was cleared, is refused before anything is written
	old := [32]byte{1}
	require.ErrorIs(t, x.stageVRCandidate(vrschedule.Staged{Intent: old}), ErrVRHandoff)
	require.Empty(t, installed)

	// the intent worker marks an intent active and stages it; the candidate of that intent passes the guard (it then needs a Q3 history, which
	// this manager lacks: the refusal that follows is the next check, not the guard)
	c := derivedFor(t, old)
	v.stagedMembers(c)
	require.Equal(t, []uint64{c.Derived.RootEpoch + 1}, installed)
	err := x.stageVRCandidate(vrschedule.Staged{Intent: old})
	require.ErrorContains(t, err, "no Q3 history")

	// the intent dies: the set is cleared, and the late callback of its candidate cannot write it again
	v.stagedMembers(vrschedule.Committed{})
	require.Equal(t, []uint64{c.Derived.RootEpoch + 1, 0}, installed)
	err = x.stageVRCandidate(vrschedule.Staged{Intent: old})
	require.ErrorContains(t, err, "no longer the active one")

	// another intent replaces it: the first one's candidate is refused, the second one's is not
	other := [32]byte{2}
	v.stagedMembers(derivedFor(t, other))
	require.ErrorContains(t, x.stageVRCandidate(vrschedule.Staged{Intent: old}), "no longer the active one")
	require.ErrorContains(t, x.stageVRCandidate(vrschedule.Staged{Intent: other}), "no Q3 history")

	// a refused installation is not cached: the next refresh tries again
	v.stagedMembers(vrschedule.Committed{})
	installed, failNext = nil, true
	third := derivedFor(t, [32]byte{3})
	v.stagedMembers(third)
	require.Empty(t, installed)
	failNext = false
	v.stagedMembers(third)
	require.Equal(t, []uint64{third.Derived.RootEpoch + 1}, installed)
}

func derivedFor(t *testing.T, digest [32]byte) vrschedule.Committed {
	t.Helper()
	in, _ := vrhandofffix.New(t).Intent()
	return vrschedule.Committed{Derived: vrschedule.Derived{VRIntent: storage.VRIntent{Digest: digest}, Intent: in, RootEpoch: 1}, Derivable: true}
}

// A node reports "catching up" while an input it needs is missing and derives nothing: the root chain being recovered, VR unreadable through
// its own execution client, the open result's source never observed; "ready" only once it derives the intent itself.
func TestTheMemberReportsCatchingUpUntilItDerivesTheIntent(t *testing.T) {
	w := vrhandofffix.New(t)
	in, d := w.Intent()
	keys, _ := w.Incumbents()
	svc := vrschedule.NewService(vrschedule.ServiceConfig{Self: "x"})
	v := &vrHandoff{svc: svc}
	require.Equal(t, "idle", v.memberStatus(false, "x").State)

	st := v.memberStatus(true, "x")
	require.Equal(t, "catching up", st.State)
	require.Contains(t, st.Reasons[0], "recovered from peers")

	v.observeErr = 3
	st = v.memberStatus(false, "x")
	require.Equal(t, "catching up", st.State)
	require.Contains(t, st.Reasons[0], "EVM chain is not synced")
	v.observeErr = 0

	v.noteDerive(vrschedule.ErrUnavailable)
	st = v.memberStatus(false, "x")
	require.Equal(t, "catching up", st.State)
	require.Contains(t, st.Reasons[0], "intent input not observed yet")
	v.noteDerive(nil)

	svc.Update(vrschedule.Committed{Derived: vrschedule.Derived{VRIntent: storage.VRIntent{Digest: d}, Intent: in, RootEpoch: w.RC.RootEpoch, Body: w.BC},
		Derivable: true, Incumbents: keys, K: w.K})
	st = v.memberStatus(false, w.J[0].RootNodeID)
	require.Equal(t, "ready", st.State)
	require.True(t, st.Successor)
	require.False(t, v.memberStatus(false, "someone-else").Successor)
}
