package consensus

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

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
	require.False(t, v.memberStatus(false, w.Members[4].Root).Successor, "an incumbent that is no successor is not labelled one")
}

// The paired shard node is told the successor's EVM validators from the intent's derivation on, the latest set wins, a refused delivery is
// retried, and an intent that dies clears it: the shard node never keeps a staged peer an intent no longer names.
func TestThePairedShardNodeHoldsTheActiveIntentsSuccessor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var delivered [][]string
	fail := true
	v := &vrHandoff{cfg: VRHandoffConfig{Log: slog.New(slog.DiscardHandler)}, shardKick: make(chan struct{}, 1)}
	v.cfg.ShardStaged = func(_ context.Context, _, _ uint64, ids []string) error {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return errors.New("not yet")
		}
		delivered = append(delivered, ids)
		return nil
	}
	v.stageIntent = func(uint64, []evmassign.Identity, []evmroot.Member) error { return nil }
	go v.shardStagedRun(ctx)
	last := func() []string {
		mu.Lock()
		defer mu.Unlock()
		if len(delivered) == 0 {
			return []string{"none"}
		}
		return delivered[len(delivered)-1]
	}

	f := vrhandofffix.New(t)
	in, _ := f.Intent()
	c := vrschedule.Committed{Derived: vrschedule.Derived{VRIntent: storage.VRIntent{Digest: [32]byte{1}}, Intent: in, RootEpoch: 1}, Derivable: true}
	v.stagedMembers(c)
	var want []string
	for _, m := range f.J {
		want = append(want, m.EVMNodeID)
	}
	time.Sleep(200 * time.Millisecond)
	require.Equal(t, []string{"none"}, last(), "a refused delivery is not recorded")
	mu.Lock()
	fail = false
	mu.Unlock()
	require.Eventually(t, func() bool { return slices.Equal(last(), want) }, 12*time.Second, 50*time.Millisecond, "retried until the shard node takes it")

	v.stagedMembers(vrschedule.Committed{}) // the intent dies
	require.Eventually(t, func() bool { return len(last()) == 0 }, 12*time.Second, 50*time.Millisecond, "an intent that died clears the shard node's staged set")
}

// A set the candidate's installation wrote is owned like the intent-level one: when the intent-level install was refused and only the
// candidate's succeeded, the intent's end still clears it.
func TestACandidateInstalledSetIsClearedWithItsIntent(t *testing.T) {
	var cleared int
	v := &vrHandoff{}
	v.stageIntent = func(epoch uint64, _ []evmassign.Identity, _ []evmroot.Member) error {
		if epoch == 0 {
			cleared++
			return nil
		}
		return errors.New("refused")
	}
	var installed int
	v.installCandidate = func(vrschedule.Staged) error { installed++; return nil }
	x := &ConsensusManager{vr: v}
	d := [32]byte{9}
	v.stagedMembers(derivedFor(t, d)) // the intent-level installation is refused: nothing is recorded
	require.False(t, v.intentStaged)
	require.NoError(t, x.stageVRCandidate(vrschedule.Staged{Intent: d}))
	require.Equal(t, 1, installed)
	require.True(t, v.intentStaged, "the candidate's write is recorded")
	v.stagedMembers(vrschedule.Committed{}) // the intent dies
	require.Equal(t, 1, cleared, "the set the candidate wrote is cleared")
	require.False(t, v.intentStaged)
}

// Generation stamps stay monotonic across restarts and a backward clock adjustment: a restarted root continues above the persisted counter even
// when the wall clock is behind it, so its first clear is never below the shard's last accepted stamp.
func TestTheStagingStampSurvivesARestartAndABackwardClock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vr-shard-stamp")
	mk := func() *vrHandoff {
		v := &vrHandoff{cfg: VRHandoffConfig{ShardStampPath: path, Log: slog.New(slog.DiscardHandler)}, shardKick: make(chan struct{}, 1)}
		v.shardStamp = readStamp(path)
		return v
	}
	v := mk()
	v.setShardStaged(1, []string{"a"})
	first := v.shardStamp
	require.Equal(t, first, readStamp(path), "persisted with the change")

	// the previous run issued a stamp far ahead of this clock (the clock then went backward)
	ahead := uint64(time.Now().Add(time.Hour).UnixNano())
	require.NoError(t, writeStamp(path, ahead))
	v = mk()
	v.setShardStaged(0, nil) // the restart's first delivery: a clear
	require.Greater(t, v.shardStamp, ahead, "above everything an earlier run issued")
	v.setShardStaged(1, []string{"b"})
	require.Greater(t, v.shardStamp, ahead+1)
}
