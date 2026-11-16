package consensus

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
)

// An operator Abort of a handoff that is committed is too late, before and after the root activated it: a root that switched into the successor in
// process (#1095) answers it exactly as a root whose committed head still holds the commit (State too_late, the record's identity), while a target that
// is not the activated handoff (another attempt, another successor body, another epoch) is still refused as not matching (ErrHandoffAbortTarget).
func TestAbortAfterTheInProcessSwitchIsTooLate(t *testing.T) {
	c := switchCluster(t, q3fixture.Options{})
	f, m := c.f, c.replicas[0].manager
	rec := f.Proof.Record
	target := abdrc.HandoffAbortTarget{Network: rec.Network, OldEpoch: rec.Epoch, PredecessorBodyID: bytes.Clone(rec.PredecessorBodyID),
		Attempt: rec.Attempt, NextBodyID: bytes.Clone(rec.NextBodyID)}

	before, err := m.HandoffAbortStatus(target)
	require.NoError(t, err, "at the commit, in the old epoch")
	require.Equal(t, "too_late", before.State)

	for i := range c.replicas {
		c.start(i)
	}
	awaitSuccessorCommit(t, c, time.Now(), LocalTimeout*time.Millisecond)
	require.EqualValues(t, 2, m.SwitchState().Target, "switched in process")
	_, _, err = m.handoffAbortStatusAtHead(target)
	require.ErrorIs(t, err, ErrHandoffAbortTarget, "the committed head is a successor block: its control state is not the target's any more")

	after, err := m.HandoffAbortStatus(target)
	require.NoError(t, err, "after the in-process switch and the successor's first commits")
	require.Equal(t, "too_late", after.State)
	require.Equal(t, fmt.Sprintf("0x%x", rec.ID()), after.RecordID)
	require.Equal(t, before.RecordID, after.RecordID)
	require.Equal(t, before.OrderedRound, after.OrderedRound)
	_, err = m.SubmitHandoffAbort(t.Context(), target)
	require.ErrorIs(t, err, ErrHandoffAbortTarget, "submitting it is refused as before; the operator reads the status, which says too late")

	mismatched := map[string]abdrc.HandoffAbortTarget{}
	other := target
	other.Attempt++
	mismatched["another attempt"] = other
	other = target
	other.NextBodyID = bytes.Repeat([]byte{0x5a}, 32)
	mismatched["another successor body"] = other
	other = target
	other.OldEpoch = 2
	mismatched["the installed epoch, which has no handoff"] = other
	other = target
	other.Network++
	mismatched["another network"] = other
	other = target
	other.PredecessorBodyID = bytes.Repeat([]byte{0x6b}, 32)
	mismatched["another predecessor"] = other
	other = target
	other.OldEpoch = 3
	mismatched["a future epoch"] = other
	other = target
	other.OldEpoch = ^uint64(0)
	mismatched["the largest epoch (no successor)"] = other
	other = target
	other.OldEpoch = 0
	mismatched["epoch zero"] = other
	for name, tgt := range mismatched {
		_, err := m.HandoffAbortStatus(tgt)
		require.ErrorIs(t, err, ErrHandoffAbortTarget, name)
	}

	// a root restarted after the successor committed: a new manager over its stores, whose committed head is a successor block
	c.restart(1)
	restarted := c.replicas[1].manager
	_, _, err = restarted.handoffAbortStatusAtHead(target)
	require.ErrorIs(t, err, ErrHandoffAbortTarget, "the restarted root's committed head is a successor block")
	again, err := restarted.HandoffAbortStatus(target)
	require.NoError(t, err, "restarted")
	require.Equal(t, "too_late", again.State)
	require.Equal(t, before.RecordID, again.RecordID)
	require.Equal(t, before.OrderedRound, again.OrderedRound)
	for name, tgt := range mismatched {
		_, err := restarted.HandoffAbortStatus(tgt)
		require.ErrorIs(t, err, ErrHandoffAbortTarget, "restarted: "+name)
	}

	// without the verified Q3 history there is no authenticated activation to answer from: the head's refusal stands
	c.stopAll()
	authority := m.q3
	m.q3 = nil
	_, err = m.HandoffAbortStatus(target)
	m.q3 = authority
	require.ErrorIs(t, err, ErrHandoffAbortTarget, "no Q3 authority")
}
