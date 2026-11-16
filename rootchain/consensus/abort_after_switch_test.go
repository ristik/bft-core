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
	for name, tgt := range mismatched {
		_, err := m.HandoffAbortStatus(tgt)
		require.ErrorIs(t, err, ErrHandoffAbortTarget, name)
	}
}
