package consensus

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A recovery triggered by a bare QC (one whose block this node does not hold) must target the block the QC certifies, not its parent: a response which
// ends at the parent is not suitable, so it is refused before anything is installed, instead of being staged, installed and then failing the trigger QC
// again. The node stays in recovery for the response which does carry the certified block, and that single response completes it.
func Test_Followup_BareQCRecoveryTargetsTheCertifiedBlock(t *testing.T) {
	f := newFollowup(t, 3, nil)
	cm := f.cm
	require.EqualValues(t, 4, f.qc4.GetRound())
	require.EqualValues(t, 2, f.qc4.GetParentRound()) // round 3 timed out: the QC extends round 2
	before := cm.blockStore.GetHighQc().GetRound()

	// the bare QC: the node holds no block for round 4, so the QC is not accepted and recovery is requested
	err := cm.processQC(f.ctx, clone(t, f.qc4))
	require.Error(t, err)
	require.True(t, cm.recovery.InRecovery())
	require.EqualValues(t, f.qc4.GetRound(), cm.recovery.ToRound(), "the target is the block the QC certifies, not its parent")

	// a response which ends at the QC's parent
	short := clone(t, f.state)
	require.EqualValues(t, 4, short.Pending[len(short.Pending)-1].Round)
	short.Pending = short.Pending[:len(short.Pending)-1]
	err = cm.onStateResponse(f.ctx, short)
	require.ErrorContains(t, err, "not suitable for recovery")
	require.EqualValues(t, before, cm.blockStore.GetHighQc().GetRound(), "nothing was installed")
	require.True(t, cm.recovery.InRecovery(), "the node waits for a response which carries the certified block")

	// the full response completes the recovery, the trigger QC included
	require.NoError(t, cm.onStateResponse(f.ctx, f.state))
	require.False(t, cm.recovery.InRecovery())
	_, err = cm.blockStore.Block(4)
	require.NoError(t, err)
	require.GreaterOrEqual(t, cm.blockStore.GetHighQc().GetRound(), uint64(4))
}
