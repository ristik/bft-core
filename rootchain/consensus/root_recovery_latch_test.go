package consensus

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// latchProbe is a restarted root with a frontier sampler, to read whether recovery latched its fault.
func latchProbe(t *testing.T, c *anchorCluster) *ConsensusManager {
	t.Helper()
	root := restartedRoot(t, firstReplica(c.replicas))
	root.frontier = &frontierSampler{}
	return root
}

// stateWithHeadCommitQc is the cluster's state with another QC as the committed head's commit QC. Every QC is a genuine, quorum-signed one of the
// cluster, so verification has nothing to object to but the epoch rule.
func stateWithHeadCommitQc(state *abdrc.StateMsg, qc *rctypes.QuorumCert) *abdrc.StateMsg {
	bad := *state
	head := *state.CommittedHead
	head.CommitQc = qc
	bad.CommittedHead = &head
	return &bad
}

// A recovery state that is refused before anything is written must not latch the frontier fault: the store is untouched, so there is nothing to be
// uncertain about, and a latch is only cleared by restarting the process (it disables the root's frontier replies for good).
func TestRecoveryRefusedBeforeAnyWriteDoesNotLatchTheFrontierFault(t *testing.T) {
	c := newAnchorCluster(t)
	state := c.pastTheFirstSuccessor()
	valid := latchProbe(t, c)
	require.NoError(t, recoverTo(t, valid, state))
	require.False(t, valid.frontier.faulted.Load(), "control: a valid state recovers without a fault")

	// The control checkpoint names another network than the root's. Verification does not compare it (it holds the network only to be non-zero);
	// NewRootBlock does, when the root builds the head, before the first write.
	root := latchProbe(t, c)
	before := root.blockStore.RootAnchor()
	bad := *state
	head := *state.CommittedHead
	control := *head.Control
	control.Network++
	head.Control = &control
	bad.CommittedHead = &head
	err := recoverTo(t, root, &bad)
	require.ErrorIs(t, err, storage.ErrNetworkProfile, "premise: the refusal is NewRootBlock's")
	require.ErrorIs(t, err, storage.ErrRefusedBeforeWrite)
	require.False(t, root.frontier.faulted.Load(), "a refusal before the first write does not latch")
	require.Equal(t, before, root.blockStore.RootAnchor(), "and the root's anchor is unchanged")
}

// A failure after the first write still latches: the store may hold part of the state.
func TestRecoveryFailingAfterTheFirstWriteStillLatchesTheFrontierFault(t *testing.T) {
	c := newAnchorCluster(t)
	state := c.pastTheFirstSuccessor()

	// A pending block whose QC names a round the new store does not hold: genuine and in the epoch, so it verifies; adding it fails after the head
	// has been written.
	bad := *state
	bad.Pending = append([]*rctypes.BlockData(nil), state.Pending...)
	first := *bad.Pending[0]
	first.Qc = state.CommittedHead.Block.Qc
	bad.Pending[0] = &first

	root := latchProbe(t, c)
	err := recoverTo(t, root, &bad)
	require.Error(t, err)
	require.False(t, errors.Is(err, storage.ErrRefusedBeforeWrite), "premise: the failure is after the first write: %v", err)
	require.True(t, root.frontier.faulted.Load(), "a failure after the first write latches")
	require.False(t, root.frontier.eligible.Load())
}

// The head's commit QC commits the head, so a QC that commits nothing is never valid there. It used to be refused by the epoch rule; since the
// empty seal was admitted (#366) it passed verification and was found only when the head was built. The typed refusal is back, at verification.
func TestRecoveryRefusesAnEmptySealAsTheHeadsCommitQc(t *testing.T) {
	c := newAnchorCluster(t)
	state := c.pastTheFirstSuccessor()
	empty := state.CommittedHead.Block.Qc
	require.True(t, commitsNothing(empty), "premise: the head block's own QC commits nothing")

	root := latchProbe(t, c)
	before := root.blockStore.RootAnchor()
	err := recoverTo(t, root, stateWithHeadCommitQc(state, empty))
	require.ErrorIs(t, err, abdrc.ErrRecoveryEpoch)
	require.False(t, root.frontier.faulted.Load(), "refused at verification, before recovery touches anything")
	require.True(t, root.recovery.InRecovery(), "a refused state leaves the root in recovery")
	require.Equal(t, before, root.blockStore.RootAnchor())
}
