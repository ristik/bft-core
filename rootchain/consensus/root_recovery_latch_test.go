package consensus

import (
	"context"
	"crypto"
	"errors"
	"github.com/unicitynetwork/bft-core/rootrecords"
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

// failPendingWrites is a store that writes the head of a recovery and fails the next block it is asked to write: the failure comes after the first
// write, whatever the staged validation of the state found.
type failPendingWrites struct{ storage.PersistentStore }

// the optional capabilities of the store a recovery needs are forwarded
func (f failPendingWrites) NetworkProfile() (uint64, bool, error) {
	return f.PersistentStore.(interface{ NetworkProfile() (uint64, bool, error) }).NetworkProfile()
}
func (f failPendingWrites) SetNetworkProfile(p uint64) error {
	return f.PersistentStore.(interface{ SetNetworkProfile(uint64) error }).SetNetworkProfile(p)
}
func (f failPendingWrites) AppendRecords(r []rootrecords.Record) error {
	return f.PersistentStore.(storage.RecordStore).AppendRecords(r)
}
func (f failPendingWrites) RecordCount() (uint64, error) {
	return f.PersistentStore.(storage.RecordStore).RecordCount()
}
func (f failPendingWrites) Records(from uint64, max int) ([]rootrecords.Record, error) {
	return f.PersistentStore.(storage.RecordStore).Records(from, max)
}

func (f failPendingWrites) WriteBlock(b *storage.ExecutedBlock, root bool) error {
	if !root {
		return errors.New("disk full")
	}
	return f.PersistentStore.WriteBlock(b, root)
}

// A state whose pending block does not fit its parent is refused by the staged validation before anything is written, with no latch.
func TestRecoveryOfAStateTheStagingRefusesWritesAndLatchesNothing(t *testing.T) {
	c := newAnchorCluster(t)
	state := c.pastTheFirstSuccessor()
	bad := *state
	bad.Pending = append([]*rctypes.BlockData(nil), state.Pending...)
	first := *bad.Pending[0]
	first.Qc = state.CommittedHead.Block.Qc
	bad.Pending[0] = &first

	root := latchProbe(t, c)
	before := root.blockStore.RootAnchor()
	err := recoverTo(t, root, &bad)
	require.Error(t, err)
	require.False(t, root.frontier.faulted.Load(), "nothing was written: nothing to latch")
	require.Equal(t, before, root.blockStore.RootAnchor())
}

// A failure after the first write still latches: the store may hold part of the state.
func TestRecoveryFailingAfterTheFirstWriteStillLatchesTheFrontierFault(t *testing.T) {
	c := newAnchorCluster(t)
	state := c.pastTheFirstSuccessor()
	require.NotEmpty(t, state.Pending, "premise: the state has a pending block to write after the head")

	root := latchProbe(t, c)
	// the store of the running root, wrapped so that the pending blocks cannot be written
	faulty := failPendingWrites{root.blockStore.GetDB()}
	var err error
	root.blockStore, err = storage.NewFromCheckpoint(crypto.SHA256, firstReplica(c.replicas).oldHead, faulty, root.orchestration, root.log, storage.ProfileHandoff)
	require.NoError(t, err)
	err = recoverTo(t, root, state)
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

// A recovery whose state ends at the genesis leaves the genesis QC as the high QC (parent round 0, round 1, current round 2): in #841 a root formed
// the QC of round 2 from votes before it held the block, and the peer which answered held the block of round 2 but not yet its QC. There is no block
// before the genesis to elect a leader from: that is no election (the round-robin fallback, as on every peer, none of which elects from the genesis
// QC), not a fault, so the frontier stays eligible. Before the fix the election failed to load round 0 and the recovery latched the frontier fault,
// which only a restart clears: the root refused every signed-frontier request while consensus went on.
func TestRecoveryToTheGenesisDoesNotLatchTheFrontierFault(t *testing.T) {
	cms, _ := createConsensusManagers(t, 2, nil)
	cm, peer := cms[0], cms[1]
	cm.frontier = &frontierSampler{}
	state, err := peer.blockStore.GetState()
	require.NoError(t, err)
	require.Empty(t, state.Pending, "premise: the peer is at its genesis")
	genesisQC := state.CommittedHead.Qc
	require.EqualValues(t, rctypes.GenesisRootRound, genesisQC.GetRound())
	require.EqualValues(t, 0, genesisQC.GetParentRound(), "premise: the genesis has no parent")
	_, err = cm.recovery.Set(genesisQC)
	require.NoError(t, err)

	require.NoError(t, cm.onStateResponse(context.Background(), state))
	require.False(t, cm.recovery.InRecovery())
	require.Equal(t, genesisQC.GetRound(), cm.blockStore.GetHighQc().GetRound(), "premise: the genesis QC is the high QC")
	require.EqualValues(t, rctypes.GenesisRootRound+1, cm.pacemaker.GetCurrentRound())
	require.False(t, cm.frontier.faulted.Load(), "a recovery to the genesis does not latch the frontier fault")
}
