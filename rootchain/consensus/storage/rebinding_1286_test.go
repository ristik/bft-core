package storage

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// installPendingRebinding is installPendingAssignment for #1286's rebinding primary J: the root committee is unchanged and only the
// last entity's EVM delegate moves from ev-d to the fresh ev-e. J is committed, activated and unacknowledged.
func installPendingRebinding(t *testing.T) pendingAssignment {
	t.Helper()
	f := newAssignmentFixture(t)
	f.rebind = true
	f.useRealOrchestration(t)
	f.seedFees(t)
	h := f.commitAssignment(t)
	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	f.addSuccessorBlock(t, s, 7, anchor)
	f.store = s
	return pendingAssignment{f: f, first: h, store: s, installed: h.activated, body1: h.commit.NextBodyID}
}

// Review P1-1 at block validation: the recovery of a committed rebinding primary reinstalls exactly K and is admitted; a recovery whose
// bindings swap K's delegates is refused.
func TestTheRecoveryOfARebindingPrimaryIsAdmittedAtBlockValidation(t *testing.T) {
	t.Run("exactly K", func(t *testing.T) {
		p := installPendingRebinding(t)
		require.Equal(t, p.f.rootMembers(), p.f.successorRoot(), "J kept the committee")
		sup := p.supersede(t, nil)
		require.NoError(t, sup.admit(t))
	})
	t.Run("K's delegates swapped", func(t *testing.T) {
		p := installPendingRebinding(t)
		sup := p.supersede(t, nil)
		c, err := evmassign.DecodeCandidate(sup.preimage)
		require.NoError(t, err)
		require.EqualValues(t, evmassign.KindRecovery, c.Kind)
		b := append([]evmassign.Binding(nil), c.Bindings...)
		b[0].EVMNodeID, b[1].EVMNodeID = b[1].EVMNodeID, b[0].EVMNodeID
		p.f.recovery.bindings = b
		swapped := p.supersedeWithPlan(t, p.f.recovery)
		err = swapped.admit(t)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
}

// Review P3-2: in the rebinding primary's shard epoch s+1 the retired EVM key (ev-d) is outside the trust base: a certification request
// it signs is refused and carries no weight, while the fresh key (ev-e) is a member.
func TestTheRetiredEVMKeyOfARebindingCountsNothingInTheNextShardEpoch(t *testing.T) {
	p := installPendingRebinding(t)
	si := mustBlock(t, p.store, 7).ShardState.States[p.f.shard]
	require.NotEqual(t, si.TR.Epoch, si.IR.Epoch, "J is installed and not acknowledged")
	err := si.ValidRequest(&certification.BlockCertificationRequest{PartitionID: 8, NodeID: "ev-d",
		InputRecord: &types.InputRecord{Version: 1, Epoch: si.TR.Epoch}})
	require.ErrorIs(t, err, ErrNodeNotInTrustBase)
	require.False(t, si.IsMember("ev-d"))
	_, err = si.SignerWeight("ev-d")
	require.Error(t, err, "no signing weight for the retired key")
	require.True(t, si.IsMember("ev-e"))
	w, err := si.SignerWeight("ev-e")
	require.NoError(t, err)
	require.Positive(t, w)
	// and after a restart (derived from committed history) the same holds
	s, err := New(crypto.SHA256, p.f.store.storage, p.f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	si = mustBlock(t, s, 7).ShardState.States[p.f.shard]
	require.False(t, si.IsMember("ev-d"))
}
