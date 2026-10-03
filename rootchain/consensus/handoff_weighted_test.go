package consensus

import (
	"bytes"
	"context"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

// setStakes replaces the manager's current trust base by a copy whose members keep their keys and carry the given stake
// (1 for unlisted members) and whose quorum threshold is the given one. The handoff caches weigh approvals with it.
func setStakes(cm *ConsensusManager, threshold uint64, stakes map[string]uint64) {
	old := cm.trustBase.Load()
	tb := &types.RootTrustBaseV1{Version: old.Version, NetworkID: old.NetworkID, Epoch: old.Epoch, EpochStart: old.EpochStart,
		QuorumThreshold: threshold, StateHash: old.StateHash, ChangeRecordHash: old.ChangeRecordHash, PreviousEntryHash: old.PreviousEntryHash}
	for _, n := range old.RootNodes {
		stake, ok := stakes[n.NodeID]
		if !ok {
			stake = 1
		}
		tb.RootNodes = append(tb.RootNodes, &types.NodeInfo{NodeID: n.NodeID, SigKey: bytes.Clone(n.SigKey), Stake: stake})
	}
	cm.trustBase.Store(tb)
}

func id(n *testutils.TestNode) string { return n.PeerConf.ID.String() }

// endorsedPlan drives the fixture to a Prepare-bound plan that the local node has endorsed (its approval is cached with
// the weight of the trust base that setStakes installed) and returns the signing domains for the other validators.
func (f *planFixture) endorsedPlan(t *testing.T, stakes map[string]uint64, threshold uint64) (abdrc.HandoffApprovalMsg, []byte, []byte) {
	t.Helper()
	cm := f.cm
	state, err := cm.blockStore.GetState()
	require.NoError(t, err)
	state.CommittedHead.ShardInfo = []abdrc.ShardInfo{{Partition: 8, IR: &types.InputRecord{BlockHash: f.parentHash}}}
	plan, err := cm.buildHandoffPlanFromState(&f.next, state, nil)
	require.NoError(t, err)
	body, err := storage.DecodeHandoffBody(plan.Body)
	require.NoError(t, err)
	bodyID := body.Identity()
	prepareRecord := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, OrderedRound: state.CommittedHead.Block.Round + 1,
		ActivationRound:   state.CommittedHead.Block.Round + 1 + storage.PrepareFreezeLapseRounds + storage.HandoffActivationMarginRounds,
		PredecessorBodyID: bytes.Clone(state.CommittedHead.Control.PredecessorBodyID),
		NextBodyID:        bodyID[:], FrozenID: make([]byte, 32), SuccessorTRHash: make([]byte, 32), Kind: "prepare"}
	control := *state.CommittedHead.Control
	control.Phase, control.OrderedRound, control.RecordBytes = "prepared", prepareRecord.OrderedRound, prepareRecord.Bytes()
	control.PreviousDigest, control.FrozenParent = bytes.Repeat([]byte{9}, 32), bytes.Clone(f.parentHash)
	head := *state.CommittedHead
	head.Control = &control
	prepared := *state
	prepared.CommittedHead = &head

	setStakes(cm, threshold, stakes)
	require.NoError(t, cm.endorseHandoffAtState(context.Background(), plan, &prepared))
	cm.handoffMu.Lock()
	stored := cm.handoffPlans[bodyID]
	record := stored.record
	signed := stored.plan
	cm.handoffMu.Unlock()
	domain, err := storage.EndorsementBytes(record)
	require.NoError(t, err)
	abortDomain, err := storage.AbortEndorsementBytes(record)
	require.NoError(t, err)
	return signed, domain, abortDomain
}

func (f *planFixture) approve(t *testing.T, n *testutils.TestNode, plan abdrc.HandoffApprovalMsg, domain, abortDomain []byte) error {
	t.Helper()
	signed := plan
	signed.Signer = id(n)
	var err error
	signed.Signature, err = n.Signer.SignBytes(domain)
	require.NoError(t, err)
	signed.AbortSignature, err = n.Signer.SignBytes(abortDomain)
	require.NoError(t, err)
	return f.cm.onHandoffApprovalMsg(context.Background(), &signed)
}

func TestHandoffApprovalCacheIsWeightedNotCounted(t *testing.T) {
	// total 9, threshold 7. The local node and the first other weigh 1; "heavy" is the second other and weighs 6.
	t.Run("heavy plus the local node is a minority by count and a quorum by weight", func(t *testing.T) {
		f := newPlanFixture(t)
		plan, domain, abortDomain := f.endorsedPlan(t, map[string]uint64{id(f.others[1]): 6}, 7)
		_, err := f.cm.readyHandoff()
		require.ErrorIs(t, err, ErrHandoffApproval, "the local approval alone weighs 1")
		require.NoError(t, f.approve(t, f.others[1], plan, domain, abortDomain))
		ready, err := f.cm.readyHandoff()
		require.NoError(t, err, "2 of 4 approvals by count carry 7 of 9 by weight")
		require.Len(t, ready.signatures, 2)
		require.EqualValues(t, 7, ready.weight)
	})
	t.Run("three light approvals are a majority by count and not a quorum", func(t *testing.T) {
		f := newPlanFixture(t)
		plan, domain, abortDomain := f.endorsedPlan(t, map[string]uint64{id(f.others[1]): 6}, 7)
		require.NoError(t, f.approve(t, f.others[0], plan, domain, abortDomain))
		require.NoError(t, f.approve(t, f.others[2], plan, domain, abortDomain))
		_, err := f.cm.readyHandoff()
		require.ErrorIs(t, err, ErrHandoffApproval, "3 of 4 approvals by count carry 3 of 9 by weight")
		require.NoError(t, f.approve(t, f.others[1], plan, domain, abortDomain))
		_, err = f.cm.readyHandoff()
		require.NoError(t, err)
	})
	t.Run("a repeated approval adds no weight", func(t *testing.T) {
		f := newPlanFixture(t)
		plan, domain, abortDomain := f.endorsedPlan(t, map[string]uint64{id(f.others[1]): 6}, 7)
		require.NoError(t, f.approve(t, f.others[0], plan, domain, abortDomain))
		require.NoError(t, f.approve(t, f.others[0], plan, domain, abortDomain))
		f.cm.handoffMu.Lock()
		var weight uint64
		for _, p := range f.cm.handoffPlans {
			weight = p.weight
		}
		f.cm.handoffMu.Unlock()
		require.EqualValues(t, 2, weight)
	})
	t.Run("approval weights that overflow are refused and leave the cache unchanged", func(t *testing.T) {
		f := newPlanFixture(t)
		plan, domain, abortDomain := f.endorsedPlan(t, map[string]uint64{id(f.node): math.MaxUint64 - 1, id(f.others[0]): 2}, 7)
		err := f.approve(t, f.others[0], plan, domain, abortDomain)
		require.ErrorIs(t, err, quorumweight.ErrWeightOverflow)
		require.ErrorIs(t, err, ErrHandoffApproval)
		f.cm.handoffMu.Lock()
		defer f.cm.handoffMu.Unlock()
		for _, p := range f.cm.handoffPlans {
			require.EqualValues(t, uint64(math.MaxUint64-1), p.weight)
			require.Len(t, p.signatures, 1)
		}
	})
}

func approvalMsg(t *testing.T, n *testutils.TestNode, target abdrc.HandoffAbortTarget, domain []byte) *abdrc.HandoffAbortApprovalMsg {
	t.Helper()
	signature, err := n.Signer.SignBytes(domain)
	require.NoError(t, err)
	return &abdrc.HandoffAbortApprovalMsg{Network: target.Network, OldEpoch: target.OldEpoch,
		PredecessorBodyID: bytes.Clone(target.PredecessorBodyID), Attempt: target.Attempt,
		NextBodyID: bytes.Clone(target.NextBodyID), Signer: id(n), Signature: signature}
}

func TestHandoffAbortCacheIsWeightedNotCounted(t *testing.T) {
	// nodes[1] weighs 6, the others 1: total 9, threshold 7
	t.Run("heavy plus one light is a quorum", func(t *testing.T) {
		cm, _, nodes, target, record := newExplicitAbortFixture(t)
		setStakes(cm, 7, map[string]uint64{id(nodes[1]): 6})
		domain, err := storage.AbortEndorsementBytes(record)
		require.NoError(t, err)
		require.NoError(t, cm.onHandoffAbortApprovalMsg(approvalMsg(t, nodes[2], target, domain)))
		_, ready := cm.readyHandoffAbort(target)
		require.False(t, ready)
		require.NoError(t, cm.onHandoffAbortApprovalMsg(approvalMsg(t, nodes[1], target, domain)))
		signatures, ready := cm.readyHandoffAbort(target)
		require.True(t, ready, "2 of 4 by count carry 7 of 9 by weight")
		require.Len(t, signatures, 2)
	})
	t.Run("three light approvals are not a quorum", func(t *testing.T) {
		cm, _, nodes, target, record := newExplicitAbortFixture(t)
		setStakes(cm, 7, map[string]uint64{id(nodes[1]): 6})
		domain, err := storage.AbortEndorsementBytes(record)
		require.NoError(t, err)
		for _, n := range []*testutils.TestNode{nodes[0], nodes[2], nodes[3]} {
			require.NoError(t, cm.onHandoffAbortApprovalMsg(approvalMsg(t, n, target, domain)))
		}
		_, ready := cm.readyHandoffAbort(target)
		require.False(t, ready, "3 of 4 by count carry 3 of 9 by weight")
	})
	t.Run("overflowing weights are refused and leave the cache unchanged", func(t *testing.T) {
		cm, _, nodes, target, record := newExplicitAbortFixture(t)
		setStakes(cm, 7, map[string]uint64{id(nodes[1]): math.MaxUint64 - 1, id(nodes[2]): 2})
		domain, err := storage.AbortEndorsementBytes(record)
		require.NoError(t, err)
		require.NoError(t, cm.onHandoffAbortApprovalMsg(approvalMsg(t, nodes[1], target, domain)))
		err = cm.onHandoffAbortApprovalMsg(approvalMsg(t, nodes[2], target, domain))
		require.ErrorIs(t, err, quorumweight.ErrWeightOverflow)
		require.ErrorIs(t, err, ErrHandoffAbortSignature)
		key, kerr := handoffAbortKeyFor(target)
		require.NoError(t, kerr)
		cm.handoffMu.Lock()
		defer cm.handoffMu.Unlock()
		require.Len(t, cm.handoffAborts[key].signatures, 1)
		require.EqualValues(t, uint64(math.MaxUint64-1), cm.handoffAborts[key].weight)
	})
}
