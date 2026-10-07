package consensus

import (
	"bytes"
	"context"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-go-base/types"
)

// v3Signers maps a node id to its signer, for the receipts the successor members sign.
func (f *planFixture) v3Signers() map[string]*testutils.TestNode {
	out := map[string]*testutils.TestNode{f.node.PeerConf.ID.String(): f.node}
	for _, o := range f.others {
		out[o.PeerConf.ID.String()] = o
	}
	return out
}

// weightedNext is the next epoch's committee: the same four keys with the exact weights 6,1,1,1 (W=9, Q=7).
func (f *planFixture) weightedNext() types.RootTrustBaseV1 {
	next := *f.old
	next.Epoch = 2
	next.RootNodes = make([]*types.NodeInfo, len(f.old.RootNodes))
	for i, n := range f.old.RootNodes {
		next.RootNodes[i] = &types.NodeInfo{NodeID: n.NodeID, SigKey: n.SigKey, Stake: 1}
	}
	next.RootNodes[0].Stake = 6
	return next
}

func (f *planFixture) receiptsFor(t *testing.T, c V3Candidate, skip ...string) []byte {
	t.Helper()
	ctx := q3format.ContextFor(c.Body, c.Attempt, c.Candidate)
	var rs []q3format.Receipt
signing:
	for _, m := range c.Body.Members {
		for _, s := range skip {
			if s == m.NodeID {
				continue signing
			}
		}
		r, err := q3format.SignReceipt(ctx, m.NodeID, f.v3Signers()[m.NodeID].Signer)
		require.NoError(t, err)
		rs = append(rs, r)
	}
	raw, err := q3format.EncodeReceipts(rs)
	require.NoError(t, err)
	return raw
}

func certifiedParentState(t *testing.T, f *planFixture) *abdrc.StateMsg {
	t.Helper()
	state, err := f.cm.blockStore.GetState()
	require.NoError(t, err)
	state.CommittedHead.ShardInfo = []abdrc.ShardInfo{{Partition: 8, IR: &types.InputRecord{BlockHash: f.parentHash}}}
	return state
}

// A V3 plan is the next committee with its exact weights and the readiness receipts of every member: each refusal below differs from the
// control in one thing.
func TestV3PlanCarriesExactWeightsAndRequiresEveryMembersReadiness(t *testing.T) {
	f := newPlanFixtureOpts(t, true)
	next := f.weightedNext()
	state := certifiedParentState(t, f)

	cand, err := f.cm.v3CandidateFromState(&next, state, nil)
	require.NoError(t, err)
	require.EqualValues(t, 7, cand.Body.RootThreshold, "W=9: the weighted threshold")
	weights := map[string]uint64{}
	for _, m := range cand.Body.Members {
		weights[m.NodeID] = m.Weight
	}
	require.EqualValues(t, 6, weights[next.RootNodes[0].NodeID], "the first member is the heavy one")
	require.EqualValues(t, 1, weights[next.RootNodes[1].NodeID])
	genesisID, err := f.old.Hash(crypto.SHA256)
	require.NoError(t, err)
	prior, err := q3format.Prior{Network: 5, Epoch: 1, BodyVersion: 1, Identity: genesisID}.Hash()
	require.NoError(t, err)
	require.Equal(t, prior, cand.Body.PredecessorHash, "the first V3 body's predecessor is the version-1 genesis body")

	receipts := f.receiptsFor(t, cand)
	plan, err := f.cm.buildHandoffPlanV3FromState(&next, state, nil, receipts)
	require.NoError(t, err)
	require.Equal(t, receipts, []byte(plan.Receipts))
	body, predecessor, err := f.cm.checkPlanBody(&plan)
	require.NoError(t, err, "the plan passes the same check an endorser and an accepting validator run")
	require.EqualValues(t, 3, body.version)
	require.Equal(t, genesisID, predecessor)

	refusedAs := func(name string, err error, cause error) {
		t.Helper()
		require.ErrorIs(t, err, ErrHandoffApproval, name)
		require.ErrorIs(t, err, cause, name)
	}
	_, err = f.cm.buildHandoffPlanV3FromState(&next, state, nil, f.receiptsFor(t, cand, f.others[2].PeerConf.ID.String()))
	refusedAs("a member's receipt is missing", err, q3format.ErrReceiptMissing)
	other := cand
	other.Attempt = 1
	_, err = f.cm.buildHandoffPlanV3FromState(&next, state, nil, f.receiptsFor(t, other))
	refusedAs("receipts of another attempt", err, q3format.ErrReceiptSignature)
	other = cand
	other.Candidate[0] ^= 1
	_, err = f.cm.buildHandoffPlanV3FromState(&next, state, nil, f.receiptsFor(t, other))
	refusedAs("receipts of another candidate", err, q3format.ErrReceiptSignature)
	_, err = f.cm.buildHandoffPlanV3FromState(&next, state, nil, nil)
	require.ErrorIs(t, err, ErrHandoffApproval, "no receipts at all")

	stripped := plan
	stripped.Receipts = nil
	_, _, err = f.cm.checkPlanBody(&stripped)
	require.ErrorIs(t, err, ErrHandoffApproval, "an approval without receipts is not checked as a plan")
	skewed := plan
	skewed.Attempt = 1
	_, _, err = f.cm.checkPlanBody(&skewed)
	require.ErrorIs(t, err, ErrHandoffApproval, "a plan whose attempt is not the body's")

	// a manager that is not wired to a verified Q3 history has no V3 plans at all
	plain := newPlanFixture(t)
	_, _, err = plain.cm.checkPlanBody(&plan)
	require.ErrorIs(t, err, ErrHandoffApproval)
	_, err = plain.cm.PlanHandoffV3(&next, nil, receipts)
	require.ErrorIs(t, err, ErrHandoffApproval)
}

// The leader orders the Freeze of a V3 plan with a version-3 companion that carries the plan's receipts, and the old committee's own
// authority accepts it.
func TestV3FreezeBuiltByTheLeaderIsAcceptedByTheCommitteesAuthority(t *testing.T) {
	ctx := context.Background()
	f := newPlanFixtureOpts(t, true)
	next := f.weightedNext()
	state := certifiedParentState(t, f)
	cand, err := f.cm.v3CandidateFromState(&next, state, nil)
	require.NoError(t, err)
	receipts := f.receiptsFor(t, cand)
	plan, err := f.cm.buildHandoffPlanV3FromState(&next, state, nil, receipts)
	require.NoError(t, err)
	id := cand.Body.Identity()
	genesisID, err := f.old.Hash(crypto.SHA256)
	require.NoError(t, err)

	prepareRecord := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, OrderedRound: state.CommittedHead.Block.Round + 1,
		ActivationRound:   state.CommittedHead.Block.Round + 1 + storage.PrepareFreezeLapseRounds + storage.HandoffActivationMarginRounds,
		PredecessorBodyID: genesisID, NextBodyID: id[:], FrozenID: make([]byte, 32), SuccessorTRHash: make([]byte, 32), Kind: "prepare"}
	control := *state.CommittedHead.Control
	control.Phase, control.OrderedRound, control.RecordBytes = "prepared", prepareRecord.OrderedRound, prepareRecord.Bytes()
	control.PreviousDigest, control.FrozenParent = bytes.Repeat([]byte{9}, 32), bytes.Clone(f.parentHash)
	prepared := *state
	head := *state.CommittedHead
	head.Control = &control
	prepared.CommittedHead = &head

	require.NoError(t, f.cm.endorseHandoffAtState(ctx, plan, &prepared), "this validator endorses the prepared V3 plan")
	stored := f.cm.handoffPlans[id]
	require.NotNil(t, stored)
	require.EqualValues(t, 3, stored.body.version)
	domain, err := storage.EndorsementBytes(stored.record)
	require.NoError(t, err)
	abortDomain, err := storage.AbortEndorsementBytes(stored.record)
	require.NoError(t, err)
	for _, other := range f.others[:2] {
		signed := stored.plan
		signed.Signer = other.PeerConf.ID.String()
		signed.Signature, err = other.Signer.SignBytes(domain)
		require.NoError(t, err)
		signed.AbortSignature, err = other.Signer.SignBytes(abortDomain)
		require.NoError(t, err)
		require.NoError(t, f.cm.onHandoffApprovalMsg(ctx, &signed))
	}
	parentQC := f.cm.blockStore.GetHighQc()
	parentBlock, err := f.cm.blockStore.Block(parentQC.GetRound())
	require.NoError(t, err)
	parentBlock.ShardState.Control = prepared.CommittedHead.Control
	parentBlock.ShardState.States[types.PartitionShardID{PartitionID: 8, ShardID: (types.ShardID{}).Key()}] = &storage.ShardInfo{IR: &types.InputRecord{BlockHash: bytes.Clone(f.parentHash)}}
	records, err := f.cm.handoffRecordsForRound(prepared.CommittedHead.Control.OrderedRound+1, parentQC)
	require.NoError(t, err)
	require.Len(t, records, 2)
	freeze, err := storage.DecodeOrderedHandoffRecord(records[0])
	require.NoError(t, err)
	companion, err := storage.ParseFreezeCompanion(records[1])
	require.NoError(t, err)
	require.EqualValues(t, 3, companion.Version, "a V3 plan is ordered with a version-3 companion")
	require.Equal(t, receipts, companion.Receipts)
	require.Equal(t, plan.Body, companion.Body)

	// the real genesis authority of this manager accepts exactly what the leader built, and refuses it with one thing changed
	parent, err := f.cm.blockStore.VerifyFreezeCompanion(freeze, records[1])
	require.NoError(t, err)
	require.Equal(t, f.parentHash, parent)
	tampered := freeze
	tampered.Attempt++
	_, err = f.cm.blockStore.VerifyFreezeCompanion(tampered, records[1])
	require.ErrorIs(t, err, storage.ErrHandoffRecord)
	noReceipts, err := (storage.FreezeV3Authorization{Version: 3, Body: companion.Body, Parent: companion.Parent, Candidate: companion.Candidate,
		Receipts: []byte{0x80}, Signatures: companion.Signatures}).Bytes()
	require.NoError(t, err)
	_, err = f.cm.blockStore.VerifyFreezeCompanion(freeze, noReceipts)
	require.ErrorIs(t, err, storage.ErrFreezeV3Receipts, "receipts that are not a member set")
}

var _ = abdrc.HandoffApprovalMsg{}
