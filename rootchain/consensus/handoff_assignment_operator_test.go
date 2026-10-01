package consensus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	testobservability "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-core/trustactivation"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

type evmSigner struct {
	id     string
	signer abcrypto.Signer
	info   *types.NodeInfo
}

func newEVMSigner(t *testing.T, id string) evmSigner {
	t.Helper()
	s, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	v, err := s.Verifier()
	require.NoError(t, err)
	pub, err := v.MarshalPublicKey()
	require.NoError(t, err)
	return evmSigner{id: id, signer: s, info: &types.NodeInfo{NodeID: id, SigKey: pub, Stake: 1}}
}

type operatorAssignmentFixture struct {
	cm          *ConsensusManager
	old, next   *types.RootTrustBaseV1
	sameRoot    *types.RootTrustBaseV1 // root epoch 2 with the committee unchanged (a configuration-only boundary)
	state       *abdrc.StateMsg
	parent      []byte
	current     *types.PartitionDescriptionRecord
	oldKeys     []evmSigner
	nextKeys    []evmSigner
	predecessor []byte
	others      []*testutils.TestNode
	node        *testutils.TestNode
}

// newOperatorAssignmentFixture builds the fixture; extra genesis shard configurations are written together with the EVM one,
// before the consensus manager enables the handoff profile (after which no configuration can be added).
func newOperatorAssignmentFixture(t *testing.T, extra ...*types.PartitionDescriptionRecord) *operatorAssignmentFixture {
	t.Helper()
	ctx := context.Background()
	f := &operatorAssignmentFixture{node: testutils.NewTestNode(t), parent: bytes.Repeat([]byte{7}, 32)}
	f.others = []*testutils.TestNode{testutils.NewTestNode(t), testutils.NewTestNode(t), testutils.NewTestNode(t)}
	obs := testobservability.Default(t)
	db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "root.db"), storage.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	orchestration, err := partitions.NewOrchestration(5, filepath.Join(t.TempDir(), "orchestration.db"), obs.Logger(), partitions.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, orchestration.Close()) })

	f.oldKeys = []evmSigner{newEVMSigner(t, "ev-a"), newEVMSigner(t, "ev-b"), newEVMSigner(t, "ev-c"), newEVMSigner(t, "ev-d")}
	infos := make([]*types.NodeInfo, 0, 4)
	for _, k := range f.oldKeys {
		infos = append(infos, k.info)
	}
	f.current = &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: 8,
		TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 5 * time.Second, Epoch: 0, EpochStart: 1,
		PartitionParams: map[string]string{"seal_registry_genesis": "g", evmassign.CouplingParam: "true"}, Validators: infos}
	require.NoError(t, orchestration.AddShardConfig(f.current))
	for _, conf := range extra {
		require.NoError(t, orchestration.AddShardConfig(conf))
	}

	signers := map[string]abcrypto.Signer{f.node.PeerConf.ID.String(): f.node.Signer}
	for _, other := range f.others {
		signers[other.PeerConf.ID.String()] = other.Signer
	}
	f.old = testtrustbase.NewTrustBaseFromSigners(t, signers).(*types.RootTrustBaseV1)
	store, err := tbstore.NewTrustBaseStore(memorydb.New(), obs.Logger())
	require.NoError(t, err)
	require.NoError(t, store.Store(f.old))
	identity := sha256.Sum256([]byte("assignment-plan-test"))
	history, err := trusthistorystore.Open(ctx, memorydb.New(), f.old, identity, trustactivation.Verifier{})
	require.NoError(t, err)
	params := *NewConsensusParams()
	params.NetworkProfileVersion = storage.ProfileHandoff
	f.cm, err = NewConsensusManager(f.node.PeerConf.ID, store, orchestration, testnetwork.NewRootMockNetwork(), f.node.Signer, db, obs,
		WithConsensusParams(params), WithRecoveryProfile2(history))
	require.NoError(t, err)
	same := *f.old
	same.Epoch = 2 // identical root members, root epoch still advances
	f.sameRoot = &same
	// The coupled change: one root entity is replaced together with the EVM assignment.
	next := same
	next.RootNodes = append([]*types.NodeInfo(nil), f.old.RootNodes...)
	replacement := testutils.NewTestNode(t)
	rv, err := replacement.Signer.Verifier()
	require.NoError(t, err)
	rkey, err := rv.MarshalPublicKey()
	require.NoError(t, err)
	next.RootNodes[3] = &types.NodeInfo{NodeID: replacement.PeerConf.ID.String(), SigKey: rkey, Stake: 1}
	f.next = &next
	f.state, err = f.cm.blockStore.GetState()
	require.NoError(t, err)
	f.state.CommittedHead.ShardInfo = []abdrc.ShardInfo{{Partition: 8, IR: &types.InputRecord{BlockHash: f.parent}}}
	f.predecessor, err = f.cm.handoffPredecessor()
	require.NoError(t, err)

	f.nextKeys = []evmSigner{f.oldKeys[0], newEVMSigner(t, "ev-e"), newEVMSigner(t, "ev-f"), newEVMSigner(t, "ev-g")}
	return f
}

// bindings pairs the sorted committee of next with the successor validators in order.
func (f *operatorAssignmentFixture) bindings(succ *types.PartitionDescriptionRecord, next *types.RootTrustBaseV1) []evmassign.Binding {
	ids := make([]string, 0, len(next.RootNodes))
	for _, n := range next.RootNodes {
		ids = append(ids, n.NodeID)
	}
	sort.Strings(ids)
	out := make([]evmassign.Binding, len(ids))
	for i, id := range ids {
		out[i] = evmassign.Binding{RootNodeID: id, EVMNodeID: succ.Validators[i].NodeID}
	}
	return out
}

func (f *operatorAssignmentFixture) succForBindings(t *testing.T) *types.PartitionDescriptionRecord {
	t.Helper()
	infos := make([]*types.NodeInfo, 0, len(f.nextKeys))
	for _, k := range f.nextKeys {
		infos = append(infos, k.info)
	}
	succ, err := evmassign.NewSuccessor(f.current, infos)
	require.NoError(t, err)
	return succ
}

func (f *operatorAssignmentFixture) proposal(t *testing.T, mutate ...func(*evmassign.PoPContext)) *evmassign.Proposal {
	t.Helper()
	infos := make([]*types.NodeInfo, 0, len(f.nextKeys))
	for _, k := range f.nextKeys {
		infos = append(infos, k.info)
	}
	succ, err := evmassign.NewSuccessor(f.current, infos)
	require.NoError(t, err)
	ctx := evmassign.PoPContext{Network: 5, Attempt: 0}
	copy(ctx.Predecessor[:], f.predecessor)
	for _, m := range mutate {
		m(&ctx)
	}
	p := &evmassign.Proposal{Validators: infos, Bindings: f.bindings(succ, f.next)}
	for _, v := range succ.Validators {
		for _, k := range f.nextKeys {
			if k.id == v.NodeID {
				pop, err := evmassign.SignPoP(k.signer, ctx, succ, k.id)
				require.NoError(t, err)
				p.PoPs = append(p.PoPs, pop)
			}
		}
	}
	return p
}

// preparedState is the committed state after the root ordered the Prepare of plan: control "prepared", with the frozen parent the
// root bound (the certified EVM IR) and the Prepare's activation round.
func (f *operatorAssignmentFixture) preparedState(t *testing.T, plan abdrc.HandoffApprovalMsg) *abdrc.StateMsg {
	t.Helper()
	body, err := storage.DecodeHandoffBody(plan.Body)
	require.NoError(t, err)
	id := body.Identity()
	round := f.state.CommittedHead.Block.Round
	record := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, Attempt: plan.Attempt, OrderedRound: round + 1, ActivationRound: plan.ActivationRound,
		PredecessorBodyID: bytes.Clone(f.predecessor), NextBodyID: id[:], FrozenID: make([]byte, 32), SuccessorTRHash: make([]byte, 32), Kind: "prepare"}
	control := *f.state.CommittedHead.Control
	control.Phase, control.Attempt, control.OrderedRound, control.RecordBytes = "prepared", plan.Attempt, record.OrderedRound, record.Bytes()
	control.PreviousDigest, control.FrozenParent = bytes.Repeat([]byte{9}, 32), bytes.Clone(f.parent)
	cp := *f.state
	head := *f.state.CommittedHead
	head.Control = &control
	cp.CommittedHead = &head
	return &cp
}

func TestOperatorBuildsAssignmentCandidateAndEndorsersVerifyIt(t *testing.T) {
	f := newOperatorAssignmentFixture(t)
	plan, err := f.cm.buildHandoffPlanFromState(f.next, f.state, f.proposal(t))
	require.NoError(t, err)
	require.NotEmpty(t, plan.CandidatePreimage)
	digest := sha256.Sum256(plan.CandidatePreimage)
	require.Equal(t, digest[:], plan.Candidate, "the approval's candidate hash is the preimage digest")
	// The body's change-record context binds that digest.
	body, err := storage.DecodeHandoffBody(plan.Body)
	require.NoError(t, err)
	require.Equal(t, evmroot.D4CandidateContextHash(5, f.predecessor, plan.Attempt, plan.Candidate, body.EarliestActivation), body.ChangeRecordHash)

	require.NoError(t, f.cm.endorseHandoffAtState(context.Background(), plan, f.preparedState(t, plan)))
	require.Len(t, f.cm.handoffPlans, 1)

	// A peer's endorsement with the preimage altered is refused before it is cached.
	tampered := plan
	tampered.Signer = f.node.PeerConf.ID.String()
	tampered.CandidatePreimage = append(bytes.Clone(plan.CandidatePreimage[:len(plan.CandidatePreimage)-1]), plan.CandidatePreimage[len(plan.CandidatePreimage)-1]^1)
	_, _, err = f.cm.validateHandoffApproval(&tampered)
	require.ErrorIs(t, err, ErrHandoffApproval)

	// A root-only plan (same committee) carries no preimage and keeps the legacy candidate hash.
	root, err := f.cm.buildHandoffPlanFromState(f.sameRoot, f.state, nil)
	require.NoError(t, err)
	require.Empty(t, root.CandidatePreimage)
	require.NotEqual(t, plan.Candidate, root.Candidate)
}

func TestOperatorRefusesBadAssignmentProposalsBeforeAnyEndorsement(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, f *operatorAssignmentFixture) (*types.RootTrustBaseV1, *abdrc.StateMsg, *evmassign.Proposal)
		want  error
	}{
		{"missing PoP", func(t *testing.T, f *operatorAssignmentFixture) (*types.RootTrustBaseV1, *abdrc.StateMsg, *evmassign.Proposal) {
			p := f.proposal(t)
			p.PoPs = p.PoPs[:len(p.PoPs)-1]
			return f.next, f.state, p
		}, evmassign.ErrPoP},
		{"PoP for another attempt", func(t *testing.T, f *operatorAssignmentFixture) (*types.RootTrustBaseV1, *abdrc.StateMsg, *evmassign.Proposal) {
			return f.next, f.state, f.proposal(t, func(c *evmassign.PoPContext) { c.Attempt = 4 })
		}, evmassign.ErrPoP},
		{"PoP for another predecessor", func(t *testing.T, f *operatorAssignmentFixture) (*types.RootTrustBaseV1, *abdrc.StateMsg, *evmassign.Proposal) {
			return f.next, f.state, f.proposal(t, func(c *evmassign.PoPContext) { c.Predecessor = [32]byte{1} })
		}, evmassign.ErrPoP},
		{"EVM-only change (committee unchanged)", func(t *testing.T, f *operatorAssignmentFixture) (*types.RootTrustBaseV1, *abdrc.StateMsg, *evmassign.Proposal) {
			p := f.proposal(t)
			p.Bindings = f.bindings(f.succForBindings(t), f.sameRoot)
			return f.sameRoot, f.state, p
		}, evmassign.ErrEVMOnly},
		{"root entity without its EVM binding", func(t *testing.T, f *operatorAssignmentFixture) (*types.RootTrustBaseV1, *abdrc.StateMsg, *evmassign.Proposal) {
			p := f.proposal(t)
			p.Bindings = p.Bindings[:len(p.Bindings)-1]
			return f.next, f.state, p
		}, evmassign.ErrCoupling},
		{"binding to an EVM key that is not in the set", func(t *testing.T, f *operatorAssignmentFixture) (*types.RootTrustBaseV1, *abdrc.StateMsg, *evmassign.Proposal) {
			p := f.proposal(t)
			p.Bindings[0].EVMNodeID = "nobody"
			return f.next, f.state, p
		}, evmassign.ErrCoupling},
		{"acknowledgement still pending", func(t *testing.T, f *operatorAssignmentFixture) (*types.RootTrustBaseV1, *abdrc.StateMsg, *evmassign.Proposal) {
			f.state.CommittedHead.ShardInfo[0].IRTR.Epoch = 1
			return f.next, f.state, f.proposal(t)
		}, storage.ErrAssignmentAckPending},
		{"supersession without an unacknowledged assignment", func(t *testing.T, f *operatorAssignmentFixture) (*types.RootTrustBaseV1, *abdrc.StateMsg, *evmassign.Proposal) {
			p := f.proposal(t)
			p.Supersede = true
			return f.next, f.state, p
		}, ErrHandoffApproval},
		{"successor repeats an installed key", func(t *testing.T, f *operatorAssignmentFixture) (*types.RootTrustBaseV1, *abdrc.StateMsg, *evmassign.Proposal) {
			p := f.proposal(t)
			p.Validators = append(p.Validators, &types.NodeInfo{NodeID: "ev-z", SigKey: f.nextKeys[1].info.SigKey, Stake: 1})
			return f.next, f.state, p
		}, evmassign.ErrValidators},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newOperatorAssignmentFixture(t)
			next, state, proposal := tc.build(t, f)
			_, err := f.cm.buildHandoffPlanFromState(next, state, proposal)
			require.ErrorIs(t, err, ErrHandoffApproval)
			require.ErrorIs(t, err, tc.want)
			require.Empty(t, f.cm.handoffPlans, "a refused proposal leaves no endorsement state")
		})
	}
	t.Run("a root-only committee change on a coupled chain is refused by the planner", func(t *testing.T) {
		f := newOperatorAssignmentFixture(t)
		_, err := f.cm.buildHandoffPlanFromState(f.next, f.state, nil)
		require.ErrorIs(t, err, ErrHandoffApproval)
		require.ErrorIs(t, err, evmassign.ErrCoupling)
	})
	t.Run("a pending acknowledgement also refuses a root-only handoff", func(t *testing.T) {
		f := newOperatorAssignmentFixture(t)
		f.state.CommittedHead.ShardInfo[0].IRTR.Epoch = 1
		_, err := f.cm.buildHandoffPlanFromState(f.sameRoot, f.state, nil)
		require.ErrorIs(t, err, storage.ErrAssignmentAckPending)
	})
}

// The abort path names which condition tripped, so a moving frozen parent can be told apart from an uncommitted one.
func TestFrozenParentLossNamesTheCondition(t *testing.T) {
	f := newOperatorAssignmentFixture(t)
	frozen, newer := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{8}, 32)
	parentWith := func(hash []byte) *storage.ExecutedBlock {
		return &storage.ExecutedBlock{ShardState: storage.ShardStates{States: map[types.PartitionShardID]*storage.ShardInfo{
			{PartitionID: 8}: {PartitionID: 8, IR: &types.InputRecord{BlockHash: hash}}}}}
	}
	require.Contains(t, f.cm.frozenParentLoss(parentWith(frozen), newer, frozen), "differs from the plan")
	require.Contains(t, f.cm.frozenParentLoss(parentWith(newer), frozen, frozen), "no longer the frozen parent")
	require.Contains(t, f.cm.frozenParentLoss(parentWith(frozen), frozen, frozen), "not in the committed state",
		"the fixture's committed state does not hold this parent")
}

// An aggregator key replacement rides in the same handoff: the planner builds it, every endorser re-verifies it against its own
// committed checkpoint, and each refusal is isolated.
func TestOperatorBuildsAndVerifiesAnAggregatorKeyReplacement(t *testing.T) {
	type shardFixture struct {
		conf    *types.PartitionDescriptionRecord
		oldKey  evmSigner
		nextKey evmSigner
	}
	setup := func(t *testing.T) (*operatorAssignmentFixture, shardFixture) {
		sf := shardFixture{oldKey: newEVMSigner(t, "agg-old"), nextKey: newEVMSigner(t, "agg-new")}
		sf.conf = &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 9, PartitionTypeID: 9, TypeIDLen: 8, UnitIDLen: 256,
			T2Timeout: 2500 * time.Millisecond, Epoch: 0, EpochStart: 1,
			PartitionParams: map[string]string{"proof_type": "aggregator_rsmt_v1"}, Validators: []*types.NodeInfo{sf.oldKey.info}}
		f := newOperatorAssignmentFixture(t, sf.conf)
		f.state.CommittedHead.ShardInfo = append(f.state.CommittedHead.ShardInfo, abdrc.ShardInfo{Partition: 9, IR: &types.InputRecord{BlockHash: bytes.Repeat([]byte{3}, 32)}})
		return f, sf
	}
	change := func(t *testing.T, f *operatorAssignmentFixture, sf shardFixture, installed *types.PartitionDescriptionRecord, mutate func(*types.PartitionDescriptionRecord)) evmassign.Change {
		succ, err := evmassign.NewSuccessor(installed, []*types.NodeInfo{sf.nextKey.info})
		require.NoError(t, err)
		if mutate != nil {
			mutate(succ)
		}
		ctx := evmassign.PoPContext{Network: 5, Attempt: 0}
		copy(ctx.Predecessor[:], f.predecessor)
		pop, err := evmassign.SignPoP(sf.nextKey.signer, ctx, succ, sf.nextKey.id)
		require.NoError(t, err)
		ch, err := evmassign.EncodeReplaceShardValidators(installed.PartitionID, installed.ShardID, installed, succ, []evmassign.PoP{pop})
		require.NoError(t, err)
		return ch
	}

	t.Run("built, endorsed and re-verified by a voter", func(t *testing.T) {
		f, sf := setup(t)
		p := f.proposal(t)
		p.Changes = []evmassign.Change{change(t, f, sf, sf.conf, nil)}
		plan, err := f.cm.buildHandoffPlanFromState(f.next, f.state, p)
		require.NoError(t, err)
		c, err := evmassign.DecodeCandidate(plan.CandidatePreimage)
		require.NoError(t, err)
		require.Len(t, c.Changes, 1)
		require.NoError(t, f.cm.endorseHandoffAtState(context.Background(), plan, f.preparedState(t, plan)))
		// A tampered change in the preimage no longer matches the digest the body binds.
		tampered := plan
		tampered.Signer = f.node.PeerConf.ID.String()
		tampered.CandidatePreimage = append(bytes.Clone(plan.CandidatePreimage[:len(plan.CandidatePreimage)-1]), plan.CandidatePreimage[len(plan.CandidatePreimage)-1]^1)
		_, _, err = f.cm.validateHandoffApproval(&tampered)
		require.ErrorIs(t, err, ErrHandoffApproval)
	})

	refusals := []struct {
		name  string
		build func(t *testing.T, f *operatorAssignmentFixture, sf shardFixture) []evmassign.Change
		want  error
	}{
		{"a proof_type change", func(t *testing.T, f *operatorAssignmentFixture, sf shardFixture) []evmassign.Change {
			return []evmassign.Change{change(t, f, sf, sf.conf, func(s *types.PartitionDescriptionRecord) { s.PartitionParams["proof_type"] = "sp1" })}
		}, evmassign.ErrConfig},
		{"a configuration that is not the installed one", func(t *testing.T, f *operatorAssignmentFixture, sf shardFixture) []evmassign.Change {
			stale := *sf.conf
			stale.T2Timeout += time.Second
			return []evmassign.Change{change(t, f, sf, &stale, nil)}
		}, evmassign.ErrContext},
		{"a shard that does not exist", func(t *testing.T, f *operatorAssignmentFixture, sf shardFixture) []evmassign.Change {
			ghost := *sf.conf
			ghost.PartitionID = 77
			return []evmassign.Change{change(t, f, sf, &ghost, nil)}
		}, evmassign.ErrChange},
		{"a reserved kind", func(t *testing.T, f *operatorAssignmentFixture, sf shardFixture) []evmassign.Change {
			ch := change(t, f, sf, sf.conf, nil)
			ch.Kind = evmassign.ChangeAddPartition
			return []evmassign.Change{ch}
		}, evmassign.ErrUnsupportedChange},
		{"a possession proof for another attempt", func(t *testing.T, f *operatorAssignmentFixture, sf shardFixture) []evmassign.Change {
			succ, err := evmassign.NewSuccessor(sf.conf, []*types.NodeInfo{sf.nextKey.info})
			require.NoError(t, err)
			ctx := evmassign.PoPContext{Network: 5, Attempt: 3}
			copy(ctx.Predecessor[:], f.predecessor)
			pop, err := evmassign.SignPoP(sf.nextKey.signer, ctx, succ, sf.nextKey.id)
			require.NoError(t, err)
			ch, err := evmassign.EncodeReplaceShardValidators(9, sf.conf.ShardID, sf.conf, succ, []evmassign.PoP{pop})
			require.NoError(t, err)
			return []evmassign.Change{ch}
		}, evmassign.ErrPoP},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			f, sf := setup(t)
			p := f.proposal(t)
			p.Changes = tc.build(t, f, sf)
			_, err := f.cm.buildHandoffPlanFromState(f.next, f.state, p)
			require.ErrorIs(t, err, ErrHandoffApproval)
			require.ErrorIs(t, err, tc.want)
			require.Empty(t, f.cm.handoffPlans, "a refused proposal leaves no endorsement state")
		})
	}
	t.Run("an unacknowledged aggregator configuration", func(t *testing.T) {
		f, sf := setup(t)
		f.state.CommittedHead.ShardInfo[1].IRTR.Epoch = 1
		p := f.proposal(t)
		p.Changes = []evmassign.Change{change(t, f, sf, sf.conf, nil)}
		_, err := f.cm.buildHandoffPlanFromState(f.next, f.state, p)
		require.ErrorIs(t, err, storage.ErrAssignmentAckPending)
	})
}
