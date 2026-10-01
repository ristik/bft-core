package consensus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"path/filepath"
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
	state       *abdrc.StateMsg
	parent      []byte
	current     *types.PartitionDescriptionRecord
	oldKeys     []evmSigner
	nextKeys    []evmSigner
	predecessor []byte
	others      []*testutils.TestNode
	node        *testutils.TestNode
}

func newOperatorAssignmentFixture(t *testing.T) *operatorAssignmentFixture {
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
		PartitionParams: map[string]string{"seal_registry_genesis": "g"}, Validators: infos}
	require.NoError(t, orchestration.AddShardConfig(f.current))

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
	next := *f.old
	next.Epoch = 2 // EVM-only rotation: identical root members, root epoch still advances
	f.next = &next
	f.state, err = f.cm.blockStore.GetState()
	require.NoError(t, err)
	f.state.CommittedHead.ShardInfo = []abdrc.ShardInfo{{Partition: 8, IR: &types.InputRecord{BlockHash: f.parent}}}
	f.predecessor, err = f.cm.handoffPredecessor()
	require.NoError(t, err)

	f.nextKeys = []evmSigner{f.oldKeys[0], newEVMSigner(t, "ev-e"), newEVMSigner(t, "ev-f"), newEVMSigner(t, "ev-g")}
	return f
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
	copy(ctx.Parent[:], f.parent)
	for _, m := range mutate {
		m(&ctx)
	}
	p := &evmassign.Proposal{Validators: infos}
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

func TestOperatorBuildsAssignmentCandidateAndEndorsersVerifyIt(t *testing.T) {
	f := newOperatorAssignmentFixture(t)
	plan, err := f.cm.buildHandoffPlanFromState(f.next, f.parent, f.state, f.proposal(t))
	require.NoError(t, err)
	require.NotEmpty(t, plan.CandidatePreimage)
	digest := sha256.Sum256(plan.CandidatePreimage)
	require.Equal(t, digest[:], plan.Candidate, "the approval's candidate hash is the preimage digest")
	// The body's change-record context binds that digest.
	body, err := storage.DecodeHandoffBody(plan.Body)
	require.NoError(t, err)
	require.Equal(t, evmroot.D4CandidateContextHash(5, f.predecessor, plan.Attempt, plan.Candidate, body.EarliestActivation), body.ChangeRecordHash)

	require.NoError(t, f.cm.endorseHandoffAtState(context.Background(), plan, f.state))
	require.Len(t, f.cm.handoffPlans, 1)

	// A peer's endorsement with the preimage altered is refused before it is cached.
	tampered := plan
	tampered.Signer = f.node.PeerConf.ID.String()
	tampered.CandidatePreimage = append(bytes.Clone(plan.CandidatePreimage[:len(plan.CandidatePreimage)-1]), plan.CandidatePreimage[len(plan.CandidatePreimage)-1]^1)
	_, _, err = f.cm.validateHandoffApproval(&tampered)
	require.ErrorIs(t, err, ErrHandoffApproval)

	// A root-only plan carries no preimage and keeps the legacy candidate hash.
	root, err := f.cm.buildHandoffPlanFromState(f.next, f.parent, f.state, nil)
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
		{"PoP for another frozen parent", func(t *testing.T, f *operatorAssignmentFixture) (*types.RootTrustBaseV1, *abdrc.StateMsg, *evmassign.Proposal) {
			return f.next, f.state, f.proposal(t, func(c *evmassign.PoPContext) { c.Parent = [32]byte{1} })
		}, evmassign.ErrPoP},
		{"PoP for another predecessor", func(t *testing.T, f *operatorAssignmentFixture) (*types.RootTrustBaseV1, *abdrc.StateMsg, *evmassign.Proposal) {
			return f.next, f.state, f.proposal(t, func(c *evmassign.PoPContext) { c.Predecessor = [32]byte{1} })
		}, evmassign.ErrPoP},
		{"combined root and EVM change", func(t *testing.T, f *operatorAssignmentFixture) (*types.RootTrustBaseV1, *abdrc.StateMsg, *evmassign.Proposal) {
			changed := *f.next
			changed.RootNodes = append([]*types.NodeInfo(nil), f.next.RootNodes...)
			replacement := testutils.NewTestNode(t)
			v, err := replacement.Signer.Verifier()
			require.NoError(t, err)
			key, err := v.MarshalPublicKey()
			require.NoError(t, err)
			changed.RootNodes[3] = &types.NodeInfo{NodeID: replacement.PeerConf.ID.String(), SigKey: key, Stake: 1}
			return &changed, f.state, f.proposal(t)
		}, evmassign.ErrCombined},
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
			_, err := f.cm.buildHandoffPlanFromState(next, f.parent, state, proposal)
			require.ErrorIs(t, err, ErrHandoffApproval)
			require.ErrorIs(t, err, tc.want)
			require.Empty(t, f.cm.handoffPlans, "a refused proposal leaves no endorsement state")
		})
	}
	t.Run("a pending acknowledgement also refuses a root-only handoff", func(t *testing.T) {
		f := newOperatorAssignmentFixture(t)
		f.state.CommittedHead.ShardInfo[0].IRTR.Epoch = 1
		_, err := f.cm.buildHandoffPlanFromState(f.next, f.parent, f.state, nil)
		require.ErrorIs(t, err, storage.ErrAssignmentAckPending)
	})
}
