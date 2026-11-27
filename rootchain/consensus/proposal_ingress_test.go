package consensus

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

func changeReqOfProof(partition types.PartitionID, proof int) *drctypes.IRChangeReq {
	return &drctypes.IRChangeReq{Partition: partition, CertReason: drctypes.Quorum, Requests: []*certification.BlockCertificationRequest{
		{PartitionID: partition, NodeID: "n", InputRecord: &types.InputRecord{Version: 1}, ZkProof: make([]byte, proof)},
	}}
}

func proposalOf(reqs ...*drctypes.IRChangeReq) *abdrc.ProposalMsg {
	return &abdrc.ProposalMsg{Block: &drctypes.BlockData{Round: 3, Epoch: 1, Payload: &drctypes.Payload{Requests: reqs}}}
}

// #1113: the leader keeps its proposal within the frame limit every root enforces, leaving out the largest change requests first.
func TestFitProposal(t *testing.T) {
	t.Run("a proposal within the limit is unchanged", func(t *testing.T) {
		p := proposalOf(changeReqOfProof(1, 1000), changeReqOfProof(2, 2000))
		dropped, err := fitProposal(p, 1<<20)
		require.NoError(t, err)
		require.Empty(t, dropped)
		require.Len(t, p.Block.Payload.Requests, 2)
	})

	t.Run("the largest requests are left out until it fits", func(t *testing.T) {
		small, mid, big := changeReqOfProof(1, 10_000), changeReqOfProof(2, 40_000), changeReqOfProof(3, 90_000)
		p := proposalOf(small, big, mid)
		dropped, err := fitProposal(p, 60_000)
		require.NoError(t, err)
		require.Equal(t, []*drctypes.IRChangeReq{big}, dropped)
		require.Equal(t, []*drctypes.IRChangeReq{small, mid}, p.Block.Payload.Requests, "the others keep their order")
		size, err := encodedSize(p)
		require.NoError(t, err)
		require.LessOrEqual(t, size, uint64(60_000))

		p = proposalOf(small, big, mid)
		dropped, err = fitProposal(p, 30_000)
		require.NoError(t, err)
		require.Equal(t, []*drctypes.IRChangeReq{big, mid}, dropped)
		require.Equal(t, []*drctypes.IRChangeReq{small}, p.Block.Payload.Requests)
	})

	t.Run("a request alone over the limit is left out", func(t *testing.T) {
		p := proposalOf(changeReqOfProof(1, 100_000))
		dropped, err := fitProposal(p, 50_000)
		require.NoError(t, err)
		require.Len(t, dropped, 1)
		require.Empty(t, p.Block.Payload.Requests)
	})

	t.Run("a proposal over the limit without requests is an error", func(t *testing.T) {
		p := proposalOf(changeReqOfProof(1, 100))
		p.Block.Payload.HandoffRecords = [][]byte{make([]byte, 10_000)}
		p.Block.Payload.Version = drctypes.VersionHandoff
		_, err := fitProposal(p, 5_000)
		require.ErrorContains(t, err, "without change requests")
	})

	t.Run("the limit is the network's, less room for the signature", func(t *testing.T) {
		p := proposalOf(changeReqOfProof(1, abdrc.MaxProposalFrame-proposalSignatureRoom), changeReqOfProof(2, 1000))
		dropped, err := fitProposal(p, abdrc.MaxProposalFrame-proposalSignatureRoom)
		require.NoError(t, err)
		require.Len(t, dropped, 1)
		require.Len(t, p.Block.Payload.Requests, 1)
		p.Signature = make([]byte, 96)
		size, err := encodedSize(p)
		require.NoError(t, err)
		require.LessOrEqual(t, size, uint64(abdrc.MaxProposalFrame))
	})
}

// #1113: proposals are admitted from the installed committee and the staged successor, and the admitted set follows them.
func TestKnownRootAndEligibleProposer(t *testing.T) {
	a, b, c, d := peer.ID("root-a"), peer.ID("root-b"), peer.ID("root-c"), peer.ID("root-d")
	x := &ConsensusManager{}
	require.False(t, x.KnownRoot(a), "no trust base: nobody")
	tb := &types.RootTrustBaseV1{Epoch: 4, RootNodes: []*types.NodeInfo{{NodeID: a.String()}, {NodeID: b.String()}}}
	x.trustBase.Store(tb)
	require.True(t, x.KnownRoot(a))
	require.True(t, x.KnownRoot(b))
	require.False(t, x.KnownRoot(c))

	x.q3StagedEVM.Store(&stagedEVMMembers{epoch: 5, roots: map[string]struct{}{c.String(): {}}})
	require.True(t, x.KnownRoot(c), "a root of the staged successor")
	require.False(t, x.KnownRoot(d))
	x.q3StagedEVM.Store(&stagedEVMMembers{epoch: 7, roots: map[string]struct{}{d.String(): {}}})
	require.False(t, x.KnownRoot(d), "a successor staged for another epoch is not the next one")
	require.False(t, x.KnownRoot(c), "and the earlier staging is gone")

	x.trustBase.Store(&types.RootTrustBaseV1{Epoch: 6, RootNodes: []*types.NodeInfo{{NodeID: c.String()}}})
	require.True(t, x.KnownRoot(c), "the set follows the installed trust base")
	require.True(t, x.KnownRoot(d), "and its staged successor")
	require.False(t, x.KnownRoot(a))

	require.False(t, x.EligibleProposer(a), "nothing published")
	x.proposers.Store(&proposerSet{round: 7, ids: [2]peer.ID{a, b}})
	require.True(t, x.EligibleProposer(a))
	require.True(t, x.EligibleProposer(b))
	require.False(t, x.EligibleProposer(c))
	x.proposers.Store(&proposerSet{round: 8, ids: [2]peer.ID{c, ""}})
	require.False(t, x.EligibleProposer(""), "an unknown leader is no one")
}

// The room fitProposal leaves for the controls ordered after it holds the largest control set a block can carry: MaxPosControls
// RuleSupport controls of MaxRuleSupportCommitments commitments each, the widest control shape.
func TestProposalControlRoom(t *testing.T) {
	commitments := make([]drctypes.SupportCommitment, drctypes.MaxRuleSupportCommitments)
	for i := range commitments {
		id := make([]byte, 32)
		id[0], id[1] = byte(i>>8), byte(i)
		commitments[i] = drctypes.SupportCommitment{Network: 1<<64 - 1, StakingID: id, Generation: 1<<64 - 1, RootKeyHash: make([]byte, 32), BindingRef: make([]byte, 32),
			RuleID: make([]byte, 32), ReleaseDigest: make([]byte, 32), Sig: make([]byte, 65)}
	}
	controls := make([]drctypes.PosControl, drctypes.MaxPosControls)
	for i := range controls {
		controls[i] = drctypes.PosControl{Network: 1<<64 - 1, OrderingEpoch: 1<<64 - 1, OrderingRound: 1<<64 - 1, Op: drctypes.OpRuleSupport,
			Registry: true, Support: commitments}
	}
	empty, err := encodedSize(&drctypes.Payload{Version: drctypes.VersionHandoff})
	require.NoError(t, err)
	full, err := encodedSize(&drctypes.Payload{Version: drctypes.VersionHandoff, PosControls: controls})
	require.NoError(t, err)
	require.Greater(t, full-empty, uint64(drctypes.MaxPosControls*drctypes.MaxRuleSupportCommitments*65), "the commitments were encoded")
	require.Less(t, full-empty, uint64(proposalControlRoom))
}
