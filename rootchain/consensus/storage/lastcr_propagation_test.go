package storage

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

func lastCRFixture(f *assignmentFixture, si *ShardInfo) {
	si.IR.BlockHash = bytes.Clone(f.parent)
	ir := &types.InputRecord{Version: 1, RoundNumber: si.TR.Round, Epoch: si.TR.Epoch, PreviousHash: []byte{1}, Hash: si.RootHash,
		BlockHash: bytes.Clone(f.parent), SummaryValue: []byte{3}, Timestamp: fxTimestamp}
	trHash, _ := si.TR.Hash()
	si.LastCR = &certification.CertificationResponse{Partition: si.PartitionID, Shard: si.ShardID, Technical: si.TR,
		UC: types.UnicityCertificate{Version: 1, InputRecord: ir, TRHash: trHash,
			UnicityTreeCertificate: &types.UnicityTreeCertificate{Version: 1, Partition: si.PartitionID},
			UnicitySeal:            &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: 1, Timestamp: fxTimestamp, Hash: []byte{4}}}}
}

// A pipeline executed BEFORE a T2 commit: the committed repeat UC replaces the LastCR pair of every surviving descendant, with the
// state roots and block identities of the descendants untouched, and the next view resolved on a pre-existing tip uses the new pair
// (another PrevUCDigest, another ViewKey), not the pair that was current when the tip was executed. A sibling of the committed block is
// not rewritten.
func TestCommittedRepeatUCReachesTheExecutedDescendants(t *testing.T) {
	// the sibling fork is a separate run: the store keeps the persisted blocks of a pruned fork above the new root, which a reopen refuses
	t.Run("with a sibling fork", func(t *testing.T) { committedRepeatUCScenario(t, true) })
	t.Run("and a reopen", func(t *testing.T) { committedRepeatUCScenario(t, false) })
}

func committedRepeatUCScenario(t *testing.T, withSibling bool) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.installShard(t, f.current, func(si *ShardInfo) { lastCRFixture(f, si) })
	h := f.commitAssignment(t)
	anchorBlock, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	f.addSuccessorBlock(t, s, 7, anchorBlock)

	genesisAnchor, err := NewRequestAnchor(f.current, crypto.SHA256, 1, f.predecessor, fxVersion)
	require.NoError(t, err)
	body := bytes.Clone(h.commit.NextBodyID)
	activation, err := newRequestActivation(h.activated, crypto.SHA256, quorumweight.PolicyUnit, nil, h.genesis.Epoch, body, h.genesis.Start, h.successorT, fxVersion)
	require.NoError(t, err)
	hist := activeHistory{chain: []*RequestActivation{genesisAnchor, activation}, body: body}
	verifier := &viewVerifier{t: t, history: hist}
	add := func(round, parent uint64, reqs ...*rctypes.IRChangeReq) *ExecutedBlock {
		t.Helper()
		p := mustBlock(t, s, parent)
		_, err := s.Add(&rctypes.BlockData{Version: 2, Round: round, Epoch: 2, Timestamp: 1_000 + round, Payload: &rctypes.Payload{Version: 2, Requests: reqs},
			Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: parent, Epoch: 2, CurrentRootHash: p.RootHash}}}, verifier)
		require.NoError(t, err)
		return mustBlock(t, s, round)
	}
	timeout := &rctypes.IRChangeReq{Partition: f.current.PartitionID, CertReason: rctypes.T2Timeout}

	b8 := add(8, 7, timeout)
	b9 := add(9, 8)
	b10 := add(10, 9)
	var sibling *ExecutedBlock
	if withSibling {
		sibling = add(11, 7)
	}
	old := b10.ShardState.States[f.shard].LastCR
	require.EqualValues(t, 1, old.UC.UnicitySeal.RootChainRoundNumber, "premise: the tip executed on the predecessor's record")

	rootsBefore := map[uint64][]byte{8: bytes.Clone(b8.RootHash), 9: bytes.Clone(b9.RootHash), 10: bytes.Clone(b10.RootHash)}
	idsBefore := map[uint64][]byte{}
	for round, b := range map[uint64]*ExecutedBlock{9: b9, 10: b10} {
		id, err := b.BlockData.Hash(crypto.SHA256)
		require.NoError(t, err)
		idsBefore[round] = id
	}
	resolve := func(tip *ExecutedBlock) *RequestRoundView {
		t.Helper()
		id, err := tip.BlockData.Hash(crypto.SHA256)
		require.NoError(t, err)
		v, err := ResolveParentView(hist, nil, tip.ShardState.States[f.shard], id, tip.GetRound()+1, crypto.SHA256, PurposeExecute, nil)
		require.NoError(t, err)
		return v
	}
	viewBefore := resolve(b10)

	_, err = s.blockTree.Commit(&rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 9, ParentRoundNumber: 8, Epoch: 2},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: 8, Epoch: 2, Timestamp: 1_008, Hash: b8.RootHash}})
	require.NoError(t, err)

	fresh := b8.ShardState.States[f.shard].LastCR
	require.NotSame(t, old, fresh)
	require.EqualValues(t, 8, fresh.UC.UnicitySeal.RootChainRoundNumber, "the committed block generated the repeat UC")
	for _, b := range []*ExecutedBlock{b9, b10} {
		require.Same(t, fresh, b.ShardState.States[f.shard].LastCR, "round %d", b.GetRound())
	}
	require.EqualValues(t, 1, old.UC.UnicitySeal.RootChainRoundNumber, "the old response is never edited")
	if withSibling {
		require.EqualValues(t, 1, sibling.ShardState.States[f.shard].LastCR.UC.UnicitySeal.RootChainRoundNumber, "the sibling subtree is not a descendant of the committed block")
	}

	// nothing else about a descendant moves
	require.Equal(t, rootsBefore[9], []byte(b9.RootHash))
	require.Equal(t, rootsBefore[10], []byte(b10.RootHash))
	for round, b := range map[uint64]*ExecutedBlock{9: b9, 10: b10} {
		id, err := b.BlockData.Hash(crypto.SHA256)
		require.NoError(t, err)
		require.Equal(t, idsBefore[round], id)
		_, _, err = b.ShardState.UnicityTree(crypto.SHA256)
		require.NoError(t, err)
	}

	// a view resolved on the pre-existing tip is the view of the new pair
	viewAfter := resolve(b10)
	require.NotEqual(t, viewBefore.ViewKey(), viewAfter.ViewKey())
	require.EqualValues(t, 1, viewBefore.prevUC.UnicitySeal.RootChainRoundNumber)
	require.EqualValues(t, 8, viewAfter.prevUC.UnicitySeal.RootChainRoundNumber)
	require.Equal(t, viewAfter.prevUC.UnicitySeal.Timestamp, resolve(mustBlock(t, s, 8)).prevUC.UnicitySeal.Timestamp,
		"the descendants and the committed root agree on the previous UC")

	// a store reopened after the commit, whose persisted pending blocks still hold the old pair, normalises them from the persisted root
	if withSibling {
		return
	}
	reopened, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	for _, round := range []uint64{9, 10} {
		require.EqualValues(t, 8, mustBlock(t, reopened, round).ShardState.States[f.shard].LastCR.UC.UnicitySeal.RootChainRoundNumber, "round %d", round)
	}
}

// Only descendants of the root receive its pairs; a shard the root does not have gets nothing, a root pair that is nil replaces nothing.
func TestPropagateLastCRIsolation(t *testing.T) {
	shard, other := types.PartitionShardID{PartitionID: 1}, types.PartitionShardID{PartitionID: 2}
	cr := func(seal uint64) *certification.CertificationResponse {
		return &certification.CertificationResponse{Partition: 1, UC: types.UnicityCertificate{UnicitySeal: &types.UnicitySeal{RootChainRoundNumber: seal}}}
	}
	mk := func(round uint64, c *certification.CertificationResponse) *node {
		b := mockExecutedBlock(round, round-1)
		b.ShardState.States[shard] = &ShardInfo{LastCR: c}
		return newNode(&b)
	}
	root, child, grand, sibling := mk(5, cr(5)), mk(6, cr(1)), mk(7, cr(1)), mk(8, cr(1))
	root.data.ShardState.States[other] = &ShardInfo{} // a root shard without a response replaces nothing
	child.data.ShardState.States[other] = &ShardInfo{LastCR: cr(3)}
	grand.data.ShardState.States[types.PartitionShardID{PartitionID: 3}] = &ShardInfo{} // a shard the root does not have
	root.addChild(child)
	child.addChild(grand)
	propagateLastCR(root)
	require.Same(t, root.data.ShardState.States[shard].LastCR, child.data.ShardState.States[shard].LastCR)
	require.Same(t, root.data.ShardState.States[shard].LastCR, grand.data.ShardState.States[shard].LastCR)
	require.EqualValues(t, 3, child.data.ShardState.States[other].LastCR.UC.UnicitySeal.RootChainRoundNumber, "a nil root pair is not copied")
	require.Nil(t, grand.data.ShardState.States[types.PartitionShardID{PartitionID: 3}].LastCR)
	require.EqualValues(t, 1, sibling.data.ShardState.States[shard].LastCR.UC.UnicitySeal.RootChainRoundNumber, "not a descendant")
}
