package storage

import (
	"crypto"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// #1177 review r2 (astra): whether a P85 Abort closes the primary's session is a fact of the authenticated endorsed state, not of what a root
// retained. A root recovered from a committed head after the Freeze (it never executed the Freeze, so it holds no candidate) executes the
// same certified Abort to the same state as the root that did: same root hash, R resolved in both. Recovery over the certified Abort then
// validates.
func TestP85AbortAfterRecoveryIsTheSameAsOnTheRootThatSawTheFreeze(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	first := f.build(t, f.candidate(t))
	require.NoError(t, f.admit(t, first)) // Prepare 2, an authorized primary Freeze 3
	committed := f.addAt(t, 4)
	parent := f.addAt(t, 5) // the empty successor certifies the endorsed head
	result := candidateOf(t, first.preimage).ResultID()
	require.Equal(t, result[:], parent.ShardState.Control.PrimaryResult, "the endorsed state records the Freeze's primary result")
	makeHead := func(b *ExecutedBlock) *abdrc.CommittedBlock {
		h := &abdrc.CommittedBlock{Block: b.BlockData, Control: b.ShardState.Control,
			CommitQc: &rctypes.QuorumCert{LedgerCommitInfo: &types.UnicitySeal{Hash: b.RootHash}}}
		var err error
		h.ShardInfo, err = toRecoveryShardInfo(b)
		require.NoError(t, err)
		return consistentHead(t, h, f.orch, ProfileHandoff)
	}
	configure := func(s *BlockStore) (IRChangeReqVerifier, error) {
		return nil, s.ConfigureHandoffAuthority(f.tb)
	}
	head := makeHead(committed)
	parent.BlockData.Qc = head.Qc
	head.CommitQc.VoteInfo.Timestamp = parent.BlockData.Timestamp
	head.CommitQc.VoteInfo.CurrentRootHash = parent.RootHash
	state := &abdrc.StateMsg{CommittedHead: head, Pending: []*rctypes.BlockData{parent.BlockData}}
	require.NoError(t, ValidateRecoveryState(crypto.SHA256, state, 5, f.orch, nil, configure, logger.New(t), ProfileHandoff))
	db, err := NewBoltStorage(filepath.Join(t.TempDir(), "recovered.db"), WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	recovered, err := NewFromState(crypto.SHA256, head, db, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	require.NoError(t, recovered.ConfigureHandoffAuthority(f.tb))
	_, err = recovered.ProcessQc(parent.BlockData.Qc)
	require.NoError(t, err)
	_, err = recovered.Add(parent.BlockData, nil)
	require.NoError(t, err)
	require.Equal(t, parent.RootHash, mustBlock(t, recovered, 5).RootHash)
	raw, err := recovered.HandoffCandidate(first.freeze.NextBodyID)
	require.NoError(t, err)
	require.Empty(t, raw, "the recovered root never retained the Freeze's candidate")

	// recovery before the Abort: the same certified Abort, the same state
	abort := first.freeze
	abort.Kind, abort.OrderedRound = "abort", 6
	block := &rctypes.BlockData{Version: 3, Round: 6, Epoch: 1, Timestamp: 4_000,
		Payload: &rctypes.Payload{Version: 3, HandoffRecords: [][]byte{abort.Bytes(), f.abortCompanionFor(t, abort)}},
		Qc:      head.CommitQc}
	warm, err := f.store.Add(block, nil)
	require.NoError(t, err)
	cold, err := recovered.Add(block, nil)
	require.NoError(t, err)
	require.Equal(t, warm, cold, "the same endorsed parent and the same Abort give the same state root")
	require.True(t, posOfBlock(t, mustBlock(t, f.store, 6)).IsResolved(result))
	require.True(t, posOfBlock(t, mustBlock(t, recovered, 6)).IsResolved(result), "the recovered root closes R as well")
	require.Empty(t, mustBlock(t, f.store, 6).ShardState.Control.PrimaryResult, "the aborted state records no result")

	// recovery over the certified Abort replays it
	nextHead := makeHead(parent)
	block.Qc = nextHead.Qc
	nextHead.CommitQc.VoteInfo.Timestamp = block.Timestamp
	nextHead.CommitQc.VoteInfo.CurrentRootHash = warm
	require.NoError(t, ValidateRecoveryState(crypto.SHA256, &abdrc.StateMsg{CommittedHead: nextHead, Pending: []*rctypes.BlockData{block}}, 6,
		f.orch, nil, configure, logger.New(t), ProfileHandoff), "recovery over the certified Abort")
}
