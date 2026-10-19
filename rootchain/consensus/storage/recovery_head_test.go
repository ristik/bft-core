package storage

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// consistentHead is the committed head a running root would send for a hand-built root block: the block's own QC and the QC of the next round
// that commits it, with the relationships (round, parent, epoch, time, state root) that recovery validates. The signatures are not checked where
// a head is installed (StateMsg.Verify does that, before), so none are made.
func consistentHead(t *testing.T, head *abdrc.CommittedBlock, orch Orchestration, profile uint64) *abdrc.CommittedBlock {
	t.Helper()
	built, err := NewRootBlock(head, crypto.SHA256, orch, profile)
	require.NoError(t, err)
	out := *head
	// a shard info of a hand-built head without a last response gets the one a committed shard has
	out.ShardInfo = append([]abdrc.ShardInfo(nil), head.ShardInfo...)
	for i := range out.ShardInfo {
		d := &out.ShardInfo[i]
		if d.UC != nil && d.TR != nil {
			continue
		}
		tr := d.IRTR
		trHash, err := tr.Hash()
		require.NoError(t, err)
		d.TR = &tr
		d.UC = &types.UnicityCertificate{Version: 1, InputRecord: d.IR, TRHash: trHash, ShardConfHash: d.ShardConfHash,
			UnicityTreeCertificate: &types.UnicityTreeCertificate{Version: 1, Partition: d.Partition},
			ShardTreeCertificate:   types.ShardTreeCertificate{Shard: d.Shard},
			UnicitySeal:            &types.UnicitySeal{Version: 1}}
	}
	b := head.Block
	info := &rctypes.RoundInfo{RoundNumber: b.Round, ParentRoundNumber: b.GetParentRound(), Epoch: b.Epoch, Timestamp: b.Timestamp, CurrentRootHash: built.RootHash}
	out.Qc = &rctypes.QuorumCert{VoteInfo: info, LedgerCommitInfo: &types.UnicitySeal{Version: 1, Hash: built.RootHash, RootChainRoundNumber: b.Round, Epoch: b.Epoch, Timestamp: b.Timestamp}}
	out.CommitQc = &rctypes.QuorumCert{
		VoteInfo:         &rctypes.RoundInfo{RoundNumber: b.Round + 1, ParentRoundNumber: b.Round, Epoch: b.Epoch, Timestamp: b.Timestamp},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, Hash: built.RootHash, RootChainRoundNumber: b.Round, Epoch: b.Epoch, Timestamp: b.Timestamp},
	}
	return &out
}
