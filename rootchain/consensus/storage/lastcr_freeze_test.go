package storage

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// commitUCs is lastCRPipeline.commit that returns the responses the commit generated.
func (p *lastCRPipeline) commitUCs(s *BlockStore, round uint64) ([]*certification.CertificationResponse, error) {
	b := mustBlock(p.t, s, round)
	return s.blockTree.Commit(&rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round + 1, ParentRoundNumber: round, Epoch: 2},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: round, Epoch: 2, Timestamp: 1_000 + round, Hash: b.RootHash}})
}

// Freeze/suppression (#475): a commit whose block and previous root both hold the committed handoff control record of the same epoch
// clears the block's changes, so no certification response is generated: the committed block and every descendant keep the root's
// pair, seal time and identity. A certification after the suppression propagates normally.
func TestCommittedControlSuppressesTheResponseAndKeepsThePair(t *testing.T) {
	p := newLastCRPipeline(t)
	s := p.s
	committed := func() *evmroot.ControlState {
		return &evmroot.ControlState{Network: 5, Epoch: 1, Phase: "committed", OrderedRound: 7, PredecessorBodyID: bytes.Repeat([]byte{1}, 32)}
	}
	_, err := p.add(s, 8, 7, p.timeout())
	require.NoError(t, err)
	b9, err := p.add(s, 9, 8)
	require.NoError(t, err)
	b10, err := p.add(s, 10, 9)
	require.NoError(t, err)
	require.Contains(t, mustBlock(t, s, 8).ShardState.Changed, p.f.shard, "premise: without the control record the timeout would certify")

	s.blockTree.root.data.ShardState.Control = committed()
	b8 := mustBlock(t, s, 8)
	b8.ShardState.Control = committed()
	tree, _, err := b8.ShardState.UnicityTree(crypto.SHA256) // the control leaf is part of the block's state root
	require.NoError(t, err)
	b8.RootHash = tree.RootHash()
	before := s.blockTree.root.data.ShardState.States[p.f.shard].LastCR
	ucs, err := p.commitUCs(s, 8)
	require.NoError(t, err)

	require.Empty(t, ucs, "no response is generated under a committed control record of the same epoch")
	require.Empty(t, mustBlock(t, s, 8).ShardState.Changed)
	for _, b := range []*ExecutedBlock{mustBlock(t, s, 8), b9, b10} {
		require.Same(t, before, b.ShardState.States[p.f.shard].LastCR, "round %d keeps the root's pair", b.GetRound())
	}
	require.EqualValues(t, 1, before.UC.UnicitySeal.RootChainRoundNumber, "the seal time and identity of the pair are unchanged")

	// a certification after the suppression (a block that no longer carries the same-epoch committed record) propagates normally
	tr := b10.ShardState.States[p.f.shard].TR // the executed repeat moved the technical record; the pair itself did not
	b11, err := p.add(s, 11, 10, p.proof(b10, reqOpts{round: tr.Round, epoch: tr.Epoch}, p.members()...))
	require.NoError(t, err)
	require.Contains(t, b11.ShardState.Changed, p.f.shard)
	ucs, err = p.commitUCs(s, 11)
	require.NoError(t, err)
	require.NotEmpty(t, ucs)
	fresh := b11.ShardState.States[p.f.shard].LastCR
	require.NotSame(t, before, fresh)
	require.EqualValues(t, 11, fresh.UC.UnicitySeal.RootChainRoundNumber)
}
