package handoff

import (
	"bytes"
	"crypto"
	stdhex "encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

type emptyRootOrchestration struct{}

func (emptyRootOrchestration) NetworkID() types.NetworkID { return 5 }
func (emptyRootOrchestration) ShardConfig(types.PartitionID, types.ShardID, uint64) (*types.PartitionDescriptionRecord, error) {
	return nil, nil
}
func (emptyRootOrchestration) ShardConfigs(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
	return map[types.PartitionShardID]*types.PartitionDescriptionRecord{}, nil
}

func signedOldProof(t *testing.T) (OldCommitProof, *types.RootTrustBaseV1) {
	t.Helper()
	signers := map[string]abcrypto.Signer{}
	for _, id := range []string{"a", "b", "c", "d"} {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		signers[id] = s
	}
	tb := testtrustbase.NewTrustBaseFromSigners(t, signers).(*types.RootTrustBaseV1)
	frozen, body, tr := bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32)
	rec := evmroot.OrderedHandoffRecord{Network: 5, Epoch: tb.Epoch, Attempt: 0, OrderedRound: 4, ActivationRound: 7,
		PredecessorBodyID: make([]byte, 32), FrozenID: frozen, NextBodyID: body, SuccessorTRHash: tr, Kind: "commit"}
	parent, err := storage.NewGenesisBlock(5, crypto.SHA256, storage.ProfileHandoff)
	require.NoError(t, err)
	for _, item := range []struct {
		round            uint64
		kind             string
		frozen, body, tr []byte
	}{
		{2, "prepare", make([]byte, 32), body, make([]byte, 32)},
		{3, "freeze", frozen, body, make([]byte, 32)},
		{4, "commit", frozen, body, tr},
	} {
		ordered := evmroot.OrderedHandoffRecord{Network: 5, Epoch: rec.Epoch, Attempt: 0, OrderedRound: item.round, ActivationRound: 7,
			PredecessorBodyID: rec.PredecessorBodyID, FrozenID: item.frozen, NextBodyID: item.body, SuccessorTRHash: item.tr, Kind: item.kind}
		block := &rctypes.BlockData{Version: 2, Round: item.round, Epoch: rec.Epoch, Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{ordered.Bytes()}},
			Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: item.round - 1, Epoch: rec.Epoch}}}
		parent, err = parent.Extend(block, nil, emptyRootOrchestration{}, crypto.SHA256, slog.Default())
		require.NoError(t, err)
	}
	control := *parent.ShardState.Control
	tree, _, err := parent.ShardState.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	path, err := tree.Certificate(evmroot.D4ControlPartition)
	require.NoError(t, err)
	stamp := types.NewTimestamp()
	vote := &rctypes.RoundInfo{Version: 1, RoundNumber: 5, Epoch: rec.Epoch, Timestamp: stamp, ParentRoundNumber: 4, CurrentRootHash: tree.RootHash()}
	voteHash, err := vote.Hash(crypto.SHA256)
	require.NoError(t, err)
	seal := &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: 4, Epoch: rec.Epoch, Timestamp: stamp, Hash: tree.RootHash(), PreviousHash: voteHash}
	signed, err := seal.SigBytes()
	require.NoError(t, err)
	qc := &rctypes.QuorumCert{VoteInfo: vote, LedgerCommitInfo: seal, Signatures: map[string]hex.Bytes{}}
	for _, id := range []string{"a", "b", "c"} {
		sig, err := signers[id].SignBytes(signed)
		require.NoError(t, err)
		qc.Signatures[id] = sig
	}
	return OldCommitProof{Profile: evmroot.D4Profile, Record: rec, Control: control, ControlPath: path, CommitQC: qc}, tb
}

func TestVerifyOldCommitProofSecp256k1(t *testing.T) {
	p, tb := signedOldProof(t)
	v, err := VerifyOldCommitProof(p, tb)
	require.NoError(t, err)
	require.Equal(t, uint64(4), v.OrderRound)
	require.Equal(t, uint64(4), v.CommitSealRound)
	require.Equal(t, p.Record.ID(), v.RecordID[:])
	var context Context
	context.Network, context.Epoch, context.MinActivation = 5, tb.Epoch, 7
	copy(context.Predecessor[:], p.Record.PredecessorBodyID)
	bound, err := VerifyOldCommitProof(p, tb, context)
	require.NoError(t, err)
	require.Equal(t, context, bound.Context)
	context.MinActivation = 8
	_, err = VerifyOldCommitProof(p, tb, context)
	require.ErrorIs(t, err, ErrProof)
	for _, tc := range []struct {
		name   string
		change func(*OldCommitProof)
	}{
		{"missing_path", func(p *OldCommitProof) { p.ControlPath = nil }},
		{"wrong_key", func(p *OldCommitProof) { p.ControlPath.Partition = 1 }},
		{"forged_control", func(p *OldCommitProof) { p.Control.OrderedRound++ }},
		{"under_quorum", func(p *OldCommitProof) { delete(p.CommitQC.Signatures, "c") }},
		{"forged_seal", func(p *OldCommitProof) { p.CommitQC.LedgerCommitInfo.Hash[0] ^= 1 }},
		{"noncommitting", func(p *OldCommitProof) { p.CommitQC.LedgerCommitInfo.RootChainRoundNumber = 0 }},
		{"invalid_timestamp", func(p *OldCommitProof) { p.CommitQC.LedgerCommitInfo.Timestamp = 1 }},
		{"invalid_vote_version", func(p *OldCommitProof) { p.CommitQC.VoteInfo.Version = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, tb := signedOldProof(t)
			tc.change(&p)
			_, err := VerifyOldCommitProof(p, tb)
			require.ErrorIs(t, err, ErrProof)
		})
	}
}

func TestIndependentOldCommitProofVector(t *testing.T) {
	var fixture struct {
		Record, Control, Digest, Root, Vote, Seal string
		Nodes, Signatures                         map[string]string
	}
	data, err := os.ReadFile("testdata/old-commit-proof.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &fixture))
	decode := func(s string) []byte { b, err := stdhex.DecodeString(s); require.NoError(t, err); return b }
	p, _ := signedOldProof(t)
	require.Equal(t, decode(fixture.Record), p.Record.Bytes())
	require.Equal(t, decode(fixture.Control), p.Control.Bytes())
	require.Equal(t, decode(fixture.Digest), p.Control.Digest())
	require.Equal(t, decode(fixture.Root), []byte(p.CommitQC.LedgerCommitInfo.Hash))
	var vote rctypes.RoundInfo
	require.NoError(t, types.Cbor.Unmarshal(decode(fixture.Vote), &vote))
	var seal types.UnicitySeal
	require.NoError(t, types.Cbor.Unmarshal(decode(fixture.Seal), &seal))
	nodes := make([]*types.NodeInfo, 0, len(fixture.Nodes))
	for id, pub := range fixture.Nodes {
		nodes = append(nodes, &types.NodeInfo{NodeID: id, SigKey: decode(pub), Stake: 1})
	}
	tb, err := types.NewTrustBase(5, nodes)
	require.NoError(t, err)
	qc := &rctypes.QuorumCert{VoteInfo: &vote, LedgerCommitInfo: &seal, Signatures: map[string]hex.Bytes{}}
	for id, sig := range fixture.Signatures {
		qc.Signatures[id] = decode(sig)
	}
	p.CommitQC = qc
	verified, err := VerifyOldCommitProof(p, tb)
	require.NoError(t, err)
	require.Equal(t, uint64(4), verified.OrderRound)
}
