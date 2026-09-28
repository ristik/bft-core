package handoff

import (
	"bytes"
	"crypto"
	stdhex "encoding/hex"
	"encoding/json"
	"os"
	"strings"
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

func TestEVMTransitionSharedVector(t *testing.T) {
	var vector struct {
		Encoded  string `json:"encoded"`
		OldEpoch uint64 `json:"oldEpoch"`
		NewEpoch uint64 `json:"newEpoch"`
		Ack      struct {
			EVMRound uint64 `json:"evmRound"`
		} `json:"ack"`
	}
	raw, err := os.ReadFile("testdata/evm-transition-v1.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &vector))
	encoded, err := stdhex.DecodeString(strings.TrimPrefix(vector.Encoded, "0x"))
	require.NoError(t, err)
	got, err := DecodeEVMTransition(encoded)
	require.NoError(t, err)
	require.Equal(t, vector.OldEpoch, got.OldEpoch)
	require.Equal(t, vector.NewEpoch, got.NewEpoch)
	require.Equal(t, vector.Ack.EVMRound, got.Ack.EVMRound)
	reencoded, err := got.Encode()
	require.NoError(t, err)
	require.Equal(t, encoded, reencoded)
}

func (emptyRootOrchestration) NetworkID() types.NetworkID { return 5 }
func (emptyRootOrchestration) ShardConfig(types.PartitionID, types.ShardID, uint64) (*types.PartitionDescriptionRecord, error) {
	return nil, nil
}
func (emptyRootOrchestration) ShardConfigs(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
	return map[types.PartitionShardID]*types.PartitionDescriptionRecord{}, nil
}

func signedOldProof(t *testing.T) (OldCommitProof, *types.RootTrustBaseV1) {
	p, tb, _ := signedOldProofWithSigners(t)
	return p, tb
}

func signedOldProofWithSigners(t *testing.T) (OldCommitProof, *types.RootTrustBaseV1, map[string]abcrypto.Signer) {
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
		previous := parent.ShardState.Control
		phase := map[string]string{"prepare": "prepared", "freeze": "frozen", "commit": "committed"}[item.kind]
		parent.ShardState.Control = &evmroot.ControlState{Network: 5, Epoch: rec.Epoch,
			PredecessorBodyID: rec.PredecessorBodyID, Attempt: 0, Phase: phase,
			OrderedRound: item.round, RecordBytes: ordered.Bytes(), PreviousDigest: previous.Digest()}
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
	return OldCommitProof{Profile: evmroot.D4Profile, Record: rec, Control: control, ControlPath: path, CommitQC: qc}, tb, signers
}

func resignOldQC(t *testing.T, qc *rctypes.QuorumCert, signers map[string]abcrypto.Signer) {
	t.Helper()
	h, err := qc.VoteInfo.Hash(crypto.SHA256)
	require.NoError(t, err)
	qc.LedgerCommitInfo.PreviousHash = h
	resignOldSealOnly(t, qc, signers)
}

func resignOldSealOnly(t *testing.T, qc *rctypes.QuorumCert, signers map[string]abcrypto.Signer) {
	t.Helper()
	message, err := qc.LedgerCommitInfo.SigBytes()
	require.NoError(t, err)
	qc.Signatures = map[string]hex.Bytes{}
	for _, id := range []string{"a", "b", "c"} {
		sig, err := signers[id].SignBytes(message)
		require.NoError(t, err)
		qc.Signatures[id] = sig
	}
}

func setOldProofRootFromPath(t *testing.T, p *OldCommitProof, signers map[string]abcrypto.Signer) {
	t.Helper()
	root, err := p.ControlPath.EvalAuthPath(p.Control.Digest(), crypto.SHA256)
	require.NoError(t, err)
	p.CommitQC.VoteInfo.CurrentRootHash = root
	p.CommitQC.LedgerCommitInfo.Hash = root
	resignOldQC(t, p.CommitQC, signers)
}

func rebuildOldProofRoot(t *testing.T, p *OldCommitProof, signers map[string]abcrypto.Signer) {
	t.Helper()
	p.Control.RecordBytes = p.Record.Bytes()
	p.Control.OrderedRound = p.Record.OrderedRound
	p.Control.Epoch = p.Record.Epoch
	tree, err := types.NewUnicityTree(crypto.SHA256, []*types.UnicityTreeData{{
		Partition: evmroot.D4ControlPartition, ShardTreeRoot: p.Control.Digest(),
	}})
	require.NoError(t, err)
	p.ControlPath, err = tree.Certificate(evmroot.D4ControlPartition)
	require.NoError(t, err)
	p.CommitQC.VoteInfo.CurrentRootHash = tree.RootHash()
	p.CommitQC.LedgerCommitInfo.Hash = tree.RootHash()
	resignOldQC(t, p.CommitQC, signers)
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

func TestInstalledEVMTransitionBindsCommittedFrozenParent(t *testing.T) {
	p, tb, signers := signedOldProofWithSigners(t)
	link, err := evmroot.FirstV2PredecessorHash(evmroot.V1Anchor{Version: 1,
		NetworkID: p.Record.Network, Epoch: p.Record.Epoch, HashIncludingSigs: p.Record.PredecessorBodyID})
	require.NoError(t, err)
	body := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: p.Record.Network, Epoch: p.Record.Epoch + 1,
		EarliestActivation: p.Record.ActivationRound,
		Members: evmroot.WeightSet{{StakingID: "next", NodeID: tb.RootNodes[0].NodeID,
			ConsensusKey: tb.RootNodes[0].SigKey, Weight: 1}}, RootThreshold: 1,
		StateSummary: bytes.Repeat([]byte{0x21}, 32), ChangeRecordHash: bytes.Repeat([]byte{0x22}, 32),
		PredecessorHash: link}
	require.NoError(t, body.Validate())
	id := body.Identity()
	p.Record.NextBodyID = id[:]
	p.Control.FrozenParent = bytes.Repeat([]byte{0x33}, 32)
	rebuildOldProofRoot(t, &p, signers)
	v, err := VerifyOldCommitProof(p, tb)
	require.NoError(t, err)
	g, err := evmroot.DeriveEpochGenesis(evmroot.VerifiedHandoff{RecordID: v.RecordID[:],
		Root: v.StateRoot[:], ControlDigest: v.ControlDigest[:], OrderRound: v.OrderRound,
		CommitSealRound: v.CommitSealRound, Epoch: v.SignerEpoch, Record: p.Record}, body)
	require.NoError(t, err)
	a := &rctypes.EpochAnchor{GenesisID: g.ID(), Epoch: g.Epoch, Slot: g.Start - 1, StateRoot: v.StateRoot[:]}
	transition, err := TransitionFromInstalledAnchor(p, tb, body, a)
	require.NoError(t, err)
	require.Equal(t, g.Start, transition.Ack.EVMRound)
	require.Equal(t, p.Control.FrozenParent, transition.Ack.FrozenParent[:])
	encoded, err := transition.Encode()
	require.NoError(t, err)
	decoded, err := DecodeEVMTransition(encoded)
	require.NoError(t, err)
	require.Equal(t, transition, decoded)
	bad := *a
	bad.GenesisID = bytes.Repeat([]byte{0x55}, 32)
	_, err = TransitionFromInstalledAnchor(p, tb, body, &bad)
	require.ErrorIs(t, err, ErrProof)
	p.Control.FrozenParent[0] ^= 1
	_, err = TransitionFromInstalledAnchor(p, tb, body, a)
	require.ErrorIs(t, err, ErrProof)
}

func TestOldCommitProofReviewGuards(t *testing.T) {
	makeOptional := func(t *testing.T, p *OldCommitProof, signers map[string]abcrypto.Signer) {
		t.Helper()
		vote := *p.CommitQC.VoteInfo
		vote.RoundNumber, vote.ParentRoundNumber = 4, 3
		seal := *p.CommitQC.LedgerCommitInfo
		seal.RootChainRoundNumber = 0
		p.OptionalQC = &rctypes.QuorumCert{VoteInfo: &vote, LedgerCommitInfo: &seal}
		resignOldQC(t, p.OptionalQC, signers)
		_, err := VerifyOldCommitProof(*p, signedTrust(t, signers))
		require.NoError(t, err)
	}
	cases := []struct {
		name   string
		change func(*testing.T, *OldCommitProof, *types.RootTrustBaseV1, map[string]abcrypto.Signer)
	}{
		{"record_control_match", func(t *testing.T, p *OldCommitProof, _ *types.RootTrustBaseV1, _ map[string]abcrypto.Signer) {
			p.Record.FrozenID = bytes.Repeat([]byte{0x99}, 32)
		}},
		{"previous_hash", func(t *testing.T, p *OldCommitProof, _ *types.RootTrustBaseV1, signers map[string]abcrypto.Signer) {
			p.CommitQC.LedgerCommitInfo.PreviousHash = bytes.Repeat([]byte{0x77}, 32)
			resignOldSealOnly(t, p.CommitQC, signers)
		}},
		{"parent_round", func(t *testing.T, p *OldCommitProof, _ *types.RootTrustBaseV1, signers map[string]abcrypto.Signer) {
			p.CommitQC.VoteInfo.ParentRoundNumber = 3
			resignOldQC(t, p.CommitQC, signers)
		}},
		{"commit_before_order", func(t *testing.T, p *OldCommitProof, _ *types.RootTrustBaseV1, signers map[string]abcrypto.Signer) {
			p.Record.OrderedRound, p.Record.ActivationRound = 5, 8
			rebuildOldProofRoot(t, p, signers)
		}},
		{"vote_epoch", func(t *testing.T, p *OldCommitProof, _ *types.RootTrustBaseV1, signers map[string]abcrypto.Signer) {
			p.CommitQC.VoteInfo.Epoch = 2
			resignOldQC(t, p.CommitQC, signers)
		}},
		{"seal_network", func(t *testing.T, p *OldCommitProof, _ *types.RootTrustBaseV1, signers map[string]abcrypto.Signer) {
			p.CommitQC.LedgerCommitInfo.NetworkID = 6
			resignOldSealOnly(t, p.CommitQC, signers)
		}},
		{"record_epoch_vs_trust", func(t *testing.T, p *OldCommitProof, _ *types.RootTrustBaseV1, signers map[string]abcrypto.Signer) {
			p.Record.Epoch = 2
			p.CommitQC.VoteInfo.Epoch = 2
			p.CommitQC.LedgerCommitInfo.Epoch = 2
			rebuildOldProofRoot(t, p, signers)
		}},
		{"optional_qc_round", func(t *testing.T, p *OldCommitProof, _ *types.RootTrustBaseV1, signers map[string]abcrypto.Signer) {
			makeOptional(t, p, signers)
			p.OptionalQC.VoteInfo.RoundNumber = 3
			p.OptionalQC.VoteInfo.ParentRoundNumber = 2
			resignOldQC(t, p.OptionalQC, signers)
		}},
		{"optional_qc_timestamp", func(t *testing.T, p *OldCommitProof, _ *types.RootTrustBaseV1, signers map[string]abcrypto.Signer) {
			makeOptional(t, p, signers)
			p.OptionalQC.VoteInfo.Timestamp++
			resignOldQC(t, p.OptionalQC, signers)
		}},
		{"control_path_step", func(t *testing.T, p *OldCommitProof, _ *types.RootTrustBaseV1, signers map[string]abcrypto.Signer) {
			p.ControlPath.HashSteps = []*types.PathItem{{Key: evmroot.D4ControlPartition, Hash: bytes.Repeat([]byte{0x55}, 32)}}
			setOldProofRootFromPath(t, p, signers)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, tb, signers := signedOldProofWithSigners(t)
			tc.change(t, &p, tb, signers)
			_, err := VerifyOldCommitProof(p, tb)
			require.ErrorIs(t, err, ErrProof)
		})
	}
	t.Run("genesis_qc", func(t *testing.T) {
		p, tb, signers := signedOldProofWithSigners(t)
		p.CommitQC.VoteInfo.RoundNumber = rctypes.GenesisRootRound
		p.CommitQC.VoteInfo.ParentRoundNumber = 0
		resignOldQC(t, p.CommitQC, signers)
		require.ErrorIs(t, verifyOldQC(p.CommitQC, tb), ErrProof)
	})
	t.Run("empty_signatures", func(t *testing.T) {
		p, tb := signedOldProof(t)
		p.CommitQC.Signatures = nil
		tb.QuorumThreshold = 0 // isolate the explicit empty-signature guard
		require.ErrorIs(t, verifyOldQC(p.CommitQC, tb), ErrProof)
	})
}

func signedTrust(t *testing.T, signers map[string]abcrypto.Signer) *types.RootTrustBaseV1 {
	t.Helper()
	return testtrustbase.NewTrustBaseFromSigners(t, signers).(*types.RootTrustBaseV1)
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
