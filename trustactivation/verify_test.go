package trustactivation_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/boltdb"
	"github.com/unicitynetwork/bft-core/m2contract"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/trustactivation"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

func activationFixture(t *testing.T) (*types.RootTrustBaseV1, m2contract.TrustInterval, []byte) {
	t.Helper()
	signers := map[string]abcrypto.Signer{}
	for _, id := range []string{"a", "b", "c", "d"} {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		signers[id] = s
	}
	old := testtrustbase.NewTrustBaseFromSigners(t, signers).(*types.RootTrustBaseV1)
	hash, err := old.Hash(crypto.SHA256)
	require.NoError(t, err)
	predecessor, err := evmroot.FirstV2PredecessorHash(evmroot.V1Anchor{Version: 1, NetworkID: uint64(old.NetworkID), Epoch: old.Epoch, HashIncludingSigs: hash})
	require.NoError(t, err)
	members := make(evmroot.WeightSet, 0, len(signers))
	for _, id := range []string{"a", "b", "c", "d"} {
		v, err := signers[id].Verifier()
		require.NoError(t, err)
		key, err := v.MarshalPublicKey()
		require.NoError(t, err)
		members = append(members, evmroot.Member{StakingID: "stake-" + id, NodeID: id, ConsensusKey: key, Weight: 1})
	}
	body := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: uint64(old.NetworkID), Epoch: old.Epoch + 1, EarliestActivation: 7, Members: members, RootThreshold: 3, StateSummary: bytes.Repeat([]byte{3}, 32), ChangeRecordHash: bytes.Repeat([]byte{4}, 32), PredecessorHash: predecessor}
	id := body.Identity()
	record := evmroot.OrderedHandoffRecord{Network: uint64(old.NetworkID), Epoch: old.Epoch, Attempt: 0, OrderedRound: 4, ActivationRound: 7, PredecessorBodyID: hash, FrozenID: bytes.Repeat([]byte{2}, 32), NextBodyID: id[:], SuccessorTRHash: bytes.Repeat([]byte{4}, 32), Kind: "commit"}
	control := evmroot.ControlState{Network: record.Network, Epoch: record.Epoch, PredecessorBodyID: hash, Attempt: 0, Phase: "committed", OrderedRound: 4, RecordBytes: record.Bytes(), PreviousDigest: bytes.Repeat([]byte{6}, 32)}
	tree, err := types.NewUnicityTree(crypto.SHA256, []*types.UnicityTreeData{{Partition: evmroot.D4ControlPartition, ShardTreeRoot: control.Digest()}})
	require.NoError(t, err)
	path, err := tree.Certificate(evmroot.D4ControlPartition)
	require.NoError(t, err)
	stamp := types.NewTimestamp()
	vote := &rctypes.RoundInfo{Version: 1, RoundNumber: 5, Epoch: old.Epoch, Timestamp: stamp, ParentRoundNumber: 4, CurrentRootHash: tree.RootHash()}
	voteHash, err := vote.Hash(crypto.SHA256)
	require.NoError(t, err)
	seal := &types.UnicitySeal{Version: 1, NetworkID: old.NetworkID, RootChainRoundNumber: 4, Epoch: old.Epoch, Timestamp: stamp, Hash: tree.RootHash(), PreviousHash: voteHash}
	signed, err := seal.SigBytes()
	require.NoError(t, err)
	qc := &rctypes.QuorumCert{VoteInfo: vote, LedgerCommitInfo: seal, Signatures: map[string]hex.Bytes{}}
	for _, id := range []string{"a", "b", "c"} {
		sig, err := signers[id].SignBytes(signed)
		require.NoError(t, err)
		qc.Signatures[id] = sig
	}
	proof := handoff.OldCommitProof{Profile: evmroot.D4Profile, Record: record, Control: control, ControlPath: path, CommitQC: qc}
	_, err = handoff.VerifyOldCommitProof(proof, old)
	require.NoError(t, err)
	encoded, err := types.Cbor.Marshal(proof)
	require.NoError(t, err)
	return old, m2contract.TrustInterval{Body: body, Activation: evmroot.ActivatedTrustBase{BodyIdentity: id[:], EpochStart: 7, ActivationCommitID: record.ID()}}, encoded
}

func TestHistoricalTrustBaseProofAndRestart(t *testing.T) {
	ctx := context.Background()
	old, interval, proof := activationFixture(t)
	identity := sha256.Sum256([]byte("execution"))
	path := filepath.Join(t.TempDir(), "trust.db")
	open := func(profile2 bool) (*shardnode.HistoricalTrustBaseStore, *boltdb.BoltDB, error) {
		db, err := boltdb.New(path)
		if err != nil {
			return nil, nil, err
		}
		s, err := shardnode.NewHistoricalTrustBaseStore(ctx, db, old, identity, profile2)
		return s, db, err
	}
	s, db, err := open(false)
	require.NoError(t, err)
	require.ErrorIs(t, s.AppendVerified(ctx, interval, proof), trusthistorystore.ErrUnsupportedV2)
	_, err = s.GetByEpoch(ctx, interval.Body.Epoch)
	require.ErrorIs(t, err, trusthistorystore.ErrNotFound)
	require.NoError(t, db.Close())

	s, db, err = open(true)
	require.NoError(t, err)
	for _, bad := range [][]byte{nil, proof[:len(proof)-1], bytes.Repeat([]byte{1}, 1<<20+1), func() []byte { p := bytes.Clone(proof); p[len(p)-1] ^= 1; return p }()} {
		require.ErrorIs(t, s.AppendVerified(ctx, interval, bad), trusthistorystore.ErrProof)
	}
	var wrongEpochProof handoff.OldCommitProof
	require.NoError(t, types.Cbor.Unmarshal(proof, &wrongEpochProof))
	wrongEpochProof.Record.Epoch++
	encodedWrongEpoch, err := types.Cbor.Marshal(wrongEpochProof)
	require.NoError(t, err)
	require.ErrorIs(t, s.AppendVerified(ctx, interval, encodedWrongEpoch), trusthistorystore.ErrProof)
	wrong := interval
	wrong.Body.Epoch++
	require.Error(t, s.AppendVerified(ctx, wrong, proof))
	_, err = s.GetByEpoch(ctx, interval.Body.Epoch)
	require.ErrorIs(t, err, trusthistorystore.ErrNotFound)
	require.NoError(t, s.AppendVerified(ctx, interval, proof))
	got, err := s.GetByEpoch(ctx, interval.Body.Epoch)
	require.NoError(t, err)
	require.Equal(t, interval.Body.Epoch, got.Epoch)
	require.Equal(t, interval.Activation.EpochStart, got.EpochStart)
	require.Equal(t, interval.Body.RootThreshold, got.QuorumThreshold)
	var signedProof handoff.OldCommitProof
	require.NoError(t, types.Cbor.Unmarshal(proof, &signedProof))
	signedBytes, err := signedProof.CommitQC.LedgerCommitInfo.SigBytes()
	require.NoError(t, err)
	require.NoError(t, got.VerifyQuorumSignatures(signedBytes, signedProof.CommitQC.Signatures))
	require.NoError(t, db.Close())

	_, db, err = open(false)
	require.ErrorIs(t, err, trusthistorystore.ErrProof)
	require.NoError(t, db.Close())
	s, db, err = open(true)
	require.NoError(t, err)
	got, err = s.GetByEpoch(ctx, interval.Body.Epoch)
	require.NoError(t, err)
	require.Equal(t, interval.Body.Epoch, got.Epoch)
	require.NoError(t, db.Close())
}

func TestVerifierRejectsInvalidPredecessorProjection(t *testing.T) {
	old, interval, proof := activationFixture(t)
	bad := interval.Body
	bad.Version = 0
	prior := trusthistorystore.Record{Epoch: old.Epoch, Start: 1, V2: &bad}
	err := (trustactivation.Verifier{}).VerifyActivation(context.Background(), prior, interval, proof)
	require.ErrorIs(t, err, trusthistorystore.ErrProof)
	require.ErrorContains(t, err, trusthistorystore.ErrHistory.Error())
}
