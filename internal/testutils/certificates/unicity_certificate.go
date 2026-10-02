package testcertificates

import (
	gocrypto "crypto"
	"testing"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	test "github.com/unicitynetwork/bft-core/internal/testutils"
)

func CreateUnicityCertificate(
	t *testing.T,
	signer crypto.Signer,
	ir *types.InputRecord,
	shardConf *types.PartitionDescriptionRecord,
	rootRound uint64,
	previousHash []byte,
	trHash []byte,
) *types.UnicityCertificate {
	t.Helper()
	shardConfHash := test.DoHash(t, shardConf)
	sTree, err := types.CreateShardTree(types.ShardingScheme{}, []types.ShardTreeInput{
		{Shard: types.ShardID{}, IR: ir, TRHash: trHash, ShardConfHash: shardConfHash},
	}, gocrypto.SHA256)
	if err != nil {
		t.Errorf("creating shard tree: %v", err)
		return nil
	}
	stCert, err := sTree.Certificate(types.ShardID{})
	if err != nil {
		t.Errorf("creating shard tree certificate: %v", err)
		return nil
	}
	data := []*types.UnicityTreeData{{
		Partition:     shardConf.PartitionID,
		ShardTreeRoot: sTree.RootHash(),
	}}
	ut, err := types.NewUnicityTree(gocrypto.SHA256, data)
	if err != nil {
		t.Error(err)
	}
	rootHash := ut.RootHash()
	unicitySeal := createUnicitySeal(rootHash, rootRound, previousHash)

	verifier, err := signer.Verifier()
	require.NoError(t, err)
	nodeID := nodeIDFromVerifier(t, verifier).String()

	err = unicitySeal.Sign(nodeID, signer)
	if err != nil {
		t.Error(err)
	}
	cert, err := ut.Certificate(shardConf.PartitionID)
	if err != nil {
		t.Error(err)
	}
	return &types.UnicityCertificate{
		Version:                1,
		InputRecord:            ir,
		TRHash:                 trHash,
		ShardConfHash:          shardConfHash,
		ShardTreeCertificate:   stCert,
		UnicityTreeCertificate: cert,
		UnicitySeal:            unicitySeal,
	}
}

// SealTimestamp is the round-creation time every test certificate's seal carries. It was the wall clock, and the canonical root input
// and the signing authority's request digest both commit to it, so two certificates built for the same statement a second apart
// differed in bytes: a test asserting "identical bytes" or re-admitting "the same request" failed whenever the two builds straddled
// a second. A test that needs another time sets UnicitySeal.Timestamp itself before signing.
const SealTimestamp uint64 = 1_700_000_000

func createUnicitySeal(rootHash []byte, roundNumber uint64, previousHash []byte) *types.UnicitySeal {
	return &types.UnicitySeal{
		Version:              1,
		Epoch:                1,
		RootChainRoundNumber: roundNumber,
		Timestamp:            SealTimestamp,
		PreviousHash:         previousHash,
		Hash:                 rootHash,
	}
}

func nodeIDFromVerifier(t *testing.T, v crypto.Verifier) peer.ID {
	pubKeyBytes, err := v.MarshalPublicKey()
	require.NoError(t, err)
	pubKey, err := p2pcrypto.UnmarshalSecp256k1PublicKey(pubKeyBytes)
	require.NoError(t, err)
	peerID, err := peer.IDFromPublicKey(pubKey)
	require.NoError(t, err)
	return peerID
}

func UnicitySealBytes(t *testing.T, unicitySeal *types.UnicitySeal) []byte {
	t.Helper()
	h, err := unicitySeal.SigBytes()
	require.NoError(t, err)
	return h
}
