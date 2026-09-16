package consensus

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/internal/frontiercodec"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestFrontierSigningIndependentEncodingVector(t *testing.T) {
	var vector map[string]string
	b, err := os.ReadFile("../../docs/design/vectors/frontier_signing_vectors.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &vector))
	expect := func(name string, actual []byte) {
		t.Helper()
		want, err := hex.DecodeString(vector[name])
		require.NoError(t, err)
		require.Equal(t, want, actual, name)
	}
	contextValue := frontierSignedContext{NetworkID: 5, PartitionID: 0xFF0001, CanonicalShardBytes: []byte{0x80}, FullShardConfHash: bytes.Repeat([]byte{0x33}, 32), RootEpoch: 1, GenesisOriginIdentity: bytes.Repeat([]byte{0x11}, 32)}
	contextCBOR, err := types.Cbor.Marshal(contextValue)
	require.NoError(t, err)
	expect("context_cbor", contextCBOR)

	type request struct {
		_       struct{} `cbor:",toarray"`
		Version uint64
		Context frontierSignedContext
		Nonce   []byte
	}
	nonce := bytes.Repeat([]byte{0x22}, 32)
	requestCBOR, err := types.Cbor.Marshal(request{Version: 1, Context: contextValue, Nonce: nonce})
	require.NoError(t, err)
	expect("request_cbor", requestCBOR)

	tuple := frontierPairIdentityTuple{Domain: frontierPairDomain, Version: 1, InputRecord: []byte{1, 2}, SealSigBytes: []byte{3, 4}, Technical: []byte{5, 6}, Context: contextValue}
	tupleCBOR, err := types.Cbor.Marshal(tuple)
	require.NoError(t, err)
	expect("pair_tuple_cbor", tupleCBOR)
	pairID := sha256.Sum256(tupleCBOR)
	expect("pair_identity", pairID[:])
	qcDigest := sha256.Sum256([]byte{0xaa, 0xbb})
	preimageCBOR, err := types.Cbor.Marshal(frontierSigningPreimage{Domain: frontierSigningDomain, Version: 1, Context: contextValue, Nonce: nonce, Author: "node-A", PairID: pairID[:], QCDigest: qcDigest[:]})
	require.NoError(t, err)
	expect("preimage_cbor", preimageCBOR)
	cutCBOR, err := types.Cbor.Marshal(frontiercodec.CutProof{Version: 1, AcquisitionBinding: bytes.Repeat([]byte{0x44}, 32), RootRound: 7, RootEpoch: 1, RootHash: bytes.Repeat([]byte{0x55}, 32), CommitQC: []byte{0xaa, 0xbb}, Pair: []byte{1, 2, 3}, ShardCertificate: []byte{4, 5}, UnicityCertificate: []byte{6, 7}})
	require.NoError(t, err)
	expect("cut_proof_cbor", cutCBOR)
	cutHash := sha256.Sum256(cutCBOR)
	expect("cut_proof_sha256", cutHash[:])
}
