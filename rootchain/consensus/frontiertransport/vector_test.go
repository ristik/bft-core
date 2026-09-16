package frontiertransport

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/internal/frontiercodec"
)

func TestIndependentRequestAndFrameVectors(t *testing.T) {
	var vector map[string]string
	raw, err := os.ReadFile("../../../docs/design/vectors/frontier_signing_vectors.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &vector))
	expect := func(name string, actual []byte) {
		t.Helper()
		want, decodeErr := hex.DecodeString(vector[name])
		require.NoError(t, decodeErr)
		require.Equal(t, want, actual, name)
	}
	contextValue := frontiercodec.Context{NetworkID: 5, PartitionID: 0xFF0001, CanonicalShardBytes: []byte{0x80}, FullShardConfHash: bytes.Repeat([]byte{0x33}, 32), RootEpoch: 1, GenesisOriginIdentity: bytes.Repeat([]byte{0x11}, 32)}
	nonce := bytes.Repeat([]byte{0x22}, 32)
	frontier, err := EncodeFrontierRequest(FrontierRequest{Version: 1, Context: contextValue, Nonce: nonce})
	require.NoError(t, err)
	expect("request_cbor", frontier)
	var framed bytes.Buffer
	require.NoError(t, writeFrame(&framed, frontier, MaxRequestBytes))
	expect("frontier_request_frame", framed.Bytes())
	cut, err := EncodeCutRequest(CutRequest{Version: 1, Context: contextValue, Nonce: nonce, AcquisitionBinding: bytes.Repeat([]byte{0x44}, 32), Floor: 7})
	require.NoError(t, err)
	expect("cut_request_cbor", cut)
	framed.Reset()
	require.NoError(t, writeFrame(&framed, cut, MaxRequestBytes))
	expect("cut_request_frame", framed.Bytes())
}
