package parentwitness

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestIndependentWireVectors(t *testing.T) {
	var v struct {
		ProtocolID string `json:"protocolID"`
		Source     struct {
			NetworkID                                                types.NetworkID   `json:"networkID"`
			PartitionID                                              types.PartitionID `json:"partitionID"`
			ShardID, Full, Address, Code, Commitment, Genesis, Block string
		}
		Request struct {
			CBOR string `json:"cbor"`
		} `json:"request"`
		Responses []struct {
			Name    string  `json:"name"`
			Outcome Outcome `json:"outcome"`
			CBOR    string  `json:"cbor"`
		} `json:"responses"`
	}
	raw, err := os.ReadFile("testdata/v1-vectors.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &v))
	require.Equal(t, ProtocolID, v.ProtocolID)
	// Decode through a generic map to avoid coupling the JSON source names to Go field tags.
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	s := doc["source"].(map[string]any)
	r := Request{Context: Context{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, FullShardConfHash: common.HexToHash(s["fullShardConfHash"].(string)), RegistryAddress: common.HexToAddress(s["registryAddress"].(string)), RegistryCodeHash: common.HexToHash(s["registryCodeHash"].(string)), GenesisCommitment: common.HexToHash(s["genesisCommitment"].(string)), EVMGenesisHash: common.HexToHash(s["evmGenesisHash"].(string)), RootEpoch: 1}, BlockHash: common.HexToHash(s["blockHash"].(string))}
	got, err := EncodeRequest(r)
	require.NoError(t, err)
	require.Equal(t, decodeHex(t, v.Request.CBOR), got)
	for _, response := range v.Responses {
		rsp := Response{Request: r, Outcome: response.Outcome, Detail: response.Name}
		if response.Outcome == OutcomeFound {
			rsp.Detail = ""
			rsp.Evidence = registryproof.Evidence{Header: []byte{1}, StorageProofs: make([][][]byte, registryproof.FieldCount)}
		}
		got, err = EncodeResponse(rsp)
		require.NoError(t, err)
		require.Equal(t, decodeHex(t, response.CBOR), got, response.Name)
	}
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	require.NoError(t, err)
	return b
}
