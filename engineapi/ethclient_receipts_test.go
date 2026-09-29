package engineapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
)

func TestGetBlockReceiptsUsesExactHashAndPreservesTypedEnvelope(t *testing.T) {
	// Mirrors Ureth's eth_getBlockReceipts TransactionReceipt response: the
	// consensus receipt fields are augmented with exact block and transaction
	// indexes by EthReceiptConverter.
	blockHash := common.HexToHash("0x1234")
	var request rpcRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		bloom := make([]byte, 256)
		result := []map[string]any{{"blockHash": blockHash.Hex(), "transactionIndex": "0x0", "transactionHash": common.HexToHash("0x5678").Hex(),
			"type": "0x2", "status": "0x1", "cumulativeGasUsed": "0x5208", "gasUsed": "0x5208", "logsBloom": fmt.Sprintf("0x%x", bloom), "logs": []any{}}}
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result}))
	}))
	defer server.Close()
	envelopes, err := NewEthClient(server.URL).GetBlockReceipts(t.Context(), data32(blockHash))
	require.NoError(t, err)
	require.Equal(t, "eth_getBlockReceipts", request.Method)
	require.Len(t, request.Params, 1)
	require.Equal(t, blockHash, common.HexToHash(fmt.Sprint(request.Params[0])))
	require.Len(t, envelopes, 1)
	var receipt gethtypes.Receipt
	require.NoError(t, receipt.UnmarshalBinary(envelopes[0]))
	require.Equal(t, uint8(gethtypes.DynamicFeeTxType), receipt.Type)
	require.Equal(t, uint64(gethtypes.ReceiptStatusSuccessful), receipt.Status)
}

func TestGetBlockReceiptsRefusesMismatchedBlockOrIndex(t *testing.T) {
	blockHash := common.HexToHash("0x1234")
	for _, tc := range []struct{ name, returnedHash, index string }{{"hash", common.HexToHash("0x9999").Hex(), "0x0"}, {"index", blockHash.Hex(), "0x1"}} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				result := []map[string]any{{"blockHash": tc.returnedHash, "transactionIndex": tc.index, "type": "0x0", "status": "0x1", "cumulativeGasUsed": "0x0", "gasUsed": "0x0", "logsBloom": "0x" + fmt.Sprintf("%0512x", 0), "logs": []any{}}}
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
			}))
			defer server.Close()
			_, err := NewEthClient(server.URL).GetBlockReceipts(t.Context(), data32(blockHash))
			require.Error(t, err)
		})
	}
}

func TestGetBlockReceiptsNullIsTemporarilyUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":null}`))
	}))
	defer server.Close()

	_, err := NewEthClient(server.URL).GetBlockReceipts(t.Context(), data32(common.HexToHash("0x1234")))
	require.EqualError(t, err, "eth_getBlockReceipts returned null")
	var retryable interface{ Temporary() bool }
	require.ErrorAs(t, err, &retryable)
	require.True(t, retryable.Temporary())
}
