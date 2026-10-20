package posrelayer

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/require"
)

// estimateServer answers the Sender's calls; eth_estimateGas fails with estimateErr for the first `failures` calls and then succeeds.
func estimateServer(t *testing.T, failures int32, estimateErr string) (*rpc.Client, *atomic.Int32) {
	t.Helper()
	var estimates atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		reply := func(result any, errMsg string) {
			resp := map[string]any{"jsonrpc": "2.0", "id": req.ID}
			if errMsg != "" {
				resp["error"] = map[string]any{"code": -32603, "message": errMsg}
			} else {
				resp["result"] = result
			}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		}
		switch req.Method {
		case "eth_getTransactionCount":
			reply("0x0", "")
		case "eth_getBlockByNumber":
			reply(map[string]any{"baseFeePerGas": "0x7"}, "")
		case "eth_estimateGas":
			if estimates.Add(1) <= failures {
				reply(nil, estimateErr)
				return
			}
			reply("0x5208", "")
		case "eth_sendRawTransaction":
			reply("0x00", "")
		default: // the receipt: mined at once
			reply(map[string]any{"status": "0x1"}, "")
		}
	}))
	t.Cleanup(srv.Close)
	c, err := rpc.Dial(srv.URL)
	require.NoError(t, err)
	t.Cleanup(c.Close)
	return c, &estimates
}

func TestSenderAsksAgainWhenTheBoundNodeRejectsTheEstimateBlock(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	c, estimates := estimateServer(t, 2, "bound execution input rejected the block: bound parent hash mismatch")
	s := Sender{Client: c, Key: key, ChainID: big.NewInt(31337), Wait: 5 * time.Second}
	_, err = s.Send(context.Background(), [20]byte{1}, nil, []byte{1})
	require.NoError(t, err)
	require.EqualValues(t, 3, estimates.Load(), "two rejected estimates, then the one that was used")
}

func TestSenderDoesNotRetryARevert(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	c, estimates := estimateServer(t, 100, "execution reverted: DuplicateOffence")
	s := Sender{Client: c, Key: key, ChainID: big.NewInt(31337), Wait: 5 * time.Second}
	_, err = s.Send(context.Background(), [20]byte{1}, nil, []byte{1})
	require.ErrorContains(t, err, "would revert")
	require.ErrorContains(t, err, "DuplicateOffence")
	require.EqualValues(t, 1, estimates.Load(), "a revert is final at the first estimate")
}

func TestSenderGivesUpOnAnEstimateThatKeepsBeingRejected(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	c, estimates := estimateServer(t, 100, "bound execution input rejected the block: bound parent hash mismatch")
	s := Sender{Client: c, Key: key, ChainID: big.NewInt(31337), Wait: 5 * time.Second}
	_, err = s.Send(context.Background(), [20]byte{1}, nil, []byte{1})
	require.ErrorContains(t, err, "bound parent hash mismatch")
	require.EqualValues(t, estimateAttempts, estimates.Load())
}
