package vrschedule

import (
	"context"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/vrstate"
	"github.com/unicitynetwork/bft-core/vrclient"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// The production RPC.QueuedSchedules and RPC.HeaderNumber through an in-process Ethereum JSON-RPC server (astra r7/r8): every VR view read
// carries the certified block's hash as the EIP-1898 selector, the queued ScheduleActivation changes (and only those) are decoded, and the
// header is fetched by hash with its hash verified.
func TestQueuedSchedulesAndHeaderNumberThroughJSONRPC(t *testing.T) {
	blockHash := [32]byte{0xcd}
	header := &gethtypes.Header{Number: big.NewInt(3), Difficulty: big.NewInt(0), GasLimit: 30_000_000}
	headerHash := [32]byte(header.Hash())
	sched, err := vrclient.ScheduleActivationPayload(vrschema.RuleID("future-rule-v9"), vrschema.Word{9}, 12, 5000, "future")
	require.NoError(t, err)
	var selectors []map[string]string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		var call struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		require.NoError(t, json.Unmarshal(body, &call))
		var result any
		switch call.Method {
		case "eth_getBlockByHash":
			var h string
			require.NoError(t, json.Unmarshal(call.Params[0], &h))
			if h == hexutil.Encode(headerHash[:]) {
				result = header
			}
		case "eth_call":
			var tx struct {
				To   common.Address `json:"to"`
				Data hexutil.Bytes  `json:"data"`
			}
			require.NoError(t, json.Unmarshal(call.Params[0], &tx))
			var at map[string]string
			require.NoError(t, json.Unmarshal(call.Params[1], &at))
			selectors = append(selectors, at)
			require.Equal(t, common.Address(vrschema.ValidatorRegistry), tx.To)
			method, merr := vrclient.VRABI.MethodById(tx.Data[:4])
			require.NoError(t, merr)
			var out []byte
			switch method.Name {
			case "pendingChanges":
				out, err = method.Outputs.Pack([]uint64{4, 5, 6})
			case "change":
				args, aerr := method.Inputs.Unpack(tx.Data[4:])
				require.NoError(t, aerr)
				switch args[0].(uint64) {
				case 4:
					out, err = method.Outputs.Pack(vrclient.ChangeView{Kind: vrclient.KindCommitteeLimits, State: 1, Payload: []byte("limits")})
				case 5:
					out, err = method.Outputs.Pack(vrclient.ChangeView{Kind: vrclient.KindScheduleActivation, State: 1, Payload: sched})
				case 6:
					out, err = method.Outputs.Pack(vrclient.ChangeView{Kind: vrclient.KindScheduleActivation, State: 2, Payload: []byte("not a schedule")})
				}
			}
			require.NoError(t, err)
			result = hexutil.Bytes(out)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": result})
	}))
	defer srv.Close()
	client, err := rpc.Dial(srv.URL)
	require.NoError(t, err)
	r := RPC{Client: client, Pins: vrstate.Pins{Registry: vrschema.ValidatorRegistry}}

	got, err := r.QueuedSchedules(context.Background(), blockHash)
	require.NoError(t, err)
	require.Len(t, got, 1, "only the decodable ScheduleActivation change")
	require.Equal(t, vrschema.RuleID("future-rule-v9"), got[0].RuleID)
	require.EqualValues(t, 12, got[0].RootEpoch)
	require.EqualValues(t, 5, got[0].ChangeID)
	require.NotEmpty(t, selectors)
	for _, at := range selectors {
		require.Equal(t, map[string]string{"blockHash": hexutil.Encode(blockHash[:])}, at, "every view read is at the certified hash (EIP-1898)")
	}

	n, err := r.HeaderNumber(context.Background(), headerHash)
	require.NoError(t, err)
	require.EqualValues(t, 3, n)
	_, err = r.HeaderNumber(context.Background(), [32]byte{0xee})
	require.ErrorIs(t, err, ErrRead, "a block the node does not hold")
}
