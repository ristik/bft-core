package evmstate

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/require"
)

// rpcWorld serves a world over JSON-RPC the way an execution client does: the head header, and eth_getProof at a block hash, with slot
// keys and values as minimal hex quantities (the shape that trips a byte-string decoder).
func rpcWorld(t *testing.T, w *world, head [32]byte) *rpc.Client {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		reply := func(v any) {
			_ = json.NewEncoder(rw).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": v})
		}
		switch req.Method {
		case "eth_getBlockByNumber":
			reply(map[string]any{"hash": hexutil.Encode(head[:]), "stateRoot": hexutil.Encode(w.root[:])})
		case "eth_getProof":
			var addr string
			var keys []string
			var block map[string]string
			require.NoError(t, json.Unmarshal(req.Params[0], &addr))
			require.NoError(t, json.Unmarshal(req.Params[1], &keys))
			require.NoError(t, json.Unmarshal(req.Params[2], &block))
			require.Equal(t, hexutil.Encode(head[:]), block["blockHash"], "proofs are asked at the pinned block hash")
			a := [20]byte(hexutil.MustDecode(addr))
			var sp []map[string]any
			for _, k := range keys {
				slot := word32(hexutil.MustDecode(k))
				v := w.contents[a][slot]
				var nodes []string
				for _, n := range w.slotProof(t, a, slot) {
					nodes = append(nodes, hexutil.Encode(n))
				}
				sp = append(sp, map[string]any{"key": hexutil.EncodeBig(new(big.Int).SetBytes(slot[:])),
					"value": hexutil.EncodeBig(new(big.Int).SetBytes(v[:])), "proof": nodes})
			}
			var account []string
			for _, n := range w.accountProof(t, a) {
				account = append(account, hexutil.Encode(n))
			}
			reply(map[string]any{"accountProof": account, "storageProof": sp})
		default:
			t.Errorf("unexpected method %s", req.Method)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := rpc.Dial(srv.URL)
	require.NoError(t, err)
	t.Cleanup(c.Close)
	return c
}

func TestTheRPCSourceBuildsTheWitnessAndTheFactsFromAClient(t *testing.T) {
	p := newPrimaryWorld(t, "published")
	resultID := hexWord(t, p.fx.ResultID)
	w := buildWorld(t,
		contract{addr: p.pins.Election, codeHash: p.pins.ElectionCode, storage: p.election},
		contract{addr: p.pins.Custody, codeHash: p.pins.CustodyCode, storage: p.custody})
	head := word32{0xaa}
	src := RPCWitnessSource{Client: rpcWorld(t, w, head), Pins: p.pins}

	want, _ := p.witness(t, resultID)
	got, err := src.PrimaryWitness(context.Background(), head[:], resultID)
	require.NoError(t, err)
	require.Equal(t, want, got, "the witness through a client is the witness the verifier reads")

	facts, err := src.PrimaryFacts(context.Background(), resultID)
	require.NoError(t, err)
	require.True(t, facts.Published)
	require.Equal(t, p.fx.Attempt, facts.Attempt)
	require.Equal(t, hexWord(t, p.fx.Expected.PopSetDigest), facts.PopSetDigest)

	_, err = src.PrimaryWitness(context.Background(), head[:5], resultID)
	require.ErrorIs(t, err, ErrBuild, "a frozen parent is a 32-byte block hash")
}
