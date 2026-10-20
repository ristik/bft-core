package posrelayer

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/require"
)

// node is a stand-in execution client: it records the raw transactions it was sent, answers the Sender's other calls and, once mineAfter raw transactions have
// reached it, has the receipt (a validator whose private pool holds the transaction is the one that builds the block).
type node struct {
	mu        sync.Mutex
	raws      []string
	sendErr   string // when set, eth_sendRawTransaction answers this error
	hasMined  bool   // answers the receipt
	estimates int
}

func (n *node) client(t *testing.T) *rpc.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		resp := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		n.mu.Lock()
		defer n.mu.Unlock()
		switch req.Method {
		case "eth_getTransactionCount":
			resp["result"] = "0x0"
		case "eth_getBlockByNumber":
			resp["result"] = map[string]any{"baseFeePerGas": "0x7"}
		case "eth_estimateGas":
			n.estimates++
			resp["result"] = "0x5208"
		case "eth_sendRawTransaction":
			var raw string
			require.NoError(t, json.Unmarshal(req.Params[0], &raw))
			n.raws = append(n.raws, raw)
			if n.sendErr != "" {
				resp["error"] = map[string]any{"code": -32000, "message": n.sendErr}
			} else {
				resp["result"] = "0x00"
			}
		default: // eth_getTransactionReceipt
			if n.hasMined {
				resp["result"] = map[string]any{"status": "0x1"}
			} else {
				resp["result"] = nil
			}
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	t.Cleanup(srv.Close)
	c, err := rpc.Dial(srv.URL)
	require.NoError(t, err)
	t.Cleanup(c.Close)
	return c
}

func TestSenderSendsTheSameTransactionToEveryClientAndFindsTheReceiptOnAnyOfThem(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	primary, second, third := &node{}, &node{}, &node{hasMined: true} // only the third validator built the block
	s := Sender{Client: primary.client(t), Also: []*rpc.Client{second.client(t), third.client(t)}, Key: key, ChainID: big.NewInt(31337), Wait: 5 * time.Second}
	h, err := s.Send(context.Background(), [20]byte{1}, nil, []byte{1})
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, [32]byte(h))
	for i, n := range []*node{primary, second, third} {
		require.Len(t, n.raws, 1, "client %d", i)
		require.Equal(t, primary.raws[0], n.raws[0], "the very same signed bytes went to client %d", i)
	}
	require.Equal(t, 1, primary.estimates+second.estimates+third.estimates, "one estimate, on the first client")
}

func TestSenderBroadcastRefusalsOfTheOthersDoNotDecideTheSend(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	// "already known" is what a node that has the transaction answers: expected. Any other refusal of a further client is reported only if the send then fails.
	primary, known, broken := &node{hasMined: true}, &node{sendErr: "already known"}, &node{sendErr: "txpool is full"}
	s := Sender{Client: primary.client(t), Also: []*rpc.Client{known.client(t), broken.client(t)}, Key: key, ChainID: big.NewInt(31337), Wait: 5 * time.Second}
	_, err = s.Send(context.Background(), [20]byte{1}, nil, []byte{1})
	require.NoError(t, err, "the first client accepted and the receipt exists")

	// nobody mines it: the failure names what the broadcast met
	primary2, broken2 := &node{}, &node{sendErr: "txpool is full"}
	s = Sender{Client: primary2.client(t), Also: []*rpc.Client{broken2.client(t)}, Key: key, ChainID: big.NewInt(31337), Wait: 1200 * time.Millisecond}
	_, err = s.Send(context.Background(), [20]byte{1}, nil, []byte{1})
	require.ErrorContains(t, err, "was not mined")
	require.ErrorContains(t, err, "txpool is full")
}

func TestSenderWithoutFurtherClientsBehavesAsBefore(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	only := &node{hasMined: true}
	s := Sender{Client: only.client(t), Key: key, ChainID: big.NewInt(31337), Wait: 5 * time.Second}
	_, err = s.Send(context.Background(), [20]byte{1}, nil, []byte{1})
	require.NoError(t, err)
	require.Len(t, only.raws, 1)
}
