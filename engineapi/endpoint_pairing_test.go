package engineapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

/*
These tests cover the reason both startup identity checks read the AUTHENTICATED Engine connection
as well as the plain one (issue #89 item 3).

--engine-url and --eth-url are separate flags, and the Engine connection is the one that decides
what this node votes for: Build, Seal and Commit all go over it. Reading identity only from the
plain endpoint therefore verifies the chain of a client that does not produce our blocks.

An earlier revision of this package documented that as unclosable, on the stated grounds that the
Engine API offers no chain-identity read. That was wrong. The specification's underlying-protocol
section requires eth_chainId and eth_getBlockByNumber on the authenticated port alongside engine_*,
and the pinned client serves them there (EngineEthApi, crates/rpc/rpc-api/src/engine.rs). No new
Engine method and no client divergence were needed.
*/

// clientStub answers the eth_* subset of one execution client. chainID and genesis are the values
// it reports; the literal string "null" makes the corresponding method return a JSON null result,
// and "" makes it return an RPC error.
type clientStub struct {
	chainID string
	genesis string
}

func (s clientStub) start(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			ID     any    `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		reply := func(result any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
		}
		fail := func() {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]any{"code": -32000, "message": "unavailable"}})
		}
		switch req.Method {
		case "eth_chainId":
			switch s.chainID {
			case "":
				fail()
			case "null":
				reply(nil)
			default:
				reply(s.chainID)
			}
		case "eth_getBlockByNumber":
			switch s.genesis {
			case "":
				fail()
			case "null":
				reply(nil)
			default:
				reply(map[string]any{
					"number": "0x0", "hash": s.genesis,
					"parentHash": "0x" + strings.Repeat("00", 32),
					"stateRoot":  "0x" + strings.Repeat("00", 32),
					"timestamp":  "0x0",
				})
			}
		default:
			fail()
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

const (
	genesisA = "0x" + "11111111111111111111111111111111" + "11111111111111111111111111111111"
	genesisB = "0x" + "22222222222222222222222222222222" + "22222222222222222222222222222222"
)

func adapterFor(engineURL, ethURL string) *Adapter {
	return NewAdapter(Config{EngineURL: engineURL, EthURL: ethURL, Secret: Secret{}}, nil)
}

func TestCheckChainID_ReadsBothConnections(t *testing.T) {
	ctx := context.Background()
	right := clientStub{chainID: "0x7a69", genesis: genesisA}
	wrongChain := clientStub{chainID: "0x7a6a", genesis: genesisB}

	t.Run("one client behind both URLs passes", func(t *testing.T) {
		url := right.start(t)
		require.NoError(t, adapterFor(url, url).CheckChainID(ctx, 31337))
	})

	t.Run("a wrong-chain Engine endpoint is refused even when the plain one is right", func(t *testing.T) {
		// The case the previous revision documented as accepted.
		err := adapterFor(wrongChain.start(t), right.start(t)).CheckChainID(ctx, 31337)
		require.ErrorContains(t, err, "chainId=31338")
		require.ErrorContains(t, err, "shard conf says 31337")
	})

	t.Run("a wrong-chain plain endpoint names the mispairing", func(t *testing.T) {
		// Reverse direction: the client that builds our blocks is on the configured chain, so
		// blaming the shard conf would send the operator to the wrong file.
		err := adapterFor(right.start(t), wrongChain.start(t)).CheckChainID(ctx, 31337)
		require.ErrorContains(t, err, "the two URLs address different execution clients")
	})

	t.Run("a null chain id is refused, not read as chain 0", func(t *testing.T) {
		url := clientStub{chainID: "null", genesis: genesisA}.start(t)
		err := adapterFor(url, url).CheckChainID(ctx, 31337)
		require.ErrorContains(t, err, "client reports no chain id")
	})

	t.Run("an erroring Engine connection is an error, not a fallback to the plain one", func(t *testing.T) {
		err := adapterFor(clientStub{chainID: "", genesis: genesisA}.start(t), right.start(t)).CheckChainID(ctx, 31337)
		require.ErrorContains(t, err, "reading chain id over the Engine connection")
	})
}

func TestCheckEndpointsPaired(t *testing.T) {
	ctx := context.Background()
	a := clientStub{chainID: "0x7a69", genesis: genesisA}
	b := clientStub{chainID: "0x7a69", genesis: genesisB}

	t.Run("one client behind both URLs passes", func(t *testing.T) {
		url := a.start(t)
		hash, err := adapterFor(url, url).CheckEndpointsPaired(ctx)
		require.NoError(t, err)
		require.Equal(t, strings.Repeat("11", 32), fmt.Sprintf("%x", hash))
	})

	t.Run("same chain id, different genesis is refused with no operator configuration", func(t *testing.T) {
		// Nothing else catches this: the chain ids agree, and --expected-genesis-hash is unset.
		_, err := adapterFor(b.start(t), a.start(t)).CheckEndpointsPaired(ctx)
		require.ErrorContains(t, err, "the two URLs address different execution clients")
	})

	t.Run("a null genesis is refused, not read as the zero hash", func(t *testing.T) {
		// json null decodes into a zero-valued header, so without explicit handling this would be
		// compared as if it were a real answer — and against a client whose genesis happens to be
		// unavailable, two nulls would even AGREE and pass.
		nullBoth := clientStub{chainID: "0x7a69", genesis: "null"}.start(t)
		_, err := adapterFor(nullBoth, nullBoth).CheckEndpointsPaired(ctx)
		require.ErrorContains(t, err, "no such block")
	})
}

func TestCheckGenesisHash_ReadsBothConnections(t *testing.T) {
	ctx := context.Background()
	want := make([]byte, 32)
	for i := range want {
		want[i] = 0x11
	}

	t.Run("matching genesis on one client passes", func(t *testing.T) {
		url := clientStub{chainID: "0x7a69", genesis: genesisA}.start(t)
		require.NoError(t, adapterFor(url, url).CheckGenesisHash(ctx, want))
	})

	t.Run("a wrong-genesis Engine endpoint is refused even when the plain one matches", func(t *testing.T) {
		err := adapterFor(clientStub{genesis: genesisB}.start(t), clientStub{genesis: genesisA}.start(t)).
			CheckGenesisHash(ctx, want)
		require.ErrorContains(t, err, "execution client genesis is")
	})

	t.Run("a wrong-genesis plain endpoint names the mispairing", func(t *testing.T) {
		err := adapterFor(clientStub{genesis: genesisA}.start(t), clientStub{genesis: genesisB}.start(t)).
			CheckGenesisHash(ctx, want)
		require.ErrorContains(t, err, "the two URLs address different execution clients")
	})

	t.Run("an unconfigured expectation is refused rather than skipped", func(t *testing.T) {
		url := clientStub{genesis: genesisA}.start(t)
		require.ErrorContains(t, adapterFor(url, url).CheckGenesisHash(ctx, nil),
			"no expected genesis hash configured")
	})
}

func TestDecodeBlockHeaderRejectsMissingIdentity(t *testing.T) {
	for _, raw := range []string{`{}`, `{"hash":null}`, `{"number":"0x0"}`} {
		t.Run(raw, func(t *testing.T) {
			_, err := decodeBlockHeader(json.RawMessage(raw))
			require.ErrorContains(t, err, "missing block hash")
		})
	}
}
