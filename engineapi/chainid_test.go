package engineapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// ethStub serves just enough eth_chainId for CheckChainID.
func ethStub(t *testing.T, chainIDHex string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": 1, "result": chainIDHex,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestAdapterCheckChainID covers the startup negative F1 (#9) requires the node itself to
// enforce. Capability exchange cannot distinguish one chain from another — the V3 method
// set is identical — so without this a node pointed at the wrong execution client starts
// happily and certifies against the wrong state.
func TestAdapterCheckChainID(t *testing.T) {
	newAdapter := func(url string) *Adapter {
		return NewAdapter(Config{EngineURL: url, EthURL: url, Secret: Secret{}}, nil)
	}

	t.Run("matching chain id passes", func(t *testing.T) {
		srv := ethStub(t, "0x7a69", http.StatusOK) // 31337
		require.NoError(t, newAdapter(srv.URL).CheckChainID(context.Background(), 31337))
	})

	t.Run("mismatched chain id is refused, naming both values", func(t *testing.T) {
		srv := ethStub(t, "0x7a6a", http.StatusOK) // 31338
		err := newAdapter(srv.URL).CheckChainID(context.Background(), 31337)
		require.ErrorContains(t, err, "chainId=31338")
		require.ErrorContains(t, err, "shard conf says 31337")
	})

	t.Run("an unreachable client is an error, not a pass", func(t *testing.T) {
		err := newAdapter("http://127.0.0.1:1").CheckChainID(context.Background(), 31337)
		require.ErrorContains(t, err, "reading chain id")
	})

	t.Run("an erroring client is an error, not a pass", func(t *testing.T) {
		srv := ethStub(t, "", http.StatusInternalServerError)
		require.Error(t, newAdapter(srv.URL).CheckChainID(context.Background(), 31337))
	})
}
