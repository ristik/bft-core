package engineapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/shardnode"
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

// TestAdapterCommitRejectsEmptyHash is the adapter half of issue #92's reproduction.
//
// shardnode/round.go's reconcile takes its recovery target from the certificate's
// InputRecord.BlockHash, which a quiet certificate carries as nil, and its comment asserts that
// this is harmless because "Commit will correctly report StatusSyncing for it". That is true of
// the in-memory fake executor and false of this adapter, which is why the fake-only chaos suite
// never surfaced the path. The adapter rejects the empty hash before any RPC is attempted — the
// error seen in the retained real-reth logs.
func TestAdapterCommitRejectsEmptyHash(t *testing.T) {
	// No server: the failure happens in argument conversion, before any request is made.
	a := NewAdapter(Config{EngineURL: "http://127.0.0.1:1", EthURL: "http://127.0.0.1:1", Secret: Secret{}}, nil)

	for _, tc := range []struct {
		name string
		hash []byte
	}{
		{"nil hash, as a quiet certificate carries", nil},
		{"empty hash", []byte{}},
		{"short hash", []byte{0x01, 0x02}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, err := a.Commit(context.Background(), tc.hash)
			require.Error(t, err, "the adapter must not accept a non-32-byte commit target")
			require.ErrorContains(t, err, "expected a 32-byte hash")
			require.Equal(t, shardnode.StatusInvalid, status)
		})
	}
}
