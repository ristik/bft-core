package cmd

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRPCBindIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8000": true, "[::1]:8000": true, "localhost:8000": true, "127.1.2.3:1": true,
		":8000": false, "0.0.0.0:8000": false, "[::]:8000": false, "10.0.0.5:8000": false, "node.example.org:8000": false, "no-port": false,
	} {
		require.Equal(t, want, rpcBindIsLoopback(addr), addr)
	}
}

func TestWarnIfRPCExposedWarnsOnlyForANetworkBind(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	warnIfRPCExposed(log, "root", "127.0.0.1:26662")
	warnIfRPCExposed(log, "root", "")
	require.Empty(t, buf.String(), "loopback and no RPC server are silent")
	warnIfRPCExposed(log, "root", "0.0.0.0:26662")
	require.Contains(t, buf.String(), "level=WARN")
	require.Contains(t, buf.String(), "address=0.0.0.0:26662")
	require.Contains(t, buf.String(), "root RPC address is not loopback")
}

// docs/operations/root-rpc-exposure.md says the shard node's Q3 endpoints are loopback-guarded: this keeps it true.
func TestShardQ3EndpointsRefuseANonLoopbackPeer(t *testing.T) {
	mux := http.NewServeMux()
	(&shardQ3Staging{}).register(mux)
	for _, path := range []string{"/api/v1/q3/stage", "/api/v1/q3/status"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "192.0.2.1:1234"
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		require.Equal(t, http.StatusForbidden, rec.Code, path)
	}
}
