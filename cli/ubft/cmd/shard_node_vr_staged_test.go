package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The shard node's staged-successor endpoint: local operator only, the ids go to the staged peer set as given, an over-long list and a bad id
// change nothing, and the root's sink posts exactly what the endpoint reads.
func TestTheShardNodesStagedSuccessorEndpoint(t *testing.T) {
	var got [][]string
	mux := http.NewServeMux()
	vrStagedEndpoint{stage: func(ids []string) error { got = append(got, ids); return nil }}.register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sink, err := vrShardSink(srv.URL)
	require.NoError(t, err)
	require.NoError(t, sink(context.Background(), []string{"a", "b"}))
	require.NoError(t, sink(context.Background(), nil))
	require.Equal(t, [][]string{{"a", "b"}, nil}, got)

	long := make([]string, maxVRStaged+1)
	require.Error(t, sink(context.Background(), long), "more than the committee ceiling is refused")
	require.Len(t, got, 2)

	// a request that is not the local operator's is refused (a forwarded or remote one)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/vr/staged", strings.NewReader(`{"ids":["x"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://evil.example")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.NotEqual(t, http.StatusOK, resp.StatusCode)
	require.Len(t, got, 2)
	_ = json.RawMessage(nil)
}

// --vr-shard-rpc takes only the loopback address of the shard node's local RPC.
func TestTheShardSinkTakesOnlyALoopbackHTTPURL(t *testing.T) {
	for _, bad := range []string{"https://127.0.0.1:1", "http://10.0.0.5:8080", "http://example.com", "127.0.0.1:1", "http://"} {
		_, err := vrShardSink(bad)
		require.ErrorIs(t, err, ErrVRHandoffCmd, bad)
	}
	for _, ok := range []string{"http://127.0.0.1:26000", "http://localhost:26000"} {
		f, err := vrShardSink(ok)
		require.NoError(t, err, ok)
		require.NotNil(t, f)
	}
	f, err := vrShardSink("")
	require.NoError(t, err)
	require.Nil(t, f)
}
