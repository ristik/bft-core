package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/shardnode"
)

type stagedCall struct {
	epoch, stamp uint64
	ids          []string
}

func stagedServer(t *testing.T, stage func(epoch, stamp uint64, ids []string) error) *httptest.Server {
	mux := http.NewServeMux()
	vrStagedEndpoint{stage: stage}.register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, url, body string) int {
	req, err := http.NewRequest(http.MethodPost, url+"/api/v1/vr/staged", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	return resp.StatusCode
}

// The shard node's staged-successor endpoint: the ids go to the staged peer set as given with their generation, an over-long list changes
// nothing, a stale generation is a conflict, and a missing, malformed or id-less body is a 400 that clears nothing (only an explicit empty list
// clears); a request that is not from a loopback peer is refused whatever the operator allowlist says.
func TestTheShardNodesStagedSuccessorEndpoint(t *testing.T) {
	var got []stagedCall
	var staleNext bool
	srv := stagedServer(t, func(e, s uint64, ids []string) error {
		if staleNext {
			return shardnode.ErrActivePeersStale
		}
		got = append(got, stagedCall{e, s, ids})
		return nil
	})
	sink, err := vrShardSink(srv.URL)
	require.NoError(t, err)
	require.NoError(t, sink(context.Background(), 2, 10, []string{"a", "b"}))
	require.NoError(t, sink(context.Background(), 0, 11, nil)) // an explicit empty list: a clear
	require.Equal(t, []stagedCall{{2, 10, []string{"a", "b"}}, {0, 11, []string{}}}, got)

	require.Error(t, sink(context.Background(), 2, 12, make([]string, maxVRStaged+1)), "more than the committee ceiling is refused")
	require.Len(t, got, 2)

	for name, body := range map[string]string{"an empty body": "", "not JSON": "garbage", "no ids": `{"shardEpoch":2,"stamp":13}`, "null ids": `{"shardEpoch":2,"stamp":13,"ids":null}`,
		"an unknown field": `{"shardEpoch":2,"stamp":13,"ids":[],"x":1}`, "an empty object": `{}`,
		"a missing epoch": `{"stamp":13,"ids":[]}`, "a null epoch": `{"shardEpoch":null,"stamp":13,"ids":[]}`, "a missing stamp": `{"shardEpoch":0,"ids":[]}`, "a null stamp": `{"shardEpoch":0,"stamp":null,"ids":[]}`,
		"a second object": `{"shardEpoch":0,"stamp":13,"ids":[]}{"shardEpoch":0,"stamp":14,"ids":["a"]}`, "trailing garbage": `{"shardEpoch":0,"stamp":13,"ids":[]} x`} {
		require.Equal(t, http.StatusBadRequest, post(t, srv.URL, body), name)
	}
	require.Len(t, got, 2, "none of them cleared or set anything")
	require.Equal(t, http.StatusOK, post(t, srv.URL, `{"shardEpoch":0,"stamp":14,"ids":[]}`))

	staleNext = true
	require.Equal(t, http.StatusConflict, post(t, srv.URL, `{"shardEpoch":2,"stamp":1,"ids":["a"]}`), "an older generation")

	// a request that is not the local operator's is refused (a browser's, with an Origin)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/vr/staged", strings.NewReader(`{"shardEpoch":2,"stamp":99,"ids":["x"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://evil.example")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.NotEqual(t, http.StatusOK, resp.StatusCode)
}

// The root's client never follows a redirect: the destination is the configured loopback one throughout.
func TestTheRootsShardClientDoesNotFollowRedirects(t *testing.T) {
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	sink, err := vrShardSink(redirector.URL)
	require.NoError(t, err)
	require.Error(t, sink(context.Background(), 2, 1, []string{"a"}), "a redirect is not success")
	require.Zero(t, hits, "and is not followed")
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
