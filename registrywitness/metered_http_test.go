package registrywitness

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMeteredHTTPDisablesBodyReplayWithoutChangingLegacyCall(t *testing.T) {
	var meteredGetBody, legacyGetBody bool
	responses := 0
	h := &HTTPCaller{url: "http://rpc.invalid", client: &http.Client{Timeout: time.Second, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		responses++
		if responses == 1 {
			meteredGetBody = r.GetBody != nil
		} else {
			legacyGetBody = r.GetBody != nil
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":null}`)), ContentLength: 39}, nil
	})}}
	_, _, err := h.CallMetered(context.Background(), "debug_getRawHeader", nil, 100)
	require.NoError(t, err)
	_, err = h.Call(context.Background(), "debug_getRawHeader", nil)
	require.NoError(t, err)
	require.False(t, meteredGetBody)
	require.True(t, legacyGetBody)
}
