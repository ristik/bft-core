package cmd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

func trustBaseServer(t *testing.T, body func() []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body()) }))
	t.Cleanup(srv.Close)
	return srv
}

func encodedTrustBases(t *testing.T, tbs ...*types.RootTrustBaseV1) []byte {
	t.Helper()
	raw, err := types.Cbor.Marshal(TrustBasesResponse{TrustBases: tbs})
	require.NoError(t, err)
	return raw
}

func TestFetchTrustBase(t *testing.T) {
	ctx := context.Background()
	tb := &types.RootTrustBaseV1{Version: 1, NetworkID: 3, Epoch: 2}

	t.Run("the requested epoch", func(t *testing.T) {
		srv := trustBaseServer(t, func() []byte { return encodedTrustBases(t, tb) })
		got, err := fetchTrustBase(ctx, srv.URL, 2)
		require.NoError(t, err)
		require.EqualValues(t, 2, got.Epoch)
	})
	t.Run("another epoch is refused", func(t *testing.T) {
		srv := trustBaseServer(t, func() []byte { return encodedTrustBases(t, tb) })
		_, err := fetchTrustBase(ctx, srv.URL, 3)
		require.ErrorContains(t, err, "no single trust base of epoch 3")
	})
	t.Run("more than one trust base is refused", func(t *testing.T) {
		srv := trustBaseServer(t, func() []byte { return encodedTrustBases(t, tb, tb) })
		_, err := fetchTrustBase(ctx, srv.URL, 2)
		require.ErrorContains(t, err, "no single trust base")
	})
	t.Run("an oversized response is refused, not parsed as a prefix", func(t *testing.T) {
		big := append(encodedTrustBases(t, tb), bytes.Repeat([]byte{0}, 1<<20)...)
		srv := trustBaseServer(t, func() []byte { return big })
		_, err := fetchTrustBase(ctx, srv.URL, 2)
		require.ErrorContains(t, err, "exceeds")
	})
	t.Run("a non-200 status is refused", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusNotFound) }))
		t.Cleanup(srv.Close)
		_, err := fetchTrustBase(ctx, srv.URL, 2)
		require.ErrorContains(t, err, "404")
	})
}
