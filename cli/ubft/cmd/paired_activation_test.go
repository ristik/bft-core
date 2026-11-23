package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
)

func TestPairedActivationBundleAllowsHexAndJSONOverhead(t *testing.T) {
	fixture := q3fixture.New(t, q3fixture.Options{})
	// The fixture exercises transport framing. Its padding is not an
	// authenticated candidate and would be refused by the installer.
	bundle := q3active.Bundle{Envelope: fixture.EnvelopeBytes, Snapshot: fixture.Snapshot, Candidate: make([]byte, 1<<20)}
	raw, err := q3active.EncodeBundle(bundle)
	require.NoError(t, err)
	bundle.Candidate = make([]byte, len(bundle.Candidate)+q3format.MaxEnvelopeBytes-len(raw))
	raw, err = q3active.EncodeBundle(bundle)
	require.NoError(t, err)
	require.Len(t, raw, q3format.MaxEnvelopeBytes)
	_, _, err = q3active.DecodeBundle(raw)
	require.NoError(t, err)

	mux := http.NewServeMux()
	rootQ3API{Bundle: func(context.Context, uint64) (q3active.Bundle, error) {
		return bundle, nil
	}}.register(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client := pairedActivationHTTP(5 * time.Second)
	t.Cleanup(client.CloseIdleConnections)

	got, err := fetchPairedActivationBundle(t.Context(), client, server.URL, 2, q3format.MaxEnvelopeBytes)
	require.NoError(t, err, "an exact-limit binary bundle fits with its JSON framing")
	require.Equal(t, raw, got)
	_, err = fetchPairedActivationBundle(t.Context(), client, server.URL, 2, len(raw)-1)
	require.Error(t, err)

	var ordinary q3BundleResponse
	require.Error(t, handoffPost(t.Context(), client, server.URL+"/api/v1/q3/bundle", []byte(`{"epoch":2}`), &ordinary),
		"the generic helper used for status and wait retains its smaller limit")
}
