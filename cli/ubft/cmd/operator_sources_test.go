package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// useOperatorSources installs a source list for one test and restores the loopback default afterwards.
func useOperatorSources(t *testing.T, list string) {
	t.Helper()
	t.Cleanup(func() {
		set, err := parseOperatorSources(defaultOperatorSources)
		require.NoError(t, err)
		activeOperatorSources.Store(set)
	})
	require.NoError(t, configureOperatorSources(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), list))
}

// operatorCall sends a well-formed operator request from the given TCP peer through a real endpoint wrapper and returns the status code.
func operatorCall(from string) int {
	handler := q3Endpoint(func(context.Context, json.RawMessage) (any, error) { return map[string]bool{"ok": true}, nil })
	req := httptest.NewRequest(http.MethodPost, "/api/v1/q3/status", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = from
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec.Code
}

// By default only loopback peers are answered, exactly as before the sources became configuration.
func TestOperatorEndpointsDefaultToLoopbackOnly(t *testing.T) {
	for _, from := range []string{"127.0.0.1:5000", "[::1]:5000", "127.8.9.10:5000", "[::ffff:127.0.0.1]:5000", "[::1%lo0]:5000"} {
		require.Equal(t, http.StatusOK, operatorCall(from), from)
	}
	for _, from := range []string{"10.1.2.3:5000", "192.0.2.7:5000", "[2001:db8::1]:5000", "[::ffff:10.1.2.3]:5000", "no-port", ""} {
		require.Equal(t, http.StatusForbidden, operatorCall(from), from)
	}
}

// A configured list replaces the default: it admits its addresses and prefixes, and refuses everything else, loopback included unless listed.
func TestConfiguredOperatorSourcesAdmitOnlyTheirRanges(t *testing.T) {
	useOperatorSources(t, "10.1.0.0/16, 192.0.2.7 ,2001:db8::/32")
	for _, from := range []string{"10.1.2.3:1", "10.1.255.255:1", "192.0.2.7:1", "[2001:db8:5::1]:1", "[::ffff:10.1.2.3]:1"} {
		require.Equal(t, http.StatusOK, operatorCall(from), from)
	}
	for _, from := range []string{"10.2.0.1:1", "192.0.2.8:1", "[2001:db9::1]:1", "127.0.0.1:1", "[::1]:1"} {
		require.Equal(t, http.StatusForbidden, operatorCall(from), from)
	}
	useOperatorSources(t, "127.0.0.0/8,::1/128,10.9.0.0/24")
	require.Equal(t, http.StatusOK, operatorCall("127.0.0.1:1"))
	require.Equal(t, http.StatusOK, operatorCall("10.9.0.200:1"))
	require.Equal(t, http.StatusForbidden, operatorCall("10.9.1.1:1"))
}

// The checks other than the source stay: media type and no Origin still apply to an admitted peer.
func TestAdmittedOperatorPeerStillNeedsAJSONRequestWithoutOrigin(t *testing.T) {
	handler := q3Endpoint(func(context.Context, json.RawMessage) (any, error) { return 1, nil })
	for name, mutate := range map[string]func(*http.Request){
		"form media type": func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") },
		"an Origin":       func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
	} {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "127.0.0.1:1"
		mutate(req)
		rec := httptest.NewRecorder()
		handler(rec, req)
		require.Equal(t, http.StatusUnsupportedMediaType, rec.Code, name)
	}
}

// A malformed list fails when it is configured and installs nothing.
func TestMalformedOperatorSourcesFailAtStartup(t *testing.T) {
	log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	cases := map[string]string{
		"not an address":       "banana",
		"prefix length":        "10.0.0.0/33",
		"trailing garbage":     "10.0.0.0/8x",
		"empty element":        "10.0.0.1,,10.0.0.2",
		"trailing comma":       "10.0.0.1,",
		"zone":                 "fe80::1%eth0",
		"a host name":          "operator.example.org",
		"one bad among good":   "10.0.0.0/8,300.1.1.1",
		"mask with spaces":     "10.0.0.0/ 8",
		"ipv6 prefix too long": "::1/129",
	}
	for name, list := range cases {
		useOperatorSources(t, "10.5.0.0/16")
		require.Error(t, configureOperatorSources(log, list), name)
		require.Equal(t, http.StatusOK, operatorCall("10.5.0.1:1"), "%s: the previous list stays installed", name)
		require.Equal(t, http.StatusForbidden, operatorCall("127.0.0.1:1"), name)
	}
	// both run functions reject it before they start anything
	require.ErrorContains(t, rootNodeRun(context.Background(), &rootNodeRunFlags{OperatorAllowedSources: "banana"}), "operator-allowed-sources")
	require.ErrorContains(t, shardNodeRun(context.Background(), &shardNodeRunFlags{OperatorAllowedSources: "10.0.0.0/33"}, func(string) bool { return false }), "operator-allowed-sources")
}

// Both commands carry the flag with the loopback default.
func TestOperatorSourcesFlagDefaultsToLoopback(t *testing.T) {
	root := rootNodeRunCmd(&baseFlags{})
	shard := shardNodeRunCmd(&baseFlags{})
	for name, f := range map[string]string{
		"root":  root.Flags().Lookup("operator-allowed-sources").DefValue,
		"shard": shard.Flags().Lookup("operator-allowed-sources").DefValue,
	} {
		require.Equal(t, defaultOperatorSources, f, name)
	}
	set, err := parseOperatorSources("")
	require.NoError(t, err)
	require.True(t, set.allows("127.0.0.1") && !set.allows("10.0.0.1"), "empty means the default")
}

// A non-loopback range is allowed but logged; the default and loopback-only lists are silent.
func TestOperatorNonLoopbackSourcesAreWarnedAbout(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	t.Cleanup(func() {
		set, _ := parseOperatorSources(defaultOperatorSources)
		activeOperatorSources.Store(set)
	})
	require.NoError(t, configureOperatorSources(log, defaultOperatorSources))
	require.NoError(t, configureOperatorSources(log, "127.0.0.1,::1"))
	require.Empty(t, buf.String())
	require.NoError(t, configureOperatorSources(log, "127.0.0.1,10.1.0.0/16"))
	require.Contains(t, buf.String(), "level=WARN")
	require.Contains(t, buf.String(), "10.1.0.0/16")
	require.NotContains(t, buf.String(), "sources=\"[127.0.0.1")
}
