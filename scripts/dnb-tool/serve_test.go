package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

type fakeBuilder struct {
	calls int
	err   error
	block chan struct{} // when set, build waits on it
}

func (f *fakeBuilder) build(_ context.Context, h common.Hash, n uint64) ([]byte, error) {
	f.calls++
	if f.block != nil {
		<-f.block
	}
	if f.err != nil {
		return nil, f.err
	}
	return []byte(fmt.Sprintf("%x/%d", h[:2], n)), nil
}

const goodBlock = "0x" + "ab00000000000000000000000000000000000000000000000000000000000001"

func get(h http.Handler, target, remote string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.RemoteAddr = remote
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func roomy() proofLimits {
	return proofLimits{perClient: 100, global: 1000, concurrent: 4, timeout: time.Second, maxClients: 100}
}

func TestLockProofServe_ServesTheBuiltProof(t *testing.T) {
	f := &fakeBuilder{}
	w := get(newProofHandler(f, "", roomy()), "/v1/lockproof?block="+goodBlock+"&nonce=7", "192.0.2.1:5000")
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/cbor", w.Header().Get("Content-Type"))
	require.Equal(t, "ab00/7", w.Body.String())
}

func TestLockProofServe_RefusesMalformedRequestsBeforeBuilding(t *testing.T) {
	f := &fakeBuilder{}
	h := newProofHandler(f, "", roomy())
	for _, target := range []string{
		"/v1/lockproof?block=" + goodBlock,                                              // no nonce
		"/v1/lockproof?nonce=7",                                                         // no block
		"/v1/lockproof?block=" + goodBlock[:65] + "&nonce=7",                            // 31.5 bytes
		"/v1/lockproof?block=" + strings.Replace(goodBlock, "ab", "zz", 1) + "&nonce=7", // not hex
		"/v1/lockproof?block=" + goodBlock + "&nonce=0",                                 // zero nonce
		"/v1/lockproof?block=" + goodBlock + "&nonce=07",                                // non-canonical
		"/v1/lockproof?block=" + goodBlock + "&nonce=-1",
		"/v1/lockproof?block=" + goodBlock + "&nonce=18446744073709551616",      // 2^64
		"/v1/lockproof?block=" + goodBlock + "&nonce=7&x=1",                     // extra parameter
		"/v1/lockproof?block=" + goodBlock + "&block=" + goodBlock + "&nonce=7", // a parameter twice
		"/v1/lockproof?block=" + goodBlock + "&nonce=7&nonce=8",
	} {
		require.Equal(t, http.StatusBadRequest, get(h, target, "192.0.2.1:5000").Code, target)
	}
	require.Equal(t, http.StatusNotFound, get(h, "/other", "192.0.2.1:5000").Code)
	r := httptest.NewRequest(http.MethodPost, "/v1/lockproof?block="+goodBlock+"&nonce=7", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
	require.Zero(t, f.calls)
}

func TestLockProofServe_MapsNotFoundAndUpstreamFailures(t *testing.T) {
	f := &fakeBuilder{err: fmt.Errorf("%w: no lock", errNotFound)}
	h := newProofHandler(f, "", roomy())
	require.Equal(t, http.StatusNotFound, get(h, "/v1/lockproof?block="+goodBlock+"&nonce=7", "192.0.2.1:1").Code)
	f.err = errors.New("dial tcp: refused")
	w := get(h, "/v1/lockproof?block="+goodBlock+"&nonce=7", "192.0.2.1:1")
	require.Equal(t, http.StatusBadGateway, w.Code)
	require.NotContains(t, w.Body.String(), "dial tcp", "upstream details stay in the log")
}

func TestLockProofServe_RateLimitsPerClientAndGlobally(t *testing.T) {
	f := &fakeBuilder{}
	l := roomy()
	l.perClient, l.global = 2, 3
	h := newProofHandler(f, "", l)
	at := time.Unix(1000, 0)
	h.now = func() time.Time { return at }
	q := "/v1/lockproof?block=" + goodBlock + "&nonce=7"
	require.Equal(t, http.StatusOK, get(h, q, "192.0.2.1:1").Code)
	require.Equal(t, http.StatusOK, get(h, q, "192.0.2.1:2").Code)
	for range 5 {
		require.Equal(t, http.StatusTooManyRequests, get(h, q, "192.0.2.1:3").Code, "one client over its own limit")
	}
	require.Equal(t, http.StatusOK, get(h, q, "192.0.2.2:1").Code, "refused requests spent none of the global budget")
	require.Equal(t, http.StatusTooManyRequests, get(h, q, "192.0.2.3:1").Code, "the global budget of 3 is spent")
	at = at.Add(time.Second)
	require.Equal(t, http.StatusOK, get(h, q, "192.0.2.1:4").Code, "a new window")
	require.Equal(t, 4, f.calls)
}

func TestLockProofServe_LimitsAnIPv6ClientByIts64(t *testing.T) {
	l := roomy()
	l.perClient = 1
	h := newProofHandler(&fakeBuilder{}, "172.30.89.1", l)
	q := "/v1/lockproof?block=" + goodBlock + "&nonce=7"
	require.Equal(t, http.StatusOK, get(h, q, "172.30.89.1:1", "X-Forwarded-For", "2001:db8:1:2::1").Code)
	require.Equal(t, http.StatusTooManyRequests, get(h, q, "172.30.89.1:2", "X-Forwarded-For", "2001:db8:1:2:ffff::9").Code, "same /64")
	require.Equal(t, http.StatusOK, get(h, q, "172.30.89.1:3", "X-Forwarded-For", "2001:db8:1:3::1").Code, "another /64")
	require.Equal(t, http.StatusOK, get(h, q, "[2001:db8:9:9::1]:5").Code, "a direct IPv6 peer")
	require.Equal(t, http.StatusTooManyRequests, get(h, q, "[2001:db8:9:9::2]:5").Code)
}

func TestLockProofServe_CapsTheTrackedClients(t *testing.T) {
	l := roomy()
	l.maxClients = 2
	h := newProofHandler(&fakeBuilder{}, "", l)
	at := time.Unix(1000, 0)
	h.now = func() time.Time { return at }
	q := "/v1/lockproof?block=" + goodBlock + "&nonce=7"
	require.Equal(t, http.StatusOK, get(h, q, "192.0.2.1:1").Code)
	require.Equal(t, http.StatusOK, get(h, q, "192.0.2.2:1").Code)
	require.Equal(t, http.StatusTooManyRequests, get(h, q, "192.0.2.3:1").Code, "a third client in one window is not tracked, so refused")
	require.Equal(t, http.StatusOK, get(h, q, "192.0.2.1:2").Code, "a tracked client is still served")
	at = at.Add(time.Second)
	require.Equal(t, http.StatusOK, get(h, q, "192.0.2.3:2").Code, "a new window forgets the clients")
}

func TestLockProofServe_UsesForwardedForOnlyFromTheTrustedProxy(t *testing.T) {
	f := &fakeBuilder{}
	l := roomy()
	l.perClient = 1
	h := newProofHandler(f, "172.30.89.1", l)
	q := "/v1/lockproof?block=" + goodBlock + "&nonce=7"
	require.Equal(t, http.StatusOK, get(h, q, "172.30.89.1:1", "X-Forwarded-For", "203.0.113.5").Code)
	require.Equal(t, http.StatusOK, get(h, q, "172.30.89.1:2", "X-Forwarded-For", "203.0.113.6").Code, "two clients behind the proxy")
	require.Equal(t, http.StatusTooManyRequests, get(h, q, "172.30.89.1:3", "X-Forwarded-For", "203.0.113.5").Code)
	require.Equal(t, http.StatusBadRequest, get(h, q, "172.30.89.1:4", "X-Forwarded-For", "not-an-ip").Code)
	// an untrusted peer's header is ignored: it is limited as itself
	require.Equal(t, http.StatusOK, get(h, q, "192.0.2.9:1", "X-Forwarded-For", "203.0.113.7").Code)
	require.Equal(t, http.StatusTooManyRequests, get(h, q, "192.0.2.9:2", "X-Forwarded-For", "203.0.113.8").Code)
}

func TestLockProofServe_RefusesBeyondTheConcurrentBuilds(t *testing.T) {
	f := &fakeBuilder{block: make(chan struct{})}
	l := roomy()
	l.concurrent = 1
	h := newProofHandler(f, "", l)
	q := "/v1/lockproof?block=" + goodBlock + "&nonce=7"
	done := make(chan int)
	go func() { done <- get(h, q, "192.0.2.1:1").Code }()
	require.Eventually(t, func() bool { return len(h.slots) == 1 }, time.Second, time.Millisecond)
	require.Equal(t, http.StatusTooManyRequests, get(h, q, "192.0.2.2:1").Code)
	close(f.block)
	require.Equal(t, http.StatusOK, <-done)
}

func TestRPCCall_TellsARefusalFromATransportFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"distance to target block exceeds maximum proof window"}}`))
	}))
	_, err := rpcCall(context.Background(), srv.URL, "eth_getProof", nil)
	var refused *rpcError
	require.ErrorAs(t, err, &refused, "an error answer is a refusal (404 at the endpoint)")
	srv.Close()
	_, err = rpcCall(context.Background(), srv.URL, "eth_getProof", nil)
	require.Error(t, err)
	require.False(t, errors.As(err, &refused), "an unreachable client is not a refusal (502 at the endpoint)")
}
