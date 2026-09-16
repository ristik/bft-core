package parentwitness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	network "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/registrywitness"
)

func localProof(ev registryproof.Evidence) registryproof.GetProofResult {
	p := registryproof.GetProofResult{Address: registryproof.RegistryAddress}
	for _, n := range ev.AccountProof {
		p.AccountProof = append(p.AccountProof, hexutil.Bytes(bytes.Clone(n)))
	}
	for i := range ev.StorageProofs {
		sp := registryproof.StorageProofResult{Key: registryproof.SlotKey(i).Hex()}
		for _, n := range ev.StorageProofs[i] {
			sp.Proof = append(sp.Proof, hexutil.Bytes(bytes.Clone(n)))
		}
		p.StorageProof = append(p.StorageProof, sp)
	}
	return p
}

func rpcResult(t *testing.T, result any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	require.NoError(t, err)
	return b
}

func exactRPCServer(t *testing.T, target Target, ev registryproof.Evidence) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var req struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		require.NotEmpty(t, req.Params)
		require.Contains(t, string(req.Params[len(req.Params)-1]), target.request.BlockHash.Hex())
		switch req.Method {
		case "debug_getRawHeader":
			_, _ = w.Write(rpcResult(t, hexutil.Bytes(ev.Header)))
		case "eth_getProof":
			_, _ = w.Write(rpcResult(t, localProof(ev)))
		default:
			t.Errorf("unexpected RPC method %q", req.Method)
		}
	}))
	return s, &calls
}

func localBudget() RequesterBudget {
	return RequesterBudget{MaxAttempts: 3, MaxProviders: 2, Overall: time.Second, PerAttempt: 500 * time.Millisecond, MaxDownloadedBytes: 2 * registrywitness.MaxResponseBytes, Backoff: time.Second}
}

type meteredCallerFunc func(context.Context, string, []any, int64) (json.RawMessage, int64, error)

func (f meteredCallerFunc) CallMetered(ctx context.Context, method string, params []any, limit int64) (json.RawMessage, int64, error) {
	return f(ctx, method, params, limit)
}

func TestRequesterLocalSuccessWithoutPeersIsOwned(t *testing.T) {
	chain, target := fixtureTarget(t)
	s, calls := exactRPCServer(t, target, chain.Blocks[1].Evidence)
	defer s.Close()
	r, err := NewRequester(context.Background(), RequesterConfig{LocalRPC: registrywitness.NewHTTPCaller(s.URL, time.Second), Budget: localBudget()})
	require.NoError(t, err)
	t.Cleanup(r.Close)
	got, err := r.Request(context.Background(), target)
	require.NoError(t, err)
	require.Equal(t, RequesterVerified, got.Outcome)
	require.Equal(t, 1, got.Attempts)
	require.Equal(t, 1, got.LocalAttempts)
	require.Zero(t, got.Providers)
	require.EqualValues(t, 2, calls.Load())
	e := got.Response.Evidence()
	e.Header[0] ^= 1
	require.Equal(t, chain.Blocks[1].Evidence.Header, got.Response.Evidence().Header)
}

func TestRequesterLocalFailuresFallBackToGenuinePeerProof(t *testing.T) {
	chain, target := fixtureTarget(t)
	var valid bytes.Buffer
	require.NoError(t, WriteResponseFrame(&valid, Response{Request: target.Request(), Outcome: OutcomeFound, Evidence: chain.Blocks[1].Evidence}))
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"expired", []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"distance to target block exceeds maximum proof window"}}`)},
		{"unavailable", []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"block not found"}}`)},
		{"invalid", []byte(`{"jsonrpc":"2.0","id":1,"result":`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(tc.body) }))
			defer s.Close()
			opener := &reviewFrameOpener{frames: [][]byte{valid.Bytes()}}
			r, err := NewRequester(context.Background(), RequesterConfig{LocalRPC: registrywitness.NewHTTPCaller(s.URL, time.Second), Opener: opener, Providers: []peer.ID{"valid"}, Budget: localBudget()})
			require.NoError(t, err)
			t.Cleanup(func() { r.Close(); opener.wg.Wait() })
			got, err := r.Request(context.Background(), target)
			require.NoError(t, err)
			require.Equal(t, RequesterVerified, got.Outcome)
			require.Equal(t, 2, got.Attempts)
			require.Equal(t, 1, got.LocalAttempts)
			require.Equal(t, 1, got.Providers)
		})
	}
}

func TestRequesterSharesDownloadedBytesAcrossLocalAndPeer(t *testing.T) {
	_, target := fixtureTarget(t)
	body := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"missing"}}`)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer s.Close()
	opener := &reviewFrameOpener{frames: [][]byte{{3, 1, 2, 3}}}
	b := localBudget()
	b.MaxDownloadedBytes = int64(len(body) + 2)
	r, err := NewRequester(context.Background(), RequesterConfig{LocalRPC: registrywitness.NewHTTPCaller(s.URL, time.Second), Opener: opener, Providers: []peer.ID{"peer"}, Budget: b})
	require.NoError(t, err)
	t.Cleanup(func() { r.Close(); opener.wg.Wait() })
	got, err := r.Request(context.Background(), target)
	require.NoError(t, err)
	require.Equal(t, RequesterBudgetExhausted, got.Outcome)
	require.EqualValues(t, len(body)+2, got.Downloaded)
	require.Equal(t, 2, got.Attempts)
}

func TestRequesterExactLocalBodyBudgetLeavesNoUnlimitedPeerAttempt(t *testing.T) {
	_, target := fixtureTarget(t)
	body := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"missing"}}`)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer s.Close()
	opener := &countingRequesterOpener{}
	b := localBudget()
	b.MaxDownloadedBytes = int64(len(body))
	r, err := NewRequester(context.Background(), RequesterConfig{LocalRPC: registrywitness.NewHTTPCaller(s.URL, time.Second), Opener: opener, Providers: []peer.ID{"peer"}, Budget: b})
	require.NoError(t, err)
	t.Cleanup(r.Close)
	got, err := r.Request(context.Background(), target)
	require.NoError(t, err)
	require.Equal(t, RequesterBudgetExhausted, got.Outcome)
	require.EqualValues(t, len(body), got.Downloaded)
	require.Zero(t, opener.calls)
}

func TestRequesterExactValidHeaderBudgetStartsNeitherProofNorPeer(t *testing.T) {
	chain, target := fixtureTarget(t)
	headerBody := rpcResult(t, hexutil.Bytes(chain.Blocks[1].Evidence.Header))
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write(headerBody)
	}))
	defer s.Close()
	opener := &countingRequesterOpener{}
	b := localBudget()
	b.MaxDownloadedBytes = int64(len(headerBody))
	r, err := NewRequester(context.Background(), RequesterConfig{LocalRPC: registrywitness.NewHTTPCaller(s.URL, time.Second), Opener: opener, Providers: []peer.ID{"peer"}, Budget: b})
	require.NoError(t, err)
	t.Cleanup(r.Close)
	got, err := r.Request(context.Background(), target)
	require.NoError(t, err)
	require.Equal(t, RequesterBudgetExhausted, got.Outcome)
	require.EqualValues(t, len(headerBody), got.Downloaded)
	require.EqualValues(t, 1, calls.Load())
	require.Zero(t, opener.calls)
}

func TestRequesterSharesOverallTimeAndCancellationWithLocal(t *testing.T) {
	_, target := fixtureTarget(t)
	t.Run("overall", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(45 * time.Millisecond)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"missing"}}`))
		}))
		defer s.Close()
		peerDeadline := make(chan time.Time, 1)
		opener := reviewOpenerFunc(func(ctx context.Context, _ peer.ID, _ string) (network.Stream, error) {
			dl, _ := ctx.Deadline()
			peerDeadline <- dl
			<-ctx.Done()
			return nil, ctx.Err()
		})
		b := localBudget()
		b.Overall, b.PerAttempt = 80*time.Millisecond, 60*time.Millisecond
		r, err := NewRequester(context.Background(), RequesterConfig{LocalRPC: registrywitness.NewHTTPCaller(s.URL, time.Second), Opener: opener, Providers: []peer.ID{"slow"}, Budget: b})
		require.NoError(t, err)
		start := time.Now()
		got, err := r.Request(context.Background(), target)
		require.NoError(t, err)
		r.Close()
		require.Equal(t, RequesterBudgetExhausted, got.Outcome)
		select {
		case dl := <-peerDeadline:
			require.LessOrEqual(t, dl, start.Add(b.Overall+10*time.Millisecond))
		case <-time.After(time.Second):
			t.Fatal("peer attempt did not receive the remaining overall deadline")
		}
	})
	t.Run("cancel local only", func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		s := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			close(started)
			select {
			case <-r.Context().Done():
			case <-release:
			}
		}))
		t.Cleanup(func() { close(release); s.Close() })
		r, err := NewRequester(context.Background(), RequesterConfig{LocalRPC: registrywitness.NewHTTPCaller(s.URL, time.Second), Budget: localBudget()})
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan RequesterResult, 1)
		go func() { got, _ := r.Request(ctx, target); done <- got }()
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("local request did not start")
		}
		cancel()
		select {
		case got := <-done:
			require.Equal(t, RequesterStopped, got.Outcome)
		case <-time.After(time.Second):
			t.Fatal("canceled local request did not finish")
		}
		r.Close()
	})
}

func TestRequesterRejectsLateLocalProofFromContextBlindCaller(t *testing.T) {
	chain, target := fixtureTarget(t)
	header, err := json.Marshal(hexutil.Bytes(chain.Blocks[1].Evidence.Header))
	require.NoError(t, err)
	proof, err := json.Marshal(localProof(chain.Blocks[1].Evidence))
	require.NoError(t, err)
	local := meteredCallerFunc(func(_ context.Context, method string, _ []any, _ int64) (json.RawMessage, int64, error) {
		if method == "debug_getRawHeader" {
			return header, int64(len(header)), nil
		}
		time.Sleep(35 * time.Millisecond) // deliberately ignores the expired call context
		return proof, int64(len(proof)), nil
	})
	b := localBudget()
	b.PerAttempt = 20 * time.Millisecond
	r, err := NewRequester(context.Background(), RequesterConfig{LocalRPC: local, Budget: b})
	require.NoError(t, err)
	t.Cleanup(r.Close)
	got, err := r.Request(context.Background(), target)
	require.NoError(t, err)
	require.Equal(t, RequesterUnavailable, got.Outcome)
	require.False(t, got.Response.Valid())
}

func TestRequesterOverallDeadlineCoversFinalPublication(t *testing.T) {
	chain, target := fixtureTarget(t)
	proofReady := make(chan struct{})
	releaseProof := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		if req.Method == "debug_getRawHeader" {
			_, _ = w.Write(rpcResult(t, hexutil.Bytes(chain.Blocks[1].Evidence.Header)))
			return
		}
		close(proofReady)
		<-releaseProof
		_, _ = w.Write(rpcResult(t, localProof(chain.Blocks[1].Evidence)))
	}))
	b := localBudget()
	b.Overall, b.PerAttempt = 70*time.Millisecond, time.Second
	r, err := NewRequester(context.Background(), RequesterConfig{LocalRPC: registrywitness.NewHTTPCaller(s.URL, time.Second), Budget: b})
	require.NoError(t, err)
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseProof) })
		r.Close()
		s.Close()
	})
	done := make(chan RequesterResult, 1)
	go func() { got, _ := r.Request(context.Background(), target); done <- got }()
	select {
	case <-proofReady:
	case <-time.After(time.Second):
		t.Fatal("proof request did not start")
	}
	r.mu.Lock()
	releaseOnce.Do(func() { close(releaseProof) })
	time.Sleep(100 * time.Millisecond)
	r.mu.Unlock()
	select {
	case got := <-done:
		require.Equal(t, RequesterBudgetExhausted, got.Outcome)
		require.False(t, got.Response.Valid())
	case <-time.After(time.Second):
		t.Fatal("request did not finish after publication lock released")
	}
}

func TestRequesterRejectsUnmeteredCustomLocalResultBeforeDecode(t *testing.T) {
	_, target := fixtureTarget(t)
	local := meteredCallerFunc(func(context.Context, string, []any, int64) (json.RawMessage, int64, error) {
		return json.RawMessage(`"0x01"`), 0, nil
	})
	r, err := NewRequester(context.Background(), RequesterConfig{LocalRPC: local, Budget: localBudget()})
	require.NoError(t, err)
	t.Cleanup(r.Close)
	got, err := r.Request(context.Background(), target)
	require.NoError(t, err)
	require.Equal(t, RequesterInvalid, got.Outcome)
	require.Contains(t, got.Detail, "unmetered result")
}

func TestRequesterTargetMovementCancelsLocalGeneration(t *testing.T) {
	chain, first := fixtureTarget(t)
	second := first
	second.request.BlockHash = chain.Blocks[2].Hash
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	s := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		once.Do(func() { close(started) })
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() { close(release); s.Close() })
	r, err := NewRequester(context.Background(), RequesterConfig{LocalRPC: registrywitness.NewHTTPCaller(s.URL, time.Second), Budget: localBudget()})
	require.NoError(t, err)
	firstDone := make(chan RequesterResult, 1)
	go func() { got, _ := r.Request(context.Background(), first); firstDone <- got }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("local request did not start")
	}
	_, err = r.Request(context.Background(), second)
	require.ErrorIs(t, err, ErrRequesterBackoff)
	select {
	case got := <-firstDone:
		require.Equal(t, RequesterSuperseded, got.Outcome)
	case <-time.After(time.Second):
		t.Fatal("superseded local request did not finish")
	}
	r.Close()
}

func TestHTTPCallerMeteredRefusesRedirectAndCountsBody(t *testing.T) {
	var redirected atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Store(true) }))
	defer destination.Close()
	body := []byte("redirect body")
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = w.Write(body)
	}))
	defer s.Close()
	_, downloaded, err := registrywitness.NewHTTPCaller(s.URL, time.Second).CallMetered(context.Background(), "debug_getRawHeader", []any{common.HexToHash("0x01")}, 100)
	require.Error(t, err)
	require.EqualValues(t, len(body), downloaded)
	require.False(t, redirected.Load())
	redirected.Store(false)
	_, err = registrywitness.NewHTTPCaller(s.URL, time.Second).Call(context.Background(), "debug_getRawHeader", []any{common.HexToHash("0x01")})
	require.Error(t, err) // destination is not a JSON-RPC response, but legacy Call followed it
	require.True(t, redirected.Load())
}

func TestHTTPCallerMeteredCountsPartialAndOversizeBodies(t *testing.T) {
	t.Run("partial", func(t *testing.T) {
		body := []byte("partial")
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write(body)
		}))
		defer s.Close()
		_, downloaded, err := registrywitness.NewHTTPCaller(s.URL, time.Second).CallMetered(context.Background(), "debug_getRawHeader", nil, 1000)
		require.Error(t, err)
		require.EqualValues(t, len(body), downloaded)
	})
	t.Run("oversize", func(t *testing.T) {
		body := bytes.Repeat([]byte{'x'}, registrywitness.MaxResponseBytes+1)
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			_, _ = w.Write(body)
		}))
		defer s.Close()
		_, downloaded, err := registrywitness.NewHTTPCaller(s.URL, time.Second).CallMetered(context.Background(), "debug_getRawHeader", nil, int64(len(body)))
		require.ErrorIs(t, err, registrywitness.ErrInvalid)
		require.EqualValues(t, len(body), downloaded)
	})
}
