package engineapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/shardnode"
)

// mockReth is a scripted stand-in for reth's two RPC surfaces (engine_* on
// one httptest.Server, eth_* on another — real reth serves them on
// different ports too). It is not a reth simulator: it returns exactly what
// each test tells it to, and its only job is proving that Client/EthClient/
// Adapter build the right requests, send the right auth header, and decode
// the right response shape. It cannot prove reth's own Engine API semantics
// match what this package assumes — that needs a live reth, unavailable in
// this environment; see docs/engine-api-adapter-plan.md's B1.1/B2/B3 gates.
type mockReth struct {
	t      *testing.T
	secret Secret

	// keyed by JSON-RPC method name
	handlers map[string]func(params json.RawMessage) (any, *rpcError)

	sawAuthHeader bool
}

func newMockReth(t *testing.T, secret Secret) *mockReth {
	return &mockReth{t: t, secret: secret, handlers: make(map[string]func(json.RawMessage) (any, *rpcError))}
}

func (m *mockReth) on(method string, h func(params json.RawMessage) (any, *rpcError)) {
	m.handlers[method] = h
}

func (m *mockReth) server(requireAuth bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requireAuth {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				m.t.Errorf("mockReth: missing bearer token on %s", r.URL.Path)
			} else {
				m.sawAuthHeader = true
			}
		}

		var req rpcRequest
		require.NoError(m.t, json.NewDecoder(r.Body).Decode(&req))

		h, ok := m.handlers[req.Method]
		if !ok {
			m.t.Fatalf("mockReth: no handler registered for %s", req.Method)
		}
		paramsJSON, err := json.Marshal(req.Params)
		require.NoError(m.t, err)

		result, rpcErr := h(paramsJSON)
		resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
		if rpcErr != nil {
			resp.Error = rpcErr
		} else {
			b, err := json.Marshal(result)
			require.NoError(m.t, err)
			resp.Result = b
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(m.t, json.NewEncoder(w).Encode(resp))
	}))
}

func fixedHash(b byte) data32 {
	var d data32
	for i := range d {
		d[i] = b
	}
	return d
}

// fixedHashBytes is fixedHash's slice form, for building shardnode.Hash
// values directly — an array literal's result isn't addressable, so
// fixedHash(b)[:] doesn't compile at a call site; this sidesteps that.
func fixedHashBytes(b byte) []byte {
	d := fixedHash(b)
	return d[:]
}

// newTestAdapter wires an Adapter against two mockReth-backed servers (one
// standing in for the authenticated :8551 engine surface, one for the
// plain :8545 eth surface — matching how a real deployment separates them).
func newTestAdapter(t *testing.T, engine, eth *mockReth) (*Adapter, func()) {
	return newTestAdapterWithVerifier(t, engine, eth, nil)
}

// newTestAdapterWithVerifier is newTestAdapter with an explicit derivation context, for the tests
// that drive Adapter.Build through the seal sibling.
func newTestAdapterWithVerifier(t *testing.T, engine, eth *mockReth, verifier *VerifierContext) (*Adapter, func()) {
	secret, err := ParseSecret(strings.Repeat("ab", 32))
	require.NoError(t, err)
	engine.secret = secret

	engineSrv := engine.server(true)
	ethSrv := eth.server(false)

	a := NewAdapter(Config{EngineURL: engineSrv.URL, EthURL: ethSrv.URL, Secret: secret, Verifier: verifier}, nil)
	return a, func() { engineSrv.Close(); ethSrv.Close() }
}

func TestAdapter_CheckCapabilities_Passes(t *testing.T) {
	engine := newMockReth(t, Secret{})
	engine.on("engine_exchangeCapabilities", func(json.RawMessage) (any, *rpcError) {
		return requiredCapabilities, nil
	})
	eth := newMockReth(t, Secret{})
	a, closeFn := newTestAdapter(t, engine, eth)
	defer closeFn()

	require.NoError(t, a.CheckCapabilities(context.Background()))
	require.True(t, engine.sawAuthHeader, "engine_* calls must carry the bearer token")
}

func TestAdapter_CheckCapabilities_FailsClosed_WhenMethodMissing(t *testing.T) {
	engine := newMockReth(t, Secret{})
	engine.on("engine_exchangeCapabilities", func(json.RawMessage) (any, *rpcError) {
		return []string{"engine_forkchoiceUpdatedV3"}, nil // missing getPayloadV3, newPayloadV3
	})
	eth := newMockReth(t, Secret{})
	a, closeFn := newTestAdapter(t, engine, eth)
	defer closeFn()

	err := a.CheckCapabilities(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "engine_getPayloadV3")
}

func TestAdapter_Head_ReadsFromEthNamespace(t *testing.T) {
	eth := newMockReth(t, Secret{})
	eth.on("eth_getBlockByNumber", func(p json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: 7, Hash: fixedHash(0x07), StateRoot: fixedHash(0x77)}, nil
	})
	a, closeFn := newTestAdapter(t, newMockReth(t, Secret{}), eth)
	defer closeFn()

	head, err := a.Head(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 7, head.Number)
	h := fixedHash(0x07)
	require.Equal(t, shardnode.Hash(h[:]), head.Hash)
}

// The D2 seal siblings are required only when a deployment selects the seal path. These four cases
// fix that boundary, because the interesting failure is the one where the requirement becomes
// unconditional by accident: that would fail startup against every stock client, for a path this
// adapter does not yet drive.

func TestAdapter_SealCapabilities_AreNotRequiredByDefault(t *testing.T) {
	engine := newMockReth(t, Secret{})
	engine.on("engine_exchangeCapabilities", func(json.RawMessage) (any, *rpcError) {
		return requiredCapabilities, nil // a stock client, no seal siblings
	})
	eth := newMockReth(t, Secret{})
	a, closeFn := newTestAdapter(t, engine, eth)
	defer closeFn()

	require.NoError(t, a.CheckCapabilities(context.Background()),
		"a stock client must still start: the seal path is not activated by this change")
}

func TestAdapter_SealCapabilities_FailClosed_WhenSelectedAndAbsent(t *testing.T) {
	engine := newMockReth(t, Secret{})
	engine.on("engine_exchangeCapabilities", func(json.RawMessage) (any, *rpcError) {
		return requiredCapabilities, nil
	})
	eth := newMockReth(t, Secret{})
	a, closeFn := newTestAdapter(t, engine, eth)
	defer closeFn()
	a.RequireSealCapabilities()

	err := a.CheckCapabilities(context.Background())
	require.Error(t, err)
	for _, m := range sealCapabilities {
		require.Contains(t, err.Error(), m, "every absent seal sibling is named")
	}
}

func TestAdapter_SealCapabilities_PassWhenSelectedAndOffered(t *testing.T) {
	engine := newMockReth(t, Secret{})
	engine.on("engine_exchangeCapabilities", func(json.RawMessage) (any, *rpcError) {
		return append(append([]string{}, requiredCapabilities...), sealCapabilities...), nil
	})
	eth := newMockReth(t, Secret{})
	a, closeFn := newTestAdapter(t, engine, eth)
	defer closeFn()
	a.RequireSealCapabilities()

	require.NoError(t, a.CheckCapabilities(context.Background()))
}

func TestAdapter_SealCapabilities_APartialSetIsMissing(t *testing.T) {
	// A client offering some of the three advertises a flow it cannot complete. ureth makes the
	// set atomic, so this is a client that should not exist; the check refuses it anyway rather
	// than trusting the other side to be well formed.
	partial := append(append([]string{}, requiredCapabilities...), sealCapabilities[0])
	engine := newMockReth(t, Secret{})
	engine.on("engine_exchangeCapabilities", func(json.RawMessage) (any, *rpcError) {
		return partial, nil
	})
	eth := newMockReth(t, Secret{})
	a, closeFn := newTestAdapter(t, engine, eth)
	defer closeFn()
	a.RequireSealCapabilities()

	err := a.CheckCapabilities(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), sealCapabilities[1])
	require.NotContains(t, err.Error(), sealCapabilities[0], "the offered one is not reported missing")
}

// ureth #33 advertises its stock non-admission capabilities and all three seal siblings, while
// withholding every stock newPayload version. The shard-node startup check must accept that set.
func TestAdapter_SealCapabilities_AcceptsUreth33Advertisement(t *testing.T) {
	advertisedByUreth33 := []string{
		"engine_forkchoiceUpdatedV1", "engine_forkchoiceUpdatedV2", "engine_forkchoiceUpdatedV3", "engine_forkchoiceUpdatedV4",
		"engine_getClientVersionV1",
		"engine_getPayloadV1", "engine_getPayloadV2", "engine_getPayloadV3", "engine_getPayloadV4", "engine_getPayloadV5", "engine_getPayloadV6",
		"engine_getPayloadBodiesByHashV1", "engine_getPayloadBodiesByHashV2", "engine_getPayloadBodiesByRangeV1", "engine_getPayloadBodiesByRangeV2",
		"engine_getBlobsV1", "engine_getBlobsV2", "engine_getBlobsV3", "engine_getBlobsV4", "engine_hasBlobs",
		"engine_forkchoiceUpdatedWithSealV1", "engine_getPayloadWithSealV1", "engine_newPayloadWithSealV1",
	}
	wantRequest := []string{
		"engine_forkchoiceUpdatedV3", "engine_getPayloadV3",
		"engine_forkchoiceUpdatedWithSealV1", "engine_getPayloadWithSealV1", "engine_newPayloadWithSealV1",
	}
	engine := newMockReth(t, Secret{})
	engine.on("engine_exchangeCapabilities", func(raw json.RawMessage) (any, *rpcError) {
		var params [][]string
		require.NoError(t, json.Unmarshal(raw, &params))
		require.Equal(t, [][]string{wantRequest}, params)
		return advertisedByUreth33, nil
	})
	a, closeFn := newTestAdapter(t, engine, newMockReth(t, Secret{}))
	defer closeFn()
	require.Contains(t, a.engine.required(), "engine_newPayloadV3", "the default client retains the stock V3 requirement")
	a.RequireSealCapabilities()
	require.NoError(t, a.CheckCapabilities(context.Background()))

	for _, missing := range wantRequest {
		t.Run(missing, func(t *testing.T) {
			offered := make([]string, 0, len(advertisedByUreth33)-1)
			for _, capability := range advertisedByUreth33 {
				if capability != missing {
					offered = append(offered, capability)
				}
			}
			engine.on("engine_exchangeCapabilities", func(json.RawMessage) (any, *rpcError) { return offered, nil })
			err := a.CheckCapabilities(context.Background())
			require.ErrorContains(t, err, missing)
		})
	}
}
