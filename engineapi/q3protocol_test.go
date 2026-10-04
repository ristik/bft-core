package engineapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/q3compat"
	"github.com/unicitynetwork/bft-core/q3format"
)

var (
	q3Genesis = "0x" + strings.Repeat("31", 32)
	q3Code    = "0x" + strings.Repeat("32", 32)
	q3Want    = q3compat.ExecutionRequirement{GenesisHash: bytes32(0x31), CodeHash: bytes32(0x32), TransitionCodec: 1}
	q3Cfg     = q3format.Q3Config(5, [32]byte{9})
)

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

func q3Wire() q3ProtocolWire {
	return q3ProtocolWire{Version: 1, Protocols: []string{"q3/1"}, RegistryLayout: 2, GenesisHash: q3Genesis, CodeHash: q3Code,
		ConfigRevisions: []uint64{1}, TransitionCodecs: []uint64{1}}
}

func q3Adapter(t *testing.T, h func(json.RawMessage) (any, *rpcError)) (*Adapter, *mockReth, func()) {
	t.Helper()
	engine := newMockReth(t, Secret{})
	engine.on(q3ProtocolMethod, h)
	a, closeFn := newTestAdapter(t, engine, newMockReth(t, Secret{}))
	return a, engine, closeFn
}

func TestCheckQ3Execution(t *testing.T) {
	a, engine, closeFn := q3Adapter(t, func(json.RawMessage) (any, *rpcError) { return q3Wire(), nil })
	defer closeFn()
	r, err := a.CheckQ3Execution(context.Background(), q3Cfg, q3Want)
	require.NoError(t, err, "acceptance control")
	require.Equal(t, uint64(2), r.RegistryLayout)
	require.True(t, engine.sawAuthHeader, "the query goes over the JWT endpoint")
	p, err := a.Q3Execution().Report(context.Background())
	require.NoError(t, err)
	require.Equal(t, r, p)

	for _, c := range []struct {
		name string
		mut  func(*q3ProtocolWire)
		want error
	}{
		{"layout 1 loaded", func(w *q3ProtocolWire) { w.RegistryLayout = 1 }, q3compat.ErrExecutionLayout},
		{"no q3 protocol", func(w *q3ProtocolWire) { w.Protocols = []string{"q3/0"} }, q3compat.ErrExecutionProtocol},
		{"future report", func(w *q3ProtocolWire) { w.Version = 2 }, q3compat.ErrExecutionVersion},
		{"no transition codec", func(w *q3ProtocolWire) { w.TransitionCodecs = nil }, q3compat.ErrExecutionCodec},
		{"other genesis", func(w *q3ProtocolWire) { w.GenesisHash = "0x" + strings.Repeat("77", 32) }, q3compat.ErrExecutionIdentity},
		{"other code", func(w *q3ProtocolWire) { w.CodeHash = "0x" + strings.Repeat("78", 32) }, q3compat.ErrExecutionIdentity},
		{"short genesis", func(w *q3ProtocolWire) { w.GenesisHash = "0x31" }, ErrQ3ProtocolMalformed},
		{"unprefixed code", func(w *q3ProtocolWire) { w.CodeHash = strings.Repeat("32", 32) }, ErrQ3ProtocolMalformed},
		{"non-hex code", func(w *q3ProtocolWire) { w.CodeHash = "0x" + strings.Repeat("zz", 32) }, ErrQ3ProtocolMalformed},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := q3Wire()
			c.mut(&w)
			a, _, closeFn := q3Adapter(t, func(json.RawMessage) (any, *rpcError) { return w, nil })
			defer closeFn()
			_, err := a.CheckQ3Execution(context.Background(), q3Cfg, q3Want)
			require.ErrorIs(t, err, c.want)
		})
	}
}

func TestQ3UnawareClientIsRefused(t *testing.T) {
	a, _, closeFn := q3Adapter(t, func(json.RawMessage) (any, *rpcError) {
		return nil, &rpcError{Code: -32601, Message: "method not found"}
	})
	defer closeFn()
	_, err := a.CheckQ3Execution(context.Background(), q3Cfg, q3Want)
	require.ErrorIs(t, err, ErrQ3ProtocolUnavailable)
	require.ErrorIs(t, a.PinQ3Execution(context.Background(), q3Cfg, q3Want), ErrQ3ProtocolUnavailable)
}

func TestPinnedQ3ExecutionIsRecheckedBeforeEngineCalls(t *testing.T) {
	current := q3Wire()
	a, engine, closeFn := q3Adapter(t, func(json.RawMessage) (any, *rpcError) { return current, nil })
	defer closeFn()
	called := 0
	engine.on("engine_exchangeCapabilities", func(json.RawMessage) (any, *rpcError) { called++; return requiredCapabilities, nil })
	require.NoError(t, a.PinQ3Execution(context.Background(), q3Cfg, q3Want))
	require.NoError(t, a.CheckCapabilities(context.Background()), "an unchanged client passes")
	require.Equal(t, 1, called)

	for name, mut := range map[string]func(*q3ProtocolWire){
		"reconnected to layout 1":   func(w *q3ProtocolWire) { w.RegistryLayout = 1 },
		"reconnected to other code": func(w *q3ProtocolWire) { w.CodeHash = "0x" + strings.Repeat("78", 32) },
		"lost the protocol":         func(w *q3ProtocolWire) { w.Protocols = nil },
		"gained a protocol":         func(w *q3ProtocolWire) { w.Protocols = []string{"q3/1", "q3/2"} },
		"gained a codec":            func(w *q3ProtocolWire) { w.TransitionCodecs = []uint64{1, 2} },
	} {
		current = q3Wire()
		mut(&current)
		before := called
		err := a.CheckCapabilities(context.Background())
		require.Error(t, err, name)
		require.Equal(t, before, called, "%s: the call is refused before it reaches the client", name)
	}
	current = q3Wire()
	current.RegistryLayout = 1
	require.ErrorIs(t, a.CheckCapabilities(context.Background()), q3compat.ErrExecutionLayout)
	current = q3Wire()
	current.Protocols = []string{"q3/1", "q3/2"} // still satisfies the requirement, but is not the pinned report
	require.ErrorIs(t, a.CheckCapabilities(context.Background()), ErrQ3ProtocolChanged)
}

func TestQ3PinDoesNotReplaceTheSealPin(t *testing.T) {
	// Both pins hold at once: setting the Q3 hook must not displace the fee-identity hook.
	baseline := sealConfigWire{Version: 1, MaxGas: 30_000_000, SystemGas: 2_000_000, BaseFeeFloor: 1_000_000, Elasticity: 2, ChangeDenominator: 8, FeeCollector: "0x" + strings.Repeat("12", 20)}
	seal := baseline
	a, engine, closeFn := q3Adapter(t, func(json.RawMessage) (any, *rpcError) { return q3Wire(), nil })
	defer closeFn()
	engine.on("engine_sealConfigV1", func(json.RawMessage) (any, *rpcError) { return seal, nil })
	engine.on("engine_exchangeCapabilities", func(json.RawMessage) (any, *rpcError) { return requiredCapabilities, nil })
	a.feeCollector = filledCollector()
	_, err := a.CheckedExecutionConfigIdentity(context.Background(), [32]byte{1})
	require.NoError(t, err)
	require.NoError(t, a.PinQ3Execution(context.Background(), q3Cfg, q3Want))
	require.NoError(t, a.CheckCapabilities(context.Background()))
	seal.ChangeDenominator = 10
	require.ErrorIs(t, a.CheckCapabilities(context.Background()), ErrSealConfigIdentity)
}

func TestQ3ExecutionReportRefusesAnUnreadVersionItself(t *testing.T) {
	w := q3Wire()
	w.Version = 2
	a, _, closeFn := q3Adapter(t, func(json.RawMessage) (any, *rpcError) { return w, nil })
	defer closeFn()
	_, err := a.Q3ExecutionReport(context.Background()) // the probe path used by readiness, which does no further check
	require.ErrorIs(t, err, q3compat.ErrExecutionVersion)
}
