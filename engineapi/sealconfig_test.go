package engineapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckedExecutionConfigIdentity(t *testing.T) {
	legacyBytes, err := hex.DecodeString("f63207575830a59dece6e1b59ecbc46faa865492715252d5a846a6996bde98ba")
	require.NoError(t, err)
	var legacy [32]byte
	copy(legacy[:], legacyBytes)
	collector := "0x" + strings.Repeat("12", 20)
	baseline := sealConfigWire{Version: 1, MaxGas: 30_000_000, SystemGas: 2_000_000, BaseFeeFloor: 1_000_000, Elasticity: 2, ChangeDenominator: 8, FeeCollector: collector}
	cases := []struct {
		name   string
		local  [20]byte
		wire   sealConfigWire
		rpcErr *rpcError
		want   error
	}{
		{"valid", filledCollector(), baseline, nil, nil},
		{"local collector unset", [20]byte{}, baseline, nil, ErrUnsetCollector},
		{"companion collector unset", filledCollector(), func() sealConfigWire { x := baseline; x.FeeCollector = "0x" + strings.Repeat("00", 20); return x }(), nil, ErrUnsetCollector},
		{"malformed collector", filledCollector(), func() sealConfigWire { x := baseline; x.FeeCollector = "not-an-address"; return x }(), nil, ErrSealConfigCollector},
		{"collector mismatch", filledCollector(), func() sealConfigWire { x := baseline; x.FeeCollector = "0x" + strings.Repeat("34", 20); return x }(), nil, ErrSealConfigCollector},
		{"wrong version", filledCollector(), func() sealConfigWire { x := baseline; x.Version = 2; return x }(), nil, ErrSealConfigVersion},
		{"invalid profile", filledCollector(), func() sealConfigWire { x := baseline; x.SystemGas = x.MaxGas; return x }(), nil, ErrSealConfigProfile},
		{"rpc unavailable", filledCollector(), baseline, &rpcError{Code: -32601, Message: "method not found"}, ErrSealConfigUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := newMockReth(t, Secret{})
			engine.on("engine_sealConfigV1", func(json.RawMessage) (any, *rpcError) { return tc.wire, tc.rpcErr })
			eth := newMockReth(t, Secret{})
			a, closeFn := newTestAdapter(t, engine, eth)
			defer closeFn()
			a.feeCollector = tc.local
			id, err := a.CheckedExecutionConfigIdentity(context.Background(), legacy)
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("want %v, got %v", tc.want, err)
				}
				return
			}
			require.NoError(t, err)
			require.NotEqual(t, [32]byte{}, id)
			require.True(t, engine.sawAuthHeader)
		})
	}
}

func filledCollector() [20]byte {
	var x [20]byte
	for i := range x {
		x[i] = 0x12
	}
	return x
}

func TestCheckedIdentityRecheckedBeforeEngineCall(t *testing.T) {
	legacy := [32]byte{1}
	baseline := sealConfigWire{Version: 1, MaxGas: 30_000_000, SystemGas: 2_000_000, BaseFeeFloor: 1_000_000, Elasticity: 2, ChangeDenominator: 8, FeeCollector: "0x" + strings.Repeat("12", 20)}
	current := baseline
	engine := newMockReth(t, Secret{})
	engine.on("engine_sealConfigV1", func(json.RawMessage) (any, *rpcError) { return current, nil })
	called := 0
	engine.on("engine_exchangeCapabilities", func(json.RawMessage) (any, *rpcError) { called++; return requiredCapabilities, nil })
	a, closeFn := newTestAdapter(t, engine, newMockReth(t, Secret{}))
	defer closeFn()
	a.feeCollector = filledCollector()
	pinned, err := a.CheckedExecutionConfigIdentity(context.Background(), legacy)
	if err != nil {
		t.Fatal(err)
	}
	current.BaseFeeFloor++
	a.engine.http.CloseIdleConnections() // the next Engine RPC uses a new connection
	var capabilities []string
	err = a.engine.call(context.Background(), "engine_exchangeCapabilities", []any{requiredCapabilities}, &capabilities)
	if !errors.Is(err, ErrSealConfigIdentity) || called != 0 {
		t.Fatalf("changed companion reached Engine call: %v, calls %d", err, called)
	}
	if _, err := a.CheckedExecutionConfigIdentity(context.Background(), legacy); !errors.Is(err, ErrSealConfigIdentity) {
		t.Fatalf("repinned changed companion: %v", err)
	}
	current = baseline
	err = a.engine.call(context.Background(), "engine_exchangeCapabilities", []any{requiredCapabilities}, &capabilities)
	if err != nil || called != 1 {
		t.Fatalf("unchanged companion refused: %v, calls %d", err, called)
	}
	if id, err := a.CheckedExecutionConfigIdentity(context.Background(), legacy); err != nil || id != pinned {
		t.Fatalf("stable recheck: %x, %v", id, err)
	}
}
