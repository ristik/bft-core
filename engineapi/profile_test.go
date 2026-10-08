package engineapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

/*
The two testdata files are eth_config results recorded from the pinned client (189c0df3), each
started from the spec `ubft engine-api genesis` generates for chain id 31337 — the second with only
`pragueTime: 4102444800` added. Both clients reported the same chain id and the same block-0 hash,
which is the case this check exists for: nothing earlier in startup can tell them apart.
*/

func loadConfig(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

func current(m map[string]any) map[string]any { return m["current"].(map[string]any) }

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestCheckProfile_RecordedResponses(t *testing.T) {
	t.Run("the generated spec is the pinned profile", func(t *testing.T) {
		p, err := checkProfile(mustJSON(t, loadConfig(t, "eth_config_cancun_at_genesis.json")), 31337)
		require.NoError(t, err)
		require.Equal(t, "0x8b51a7f5", p.ForkID, "the fork id reported is the one the check read")
	})
	t.Run("the same spec with Prague scheduled later is refused", func(t *testing.T) {
		_, err := checkProfile(mustJSON(t, loadConfig(t, "eth_config_prague_scheduled.json")), 31337)
		require.ErrorContains(t, err, "schedules a fork at timestamp 4102444800 after its current one")
		require.ErrorContains(t, err, `"next" is not null`)
	})
}

// Every case starts from the recorded pinned response and changes one thing, so each refusal is
// attributable to that one thing rather than to an unrelated difference in the fixture.
func TestCheckProfile_EachPinnedFieldIsEnforced(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(m map[string]any)
		expect string
	}{
		{"next scheduled", func(m map[string]any) { m["next"] = map[string]any{"activationTime": 99} }, "schedules a fork at timestamp 99"},
		{"last scheduled with next null", func(m map[string]any) { m["last"] = map[string]any{"activationTime": 7} }, `"last" is not null`},
		{"next scheduled but unreadable", func(m map[string]any) { m["next"] = "soon" }, "at an unreadable time"},
		{"next absent is not 'nothing scheduled'", func(m map[string]any) { delete(m, "next") }, `no "next" entry`},
		{"last absent is not 'nothing scheduled'", func(m map[string]any) { delete(m, "last") }, `no "last" entry`},
		{"current absent", func(m map[string]any) { delete(m, "current") }, "no current fork configuration"},
		{"current null", func(m map[string]any) { m["current"] = nil }, "no current fork configuration"},
		{"another chain", func(m map[string]any) { current(m)["chainId"] = "0x7a6a" }, "eth_config reports chainId=31338, shard conf says 31337"},
		{"chain id absent", func(m map[string]any) { delete(current(m), "chainId") }, "reports no chain id"},
		{"current fork activated after genesis", func(m map[string]any) { current(m)["activationTime"] = 1 }, "activated at timestamp 1"},
		{"activation time absent is not genesis", func(m map[string]any) { delete(current(m), "activationTime") }, "reports no activation time"},
		{"blob schedule differs", func(m map[string]any) {
			current(m)["blobSchedule"] = map[string]any{"target": 6, "max": 9, "baseFeeUpdateFraction": 5007716}
		}, "blob schedule is"},
		{"blob schedule absent", func(m map[string]any) { delete(current(m), "blobSchedule") }, "reports no blob schedule"},
		{"Shanghai only: no beacon-roots contract", func(m map[string]any) { current(m)["systemContracts"] = map[string]any{} }, "missing BEACON_ROOTS_ADDRESS"},
		{"system contracts absent", func(m map[string]any) { delete(current(m), "systemContracts") }, "missing BEACON_ROOTS_ADDRESS"},
		{"a Prague system contract active", func(m map[string]any) {
			current(m)["systemContracts"].(map[string]any)["HISTORY_STORAGE_ADDRESS"] = "0x0000f90827f1c53a10cb7a02335b175320002935"
		}, "unexpected HISTORY_STORAGE_ADDRESS"},
		{"beacon-roots contract moved", func(m map[string]any) {
			current(m)["systemContracts"].(map[string]any)["BEACON_ROOTS_ADDRESS"] = "0x00000000000000000000000000000000000000ff"
		}, "moved BEACON_ROOTS_ADDRESS"},
		{"an extra precompile", func(m map[string]any) {
			current(m)["precompiles"].(map[string]any)["BLS12_G1ADD"] = "0x000000000000000000000000000000000000000b"
		}, "unexpected BLS12_G1ADD"},
		{"a precompile missing", func(m map[string]any) { delete(current(m)["precompiles"].(map[string]any), "KZG_POINT_EVALUATION") }, "missing KZG_POINT_EVALUATION"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := loadConfig(t, "eth_config_cancun_at_genesis.json")
			tc.mutate(m)
			_, err := checkProfile(mustJSON(t, m), 31337)
			require.ErrorContains(t, err, tc.expect)
		})
	}

	t.Run("address comparison is case-insensitive", func(t *testing.T) {
		m := loadConfig(t, "eth_config_cancun_at_genesis.json")
		current(m)["systemContracts"].(map[string]any)["BEACON_ROOTS_ADDRESS"] = "0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02"
		_, err := checkProfile(mustJSON(t, m), 31337)
		require.NoError(t, err)
	})
}

func TestCheckProfile_UnusableResponses(t *testing.T) {
	for _, tc := range []struct{ name, raw, expect string }{
		{"null", "null", "no fork configuration"},
		{"empty", "", "no fork configuration"},
		{"not an object", `"cancun"`, "decoding eth_config"},
		{"current not an object", `{"current": 5, "next": null, "last": null}`, "decoding eth_config current fork"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := checkProfile(json.RawMessage(tc.raw), 31337)
			require.ErrorContains(t, err, tc.expect)
		})
	}
}

// TestCheckExecutionProfile_ReadsThePlainConnection pins which connection answers, and that a client
// without eth_config fails closed rather than being treated as having nothing scheduled.
func TestCheckExecutionProfile_ReadsThePlainConnection(t *testing.T) {
	recorded, err := os.ReadFile("testdata/eth_config_cancun_at_genesis.json")
	require.NoError(t, err)

	serve := func(t *testing.T, answer func(w http.ResponseWriter, id any)) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Method string `json:"method"`
				ID     any    `json:"id"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			w.Header().Set("Content-Type", "application/json")
			if req.Method != "eth_config" {
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID,
					"error": map[string]any{"code": -32601, "message": "Method not found"}})
				return
			}
			answer(w, req.ID)
		}))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	withResult := func(w http.ResponseWriter, id any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": json.RawMessage(recorded)})
	}
	methodNotFound := func(w http.ResponseWriter, id any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id,
			"error": map[string]any{"code": -32601, "message": "Method not found"}})
	}

	t.Run("answered over the plain connection", func(t *testing.T) {
		// The Engine URL answers nothing: the pinned client's authenticated port does not serve
		// eth_config, so the check must not depend on it.
		a := adapterFor(serve(t, methodNotFound), serve(t, withResult))
		p, err := a.CheckExecutionProfile(context.Background(), 31337)
		require.NoError(t, err)
		require.Equal(t, "0x8b51a7f5", p.ForkID)
	})
	t.Run("a client without eth_config is refused, not assumed compliant", func(t *testing.T) {
		a := adapterFor(serve(t, withResult), serve(t, methodNotFound))
		_, err := a.CheckExecutionProfile(context.Background(), 31337)
		require.ErrorContains(t, err, "reading eth_config (EIP-7910) over the plain connection")
		require.ErrorContains(t, err, "Method not found")
	})
	t.Run("an unreachable plain endpoint is refused", func(t *testing.T) {
		a := adapterFor(serve(t, withResult), "http://127.0.0.1:1")
		_, err := a.CheckExecutionProfile(context.Background(), 31337)
		require.ErrorContains(t, err, "reading eth_config")
	})
}

// A fresh-B1 deployment's client adds exactly the four Unicity native precompiles to the pinned Cancun set; the plain check still refuses them.
func TestCheckProfile_UnicityPrecompilesOfAB1Deployment(t *testing.T) {
	withNative := func(mutate func(p map[string]any)) json.RawMessage {
		m := loadConfig(t, "eth_config_cancun_at_genesis.json")
		p := current(m)["precompiles"].(map[string]any)
		for k, v := range unicityNativePrecompiles {
			p[k] = v
		}
		if mutate != nil {
			mutate(p)
		}
		return mustJSON(t, m)
	}
	t.Run("expected set accepted", func(t *testing.T) {
		_, err := checkProfileWith(withNative(nil), 31337, unicityNativePrecompiles)
		require.NoError(t, err)
	})
	t.Run("the plain profile still refuses them", func(t *testing.T) {
		_, err := checkProfile(withNative(nil), 31337)
		require.ErrorContains(t, err, "unexpected unicity-b1-Member")
	})
	t.Run("a B1 deployment refuses a client without B2", func(t *testing.T) {
		_, err := checkProfileWith(withNative(func(p map[string]any) { delete(p, "unicity-b2-sdk3") }), 31337, unicityNativePrecompiles)
		require.ErrorContains(t, err, "missing unicity-b2-sdk3")
	})
	t.Run("a B1 deployment refuses a moved verifier", func(t *testing.T) {
		_, err := checkProfileWith(withNative(func(p map[string]any) { p["unicity-b1-Uc"] = "0x0000000000000000000000000000000000000200" }), 31337, unicityNativePrecompiles)
		require.ErrorContains(t, err, "moved unicity-b1-Uc")
	})
	t.Run("a B1 deployment refuses S1 at 0x0103", func(t *testing.T) {
		_, err := checkProfileWith(withNative(func(p map[string]any) { p["unicity-s1"] = "0x0000000000000000000000000000000000000103" }), 31337, unicityNativePrecompiles)
		require.ErrorContains(t, err, "unexpected unicity-s1")
	})
}
