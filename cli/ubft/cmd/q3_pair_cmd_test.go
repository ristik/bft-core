package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/engineapi"
	testobserve "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-go-base/types"
)

type rpcResult struct {
	result any
	err    string
}

func rpcServer(t *testing.T, handlers map[string]func(params json.RawMessage) rpcResult) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		h, ok := handlers[req.Method]
		resp := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		if !ok {
			resp["error"] = map[string]any{"code": -32601, "message": "no handler for " + req.Method}
		} else if res := h(req.Params); res.err != "" {
			resp["error"] = map[string]any{"code": -39002, "message": res.err}
		} else {
			resp["result"] = res.result
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func hexOf(b []byte) string { return "0x" + hex.EncodeToString(b) }

// laneRootInput is a fresh-B1 canonical root input as the tools read it: the transition array is its 11th field, followed by the B1 update hash and
// the root-records hash (13 fields; the legacy tuple ends with the transitions).
func laneRootInput(transitions [][]byte) []any {
	d := make([]any, len(transitions))
	for i, tr := range transitions {
		d[i] = tr
	}
	return []any{uint64(2), uint64(3), uint64(8), []byte{0x80}, uint64(5), uint64(1), uint64(1), make([]byte, 32), []any{uint64(1)},
		[]any{uint64(5), uint64(1), "leader", []byte{1}, []byte{2}}, d, make([]byte, 32), make([]byte, 32)}
}

// laneRetained serves one block's header and companion the way the execution client's plain endpoint does.
func laneRetained(t *testing.T) (*httptest.Server, []byte, [][]byte) {
	t.Helper()
	transitions := [][]byte{{0xa1, 0x01}, {0xb2}}
	rootInput, err := types.Cbor.Marshal(laneRootInput(transitions))
	require.NoError(t, err)
	th, err := engineapi.TransitionsHash(transitions)
	require.NoError(t, err)
	w := func(b byte) [32]byte { return [32]byte{0: b, 31: b} }
	digest, err := engineapi.AttributesDigest(100, w(3), [20]byte{0: 7}, w(4))
	require.NoError(t, err)
	binding, err := (engineapi.PairBinding{NetworkID: 3, RootGenesisID: w(1), ExecutionGenesisHash: w(2), ParentHash: w(0x22), ParentNumber: 4, OriginRootEpoch: 1,
		OriginRootRound: 9, ConfigurationID: w(7), ActivationID: w(8), RootInputHash: sha256.Sum256(rootInput), TransitionsHash: th,
		Kind: engineapi.PairBuild, SubjectID: digest}).Encode()
	require.NoError(t, err)
	h := func(b byte) string { x := w(b); return hexOf(x[:]) }
	header := map[string]any{"number": "0x5", "hash": h(0x11), "parentHash": h(0x22), "stateRoot": h(0x55), "mixHash": h(3),
		"miner": "0x0700000000000000000000000000000000000000", "timestamp": "0x64", "extraData": h(0x66), "parentBeaconBlockRoot": h(4), "withdrawals": []any{}}
	return rpcServer(t, map[string]func(json.RawMessage) rpcResult{
		"eth_getBlockByNumber": func(json.RawMessage) rpcResult { return rpcResult{result: header} },
		"unicity_getSealCompanionV1": func(json.RawMessage) rpcResult {
			return rpcResult{result: map[string]any{"status": "found", "companion": map[string]any{"rootInput": hexOf(rootInput), "pairBinding": hexOf(binding)}}}
		},
	}), rootInput, transitions
}

func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := New(testobserve.NewFactory(t))
	var out bytes.Buffer
	cmd.baseCmd.SetOut(&out)
	cmd.baseCmd.SetErr(&out)
	cmd.baseCmd.SetArgs(args)
	err := cmd.Execute(context.Background())
	return out.String(), err
}

func TestPairExportWritesTheRootInputTransitionsAndState(t *testing.T) {
	eth, rootInput, transitions := laneRetained(t)
	dir := t.TempDir()
	ri, tr, st := filepath.Join(dir, "ri.bin"), filepath.Join(dir, "tr.bin"), filepath.Join(dir, "state.json")
	_, err := runCLI(t, "q3", "pair-export", "--eth-url", eth.URL, "--root-input-out", ri, "--transitions-out", tr, "--state-out", st)
	require.NoError(t, err)
	got, err := os.ReadFile(ri)
	require.NoError(t, err)
	require.Equal(t, rootInput, got)
	want, err := types.Cbor.Marshal([]any{transitions[0], transitions[1]})
	require.NoError(t, err)
	got, err = os.ReadFile(tr)
	require.NoError(t, err)
	require.Equal(t, want, got)
	var state struct {
		Number    uint64 `json:"number"`
		Head      string `json:"head"`
		StateRoot string `json:"stateRoot"`
	}
	raw, err := os.ReadFile(st)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &state))
	require.EqualValues(t, 5, state.Number)
	require.True(t, strings.HasPrefix(state.Head, "0x11"))
	require.True(t, strings.HasPrefix(state.StateRoot, "0x55"))

	// a node with no retained companion exports nothing
	none := rpcServer(t, map[string]func(json.RawMessage) rpcResult{
		"eth_getBlockByNumber": func(json.RawMessage) rpcResult {
			return rpcResult{result: map[string]any{"number": "0x5", "hash": "0x" + strings.Repeat("11", 32), "parentHash": "0x" + strings.Repeat("22", 32), "stateRoot": "0x" + strings.Repeat("55", 32)}}
		},
		"unicity_getSealCompanionV1": func(json.RawMessage) rpcResult { return rpcResult{result: map[string]any{"status": "unknown"}} },
	})
	_, err = runCLI(t, "q3", "pair-export", "--eth-url", none.URL, "--root-input-out", filepath.Join(dir, "a"), "--transitions-out", filepath.Join(dir, "b"), "--state-out", filepath.Join(dir, "c"))
	require.ErrorIs(t, err, engineapi.ErrPairCompanion)
	_, statErr := os.Stat(filepath.Join(dir, "a"))
	require.True(t, os.IsNotExist(statErr), "no partial export")
}

func TestPairControlExitsZeroOnlyForAnAcceptedControl(t *testing.T) {
	eth, _, _ := laneRetained(t)
	jwt := filepath.Join(t.TempDir(), "jwt.hex")
	require.NoError(t, os.WriteFile(jwt, []byte(strings.Repeat("ab", 32)), 0o600))
	accept := true
	engine := rpcServer(t, map[string]func(json.RawMessage) rpcResult{
		"engine_forkchoiceUpdatedWithSealV1": func(json.RawMessage) rpcResult {
			if accept {
				return rpcResult{result: map[string]any{"payloadStatus": map[string]any{"status": "VALID"}, "payloadId": "0x0102030405060708"}}
			}
			return rpcResult{result: map[string]any{"payloadStatus": map[string]any{"status": "INVALID", "validationError": "pair binding refused: ParentHashMismatch"}}}
		},
	})
	args := func(kind string) []string {
		return []string{"q3", "pair-control", "--kind", kind, "--engine-url", engine.URL, "--jwt-secret", jwt, "--eth-url", eth.URL}
	}
	out, err := runCLI(t, args("accept")...)
	require.NoError(t, err)
	require.Contains(t, out, "pair control accept: accepted")

	accept = false
	_, err = runCLI(t, args("wrong-parent")...)
	require.ErrorContains(t, err, "pair control wrong-parent: refused")
	require.ErrorContains(t, err, "pair binding refused: ParentHashMismatch", "the typed cause reaches the lane")

	_, err = runCLI(t, args("bogus")...)
	require.Error(t, err)
	_, err = runCLI(t, "q3", "pair-control", "--kind", "accept", "--engine-url", engine.URL, "--jwt-secret", filepath.Join(t.TempDir(), "missing"), "--eth-url", eth.URL)
	require.Error(t, err, "no secret file")
}

// The execution client refuses a build below its finalized block ("Too deep reorg") after the pair gate has accepted the job. For the control that
// changes nothing that answer is the gate's acceptance and the command says exactly that; for a control that changes something the same answer is
// not an acceptance, so the command still exits non-zero and the lane finds no typed cause.
func TestPairControlReportsTheGatesAcceptanceWhenTheEngineRefusesTheBuildBelowItsFinalizedBlock(t *testing.T) {
	eth, _, _ := laneRetained(t)
	jwt := filepath.Join(t.TempDir(), "jwt.hex")
	require.NoError(t, os.WriteFile(jwt, []byte(strings.Repeat("ab", 32)), 0o600))
	engine := rpcServer(t, map[string]func(json.RawMessage) rpcResult{
		"engine_forkchoiceUpdatedWithSealV1": func(json.RawMessage) rpcResult { return rpcResult{err: "Too deep reorg"} },
	})
	args := func(kind string) []string {
		return []string{"q3", "pair-control", "--kind", kind, "--engine-url", engine.URL, "--jwt-secret", jwt, "--eth-url", eth.URL}
	}
	out, err := runCLI(t, args("accept")...)
	require.NoError(t, err, "the unchanged control is accepted by the gate")
	require.Contains(t, out, "pair control accept: accepted by the pair gate (the engine then refused the build below its finalized block: ")
	require.Contains(t, out, "Too deep reorg", "the engine's answer is shown")
	require.NotContains(t, out, "refused:")

	for _, kind := range []string{"wrong-parent", "wrong-job", "substituted-input", "missing-evidence"} {
		out, err = runCLI(t, args(kind)...)
		require.ErrorContains(t, err, "pair control "+kind+": refused", "%s: the same answer is no acceptance for a changed control", kind)
		require.NotContains(t, out, "accepted", kind)
	}
}

func TestPairAdmitReportsTheGatesAnswer(t *testing.T) {
	eth, _, _ := laneRetained(t)
	jwt := filepath.Join(t.TempDir(), "jwt.hex")
	require.NoError(t, os.WriteFile(jwt, []byte(strings.Repeat("ab", 32)), 0o600))
	refuse := ""
	engine := rpcServer(t, map[string]func(json.RawMessage) rpcResult{
		"engine_admitParentV1": func(json.RawMessage) rpcResult { return rpcResult{result: nil, err: refuse} },
	})
	args := []string{"q3", "pair-admit", "--engine-url", engine.URL, "--jwt-secret", jwt, "--eth-url", eth.URL}
	out, err := runCLI(t, args...)
	require.NoError(t, err)
	require.Contains(t, out, "presented by the operator from retained evidence", "the output says whose evidence this is")

	refuse = "recovery admission refused: retained binding refused at 5: pair binding refused: RootGenesisMismatch"
	_, err = runCLI(t, args...)
	require.ErrorContains(t, err, "RootGenesisMismatch")
}
