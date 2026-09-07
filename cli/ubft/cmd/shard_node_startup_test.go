package cmd_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

/*
These tests drive the REAL `ubft shard-node run` binary against a controlled JSON-RPC fixture and
assert it refuses to start, with a bounded non-zero exit and a specific diagnostic, before it can
submit any certification request.

Why the binary and not the adapter: engineapi has unit tests for CheckCapabilities and
CheckChainID, but a unit test cannot show that the CLI actually wires them into startup, in the
right order, and fails closed. Issue #89 item 1 asks for exactly that boundary, and notes that no
second reth build is needed for it.

Honest labelling: this is FIXTURE evidence. The fixture answers the two RPCs startup depends on and
nothing else. It proves the CLI's refusal behaviour; it does not prove interoperability with any
other real execution client, which #89 keeps as a separate optional test.
*/

// engineFixture is a scriptable stand-in for an execution client's two startup endpoints.
type engineFixture struct {
	capabilities []string // what engine_exchangeCapabilities offers
	chainID      string   // hex, e.g. "0x7a69"; empty means eth_chainId returns an error
	capErr       bool     // engine_exchangeCapabilities returns HTTP 500
	malformed    bool     // engine_exchangeCapabilities returns unparseable JSON
}

func (f engineFixture) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			ID     any    `json:"id"`
		}
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		_ = json.Unmarshal(body, &req)

		switch req.Method {
		case "engine_exchangeCapabilities":
			if f.capErr {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if f.malformed {
				_, _ = w.Write([]byte("{this is not json"))
				return
			}
			writeResult(w, req.ID, f.capabilities)
		case "eth_chainId":
			if f.chainID == "" {
				writeError(w, req.ID, "chain id unavailable")
				return
			}
			writeResult(w, req.ID, f.chainID)
		default:
			writeError(w, req.ID, "unexpected method "+req.Method+
				" — startup must not reach past its compatibility checks")
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func writeResult(w http.ResponseWriter, id any, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func writeError(w http.ResponseWriter, id any, msg string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32000, "message": msg},
	})
}

// buildUbft builds the CLI once per test binary run.
func buildUbft(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "ubft")
	cmd := exec.Command("go", "build", "-o", bin, "./cli/ubft")
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "building ubft: %s", out)
	return bin
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	// this package is <root>/cli/ubft/cmd
	return filepath.Clean(filepath.Join(wd, "..", "..", ".."))
}

// shardHome prepares the minimal node home `shard-node run` needs before it reaches its
// execution-client checks, using the same generator invocations helper.sh uses so the shard conf's
// chain_id partition param is the real thing rather than a hand-written stand-in.
func shardHome(t *testing.T, bin string) (home, shardConf, trustBase string) {
	t.Helper()
	root := repoRoot(t)
	home = t.TempDir()

	run(t, root, bin, "shard-node", "init", "--home", home, "-g")
	nodeInfo := filepath.Join(home, "node-info.json")

	run(t, root, bin, "shard-conf", "generate", "--home", home,
		"--network-id", "3", "--partition-id", "8", "--partition-type-id", "8",
		"--shard-id", "0x80", "--epoch-start", "1", "--t2-timeout", "2500",
		"--partition-params", "proof_type=exec,chain_id=31337",
		"--node-info", nodeInfo)
	shardConf = filepath.Join(home, "shard-conf-8_0.json")
	require.FileExists(t, shardConf)

	run(t, root, bin, "trust-base", "generate", "--home", home,
		"--epoch", "1", "--epoch-start", "1", "--network-id", "3", "--node-info", nodeInfo)
	trustBase = filepath.Join(home, "trust-base.json")
	require.FileExists(t, trustBase)
	run(t, root, bin, "trust-base", "sign", "--home", home, "--trust-base", trustBase)

	require.NoError(t, os.WriteFile(filepath.Join(home, "jwt.hex"),
		[]byte(strings.Repeat("ab", 32)), 0o600))
	return home, shardConf, trustBase
}

func run(t *testing.T, dir, bin string, args ...string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "%s %s: %s", bin, strings.Join(args, " "), out)
}

// runShardNode starts `shard-node run` against the fixture and returns its combined output and
// exit code. Bounded: the process is killed if it has not exited, so a regression that lets
// startup proceed shows up as a test failure rather than a hang.
func runShardNode(t *testing.T, bin, home, shardConf, trustBase, engineURL, ethURL string, budget time.Duration) (out string, code int, timedOut bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "shard-node", "run",
		"--home", home,
		"--executor", "engine-api",
		"--address", "/ip4/127.0.0.1/tcp/0",
		"--shard-conf", shardConf,
		"--trust-base", trustBase,
		"--engine-url", engineURL,
		"--eth-url", ethURL,
		"--jwt-secret", filepath.Join(home, "jwt.hex"),
		"--log-format", "text", "--log-level", "info",
	)
	cmd.Dir = repoRoot(t)
	raw, _ := cmd.CombinedOutput()

	code = -1
	if ee, ok := errExit(cmd); ok {
		code = ee
	}
	return string(raw), code, ctx.Err() == context.DeadlineExceeded
}

func errExit(cmd *exec.Cmd) (int, bool) {
	if cmd.ProcessState == nil {
		return 0, false
	}
	return cmd.ProcessState.ExitCode(), true
}

func TestShardNodeRun_RefusesIncompatibleExecutionClient(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the CLI binary")
	}
	bin := buildUbft(t)
	home, shardConf, trustBase := shardHome(t, bin)

	all := []string{"engine_forkchoiceUpdatedV3", "engine_getPayloadV3", "engine_newPayloadV3"}
	without := func(drop string) []string {
		var out []string
		for _, c := range all {
			if c != drop {
				out = append(out, c)
			}
		}
		return out
	}

	cases := []struct {
		name    string
		fixture engineFixture
		expect  string
	}{
		{"missing forkchoiceUpdatedV3", engineFixture{capabilities: without("engine_forkchoiceUpdatedV3"), chainID: "0x7a69"}, "missing required capabilities"},
		{"missing getPayloadV3", engineFixture{capabilities: without("engine_getPayloadV3"), chainID: "0x7a69"}, "missing required capabilities"},
		{"missing newPayloadV3", engineFixture{capabilities: without("engine_newPayloadV3"), chainID: "0x7a69"}, "missing required capabilities"},
		{"offers nothing at all", engineFixture{capabilities: []string{}, chainID: "0x7a69"}, "missing required capabilities"},
		{"capability exchange fails", engineFixture{capErr: true, chainID: "0x7a69"}, "checking capabilities"},
		{"capability response is malformed", engineFixture{malformed: true, chainID: "0x7a69"}, "checking capabilities"},
		{"chain id unavailable", engineFixture{capabilities: all, chainID: ""}, "reading chain id"},
		{"chain id mismatch", engineFixture{capabilities: all, chainID: "0x7a6a"}, "chainId=31338, shard conf says 31337"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := tc.fixture.start(t)
			out, code, timedOut := runShardNode(t, bin, home, shardConf, trustBase, srv.URL, srv.URL, 45*time.Second)

			require.False(t, timedOut,
				"startup must fail closed promptly, not hang or proceed:\n%s", out)
			require.NotEqual(t, 0, code, "startup must exit non-zero:\n%s", out)
			require.Contains(t, out, tc.expect, "expected the specific diagnostic:\n%s", out)

			// Nothing may have been submitted: the fixture answers only the two startup RPCs and
			// reports any other method as unexpected, so reaching the round loop would show here.
			require.NotContains(t, out, "submitting block certification request",
				"startup must refuse before any certification submission")
			require.NotContains(t, out, "shard node starting",
				"startup must refuse before the node announces it is running")
		})
	}
}

// TestShardNodeRun_AcceptsACompatibleFixture is the positive control, and it is what makes the
// negatives above meaningful: without it they could all be passing because startup fails for some
// unrelated reason.
//
// With the required capabilities and the configured chain id, startup gets PAST its
// compatibility checks and announces the node is starting — at which point it blocks waiting for a
// root chain the fixture cannot be. So the expected outcome is the opposite of the negatives: no
// early exit, and the startup line present. That is the whole claim; the node is not functional
// here, which the real-reth lanes cover.
func TestShardNodeRun_AcceptsACompatibleFixture(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the CLI binary")
	}
	bin := buildUbft(t)
	home, shardConf, trustBase := shardHome(t, bin)

	srv := engineFixture{
		capabilities: []string{"engine_forkchoiceUpdatedV3", "engine_getPayloadV3", "engine_newPayloadV3"},
		chainID:      "0x7a69",
	}.start(t)

	out, _, timedOut := runShardNode(t, bin, home, shardConf, trustBase, srv.URL, srv.URL, 20*time.Second)

	require.True(t, timedOut,
		"a compatible client must let startup proceed; it exited instead:\n%s", out)
	require.Contains(t, out, "shard node starting",
		"startup must get past its compatibility checks with a compatible fixture:\n%s", out)
	require.NotContains(t, out, "missing required capabilities", out)
	require.NotContains(t, out, "chain-identity check", out)
}
