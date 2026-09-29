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
	"sync"
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

// engineFixture is a scriptable stand-in for ONE execution client.
//
// A single fixture server answers both engine_* and the eth_* subset, which is what a real client
// does: the Engine API specification's "underlying protocol" section requires eth_chainId and
// eth_getBlockByNumber on the authenticated port alongside engine_*, and the pinned client serves
// them there (EngineEthApi, crates/rpc/rpc-api/src/engine.rs). Pointing --engine-url and --eth-url
// at the SAME fixture therefore models a correctly paired deployment, and pointing them at TWO
// fixtures models a mispaired one — which is the whole subject of TestShardNodeRun_EndpointPairing.
type engineFixture struct {
	capabilities []string // what engine_exchangeCapabilities offers
	chainID      string   // hex, e.g. "0x7a69"; empty means eth_chainId returns an RPC error
	capErr       bool     // engine_exchangeCapabilities returns HTTP 500
	malformed    bool     // engine_exchangeCapabilities returns unparseable JSON
	genesisHash  string   // 0x-prefixed; empty means eth_getBlockByNumber returns an RPC error
	nullChainID  bool     // eth_chainId succeeds with a JSON null result
	nullBlock    bool     // eth_getBlockByNumber succeeds with a JSON null result
	// ethConfig names an eth_config result recorded from the pinned client, under
	// engineapi/testdata; empty means the pinned profile's own recording, so every case that is
	// not about the fork schedule gets past that check for its own reason.
	ethConfig    string
	ethConfigErr bool // eth_config returns "Method not found", as a client without EIP-7910 would
}

func (f engineFixture) start(t *testing.T) *httptest.Server {
	t.Helper()
	cfgName := f.ethConfig
	if cfgName == "" {
		cfgName = "eth_config_cancun_at_genesis.json"
	}
	ethConfig, err := os.ReadFile(filepath.Join(repoRoot(t), "engineapi", "testdata", cfgName))
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			ID     any    `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		switch req.Method {
		case "eth_config":
			if f.ethConfigErr {
				writeError(w, req.ID, "Method not found")
				return
			}
			writeResult(w, req.ID, json.RawMessage(ethConfig))
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
		case "eth_getBlockByNumber":
			if f.nullBlock {
				writeResult(w, req.ID, nil)
				return
			}
			if f.genesisHash == "" {
				writeError(w, req.ID, "block unavailable")
				return
			}
			writeResult(w, req.ID, map[string]any{
				"number": "0x0", "hash": f.genesisHash,
				"parentHash": "0x" + strings.Repeat("00", 32),
				"stateRoot":  "0x" + strings.Repeat("00", 32),
				"timestamp":  "0x0",
			})
		case "eth_chainId":
			if f.nullChainID {
				writeResult(w, req.ID, nil)
				return
			}
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

var (
	ubftBuildOnce sync.Once
	ubftBuildPath string
	ubftBuildErr  error
	ubftBuildOut  []byte
)

// buildUbft builds the CLI once per test binary run. Rebuilding it in every
// integration test dominated this package's runtime without adding coverage.
func buildUbft(t *testing.T) string {
	t.Helper()
	ubftBuildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "bft-ubft-test-")
		if err != nil {
			ubftBuildErr = err
			return
		}
		ubftBuildPath = filepath.Join(dir, "ubft")
		cmd := exec.Command("go", "build", "-o", ubftBuildPath, "./cli/ubft")
		cmd.Dir = repoRoot(t)
		ubftBuildOut, ubftBuildErr = cmd.CombinedOutput()
	})
	require.NoErrorf(t, ubftBuildErr, "building ubft: %s", ubftBuildOut)
	return ubftBuildPath
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
	return shardHomeWithParams(t, bin, "proof_type=exec,chain_id=31337")
}

// shardHomeWithParams is shardHome with the shard conf's partition params chosen by the caller.
func shardHomeWithParams(t *testing.T, bin, partitionParams string) (home, shardConf, trustBase string) {
	t.Helper()
	root := repoRoot(t)
	home = t.TempDir()

	run(t, root, bin, "shard-node", "init", "--home", home, "-g")
	nodeInfo := filepath.Join(home, "node-info.json")

	run(t, root, bin, "shard-conf", "generate", "--home", home,
		"--network-id", "3", "--partition-id", "8", "--partition-type-id", "8",
		"--shard-id", "0x80", "--epoch-start", "1", "--t2-timeout", "2500",
		"--partition-params", partitionParams,
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

	all := []string{"engine_forkchoiceUpdatedV3", "engine_getPayloadV3", "engine_newPayloadV3", "engine_forkchoiceUpdatedWithSealV1", "engine_getPayloadWithSealV1", "engine_newPayloadWithSealV1"}
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
		{"missing newPayloadWithSealV1", engineFixture{capabilities: without("engine_newPayloadWithSealV1"), chainID: "0x7a69"}, "missing required capabilities"},
		{"offers nothing at all", engineFixture{capabilities: []string{}, chainID: "0x7a69"}, "missing required capabilities"},
		{"capability exchange fails", engineFixture{capErr: true, chainID: "0x7a69"}, "checking capabilities"},
		{"capability response is malformed", engineFixture{malformed: true, chainID: "0x7a69"}, "checking capabilities"},
		{"chain id unavailable", engineFixture{capabilities: all, chainID: ""}, "reading chain id over the Engine connection"},
		{"chain id is null", engineFixture{capabilities: all, nullChainID: true}, "client reports no chain id"},
		{"chain id mismatch", engineFixture{capabilities: all, chainID: "0x7a6a"}, "chainId=31338, shard conf says 31337"},
		{"genesis is null", engineFixture{capabilities: all, chainID: "0x7a69", nullBlock: true}, "no such block"},
		// The fork schedule (#89 item 2). The recording is from a real client whose genesis is
		// identical to the pinned profile's — only a later Prague is scheduled — so nothing before
		// this check can refuse it.
		{"a fork scheduled after Cancun", engineFixture{capabilities: all, chainID: "0x7a69", ethConfig: "eth_config_prague_scheduled.json"},
			"startup execution-profile check"},
		{"fork schedule unreadable", engineFixture{capabilities: all, chainID: "0x7a69", ethConfigErr: true},
			"reading eth_config (EIP-7910) over the plain connection"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Every case must fail for the reason it names, so give each fixture a valid genesis
			// unless the case is specifically about the genesis read. Without this a capability
			// case could pass on the unconditional pairing check's error instead of its own.
			if tc.fixture.genesisHash == "" && !tc.fixture.nullBlock {
				tc.fixture.genesisHash = expectedGenesis
			}
			srv := tc.fixture.start(t)
			out, code, timedOut := runShardNode(t, bin, home, shardConf, trustBase, srv.URL, srv.URL, 5*time.Second)

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
		capabilities: []string{"engine_forkchoiceUpdatedV3", "engine_getPayloadV3", "engine_forkchoiceUpdatedWithSealV1", "engine_getPayloadWithSealV1", "engine_newPayloadWithSealV1"},
		chainID:      "0x7a69",
		genesisHash:  expectedGenesis,
	}.start(t)

	out, _, timedOut := runShardNode(t, bin, home, shardConf, trustBase, srv.URL, srv.URL, 5*time.Second)

	require.True(t, timedOut,
		"a compatible client must let startup proceed; it exited instead:\n%s", out)
	require.Contains(t, out, "shard node starting",
		"startup must get past its compatibility checks with a compatible fixture:\n%s", out)
	require.NotContains(t, out, "missing required capabilities", out)
	require.NotContains(t, out, "chain-identity check", out)
	require.NotContains(t, out, "endpoint-pairing check", out)
	require.NotContains(t, out, "execution-profile check", out)
	// The default path constructs nothing of the certified-block record (#14).
	require.NotContains(t, out, "certified record", out)
	require.NotContains(t, out, "certified-record", out)
}

func TestShardNodeRun_RefusesClientBlockZeroDifferentFromConfiguredOrigin(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the CLI binary")
	}
	bin := buildUbft(t)
	home, shardConf, trustBase := shardHome(t, bin)
	dir := t.TempDir()
	genesisPath := filepath.Join(dir, "genesis.json")
	fullPath := filepath.Join(dir, "full-shard-conf.json")
	run(t, repoRoot(t), bin, "engine-api", "genesis", "--shard-conf", shardConf,
		"--out", genesisPath, "--full-shard-conf", fullPath)

	server := engineFixture{
		capabilities: []string{"engine_forkchoiceUpdatedV3", "engine_getPayloadV3",
			"engine_forkchoiceUpdatedWithSealV1", "engine_getPayloadWithSealV1", "engine_newPayloadWithSealV1"},
		chainID: "0x7a69", genesisHash: otherGenesis,
	}.start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "shard-node", "run",
		"--home", home, "--executor", "engine-api", "--address", "/ip4/127.0.0.1/tcp/0",
		"--full-shard-conf", fullPath, "--genesis", genesisPath, "--trust-base", trustBase,
		"--execution-journal", filepath.Join(home, "execution-journal.db"),
		"--engine-url", server.URL, "--eth-url", server.URL,
		"--jwt-secret", filepath.Join(home, "jwt.hex"), "--log-format", "text")
	cmd.Dir = repoRoot(t)
	output, err := cmd.CombinedOutput()
	require.Error(t, err)
	require.NoError(t, ctx.Err(), "startup did not refuse in time: %s", output)
	require.Contains(t, string(output), "genesis check against the configured origin")
	require.NotContains(t, string(output), "shard node starting")
}

/*
TestShardNodeRun_RefusesAShardConfWithNoChainID covers the one identity input that comes from local
configuration rather than from the client: the shard conf's chain_id partition param.

Every other chain-id case in this file is about the CLIENT's answer — unavailable, null, different.
None of them shows what happens when the node itself has nothing to compare against, and an
unavailable-RPC refusal cannot stand in for that: the failure is in the operator's file, and the
diagnostic has to say so. The fixture here is fully compatible, so the refusal cannot come from it.
*/
func TestShardNodeRun_RefusesAShardConfWithNoChainID(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the CLI binary")
	}
	bin := buildUbft(t)
	home, shardConf, trustBase := shardHomeWithParams(t, bin, "proof_type=exec")

	// The premise: the generated shard conf really has no chain_id, rather than the test passing
	// because the generator quietly supplied one.
	raw, err := os.ReadFile(shardConf)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "chain_id", "premise: the shard conf must carry no chain_id param")
	require.Contains(t, string(raw), "proof_type", "premise: the partition params were written at all")

	srv := engineFixture{
		capabilities: []string{"engine_forkchoiceUpdatedV3", "engine_getPayloadV3", "engine_newPayloadV3", "engine_forkchoiceUpdatedWithSealV1", "engine_getPayloadWithSealV1", "engine_newPayloadWithSealV1"},
		chainID:      "0x7a69",
		genesisHash:  expectedGenesis,
	}.start(t)
	out, code, timedOut := runShardNode(t, bin, home, shardConf, trustBase, srv.URL, srv.URL, 5*time.Second)

	require.False(t, timedOut, "must fail closed promptly, not hang or proceed:\n%s", out)
	require.NotEqual(t, 0, code, "must exit non-zero:\n%s", out)
	require.Contains(t, out, "requires a chain_id partition param in the shard conf, which has none", out)
	require.NotContains(t, out, "shard node starting", "must refuse before announcing it is running")
	require.NotContains(t, out, "submitting block certification request")
}

const (
	expectedGenesis = "0x1111111111111111111111111111111111111111111111111111111111111111"
	otherGenesis    = "0x2222222222222222222222222222222222222222222222222222222222222222"
)

// runShardNodeWithGenesis is runShardNode plus --expected-genesis-hash.
func runShardNodeWithGenesis(t *testing.T, bin, home, shardConf, trustBase, engineURL, ethURL, wantGenesis string, budget time.Duration) (string, int, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	args := []string{"shard-node", "run",
		"--home", home, "--executor", "engine-api",
		"--address", "/ip4/127.0.0.1/tcp/0",
		"--shard-conf", shardConf, "--trust-base", trustBase,
		"--engine-url", engineURL, "--eth-url", ethURL,
		"--jwt-secret", filepath.Join(home, "jwt.hex"),
		"--log-format", "text", "--log-level", "info",
	}
	if wantGenesis != "" {
		args = append(args, "--expected-genesis-hash", wantGenesis)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = repoRoot(t)
	raw, _ := cmd.CombinedOutput()

	code := -1
	if ee, ok := errExit(cmd); ok {
		code = ee
	}
	return string(raw), code, ctx.Err() == context.DeadlineExceeded
}

/*
TestShardNodeRun_GenesisBinding covers #89 item 2: an operator-configured expected genesis hash,
validated before the node can vote.

Chain id does not establish genesis identity — the same-chain-id/different-genesis case below is
the point. The expected value is operator-supplied; deriving it from the client under test would
compare a value with itself.
*/
func TestShardNodeRun_GenesisBinding(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the CLI binary")
	}
	bin := buildUbft(t)
	home, shardConf, trustBase := shardHome(t, bin)
	all := []string{"engine_forkchoiceUpdatedV3", "engine_getPayloadV3", "engine_newPayloadV3", "engine_forkchoiceUpdatedWithSealV1", "engine_getPayloadWithSealV1", "engine_newPayloadWithSealV1"}

	t.Run("same chain id, different genesis is refused before voting", func(t *testing.T) {
		srv := engineFixture{capabilities: all, chainID: "0x7a69", genesisHash: otherGenesis}.start(t)
		out, code, timedOut := runShardNodeWithGenesis(t, bin, home, shardConf, trustBase,
			srv.URL, srv.URL, expectedGenesis, 5*time.Second)

		require.False(t, timedOut, "must fail closed promptly:\n%s", out)
		require.NotEqual(t, 0, code, "must exit non-zero:\n%s", out)
		require.Contains(t, out, "startup genesis check", out)
		require.Contains(t, out, "configured expectation is", out)
		require.NotContains(t, out, "shard node starting", "must refuse before announcing it is running")
		require.NotContains(t, out, "submitting block certification request")
	})

	t.Run("genesis unavailable is refused, not skipped", func(t *testing.T) {
		srv := engineFixture{capabilities: all, chainID: "0x7a69", genesisHash: ""}.start(t)
		out, code, _ := runShardNodeWithGenesis(t, bin, home, shardConf, trustBase,
			srv.URL, srv.URL, expectedGenesis, 45*time.Second)
		require.NotEqual(t, 0, code, out)
		require.Contains(t, out, "reading genesis block over the Engine connection", out)
	})

	t.Run("malformed expected value is refused", func(t *testing.T) {
		srv := engineFixture{capabilities: all, chainID: "0x7a69", genesisHash: expectedGenesis}.start(t)
		out, code, _ := runShardNodeWithGenesis(t, bin, home, shardConf, trustBase,
			srv.URL, srv.URL, "0xdeadbeef", 45*time.Second)
		require.NotEqual(t, 0, code, out)
		require.Contains(t, out, "expected-genesis-hash", out)
	})

	t.Run("matching genesis lets startup proceed", func(t *testing.T) {
		srv := engineFixture{capabilities: all, chainID: "0x7a69", genesisHash: expectedGenesis}.start(t)
		out, _, timedOut := runShardNodeWithGenesis(t, bin, home, shardConf, trustBase,
			srv.URL, srv.URL, expectedGenesis, 5*time.Second)
		require.True(t, timedOut, "a matching genesis must let startup proceed; it exited:\n%s", out)
		require.Contains(t, out, "shard node starting", out)
	})
}

/*
TestShardNodeRun_EndpointPairing covers #89 item 3: --engine-url and --eth-url are configured
independently, so nothing structurally stops an operator from pointing them at two different
execution clients — and the Engine connection is the one that decides what this node votes for
(Build, Seal and Commit all go over it).

An earlier revision of this file asserted the OPPOSITE: that startup accepted a mismatched Engine
endpoint, on the stated rationale that standard Engine API offers no chain-identity read. That
rationale was wrong. The Engine API specification's "underlying protocol" section requires an
execution client to serve eth_chainId and eth_getBlockByNumber on the same authenticated port as
engine_*, and the pinned client does (EngineEthApi, crates/rpc/rpc-api/src/engine.rs). Closing this
needs no new Engine method and no divergence from upstream reth, so the gap is now closed and these
cases assert refusal.

What refusal establishes, and what it does not. Matching chain id and genesis across the two
connections establishes agreement on chain and genesis. It does NOT establish that the two URLs
address the same client PROCESS — two clients started from the same genesis agree on both values
until they build different blocks — and it says nothing about future fork activations. That
narrower limitation is retained deliberately; see docs/design/f1-baseline.md §5.8.
*/
func TestShardNodeRun_EndpointPairing(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the CLI binary")
	}
	bin := buildUbft(t)
	home, shardConf, trustBase := shardHome(t, bin)
	all := []string{"engine_forkchoiceUpdatedV3", "engine_getPayloadV3", "engine_newPayloadV3", "engine_forkchoiceUpdatedWithSealV1", "engine_getPayloadWithSealV1", "engine_newPayloadWithSealV1"}

	// The plain RPC endpoint the operator intended: right chain, right genesis.
	correct := engineFixture{capabilities: all, chainID: "0x7a69", genesisHash: expectedGenesis}

	cases := []struct {
		name string
		// engine and eth are separate fixtures — a mispaired deployment — unless samePair is set.
		engine, eth engineFixture
		samePair    bool
		wantGenesis string // passed as --expected-genesis-hash; empty means the flag is omitted
		refuse      bool
		expect      string
	}{
		{
			// The case the earlier revision recorded as accepted.
			name:   "engine endpoint is on a different chain",
			engine: engineFixture{capabilities: all, chainID: "0x7a6a", genesisHash: otherGenesis},
			eth:    correct, wantGenesis: expectedGenesis, refuse: true,
			expect: "chainId=31338, shard conf says 31337",
		},
		{
			// Reverse direction: the Engine endpoint is right and the plain one is wrong. The
			// diagnostic must name the mispairing rather than blame the shard conf, because the
			// client that builds our blocks is on the configured chain.
			name:        "plain endpoint is on a different chain",
			engine:      correct,
			eth:         engineFixture{capabilities: all, chainID: "0x7a6a", genesisHash: otherGenesis},
			wantGenesis: expectedGenesis, refuse: true,
			expect: "the two URLs address different execution clients",
		},
		{
			// Same chain id, different genesis, and NO operator-configured expectation. This is
			// what makes the pairing check unconditional worth having: nothing else catches it.
			name:   "same chain id, different genesis, no expected hash configured",
			engine: engineFixture{capabilities: all, chainID: "0x7a69", genesisHash: otherGenesis},
			eth:    correct, wantGenesis: "", refuse: true,
			expect: "the two URLs address different execution clients",
		},
		{
			// Same, with an expected hash configured. The PAIRING diagnostic must win: the
			// pairing check runs first precisely so an operator is told the two URLs disagree,
			// rather than being told one of them mismatches an expected value and left to work
			// out which. If that ordering is ever changed, this case fails.
			name:   "same chain id, different genesis, with an expected hash",
			engine: engineFixture{capabilities: all, chainID: "0x7a69", genesisHash: otherGenesis},
			eth:    correct, wantGenesis: expectedGenesis, refuse: true,
			expect: "the two URLs address different execution clients",
		},
		{
			// Correctly PAIRED but wrong: both URLs address one client, whose genesis is not the
			// configured one. Pairing passes and the genesis check refuses — which is what shows
			// CheckGenesisHash still does its own job now that a pairing check precedes it.
			name:     "both URLs agree on the wrong genesis",
			engine:   engineFixture{capabilities: all, chainID: "0x7a69", genesisHash: otherGenesis},
			samePair: true, wantGenesis: expectedGenesis, refuse: true,
			expect: "execution client genesis is",
		},
		{
			// An RPC error on the Engine connection must fail closed, not fall back to the plain
			// endpoint's answer.
			name:   "engine connection errors on the genesis read",
			engine: engineFixture{capabilities: all, chainID: "0x7a69", genesisHash: ""},
			eth:    correct, wantGenesis: expectedGenesis, refuse: true,
			expect: "reading genesis block over the Engine connection",
		},
		{
			// Same, for a JSON null result — which decodes to a zero-valued header and would
			// otherwise be compared as if it were a real answer.
			name:   "engine connection returns null for the genesis read",
			engine: engineFixture{capabilities: all, chainID: "0x7a69", nullBlock: true},
			eth:    correct, wantGenesis: expectedGenesis, refuse: true,
			expect: "no such block",
		},
		{
			name:   "engine connection returns null for the chain id",
			engine: engineFixture{capabilities: all, nullChainID: true, genesisHash: expectedGenesis},
			eth:    correct, wantGenesis: expectedGenesis, refuse: true,
			expect: "client reports no chain id",
		},
		{
			// POSITIVE CONTROL. Without it the refusals above could all be passing because
			// startup fails for some unrelated reason: one fixture serving both URLs is a
			// correctly paired client, and startup must proceed.
			name: "one client behind both URLs is accepted", engine: correct, samePair: true,
			wantGenesis: expectedGenesis, refuse: false,
		},
		{
			// Second positive control: correctly paired, and no expected genesis configured. The
			// unconditional pairing check must not turn into a hard requirement for the flag.
			name: "one client behind both URLs, no expected hash", engine: correct, samePair: true,
			wantGenesis: "", refuse: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engineSrv := tc.engine.start(t)
			ethURL := engineSrv.URL
			if !tc.samePair {
				ethURL = tc.eth.start(t).URL
			}

			budget := 5 * time.Second
			if !tc.refuse {
				budget = 5 * time.Second
			}
			out, code, timedOut := runShardNodeWithGenesis(t, bin, home, shardConf, trustBase,
				engineSrv.URL, ethURL, tc.wantGenesis, budget)

			if !tc.refuse {
				require.True(t, timedOut, "a correctly paired client must let startup proceed; it exited:\n%s", out)
				require.Contains(t, out, "shard node starting", out)
				require.NotContains(t, out, "endpoint-pairing check", out)
				return
			}

			require.False(t, timedOut, "must fail closed promptly, not hang or proceed:\n%s", out)
			require.NotEqual(t, 0, code, "must exit non-zero:\n%s", out)
			require.Contains(t, out, tc.expect, "expected the specific diagnostic:\n%s", out)
			require.NotContains(t, out, "shard node starting", "must refuse before announcing it is running")
			require.NotContains(t, out, "submitting block certification request")
		})
	}
}
