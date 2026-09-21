package cmd_test

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// runShardNodeArgs starts `shard-node run` with args and returns its combined output and exit code, killing
// it after budget.
func runShardNodeArgs(t *testing.T, bin string, budget time.Duration, args ...string) (out string, code int, timedOut bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, append([]string{"shard-node", "run"}, args...)...)
	cmd.Dir = repoRoot(t)
	raw, _ := cmd.CombinedOutput()
	code = -1
	if ee, ok := errExit(cmd); ok {
		code = ee
	}
	return string(raw), code, ctx.Err() == context.DeadlineExceeded
}

/*
TestShardNodeRun_CertifiedRecordStoreFailsClosed covers the opt-in record store at the command boundary. The
operator asked for a store, so a configuration the wiring cannot check stops startup before the node announces
it is running, and before the store file is created. The positive control that the default path is unchanged
is TestShardNodeRun_AcceptsACompatibleFixture, which also asserts that nothing about the record appears there.

Fixture evidence: the shard configuration here is not a SealRegistry deployment, so these cases establish the
refusals, not a reload against a registry chain, which recordwiring's tests cover with signed records.
*/
// TestShardNodeRun_GateFlagRequiresTheRecordStore drives the same boundary for the record gate: the flag
// alone is refused before any executor or store work, so the operator's mistake is the diagnostic rather
// than a node that cannot prove readiness.
func TestShardNodeRun_GateFlagRequiresTheRecordStore(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the CLI binary")
	}
	bin := buildUbft(t)
	home, shardConf, trustBase := shardHome(t, bin)

	out, code, timedOut := runShardNodeArgs(t, bin, 45*time.Second,
		"--home", home, "--address", "/ip4/127.0.0.1/tcp/0",
		"--shard-conf", shardConf, "--trust-base", trustBase,
		"--log-format", "text", "--log-level", "info",
		"--certified-record-gate",
	)

	require.False(t, timedOut, "startup must fail closed promptly:\n%s", out)
	require.NotEqual(t, 0, code, "startup must exit non-zero:\n%s", out)
	require.Contains(t, out, "--certified-record-gate requires --certified-record-store", out)
	require.NotContains(t, out, "shard node starting", "startup must refuse before the node announces it is running")
}

func TestShardNodeRun_CertifiedRecordStoreFailsClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the CLI binary")
	}
	bin := buildUbft(t)
	home, shardConf, trustBase := shardHome(t, bin)
	srv := engineFixture{
		capabilities: []string{"engine_forkchoiceUpdatedV3", "engine_getPayloadV3", "engine_newPayloadV3", "engine_forkchoiceUpdatedWithSealV1", "engine_getPayloadWithSealV1", "engine_newPayloadWithSealV1"},
		chainID:      "0x7a69",
		genesisHash:  expectedGenesis,
	}.start(t)

	common := []string{
		"--home", home, "--address", "/ip4/127.0.0.1/tcp/0",
		"--shard-conf", shardConf, "--trust-base", trustBase,
		"--log-format", "text", "--log-level", "info",
	}
	cases := []struct {
		name   string
		args   []string
		expect []string
	}{
		{"a shard configuration that is not a SealRegistry deployment", []string{
			"--executor", "engine-api", "--engine-url", srv.URL, "--eth-url", srv.URL,
			"--jwt-secret", filepath.Join(home, "jwt.hex"),
		}, []string{"checking the certified-record deployment", "seal_registry_genesis"}},
		{"an executor that cannot hold SealRegistry state", []string{
			"--executor", "fake",
		}, []string{"--certified-record-store needs --executor engine-api"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := filepath.Join(t.TempDir(), "certified.db")
			args := append(append(append([]string{}, common...), tc.args...), "--certified-record-store", store)
			out, code, timedOut := runShardNodeArgs(t, bin, 45*time.Second, args...)

			require.False(t, timedOut, "startup must fail closed promptly:\n%s", out)
			require.NotEqual(t, 0, code, "startup must exit non-zero:\n%s", out)
			for _, want := range tc.expect {
				require.Contains(t, out, want, "expected the specific diagnostic:\n%s", out)
			}
			require.NotContains(t, out, "shard node starting", "startup must refuse before the node announces it is running")
			require.NoFileExists(t, store, "the store is not created for a configuration that was refused")
		})
	}
}
