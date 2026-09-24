package cmd_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestShardNodeDoctorUsesRunSealCapabilities(t *testing.T) {
	bin := buildUbft(t)
	home := t.TempDir()
	secret := filepath.Join(home, "jwt.hex")
	require.NoError(t, os.WriteFile(secret, []byte(strings.Repeat("ab", 32)), 0o600))

	base := []string{"engine_forkchoiceUpdatedV3", "engine_getPayloadV3"}
	seal := []string{"engine_forkchoiceUpdatedWithSealV1", "engine_getPayloadWithSealV1", "engine_newPayloadWithSealV1"}
	for _, tc := range []struct {
		name         string
		capabilities []string
		want         string
	}{
		{"seal-only client", append(append([]string{}, base...), seal...), "[PASS] engine link"},
		{"stock-only client", append(append([]string{}, base...), "engine_newPayloadV3"), "[FAIL] engine link"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := engineFixture{capabilities: tc.capabilities}.start(t)
			// Under coverage/race or machine contention, starting the subprocess
			// can take longer than the check's own 250 ms dial timeout.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, "shard-node", "doctor",
				"--home", home, "--executor", "engine-api",
				"--engine-url", server.URL, "--eth-url", server.URL,
				"--jwt-secret", secret, "--dial-timeout", "250ms")
			cmd.Dir = repoRoot(t)
			output, err := cmd.CombinedOutput()
			require.Error(t, err, "other doctor checks lack node configuration")
			require.NoError(t, ctx.Err(), "doctor did not finish: %s", output)
			require.Contains(t, string(output), tc.want)
			if tc.name == "stock-only client" {
				require.Contains(t, string(output), "engine_newPayloadWithSealV1")
			}
		})
	}
}
