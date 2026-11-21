package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPairedUTBVerifierPreflight(t *testing.T) {
	root, err := filepath.Abs("../..")
	require.NoError(t, err)
	fixture := t.TempDir()
	bin := filepath.Join(fixture, "bin")
	contracts := filepath.Join(fixture, "contracts")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(contracts, "script"), 0o755))
	executable := []byte("#!/bin/sh\nexit 0\n")
	for _, f := range []string{filepath.Join(bin, "cast"), filepath.Join(bin, "forge"), filepath.Join(contracts, "script", "vr-genesis.sh")} {
		require.NoError(t, os.WriteFile(f, executable, 0o755))
	}
	measured := filepath.Join(fixture, "fresh.json")
	require.NoError(t, os.WriteFile(measured, []byte("{}\n"), 0o644))
	verifier := filepath.Join(fixture, "verifier executable")
	require.NoError(t, os.WriteFile(verifier, executable, 0o755))
	nonexec := filepath.Join(fixture, "non-executable")
	require.NoError(t, os.WriteFile(nonexec, executable, 0o644))
	missing := filepath.Join(fixture, "missing")
	link := filepath.Join(fixture, "verifier-link")
	require.NoError(t, os.Symlink(verifier, link))

	// Every invocation that gets past the verifier check stops at the missing
	// ureth binary, before any build, cleanup, slot use or devnet startup.
	env := []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + fixture,
		"VR_LANE=1", "Q3_B1=1", "M2_PROFILE2=1", "VR_STEPS=scripts/vr-boundary-steps.sh",
		"VR_CONTRACTS=" + contracts, "VR_FRESH_MEASUREMENT=" + measured,
		"URETH_BIN=" + missing,
	}
	for _, tc := range []struct {
		name, primary, alias, diagnostic string
		enabled, deprecated              bool
	}{
		{"legacy directory", "", fixture, "UTB_EVIDENCE must be the verifier executable (got a directory)", true, false},
		{"preferred directory", fixture, verifier, "UTB_VERIFIER must be the verifier executable (got a directory)", true, false},
		{"missing file", missing, "", "UTB_VERIFIER must be the verifier executable (expected an executable file)", true, false},
		{"non-executable file", nonexec, "", "UTB_VERIFIER must be the verifier executable (expected an executable file)", true, false},
		{"legacy executable", "", verifier, "", true, true},
		{"preferred symlink overrides legacy directory", link, fixture, "", true, false},
		{"UTB disabled", fixture, "", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "scripts/reth-paired-devnet.sh")
			cmd.Dir = root
			cmd.Env = append(append([]string{}, env...), "UTB_VERIFIER="+tc.primary, "UTB_EVIDENCE="+tc.alias, "VR_UTB=0")
			if tc.enabled {
				cmd.Env = append(cmd.Env, "VR_UTB=1")
			}
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit, "%s", out)
			if tc.diagnostic != "" {
				require.Contains(t, string(out), tc.diagnostic)
				require.NotContains(t, string(out), "ureth-pin:")
				require.Equal(t, 2, exit.ExitCode())
			} else {
				require.Contains(t, string(out), "ureth-pin: no unicity-reth binary")
				require.Equal(t, 1, exit.ExitCode())
			}
			require.Equal(t, tc.deprecated, strings.Contains(string(out), "UTB_EVIDENCE is deprecated"), "%s", out)
		})
	}
}

func TestCombinedUTBPreflightRejectsDirectoryBeforeBuildingVerifier(t *testing.T) {
	cmd := exec.Command("bash", "scripts/utb-lane.sh", "--preflight")
	cmd.Dir = "../.."
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "UTB_VERIFIER=", "UTB_EVIDENCE=" + t.TempDir(), "LANE_PINNED=0"}
	out, err := cmd.CombinedOutput()
	require.Error(t, err)
	require.Contains(t, string(out), "UTB_EVIDENCE must be the verifier executable (got a directory)")
	require.NotContains(t, string(out), "-- tools")
}
