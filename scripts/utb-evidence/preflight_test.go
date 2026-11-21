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
	checkout := filepath.Join(fixture, "checkout")
	require.NoError(t, os.MkdirAll(filepath.Join(checkout, "build"), 0o755))
	for _, name := range []string{"scripts", "helper.sh", "deploy"} {
		require.NoError(t, os.Symlink(filepath.Join(root, name), filepath.Join(checkout, name)))
	}
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
		"URETH_BIN=" + missing, "AGG_BIN=" + verifier,
	}
	for _, tc := range []struct {
		name, primary, alias, diagnostic string
		enabled, deprecated, hasDefault  bool
		extra                            []string
	}{
		{"legacy directory", "", fixture, "UTB_EVIDENCE must be the verifier executable (got a directory)", true, false, false, nil},
		{"preferred directory", fixture, verifier, "UTB_VERIFIER must be the verifier executable (got a directory)", true, false, false, nil},
		{"missing file", missing, "", "UTB_VERIFIER must be the verifier executable (expected an executable file)", true, false, false, nil},
		{"non-executable file", nonexec, "", "UTB_VERIFIER must be the verifier executable (expected an executable file)", true, false, false, nil},
		{"legacy executable", "", verifier, "", true, true, false, nil},
		{"preferred symlink overrides legacy directory", link, fixture, "", true, false, false, nil},
		{"UTB disabled", fixture, "", "", false, false, false, nil},
		{"aggregator boundary requires default", "", "", "UTB_VERIFIER must be the verifier executable (expected an executable file): build/utb-evidence", true, false, false, []string{"VR_AGG=1"}},
		{"aggregator boundary accepts default executable", "", "", "", true, false, true, []string{"VR_AGG=1"}},
		{"PoS boundary requires default", "", "", "UTB_VERIFIER must be the verifier executable (expected an executable file): build/utb-evidence", true, false, false, []string{"VR_POS=1"}},
		{"bring-up without boundary steps", "", "", "", true, false, false, []string{"VR_AGG=1", "VR_STEPS="}},
		{"seed-only steps", "", "", "", true, false, false, []string{"VR_AGG=1", "VR_JOINER=1", "VR_SEED=1"}},
		{"joiner-only steps", "", "", "", true, false, false, []string{"VR_AGG=1", "VR_JOINER=1", "VR_JOINER_ONLY=1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "scripts/reth-paired-devnet.sh")
			cmd.Dir = checkout
			if tc.hasDefault {
				path := filepath.Join(checkout, "build", "utb-evidence")
				require.NoError(t, os.WriteFile(path, executable, 0o755))
				t.Cleanup(func() { require.NoError(t, os.Remove(path)) })
			}
			cmd.Env = append(append([]string{}, env...), "UTB_VERIFIER="+tc.primary, "UTB_EVIDENCE="+tc.alias, "VR_UTB=0")
			if tc.enabled {
				cmd.Env = append(cmd.Env, "VR_UTB=1")
			}
			cmd.Env = append(cmd.Env, tc.extra...)
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
	for _, tc := range []struct{ name, variable, path string }{
		{"existing legacy directory", "UTB_EVIDENCE", t.TempDir()},
		{"absent directory-form path", "UTB_VERIFIER", filepath.Join(t.TempDir(), "absent") + "/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(fixture, "gh"), []byte("#!/bin/sh\necho MERGED\n"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(fixture, "go"), []byte("#!/bin/sh\nexit 1\n"), 0o755))
			cmd := exec.Command("bash", "scripts/utb-lane.sh", "--preflight")
			cmd.Dir = "../.."
			cmd.Env = []string{"PATH=" + fixture + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + fixture, "AGRE_ROOT=" + fixture, "LANE_PINNED=0", tc.variable + "=" + tc.path}
			out, err := cmd.CombinedOutput()
			require.Error(t, err)
			require.Contains(t, string(out), tc.variable+" must be the verifier executable (got a directory)")
			require.NotContains(t, string(out), "-- tools")
		})
	}
}

func TestCombinedUTBPreflightChecksBuildOutput(t *testing.T) {
	for _, tc := range []struct{ name, build, status string }{
		{"missing output", "exit 0", "  FAIL  "},
		{"non-executable output", "touch \"$3\"", "  FAIL  "},
		{"executable output", "touch \"$3\" && chmod +x \"$3\"", "  ok    "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := t.TempDir()
			bin := filepath.Join(fixture, "bin")
			require.NoError(t, os.Mkdir(bin, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(bin, "gh"), []byte("#!/bin/sh\necho MERGED\n"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(bin, "go"), []byte("#!/bin/sh\n[ \"$1\" = build ] && [ \"$2\" = -o ] || exit 3\n"+tc.build+"\n"), 0o755))
			path := filepath.Join(fixture, "verifier")
			cmd := exec.Command("bash", "scripts/utb-lane.sh", "--preflight")
			cmd.Dir = "../.."
			cmd.Env = []string{
				"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + fixture,
				"AGRE_ROOT=" + fixture, "UBFT=" + filepath.Join(fixture, "missing-ubft"),
				"UTB_VERIFIER=" + path, "LANE_PINNED=0",
			}
			out, err := cmd.CombinedOutput()
			require.Error(t, err, "the fixture does not meet unrelated preflight prerequisites")
			require.Contains(t, string(out), tc.status+"utb-evidence builds (scripts/utb-evidence) into "+path)
		})
	}
}

func TestCombinedUTBPrepValidatesBeforeQueueing(t *testing.T) {
	fixture := t.TempDir()
	briefs := filepath.Join(fixture, "briefs")
	require.NoError(t, os.Mkdir(briefs, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(briefs, "devnet-lock.sh"), []byte("#!/bin/sh\necho lock reached\nexit 47\n"), 0o755))
	planned := filepath.Join(fixture, "planned")
	for _, tc := range []struct {
		name, primary, alias, diagnostic string
	}{
		{"preferred directory", fixture, "", "UTB_VERIFIER must be the verifier executable"},
		{"legacy directory", "", fixture, "UTB_EVIDENCE must be the verifier executable"},
		{"directory-form planned path", planned + "/", "", "UTB_VERIFIER must be the verifier executable"},
		{"planned build path", planned, "", ""},
		{"unset", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "scripts/utb-lane.sh", "--prep")
			cmd.Dir = "../.."
			cmd.Env = []string{
				"PATH=" + os.Getenv("PATH"), "HOME=" + fixture, "AGRE_ROOT=" + fixture,
				"P85_CONTRACTS=" + fixture, "UTB_VERIFIER=" + tc.primary, "UTB_EVIDENCE=" + tc.alias,
			}
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit, "%s", out)
			if tc.diagnostic != "" {
				require.Contains(t, string(out), tc.diagnostic)
				require.NotContains(t, string(out), "lock reached")
				require.Equal(t, 2, exit.ExitCode())
			} else {
				require.Contains(t, string(out), "lock reached")
				require.Equal(t, 47, exit.ExitCode())
			}
		})
	}
}
