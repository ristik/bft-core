package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// trust-bundle (deploy_nb2.py's trust input) writes the same release bundle and genesis EntryID as the dnb-tool built with
// bridgeprofile (76d612b3f): the golden files are that binary's output on testdata/trust-base.json.
func TestTrustBundleBytesArePinned(t *testing.T) {
	dir := t.TempDir()
	bundle, pin := filepath.Join(dir, "bundle.cbor"), filepath.Join(dir, "pin")
	require.NoError(t, trustBundle([]string{"--trust-base", "testdata/trust-base.json", "--out", bundle, "--out-pin", pin}))
	for got, want := range map[string]string{bundle: "testdata/trust-base.bundle.golden.cbor", pin: "testdata/trust-base.genesis.golden.entryid"} {
		g, err := os.ReadFile(got)
		require.NoError(t, err)
		w, err := os.ReadFile(want)
		require.NoError(t, err)
		require.Equal(t, w, g, want)
	}
}
