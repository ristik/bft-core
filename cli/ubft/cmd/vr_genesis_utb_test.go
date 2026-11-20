package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTheVRGenesisUTBEntryIsTheOneTheManifestBuildsAndIsChecked(t *testing.T) {
	tb, err := readTrustBase(vrTestdata(t, "trust-base.json"))
	require.NoError(t, err)
	dir := t.TempDir()
	entry, idFile := filepath.Join(dir, "utb-genesis.cbor"), filepath.Join(dir, "utb-genesis.id")
	pin, err := writeVRUTBGenesis(tb, entry, idFile)
	require.NoError(t, err)

	// the same entry and pin `trust-base utb-manifest` derives from the trust base
	out, err := runManifest(t, "--trust-base", vrTestdata(t, "trust-base.json"), "--out-dir", filepath.Join(dir, "m"))
	require.NoError(t, err)
	require.Contains(t, out, pin)
	got, err := os.ReadFile(entry)
	require.NoError(t, err)
	want, err := os.ReadFile(filepath.Join(dir, "m", "utb-genesis.cbor"))
	require.NoError(t, err)
	require.Equal(t, want, got)

	checked, err := checkVRUTBGenesis(tb, entry, idFile)
	require.NoError(t, err)
	require.Equal(t, pin, checked)

	t.Run("a wrong pin is refused", func(t *testing.T) {
		bad := filepath.Join(dir, "bad.id")
		require.NoError(t, os.WriteFile(bad, []byte(flipHex(pin)+"\n"), 0o600))
		_, err := checkVRUTBGenesis(tb, entry, bad)
		require.ErrorIs(t, err, ErrVRGenesis)
	})
	t.Run("a different entry is refused", func(t *testing.T) {
		other := append([]byte(nil), got...)
		other[len(other)-1] ^= 1
		f := filepath.Join(dir, "other.cbor")
		require.NoError(t, os.WriteFile(f, other, 0o600))
		_, err := checkVRUTBGenesis(tb, f, idFile)
		require.ErrorIs(t, err, ErrVRGenesis)
	})
	t.Run("the pair goes together", func(t *testing.T) {
		_, err := vrUTBPair("x", "")
		require.ErrorIs(t, err, ErrVRGenesis)
	})
}
