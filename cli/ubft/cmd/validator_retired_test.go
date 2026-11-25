package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestCheckRetiredRootKey(t *testing.T) {
	old, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	fresh, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	oldKey, freshKey := ethcrypto.CompressPubkey(&old.PublicKey), ethcrypto.CompressPubkey(&fresh.PublicKey)
	dir := t.TempDir()
	list := filepath.Join(dir, "retired-root-keys.json")
	require.NoError(t, os.WriteFile(list, []byte(`{"format":"unicity-retired-root-keys/1","keyHashes":["`+hexutil.Encode(ethcrypto.Keccak256(oldKey))+`"]}`), 0o600))

	require.NoError(t, checkRetiredRootKey("", oldKey), "no list: nothing to check")
	require.NoError(t, checkRetiredRootKey(list, freshKey))
	err = checkRetiredRootKey(list, oldKey)
	require.ErrorIs(t, err, ErrValidator)
	require.Contains(t, err.Error(), "earlier root history")

	// a list that cannot be read or is not the format is an error, never an empty list
	require.ErrorIs(t, checkRetiredRootKey(filepath.Join(dir, "missing.json"), freshKey), ErrValidator)
	bad := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte(`{"format":"other","keyHashes":[]}`), 0o600))
	require.ErrorIs(t, checkRetiredRootKey(bad, freshKey), ErrValidator)
	require.NoError(t, os.WriteFile(bad, []byte(`{"format":"unicity-retired-root-keys/1"}`), 0o600))
	require.ErrorIs(t, checkRetiredRootKey(bad, freshKey), ErrValidator)
}
