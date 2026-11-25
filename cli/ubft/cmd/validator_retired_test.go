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

// apply and rotate read the release's shipped list by default when it exists; --no-retired-root-keys opts out; an explicit list always applies;
// other commands and a missing shipped list (a first generation) check nothing.
func TestRetiredRootKeysDefaultsToTheShippedList(t *testing.T) {
	home := t.TempDir()
	v := &loadedValidator{home: home}
	enroll := &txFlags{enrollsRootKey: true}
	require.Empty(t, enroll.retiredRootKeys(v), "no shipped list: a first generation")
	require.NoError(t, os.MkdirAll(filepath.Join(home, "release"), 0o700))
	shipped := filepath.Join(home, releaseRetiredRootKeys)
	require.NoError(t, os.WriteFile(shipped, []byte(`{"format":"unicity-retired-root-keys/1","keyHashes":[]}`), 0o600))
	require.Equal(t, shipped, enroll.retiredRootKeys(v))
	require.Empty(t, (&txFlags{enrollsRootKey: true, NoRetiredRootKeys: true}).retiredRootKeys(v), "opted out")
	require.Empty(t, (&txFlags{}).retiredRootKeys(v), "exit, claim and the other commands do not enroll a root key")
	require.Equal(t, "/x/list.json", (&txFlags{RetiredRootKeys: "/x/list.json", NoRetiredRootKeys: true}).retiredRootKeys(v), "an explicit list is always checked")
}

// #1297 (astra r2): a key that rotated in or joined during generation k is in k's UTB history, hence in generation k+1's shipped list, and
// apply/rotate refuse it by default.
func TestARotatedInKeyOfThePriorGenerationIsRefusedByDefault(t *testing.T) {
	rotated, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	key := ethcrypto.CompressPubkey(&rotated.PublicKey)
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, "release"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(home, releaseRetiredRootKeys),
		[]byte(`{"format":"unicity-retired-root-keys/1","keyHashes":["`+hexutil.Encode(ethcrypto.Keccak256(key))+`"]}`), 0o600))
	f := &txFlags{enrollsRootKey: true}
	require.ErrorContains(t, checkRetiredRootKey(f.retiredRootKeys(&loadedValidator{home: home}), key), "earlier root history")
}
