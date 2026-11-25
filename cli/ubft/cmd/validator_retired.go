package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// retiredRootKeysFormat is the release's published list of the root key hashes of earlier root histories (deploy/testnet/root_keys.py writes
// it as network/retired-root-keys.json). Post-term evidence (#1297, D5 section 2.1) charges a quorum seal from its signed bytes, which bind the
// network but not the root genesis, so a root key must sign one root history only: enrollment and rotation refuse a key on the list.
const retiredRootKeysFormat = "unicity-retired-root-keys/1"

// releaseRetiredRootKeys is where the installed release keeps the list, relative to the validator home (the handbook installs the release
// into <home>/release; the validator container mounts it there).
const releaseRetiredRootKeys = "release/retired-root-keys.json"

// retiredRootKeys is the list a command checks the configured root key against: an explicit --retired-root-keys always; for apply and rotate
// otherwise the release's shipped list when it exists, unless --no-retired-root-keys. A missing shipped list (a first generation, or a release
// from before #1297) checks nothing.
func (f *txFlags) retiredRootKeys(v *loadedValidator) string {
	if f.RetiredRootKeys != "" {
		return f.RetiredRootKeys
	}
	if !f.enrollsRootKey || f.NoRetiredRootKeys {
		return ""
	}
	p := filepath.Join(v.home, releaseRetiredRootKeys)
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// checkRetiredRootKey refuses rootKey (33-byte compressed) when keccak256(rootKey), the root key hash custody and VR store, is in the list at
// path. An empty path checks nothing; an unreadable or malformed list is an error, never an empty list.
func checkRetiredRootKey(path string, rootKey []byte) error {
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return fmt.Errorf("%w: retired root keys: %w", ErrValidator, err)
	}
	var doc struct {
		Format    string   `json:"format"`
		KeyHashes []string `json:"keyHashes"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Format != retiredRootKeysFormat || doc.KeyHashes == nil {
		return fmt.Errorf("%w: %s is not a %s list", ErrValidator, path, retiredRootKeysFormat)
	}
	h := hexutil.Encode(ethcrypto.Keccak256(rootKey))
	for _, x := range doc.KeyHashes {
		if strings.EqualFold(x, h) {
			return fmt.Errorf("%w: the root signing key (hash %s) belongs to an earlier root history (%s): a root key signs one root history only, make a fresh one (D5 section 2.1)", ErrValidator, h, path)
		}
	}
	return nil
}
