package cmd

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/utb"
)

// vrUTBGenesis is the signed trust-base history's genesis of a VR generation: the entry the epoch-1 trust base builds (the same builder as
// `trust-base utb-manifest`, so every component derives one entry) and its EntryID, the pin. A VR generation's epoch-1 committee is the trust base
// the plan already binds, so the entry adds no input.
func vrUTBGenesis(tb *types.RootTrustBaseV1) (raw []byte, id [types.TrustBaseV2IDLen]byte, err error) {
	if tb.Epoch != 1 {
		return nil, id, fmt.Errorf("%w: the UTB genesis entry is built from the epoch-1 trust base, this one is epoch %d", ErrVRGenesis, tb.Epoch)
	}
	entry, err := utb.BuildUnsigned(nil, utb.FromProjection(tb))
	if err != nil {
		return nil, id, fmt.Errorf("%w: the UTB genesis entry cannot be built from the trust base: %w", ErrVRGenesis, err)
	}
	if raw, err = entry.MarshalCBOR(); err != nil {
		return nil, id, err
	}
	if id, err = entry.EntryID(); err != nil {
		return nil, id, err
	}
	return raw, id, nil
}

// writeVRUTBGenesis writes the genesis entry and its pin (0x + 64 hex, a newline) where the lane's roots, shard nodes and aggregator read them.
func writeVRUTBGenesis(tb *types.RootTrustBaseV1, entryFile, idFile string) (string, error) {
	raw, id, err := vrUTBGenesis(tb)
	if err != nil {
		return "", err
	}
	pin := lowerHex(id[:])
	if err := os.WriteFile(entryFile, raw, 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(idFile, []byte(pin+"\n"), 0o600); err != nil {
		return "", err
	}
	return pin, nil
}

// checkVRUTBGenesis refuses a genesis entry file or pin that is not what the generation's epoch-1 trust base builds.
func checkVRUTBGenesis(tb *types.RootTrustBaseV1, entryFile, idFile string) (string, error) {
	want, id, err := vrUTBGenesis(tb)
	if err != nil {
		return "", err
	}
	got, err := os.ReadFile(entryFile) // #nosec G304 -- operator supplied local file
	if err != nil {
		return "", err
	}
	if !bytes.Equal(got, want) {
		return "", fmt.Errorf("%w: %s is not the genesis entry the epoch-1 trust base builds", ErrVRGenesis, entryFile)
	}
	rawPin, err := os.ReadFile(idFile) // #nosec G304 -- operator supplied local file
	if err != nil {
		return "", err
	}
	pin, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(rawPin)), "0x"))
	if err != nil || !bytes.Equal(pin, id[:]) {
		return "", fmt.Errorf("%w: the pin in %s is not the EntryID %s of the genesis entry", ErrVRGenesis, idFile, lowerHex(id[:]))
	}
	return lowerHex(id[:]), nil
}

// vrUTBFlags registers the pair of paths a plan writes and a verify checks. Both flags go together or not at all.
func vrUTBFlags(cmd interface {
	StringVar(*string, string, string, string)
}, entry, id *string, verb string) {
	cmd.StringVar(entry, "utb-genesis", "", "the UTB genesis entry file to "+verb+" (the signed trust-base history of the generation; needs --utb-genesis-id)")
	cmd.StringVar(id, "utb-genesis-id", "", "the file holding the genesis entry's pinned EntryID, to "+verb)
}

func vrUTBPair(entry, id string) (bool, error) {
	if (entry == "") != (id == "") {
		return false, fmt.Errorf("%w: --utb-genesis and --utb-genesis-id go together", ErrVRGenesis)
	}
	return entry != "", nil
}
