package cmd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/utb"
	"github.com/unicitynetwork/bft-core/utbstore"
)

// shardUTBEntriesDBFileName is the default file of a shard node's store of finalized entries.
const shardUTBEntriesDBFileName = "shard-utb-entries.db"

// openUTBStore opens the permanent store of finalized signed trust-base entries, rooted in the genesis entry file and its pinned EntryID. The profile
// needs the handoff profile (the entries are produced by handoffs) and a pin: a genesis file alone authenticates nothing.
func (f *rootNodeRunFlags) openUTBStore(genesisTrustBase *types.RootTrustBaseV1) (*utbstore.Store, func(), error) {
	if !f.Profile2 {
		return nil, nil, errors.New("--utb-genesis requires profile 2")
	}
	return openUTBEntryStore(f.baseFlags, f.UTBGenesisFile, f.UTBGenesisID, f.UTBEntriesDBFile, rootUTBEntriesDBFileName, genesisTrustBase)
}

// openUTBEntryStore opens the store of finalized entries rooted in the genesis entry file and its pin, after checking that the file is the genesis entry
// the deployment's own genesis trust base builds. Roots and shard nodes use it alike.
func openUTBEntryStore(base *baseFlags, genesisFile, genesisID, dbFile, defaultDBName string, genesisTrustBase *types.RootTrustBaseV1) (*utbstore.Store, func(), error) {
	if genesisID == "" {
		return nil, nil, errors.New("--utb-genesis requires --utb-genesis-id: the genesis entry is authenticated by its pinned identity")
	}
	raw, err := os.ReadFile(genesisFile)
	if err != nil {
		return nil, nil, fmt.Errorf("reading the UTB genesis entry: %w", err)
	}
	genesis, err := types.DecodeRootTrustBaseV2(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("the UTB genesis entry: %w", err)
	}
	pinBytes, err := hex.DecodeString(strings.TrimPrefix(genesisID, "0x"))
	if err != nil || len(pinBytes) != types.TrustBaseV2IDLen {
		return nil, nil, fmt.Errorf("--utb-genesis-id must be a 0x-prefixed %d-byte hex string", types.TrustBaseV2IDLen)
	}
	var pin [types.TrustBaseV2IDLen]byte
	copy(pin[:], pinBytes)
	// A nil trust base is the offline tooling (export, import): it has only the pin, which utbstore.Open checks against the genesis entry.
	if genesisTrustBase != nil {
		// the pinned genesis entry must be the one the root's own genesis trust base builds, so a mismatch is a start-up error and not a surprise at the
		// first handoff (when the old committee would endorse a successor linked to an entry no other component derives)
		want, err := utb.BuildUnsigned(nil, utb.FromProjection(genesisTrustBase))
		if err != nil {
			return nil, nil, fmt.Errorf("the UTB genesis entry cannot be derived from the genesis trust base: %w", err)
		}
		wantID, err := want.EntryID()
		if err != nil {
			return nil, nil, err
		}
		gotID, err := genesis.EntryID()
		if err != nil {
			return nil, nil, err
		}
		if wantID != gotID || wantID != pin {
			return nil, nil, fmt.Errorf("the UTB genesis entry does not match the genesis trust base: the trust base builds %x, the file is %x, the pin is %x", wantID, gotID, pin)
		}
	}
	db, err := base.initDB(dbFile, defaultDBName)
	if err != nil {
		return nil, nil, err
	}
	closeDB := func() {
		if closer, ok := db.(io.Closer); ok {
			_ = closer.Close()
		}
	}
	store, err := utbstore.Open(db, genesis, pin)
	if err != nil {
		closeDB()
		return nil, nil, fmt.Errorf("opening the UTB entry store: %w", err)
	}
	return store, closeDB, nil
}
