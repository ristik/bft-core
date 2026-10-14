package cmd

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/gettrustbase"
)

// The release bundle is the GetTrustBase response format (one tagged CBOR object) holding the complete history, genesis through the release tip.
// Packaging authenticity is external to the file: the verifier checks the chain against the pinned genesis EntryID.

// bundleFileBudget bounds a bundle read from disk before it is decoded. It is an allocation guard for a file the release supplies, not a history cap.
const bundleFileBudget = 1 << 30

type utbStoreFlags struct {
	genesis, genesisID, entriesDB string
}

func (f *utbStoreFlags) add(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.genesis, "utb-genesis", "", "the canonical genesis entry file")
	cmd.Flags().StringVar(&f.genesisID, "utb-genesis-id", "", "the EntryID of the genesis entry (0x-prefixed SHA-256): the pin")
	cmd.Flags().StringVar(&f.entriesDB, "utb-entries-db", "", "the UTB finalized entries database (default: $UBFT_HOME/"+rootUTBEntriesDBFileName+")")
	_ = cmd.MarkFlagRequired("utb-genesis")
	_ = cmd.MarkFlagRequired("utb-genesis-id")
}

func (f *utbStoreFlags) runFlags(base *baseFlags) *rootNodeRunFlags {
	return &rootNodeRunFlags{baseFlags: base, Profile2: true, UTBGenesisFile: f.genesis, UTBGenesisID: f.genesisID, UTBEntriesDBFile: f.entriesDB}
}

func parsePin(s string) ([types.TrustBaseV2IDLen]byte, error) {
	var pin [types.TrustBaseV2IDLen]byte
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != len(pin) {
		return pin, fmt.Errorf("the genesis id must be a 0x-prefixed %d-byte hex string", len(pin))
	}
	copy(pin[:], b)
	return pin, nil
}

// trustBaseUTBExportCmd writes the whole retained history of a root's entry store as one bundle. It fails on a gap rather than shortening history.
func trustBaseUTBExportCmd(base *baseFlags) *cobra.Command {
	var sf utbStoreFlags
	var out string
	cmd := &cobra.Command{Use: "utb-export", Short: "Export the complete signed trust-base history as one tagged CBOR bundle (the release bundle)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, closeStore, err := sf.runFlags(base).openUTBStore()
			if err != nil {
				return err
			}
			defer closeStore()
			file, err := gettrustbase.ExportStore(store)
			if err != nil {
				return err
			}
			if err := os.WriteFile(out, file, 0o644); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "exported epochs %d..%d (%d bytes)\n", store.GenesisEpoch(), store.Tip().Epoch, len(file))
			return err
		}}
	sf.add(cmd)
	cmd.Flags().StringVar(&out, "out", "utb-bundle.cbor", "where to write the bundle")
	return cmd
}

// trustBaseUTBImportCmd loads a shipped bundle into an entry store through the store's one append path.
func trustBaseUTBImportCmd(base *baseFlags) *cobra.Command {
	var sf utbStoreFlags
	var in string
	cmd := &cobra.Command{Use: "utb-import", Short: "Load a complete signed trust-base bundle into the entry store (older bundles never roll it back)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			bundle, err := readBundle(in)
			if err != nil {
				return err
			}
			store, closeStore, err := sf.runFlags(base).openUTBStore()
			if err != nil {
				return err
			}
			defer closeStore()
			added, err := gettrustbase.InstallBundle(store, bundle)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "added %d entries; tip epoch %d\n", added, store.Tip().Epoch)
			return err
		}}
	sf.add(cmd)
	cmd.Flags().StringVar(&in, "bundle", "", "the bundle file")
	_ = cmd.MarkFlagRequired("bundle")
	return cmd
}

// trustBaseUTBVerifyCmd is the offline verifier of an exported chain: it needs only the file and the pinned genesis identity.
func trustBaseUTBVerifyCmd() *cobra.Command {
	var in, genesisID string
	cmd := &cobra.Command{Use: "utb-verify", Short: "Verify an exported signed trust-base bundle offline against the pinned genesis EntryID",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pin, err := parsePin(genesisID)
			if err != nil {
				return err
			}
			bundle, err := readBundle(in)
			if err != nil {
				return err
			}
			if err := gettrustbase.VerifyBundle(bundle, pin); err != nil {
				return err
			}
			tipID, err := bundle.Tip().EntryID()
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "ok: epochs %d..%d, tip 0x%x\n", bundle.Entries[0].Epoch, bundle.Tip().Epoch, tipID)
			return err
		}}
	cmd.Flags().StringVar(&in, "bundle", "", "the bundle file")
	cmd.Flags().StringVar(&genesisID, "utb-genesis-id", "", "the EntryID of the genesis entry (0x-prefixed SHA-256)")
	_ = cmd.MarkFlagRequired("bundle")
	_ = cmd.MarkFlagRequired("utb-genesis-id")
	return cmd
}

func readBundle(path string) (*gettrustbase.Bundle, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > bundleFileBudget {
		return nil, fmt.Errorf("bundle of %d bytes exceeds the %d byte file budget", info.Size(), bundleFileBudget)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// entries are bounded by the file itself: each is at least a few bytes, so the file size bounds the count
	return gettrustbase.DecodeBundle(data, gettrustbase.BundleLimits{MaxBytes: len(data), MaxEntries: len(data)/16 + 1})
}
