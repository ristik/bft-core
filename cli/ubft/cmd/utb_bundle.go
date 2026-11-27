package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	return &rootNodeRunFlags{baseFlags: base, HandoffProfile: true, UTBGenesisFile: f.genesis, UTBGenesisID: f.genesisID, UTBEntriesDBFile: f.entriesDB}
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
			store, closeStore, err := sf.runFlags(base).openUTBStore(nil)
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
			store, closeStore, err := sf.runFlags(base).openUTBStore(nil)
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
	var in, genesisID, keysOut, url, forwardedFor, saveBundle string
	var from uint64
	cmd := &cobra.Command{Use: "utb-verify", Short: "Verify an exported signed trust-base bundle offline against the pinned genesis EntryID",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pin, err := parsePin(genesisID)
			if err != nil {
				return err
			}
			var bundle *types.TrustBaseBundle
			switch {
			case (in == "") == (url == ""):
				return fmt.Errorf("give exactly one of --bundle and --url")
			case url != "":
				raw, err := fetchUTBHistory(cmd.Context(), url, forwardedFor, from)
				if err != nil {
					return err
				}
				if bundle, err = types.DecodeTrustBaseBundle(raw, types.TrustBaseLimits{MaxBytes: len(raw), MaxEntries: len(raw)/16 + 1}); err != nil {
					return err
				}
				if saveBundle != "" {
					if err := os.WriteFile(saveBundle, raw, 0o644); err != nil { // #nosec G306 -- the public signed history
						return err
					}
				}
			default:
				if bundle, err = readBundle(in); err != nil {
					return err
				}
			}
			if err := types.VerifyTrustBaseBundle(bundle, pin); err != nil {
				return err
			}
			tipID, err := bundle.Tip().EntryID()
			if err != nil {
				return err
			}
			if keysOut != "" {
				doc, err := utbRootKeys(bundle, pin, tipID)
				if err != nil {
					return err
				}
				if err := os.WriteFile(keysOut, doc, 0o644); err != nil { // #nosec G306 -- public signing keys
					return err
				}
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "ok: epochs %d..%d, tip 0x%x\n", bundle.Entries[0].Epoch, bundle.Tip().Epoch, tipID)
			return err
		}}
	cmd.Flags().StringVar(&in, "bundle", "", "the bundle file")
	cmd.Flags().StringVar(&url, "url", "", "instead of --bundle: the base URL of a served history (GET <url>/api/v1/trustbases, a root or the public gateway), read page by page "+
		"from --from at one snapshot and assembled into one bundle")
	cmd.Flags().Uint64Var(&from, "from", 1, "with --url: the genesis epoch of the history")
	cmd.Flags().StringVar(&forwardedFor, "forwarded-for", "", "with --url: an X-Forwarded-For client address (a gateway that trusts its proxy)")
	cmd.Flags().StringVar(&saveBundle, "save-bundle", "", "with --url: also write the assembled bundle file")
	cmd.Flags().StringVar(&keysOut, "keys-out", "", "after verification, write every root signing key of every epoch of the history as JSON (unicity-utb-root-keys/1): the "+
		"retired-key inventory a reset generation takes as --prior-generation (#1297: keys that joined or rotated after genesis included)")
	cmd.Flags().StringVar(&genesisID, "utb-genesis-id", "", "the EntryID of the genesis entry (0x-prefixed SHA-256)")
	_ = cmd.MarkFlagRequired("utb-genesis-id")
	return cmd
}

// utbRootKeysFormat is the document `utb-verify --keys-out` writes: the public root signing keys of every epoch of a verified history.
const utbRootKeysFormat = "unicity-utb-root-keys/1"

// utbRootKeys renders the verified history's root signing keys, epoch by epoch (deploy/testnet/root_keys.py reads it).
func utbRootKeys(bundle *types.TrustBaseBundle, pin, tip [types.TrustBaseV2IDLen]byte) ([]byte, error) {
	type epochKeys struct {
		Epoch uint64   `json:"epoch"`
		Keys  []string `json:"keys"`
	}
	doc := struct {
		Format    string      `json:"format"`
		NetworkID uint64      `json:"networkId"`
		GenesisID string      `json:"genesisId"`
		TipID     string      `json:"tipId"`
		Epochs    []epochKeys `json:"epochs"`
	}{Format: utbRootKeysFormat, NetworkID: uint64(bundle.Entries[0].NetworkID), GenesisID: fmt.Sprintf("0x%x", pin), TipID: fmt.Sprintf("0x%x", tip)}
	for _, e := range bundle.Entries {
		ek := epochKeys{Epoch: e.Epoch, Keys: []string{}}
		for _, m := range e.RootNodes {
			ek.Keys = append(ek.Keys, fmt.Sprintf("0x%x", []byte(m.SigKey)))
		}
		doc.Epochs = append(doc.Epochs, ek)
	}
	out, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// fetchUTBHistory reads a served signed history page by page (GET /api/v1/trustbases) at the snapshot the first page names, and encodes the
// entries as one bundle; the caller verifies it against the pin.
func fetchUTBHistory(ctx context.Context, base, forwardedFor string, from uint64) ([]byte, error) {
	var raw [][]byte
	query := fmt.Sprintf("from=%d&maxEntries=%d", from, types.DefaultTrustBaseMaxEntries)
	for pages := 0; ; pages++ {
		if pages > 1<<16 {
			return nil, fmt.Errorf("the served history did not end")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(base, "/")+"/api/v1/trustbases?"+query, nil)
		if err != nil {
			return nil, err
		}
		if forwardedFor != "" {
			req.Header.Set("X-Forwarded-For", forwardedFor)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, int64(types.DefaultTrustBaseMaxResponse)+1))
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GET trustbases: HTTP %d", resp.StatusCode)
		}
		page, _, err := types.DecodeTrustBaseResponse(body, types.TrustBasePageLimits)
		if err != nil {
			return nil, err
		}
		if page.Status != types.TrustBaseStatusOK {
			return nil, fmt.Errorf("GET trustbases: status %s", page.Status)
		}
		for _, e := range page.Entries {
			raw = append(raw, e)
		}
		if page.NextEpoch == nil {
			return types.EncodeTrustBaseBundle(raw)
		}
		query = fmt.Sprintf("from=%d&maxEntries=%d&snapshotEnd=%d&snapshotEntryId=0x%x", *page.NextEpoch, types.DefaultTrustBaseMaxEntries, page.EffectiveEnd, page.EndEntryID)
	}
}

func readBundle(path string) (*types.TrustBaseBundle, error) {
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
	return types.DecodeTrustBaseBundle(data, types.TrustBaseLimits{MaxBytes: len(data), MaxEntries: len(data)/16 + 1})
}
