package cmd

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"

	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/utb"
)

const utbManifestSchema = "unicity/utb-deployment-manifest/1"

// utbManifest is the one record a fresh UTB deployment is generated from and checked against: the exact inputs, the artifacts derived from them in
// dependency order with their digests, and the builds that will run it. Nothing in it is hand-edited; --check recomputes every derived value.
type utbManifest struct {
	Schema string `json:"schema"`
	// Inputs: the genesis trust base (its file digest) and the identities derived from it.
	Inputs struct {
		TrustBaseFile   string `json:"trustBaseFile"`
		TrustBaseSHA256 string `json:"trustBaseSha256"`
		NetworkID       uint32 `json:"networkId"`
	} `json:"inputs"`
	// Derived, in dependency order. The three identities are distinct: the root-chain genesis identity (the V1 genesis trust base hash, what the EVM and
	// the Q3 history are rooted in), the UTB genesis EntryID (the pin of the signed chain), and the protocol tuple identity.
	Derived struct {
		RootGenesisID        string `json:"rootGenesisId"`
		UTBGenesisFile       string `json:"utbGenesisFile"`
		UTBGenesisSHA256     string `json:"utbGenesisSha256"`
		UTBGenesisEntryID    string `json:"utbGenesisEntryId"`
		ProtocolConfigID     string `json:"protocolConfigId"`
		ProtocolRevision     uint64 `json:"protocolRevision"`
		VoteCodec            uint64 `json:"voteCodec"`
		SigningScheme        uint64 `json:"signingScheme"`
		LegacyProtocolConfig string `json:"legacyProtocolConfigId"`
	} `json:"derived"`
	Order []string `json:"order"`
	Build struct {
		BFTCoreRevision string `json:"bftCoreRevision"`
		BFTCoreModified bool   `json:"bftCoreModified"`
		BFTGoBase       string `json:"bftGoBase"`
		Go              string `json:"go"`
	} `json:"build"`
	// Components are the other pinned builds and checkouts of the deployment (name -> digest or commit), recorded as given.
	Components map[string]string `json:"components,omitempty"`
}

func fileSHA256(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// currentBuild reads what the running binary was built from: the bft-core revision and the exact bft-go-base module (path, version, sum, replacement).
func currentBuild() (revision string, modified bool, goBase, goVersion string) {
	goVersion = runtime.Version()
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", false, "", goVersion
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	for _, m := range info.Deps {
		if m.Path == "github.com/unicitynetwork/bft-go-base" {
			if m.Replace != nil {
				m = m.Replace
			}
			goBase = fmt.Sprintf("%s %s %s", m.Path, m.Version, m.Sum)
		}
	}
	return revision, modified, goBase, goVersion
}

// deriveUTBManifest computes every derived value of the manifest from the genesis trust base, and writes the genesis entry to outDir.
func deriveUTBManifest(trustBasePath, outDir string, components map[string]string) (*utbManifest, error) {
	tb, err := util.ReadJsonFile(trustBasePath, &types.RootTrustBaseV1{})
	if err != nil {
		return nil, fmt.Errorf("failed to load trust base %q: %w", trustBasePath, err)
	}
	if tb.Epoch != 1 {
		return nil, fmt.Errorf("trust base %q is epoch %d: a fresh deployment starts at the epoch-1 trust base", trustBasePath, tb.Epoch)
	}
	rootID, err := tb.Hash(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	entry, err := utb.BuildUnsigned(nil, utb.FromProjection(tb))
	if err != nil {
		return nil, fmt.Errorf("the genesis entry cannot be built from the trust base: %w", err)
	}
	raw, err := entry.MarshalCBOR()
	if err != nil {
		return nil, err
	}
	entryID, err := entry.EntryID()
	if err != nil {
		return nil, err
	}
	var genesis [32]byte
	copy(genesis[:], rootID)
	cfg, plain := q3format.Q3ConfigUTB(uint64(tb.NetworkID), genesis), q3format.Q3Config(uint64(tb.NetworkID), genesis)
	cfgID, plainID := cfg.Identity(), plain.Identity()

	m := &utbManifest{Schema: utbManifestSchema, Components: components}
	m.Inputs.TrustBaseFile = trustBasePath
	if m.Inputs.TrustBaseSHA256, err = fileSHA256(trustBasePath); err != nil {
		return nil, err
	}
	m.Inputs.NetworkID = uint32(tb.NetworkID)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	m.Derived.UTBGenesisFile = filepath.Join(outDir, "utb-genesis.cbor")
	if err := os.WriteFile(m.Derived.UTBGenesisFile, raw, 0o644); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	m.Derived.RootGenesisID = "0x" + hex.EncodeToString(rootID)
	m.Derived.UTBGenesisSHA256 = hex.EncodeToString(sum[:])
	m.Derived.UTBGenesisEntryID = "0x" + hex.EncodeToString(entryID[:])
	m.Derived.ProtocolConfigID = "0x" + hex.EncodeToString(cfgID[:])
	m.Derived.LegacyProtocolConfig = "0x" + hex.EncodeToString(plainID[:])
	m.Derived.ProtocolRevision, m.Derived.VoteCodec, m.Derived.SigningScheme = cfg.Revision, cfg.VoteCodec, cfg.SigningScheme
	m.Order = []string{"trust-base", "root-genesis-id", "utb-genesis", "utb-genesis-entry-id", "protocol-config"}
	m.Build.BFTCoreRevision, m.Build.BFTCoreModified, m.Build.BFTGoBase, m.Build.Go = currentBuild()
	return m, nil
}

// checkUTBManifest recomputes the derived values from the manifest's inputs and reports every difference, including a changed or missing artifact file.
func checkUTBManifest(manifestPath string) error {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var m utbManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("manifest %q: %w", manifestPath, err)
	}
	if m.Schema != utbManifestSchema {
		return fmt.Errorf("manifest %q: schema %q, expected %q", manifestPath, m.Schema, utbManifestSchema)
	}
	tmp, err := os.MkdirTemp("", "utb-manifest-check-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	again, err := deriveUTBManifest(m.Inputs.TrustBaseFile, tmp, m.Components)
	if err != nil {
		return err
	}
	var diffs []string
	cmp := func(name, have, want string) {
		if have != want {
			diffs = append(diffs, fmt.Sprintf("%s: manifest %s, recomputed %s", name, have, want))
		}
	}
	cmp("trustBaseSha256", m.Inputs.TrustBaseSHA256, again.Inputs.TrustBaseSHA256)
	cmp("rootGenesisId", m.Derived.RootGenesisID, again.Derived.RootGenesisID)
	cmp("utbGenesisSha256", m.Derived.UTBGenesisSHA256, again.Derived.UTBGenesisSHA256)
	cmp("utbGenesisEntryId", m.Derived.UTBGenesisEntryID, again.Derived.UTBGenesisEntryID)
	cmp("protocolConfigId", m.Derived.ProtocolConfigID, again.Derived.ProtocolConfigID)
	cmp("legacyProtocolConfigId", m.Derived.LegacyProtocolConfig, again.Derived.LegacyProtocolConfig)
	if got, err := fileSHA256(m.Derived.UTBGenesisFile); err != nil {
		diffs = append(diffs, fmt.Sprintf("the genesis entry file %q: %v", m.Derived.UTBGenesisFile, err))
	} else {
		cmp("utbGenesisFile content", got, again.Derived.UTBGenesisSHA256)
	}
	if len(diffs) > 0 {
		return fmt.Errorf("the manifest does not describe this deployment:\n  %s", strings.Join(diffs, "\n  "))
	}
	return nil
}

func trustBaseUTBManifestCmd() *cobra.Command {
	var tbPath, outDir, check string
	var components []string
	cmd := &cobra.Command{Use: "utb-manifest", Short: "Generate (or --check) the manifest and genesis artifacts of a fresh UTB deployment from its genesis trust base",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if check != "" {
				if err := checkUTBManifest(check); err != nil {
					return err
				}
				_, err := fmt.Fprintln(cmd.OutOrStdout(), "manifest ok")
				return err
			}
			if tbPath == "" {
				return errors.New("--trust-base is required")
			}
			comp := map[string]string{}
			for _, c := range components {
				name, value, ok := strings.Cut(c, "=")
				if !ok || name == "" || value == "" {
					return fmt.Errorf("--component %q: want name=digest-or-commit", c)
				}
				comp[name] = value
			}
			m, err := deriveUTBManifest(tbPath, outDir, comp)
			if err != nil {
				return err
			}
			out, err := json.MarshalIndent(m, "", "  ")
			if err != nil {
				return err
			}
			path := filepath.Join(outDir, "utb-manifest.json")
			if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
				return err
			}
			names := make([]string, 0, len(comp))
			for n := range comp {
				names = append(names, n)
			}
			sort.Strings(names)
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\nroot genesis id  %s\nutb genesis id    %s\n", path, m.Derived.RootGenesisID, m.Derived.UTBGenesisEntryID)
			return err
		}}
	cmd.Flags().StringVar(&tbPath, "trust-base", "", "the genesis (epoch 1) trust base file")
	cmd.Flags().StringVar(&outDir, "out-dir", "utb-deployment", "where to write the genesis entry and the manifest")
	cmd.Flags().StringArrayVar(&components, "component", nil, "a pinned build or checkout of the deployment, name=digest-or-commit (repeatable)")
	cmd.Flags().StringVar(&check, "check", "", "recompute and compare a manifest instead of generating one")
	return cmd
}
