package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier"
)

// defaultGasLimit is a starting point for exec-mode, not a validated
// operational limit — see docs/engine-api-adapter-plan.md §8's note that
// the real gas-limit-versus-T2 budget has to be measured, not assumed.
// Override with --gas-limit once you have that measurement.
const defaultGasLimit = 30_000_000

type engineAPIGenesisFlags struct {
	*baseFlags
	shardConfFlags

	Out       string
	GasLimit  uint64
	Coinbase  string
	ExtraData string

	// FullShardConf is where the full shard configuration (the base configuration plus
	// seal_registry_genesis) is written. Empty selects the default beside --out.
	FullShardConf string

	// AllocSource is an operator-supplied standard genesis JSON used as the source instead of the
	// built-in template. It is mutually exclusive with the template-shaping flags below, because a
	// flag and the file would otherwise silently fight over the same genesis field.
	AllocSource string
	// Manifest is a versioned allocation/build manifest compiled into the standard JSON source
	// consumed by registrygenesis.PrepareGenesisJSON.
	Manifest string
	// RootEpoch is the root epoch of the genesis record's Pins. It must be non-zero:
	// rootinput.ObservationProfileBindingV2 refuses RootEpoch 0.
	RootEpoch uint64
	// RegistryLayout selects the SealRegistry: 1 is the historical sealRegistry/v1 (the default, so existing
	// deployments are unchanged), 2 the assignment-aware registry an M3 launch genesis must use so the
	// validator assignment can ever change.
	RegistryLayout uint64

	// B1Profile and TrustBase select the fresh-B1 registry (layout 3): the profile is the one `engine-api b1-profile` derived from the
	// trust base, and IdentitiesOut receives the identity document the bridge vault deployment is checked against.
	B1Profile     string
	TrustBase     string
	IdentitiesOut string
}

func newEngineAPICmd(baseFlags *baseFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "engine-api",
		Short: "Tools for the Engine API executor",
	}
	cmd.AddCommand(engineAPIGenesisCmd(baseFlags))
	cmd.AddCommand(engineAPIExportManifestCmd())
	cmd.AddCommand(engineAPIB1ProfileCmd(baseFlags))
	return cmd
}

func engineAPIExportManifestCmd() *cobra.Command {
	var manifest, out string
	cmd := &cobra.Command{
		Use:   "export-manifest",
		Short: "Execute pinned genesis constructors and export initialized account state",
		Long:  "Run the pinned FeeCollector, WUCT, and vesting-vault constructors in an in-process Cancun EVM, then write the constructor-executed contract accounts into a new manifest. The operation is offline and deterministic; pass the exported file to engine-api genesis --manifest.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if manifest == "" || out == "" {
				return fmt.Errorf("--manifest and --out are required")
			}
			data, err := os.ReadFile(manifest)
			if err != nil {
				return fmt.Errorf("reading manifest %q: %w", manifest, err)
			}
			exported, err := registrygenesis.ExportAllocationManifest(data)
			if err != nil {
				return err
			}
			if err := os.WriteFile(out, exported, 0o644); err != nil {
				return fmt.Errorf("writing exported manifest %q: %w", out, err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&manifest, "manifest", "", "versioned allocation/build manifest to export")
	cmd.Flags().StringVar(&out, "out", "", "path to write constructor-exported manifest")
	return cmd
}

func engineAPIGenesisCmd(baseFlags *baseFlags) *cobra.Command {
	flags := &engineAPIGenesisFlags{baseFlags: baseFlags}
	cmd := &cobra.Command{
		Use:   "genesis",
		Short: "Generate a finalized reth-compatible genesis.json derived from a shard conf",
		Long: `Generate a finalized reth-compatible genesis.json whose chainId is taken directly from the
shard conf's "chain_id" partition param, so the two files can never drift apart — see
docs/adr/0001-executor-boundary.md decision 3.

Schedules Shanghai and Cancun at genesis (timestamp 0) and deliberately leaves every fork
after Cancun (Prague, Osaka, ...) out of the schedule entirely, matching the exact V3
Engine API method set this adapter speaks. Scheduling every fork at 0 would activate
post-Cancun consensus rules the moment reth's own defaults decide they apply, silently
requiring engine_newPayloadV4+ this adapter does not implement.

The output is the FINALIZED genesis: registrygenesis.PrepareGenesisJSON inserts the pinned
SealRegistry account at a_sr (its runtime code and the 22 initialized storage words) into the
source allocation and derives the full shard configuration and genesis origin from it.

Use --manifest with a strict versioned allocation/build manifest exported by
engine-api export-manifest. The exporter executes and verifies the pinned constructors; this
command reruns them and refuses contract state that differs from the verified output. The manifest's
chain ID must match the shard configuration, its fee beneficiary must retain the exported
FeeCollector code, and allocation balances must sum exactly to nativeSupply.

Two artifacts are written. --out is the finalized standard JSON the execution client is started
from. --full-shard-conf (default: beside --out) is the full shard configuration — the base conf
plus seal_registry_genesis — whose hash is the fullShardConfHash an observation's ShardConfHash
must equal; a node handed only the base conf can never satisfy that check.

The derived identities are printed so an operator can compare them; they are deliberately not
written beside the artifacts, because a second trusted file of derived metadata would be a second
source of truth and the origin is re-derivable from the finalized JSON.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return engineAPIGenesis(flags, cmd.Flags().Changed, cmd.OutOrStdout())
		},
	}
	flags.addShardConfFlags(cmd, false)
	cmd.Flags().StringVar(&flags.Out, "out", "", "output path for the finalized genesis.json (required)")
	cmd.Flags().Uint64Var(&flags.GasLimit, "gas-limit", defaultGasLimit,
		"per-block gas limit — a starting point, not a validated operational limit (see docs/engine-api-adapter-plan.md §8)")
	cmd.Flags().StringVar(&flags.Coinbase, "coinbase", "0x0000000000000000000000000000000000000000",
		"genesis coinbase address")
	cmd.Flags().StringVar(&flags.ExtraData, "extra-data", "0x", "genesis extraData, as a 0x-prefixed hex string")
	cmd.Flags().StringVar(&flags.FullShardConf, "full-shard-conf", "",
		"path to write the full shard configuration (the base conf plus seal_registry_genesis); default: <out without its extension>-full-shard-conf.json")
	cmd.Flags().StringVar(&flags.AllocSource, "alloc-source", "",
		"standard genesis JSON to use as the source instead of the built-in template; refuses to combine with --gas-limit, --coinbase or --extra-data")
	cmd.Flags().StringVar(&flags.Manifest, "manifest", "",
		"versioned allocation/build manifest to compile into the standard genesis JSON pipeline; mutually exclusive with --alloc-source and template-shaping flags")
	cmd.Flags().Uint64Var(&flags.RootEpoch, "root-epoch", 1,
		"root epoch of the genesis record's pins (must be non-zero)")
	cmd.Flags().Uint64Var(&flags.RegistryLayout, "registry-layout", 1,
		"SealRegistry layout: 1 is the historical sealRegistry/v1; 2 is the assignment-aware sealRegistry/v2 an M3 launch genesis needs "+
			"(a live chain cannot be migrated to it, and a hash repin cannot replace live contract code)")
	cmd.Flags().StringVar(&flags.B1Profile, "b1-profile", "",
		"fresh-B1 deployment: the profile `engine-api b1-profile` derived; allocates the B1 registry (layout 3) instead of a historical one")
	cmd.Flags().StringVar(&flags.TrustBase, "trust-base", "", "with --b1-profile: the signed root trust base the profile was derived from")
	cmd.Flags().StringVar(&flags.IdentitiesOut, "identities-out", "",
		"with --b1-profile: write the genesis identity document (root genesis, execution genesis, profile hash, registry words) the bridge vault deployment is checked against")
	if err := cmd.MarkFlagRequired("out"); err != nil {
		panic(err)
	}
	return cmd
}

// gethGenesis is the go-ethereum-compatible genesis format reth also
// accepts. Hand-rolled rather than imported from go-ethereum — see
// docs/adr/0001-executor-boundary.md decision 1: the same reasoning that
// keeps engineapi's Engine API types out of a go-ethereum dependency
// applies here too, and this is a small, stable, well-documented format.
//
// It is only the SOURCE template: registrygenesis.PrepareGenesisJSON parses it, inserts the pinned
// registry account and re-emits the finalized JSON.
type gethGenesis struct {
	Config     gethChainConfig   `json:"config"`
	Nonce      string            `json:"nonce"`
	Timestamp  string            `json:"timestamp"`
	ExtraData  string            `json:"extraData"`
	GasLimit   string            `json:"gasLimit"`
	Difficulty string            `json:"difficulty"`
	MixHash    string            `json:"mixHash"`
	Coinbase   string            `json:"coinbase"`
	Alloc      map[string]string `json:"alloc"`
	BaseFee    string            `json:"baseFeePerGas"`
}

// gethChainConfig's fork-activation fields are deliberately explicit and
// individually named, not a generic map, so it's visually obvious on
// review which forks are scheduled and which are not — the entire point
// of decision 3.
type gethChainConfig struct {
	ChainID             uint64 `json:"chainId"`
	HomesteadBlock      uint64 `json:"homesteadBlock"`
	EIP150Block         uint64 `json:"eip150Block"`
	EIP155Block         uint64 `json:"eip155Block"`
	EIP158Block         uint64 `json:"eip158Block"`
	ByzantiumBlock      uint64 `json:"byzantiumBlock"`
	ConstantinopleBlock uint64 `json:"constantinopleBlock"`
	PetersburgBlock     uint64 `json:"petersburgBlock"`
	IstanbulBlock       uint64 `json:"istanbulBlock"`
	BerlinBlock         uint64 `json:"berlinBlock"`
	LondonBlock         uint64 `json:"londonBlock"`
	MergeNetsplitBlock  uint64 `json:"mergeNetsplitBlock"`

	// ShanghaiTime/CancunTime: the two forks this adapter's V3 Engine API
	// calls actually support. Deliberately the *last* two fields set —
	// nothing past Cancun appears here at all. See B1.7's startup
	// capability check (engineapi.Adapter.CheckCapabilities) for the other
	// half of this guarantee: even if a differently-generated chain spec
	// somehow scheduled a later fork, the adapter refuses to start against
	// an execution client that requires methods beyond V3.
	ShanghaiTime uint64 `json:"shanghaiTime"`
	CancunTime   uint64 `json:"cancunTime"`

	TerminalTotalDifficulty       uint64 `json:"terminalTotalDifficulty"`
	TerminalTotalDifficultyPassed bool   `json:"terminalTotalDifficultyPassed"`
}

func engineAPIGenesis(flags *engineAPIGenesisFlags, changed func(string) bool, out io.Writer) error {
	shardConfs, err := flags.loadShardConfs(flags.baseFlags)
	if err != nil {
		return fmt.Errorf("loading shard conf: %w", err)
	}
	if len(shardConfs) != 1 {
		return fmt.Errorf("engine-api genesis requires exactly one --shard-conf, got %d", len(shardConfs))
	}
	shardConf := shardConfs[0]
	if flags.RegistryLayout == registryproof.LayoutVersion2 || flags.B1Profile != "" {
		// Both launch geneses, the assignment-aware layout 2 and the fresh-B1 layout 3, always require coupled validator-set changes: the
		// parameter is part of the hashed full configuration, so every root validator enforces it. An explicit opt-out is a mistake, not a choice.
		layout := flags.RegistryLayout
		if flags.B1Profile != "" {
			layout = b1RegistryLayout
		}
		if v, set := shardConf.PartitionParams[evmassign.CouplingParam]; set && v != "true" {
			return fmt.Errorf("a registry layout %d genesis requires %s=true, the shard conf says %q", layout, evmassign.CouplingParam, v)
		}
		if shardConf.PartitionParams == nil {
			shardConf.PartitionParams = map[string]string{}
		}
		shardConf.PartitionParams[evmassign.CouplingParam] = "true"
	}

	chainID, ok := zkverifier.ParseChainIDFromParams(shardConf.PartitionParams)
	if !ok {
		return fmt.Errorf("shard conf has no chain_id partition param — set --partition-params chain_id=<id> when generating it")
	}
	if flags.RootEpoch == 0 {
		return fmt.Errorf("--root-epoch must be non-zero: rootinput.ObservationProfileBindingV2 refuses a configured root epoch of 0")
	}
	fullPath := flags.FullShardConf
	if fullPath == "" {
		fullPath = defaultFullShardConfPath(flags.Out)
	}
	outAbs, err := filepath.Abs(flags.Out)
	if err != nil {
		return fmt.Errorf("resolving --out: %w", err)
	}
	fullAbs, err := filepath.Abs(fullPath)
	if err != nil {
		return fmt.Errorf("resolving --full-shard-conf: %w", err)
	}
	if outAbs == fullAbs {
		return fmt.Errorf("--out and --full-shard-conf must name different files")
	}
	for _, path := range []string{flags.Out, fullPath} {
		info, err := os.Lstat(path)
		if err == nil && info.IsDir() {
			return fmt.Errorf("output path %q is a directory", path)
		}
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("checking output path %q: %w", path, err)
		}
	}

	var (
		art     registrygenesis.Artifact
		pins    registrygenesis.Pins
		profile b1state.Profile
	)
	if flags.B1Profile != "" {
		if flags.RegistryLayout != 1 && flags.RegistryLayout != b1RegistryLayout {
			return fmt.Errorf("--b1-profile selects registry layout %d; --registry-layout %d contradicts it", b1RegistryLayout, flags.RegistryLayout)
		}
		flags.RegistryLayout = b1RegistryLayout
		if flags.TrustBase == "" {
			return fmt.Errorf("--b1-profile requires --trust-base")
		}
		if profile, err = readB1Profile(flags.B1Profile); err != nil {
			return err
		}
		tb, err := readTrustBase(flags.TrustBase)
		if err != nil {
			return err
		}
		h, err := bindB1Profile(profile, tb, shardConf)
		if err != nil {
			return err
		}
		if art, pins, err = registrygenesis.B1Artifact(profile, h); err != nil {
			return fmt.Errorf("binding the fresh-B1 registry: %w", err)
		}
		if changed("root-epoch") && flags.RootEpoch != pins.RootEpoch {
			return fmt.Errorf("--root-epoch %d contradicts the trust base's genesis epoch %d", flags.RootEpoch, pins.RootEpoch)
		}
		if !changed("gas-limit") {
			flags.GasLimit = profile.MaxGas
		}
	} else {
		if flags.TrustBase != "" || flags.IdentitiesOut != "" {
			return fmt.Errorf("--trust-base and --identities-out require --b1-profile")
		}
		if art, err = registrygenesis.PinnedArtifactForLayout(flags.RegistryLayout); err != nil {
			return fmt.Errorf("loading the pinned seal-registry artifact: %w", err)
		}
		pins = registrygenesis.Pins{
			RootEpoch:        flags.RootEpoch,
			RegistryCodeHash: art.CodeHash,
			SystemAddress:    registrygenesis.SystemAddress,
			RegistryAddress:  registryproof.RegistryAddress,
		}
	}

	source, err := engineAPIGenesisSource(flags, changed, chainID)
	if err != nil {
		return err
	}
	prepared, err := registrygenesis.PrepareGenesisJSON(shardConf, pins, art, source, registrygenesis.DefaultGenesisJSONLimits())
	if err != nil {
		return fmt.Errorf("preparing the finalized genesis: %w", err)
	}

	// The full shard configuration is the base conf plus seal_registry_genesis, and its hash is the
	// fullShardConfHash an observation's ShardConfHash must equal (rootinput.DeriveV2); a node handed
	// only the base conf can never satisfy that check.
	full, err := prepared.FullConfig()
	if err != nil {
		return fmt.Errorf("deriving the full shard configuration: %w", err)
	}
	fullJSON, err := json.MarshalIndent(full, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding the full shard configuration: %w", err)
	}

	// Stage both artifacts beside their destinations before publishing either name. A failed
	// second write then cannot leave a new genesis without its matching full configuration.
	genesisTemp, err := stageGenesisFile(flags.Out, prepared.GenesisJSON())
	if err != nil {
		return fmt.Errorf("staging %q: %w", flags.Out, err)
	}
	defer os.Remove(genesisTemp)
	fullTemp, err := stageGenesisFile(fullPath, fullJSON)
	if err != nil {
		return fmt.Errorf("staging the full shard configuration at %q: %w", fullPath, err)
	}
	defer os.Remove(fullTemp)
	if err := os.Rename(genesisTemp, flags.Out); err != nil {
		return fmt.Errorf("publishing %q: %w", flags.Out, err)
	}
	if err := os.Rename(fullTemp, fullPath); err != nil {
		return fmt.Errorf("publishing the full shard configuration at %q: %w", fullPath, err)
	}

	origin := prepared.Origin()
	if flags.IdentitiesOut != "" {
		doc, err := newB1Identities(profile, origin.BlockHash(), prepared.B1Words())
		if err != nil {
			return fmt.Errorf("encoding the identity document: %w", err)
		}
		if err := os.WriteFile(flags.IdentitiesOut, doc, 0o644); err != nil { // #nosec G306 -- public identities
			return fmt.Errorf("writing %q: %w", flags.IdentitiesOut, err)
		}
		fmt.Fprintf(out, "wrote %s (genesis identities)\n", flags.IdentitiesOut)
	}
	fmt.Fprintf(out, "wrote %s (chainId=%d, shanghai+cancun at genesis, registry account at %s)\n",
		flags.Out, chainID, registryproof.RegistryAddress)
	fmt.Fprintf(out, "wrote %s (full shard configuration)\n", fullPath)
	// The identities, printed for an operator to compare. Deliberately not written beside the
	// artifact: the origin is re-derivable from the finalized JSON, and a sidecar would be a second
	// trusted file and a second source of truth.
	fmt.Fprintf(out, "registry layout:            %d (code hash %s)\n", max(flags.RegistryLayout, 1), art.CodeHash)
	fmt.Fprintf(out, "full shard conf hash:       %s\n", origin.FullShardConfHash())
	if flags.RegistryLayout == registryproof.LayoutVersion2 {
		fmt.Fprintf(out, "initial assignment:         shard epoch %d, active configuration hash %s (immutable genesis hash)\n",
			shardConf.Epoch, origin.FullShardConfHash())
	}
	fmt.Fprintf(out, "state root:                 %s\n", origin.StateRoot())
	fmt.Fprintf(out, "block hash:                 %s\n", origin.BlockHash())
	fmt.Fprintf(out, "execution config identity:  %s\n", origin.ExecutionConfigIdentity())
	fmt.Fprintf(out, "origin identity:            %s\n", origin.Identity())
	return nil
}

func stageGenesisFile(path string, data []byte) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return "", err
	}
	name := file.Name()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

// defaultFullShardConfPath is where the full shard configuration goes when --full-shard-conf is not
// given: beside --out, named after it. The flag is defaulted rather than required so every existing
// caller keeps working, while the artifact the next unit needs is always emitted.
func defaultFullShardConfPath(out string) string {
	ext := filepath.Ext(out)
	return strings.TrimSuffix(out, ext) + "-full-shard-conf.json"
}

// engineAPIGenesisSource returns the standard genesis JSON to prepare from: the operator's file when
// --alloc-source is given, otherwise this command's own template.
//
// The template-shaping flags and --alloc-source are mutually exclusive rather than merged. Both the
// file and a flag would name the same genesis field (gasLimit is even required by the source), and
// silently letting one win is exactly the ambiguity the operator cannot see afterwards.
func engineAPIGenesisSource(flags *engineAPIGenesisFlags, changed func(string) bool, chainID uint64) ([]byte, error) {
	if flags.Manifest != "" {
		if flags.AllocSource != "" {
			return nil, fmt.Errorf("--manifest and --alloc-source are mutually exclusive")
		}
		for _, name := range []string{"gas-limit", "coinbase", "extra-data"} {
			if changed(name) {
				return nil, fmt.Errorf("--manifest %q and --%s both specify genesis fields; the manifest is authoritative, so this refuses rather than silently picking a winner", flags.Manifest, name)
			}
		}
		data, err := os.ReadFile(flags.Manifest) // #nosec G304 -- operator-supplied config path, same trust level as --shard-conf
		if err != nil {
			return nil, fmt.Errorf("reading --manifest %q: %w", flags.Manifest, err)
		}
		compiled, err := registrygenesis.CompileAllocationManifest(data, chainID)
		if err != nil {
			return nil, fmt.Errorf("compiling --manifest %q: %w", flags.Manifest, err)
		}
		return compiled, nil
	}
	if flags.AllocSource != "" {
		for _, name := range []string{"gas-limit", "coinbase", "extra-data"} {
			if changed(name) {
				return nil, fmt.Errorf("--alloc-source %q and --%s both specify genesis fields; the source file is authoritative, so this refuses rather than silently picking a winner", flags.AllocSource, name)
			}
		}
		data, err := os.ReadFile(flags.AllocSource) // #nosec G304 -- operator-supplied config path, same trust level as --shard-conf
		if err != nil {
			return nil, fmt.Errorf("reading --alloc-source %q: %w", flags.AllocSource, err)
		}
		return data, nil
	}

	template := gethGenesis{
		Config: gethChainConfig{
			ChainID:                       chainID,
			HomesteadBlock:                0,
			EIP150Block:                   0,
			EIP155Block:                   0,
			EIP158Block:                   0,
			ByzantiumBlock:                0,
			ConstantinopleBlock:           0,
			PetersburgBlock:               0,
			IstanbulBlock:                 0,
			BerlinBlock:                   0,
			LondonBlock:                   0,
			MergeNetsplitBlock:            0,
			ShanghaiTime:                  0,
			CancunTime:                    0,
			TerminalTotalDifficulty:       0,
			TerminalTotalDifficultyPassed: true,
		},
		Nonce:      "0x0",
		Timestamp:  "0x0",
		ExtraData:  flags.ExtraData,
		GasLimit:   fmt.Sprintf("0x%x", flags.GasLimit),
		Difficulty: "0x0",
		MixHash:    "0x0000000000000000000000000000000000000000000000000000000000000000",
		Coinbase:   flags.Coinbase,
		Alloc:      map[string]string{},
		BaseFee:    "0x3b9aca00", // 1 gwei — a starting point; EIP-1559 adjusts it from here
	}
	data, err := json.MarshalIndent(template, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding the genesis template: %w", err)
	}
	return data, nil
}
