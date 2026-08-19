package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

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
}

func newEngineAPICmd(baseFlags *baseFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "engine-api",
		Short: "Tools for the Engine API executor",
	}
	cmd.AddCommand(engineAPIGenesisCmd(baseFlags))
	return cmd
}

func engineAPIGenesisCmd(baseFlags *baseFlags) *cobra.Command {
	flags := &engineAPIGenesisFlags{baseFlags: baseFlags}
	cmd := &cobra.Command{
		Use:   "genesis",
		Short: "Generate a reth-compatible genesis.json derived from a shard conf",
		Long: `Generate a reth-compatible genesis.json whose chainId is taken directly from the
shard conf's "chain_id" partition param, so the two files can never drift apart — see
docs/adr/0001-executor-boundary.md decision 3.

Schedules Shanghai and Cancun at genesis (timestamp 0) and deliberately leaves every fork
after Cancun (Prague, Osaka, ...) out of the schedule entirely, matching the exact V3
Engine API method set this adapter speaks. Scheduling every fork at 0 would activate
post-Cancun consensus rules the moment reth's own defaults decide they apply, silently
requiring engine_newPayloadV4+ this adapter does not implement.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return engineAPIGenesis(flags)
		},
	}
	flags.addShardConfFlags(cmd, false)
	cmd.Flags().StringVar(&flags.Out, "out", "", "output path for the generated genesis.json (required)")
	cmd.Flags().Uint64Var(&flags.GasLimit, "gas-limit", defaultGasLimit,
		"per-block gas limit — a starting point, not a validated operational limit (see docs/engine-api-adapter-plan.md §8)")
	cmd.Flags().StringVar(&flags.Coinbase, "coinbase", "0x0000000000000000000000000000000000000000",
		"genesis coinbase address")
	cmd.Flags().StringVar(&flags.ExtraData, "extra-data", "0x", "genesis extraData, as a 0x-prefixed hex string")
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

func engineAPIGenesis(flags *engineAPIGenesisFlags) error {
	shardConfs, err := flags.loadShardConfs(flags.baseFlags)
	if err != nil {
		return fmt.Errorf("loading shard conf: %w", err)
	}
	if len(shardConfs) != 1 {
		return fmt.Errorf("engine-api genesis requires exactly one --shard-conf, got %d", len(shardConfs))
	}
	shardConf := shardConfs[0]

	chainID, ok := zkverifier.ParseChainIDFromParams(shardConf.PartitionParams)
	if !ok {
		return fmt.Errorf("shard conf has no chain_id partition param — set --partition-params chain_id=<id> when generating it")
	}

	genesis := gethGenesis{
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

	// Written directly with json.MarshalIndent rather than this CLI's usual
	// util.WriteJsonFile helper: that helper is for bft-core's own CBOR+JSON
	// dual-tagged types, and reth's genesis format is neither — a plain
	// struct with its own field-presence rules is clearer here.
	data, err := json.MarshalIndent(genesis, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding genesis: %w", err)
	}
	if err := os.WriteFile(flags.Out, data, 0600); err != nil { // #nosec G306 -- matches util.WriteJsonFile's own mode
		return fmt.Errorf("writing %q: %w", flags.Out, err)
	}
	fmt.Printf("wrote %s (chainId=%d, shanghai+cancun at genesis, gasLimit=%d)\n", flags.Out, chainID, flags.GasLimit)
	return nil
}
