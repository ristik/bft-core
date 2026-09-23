package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier"
)

// doctorCheck is one preflight check. Framework checks apply to any shard
// node; adapter checks are contributed by whichever executor is selected —
// see docs/engine-api-adapter-plan.md §8: if a check can't be assigned to
// one side or the other, the interface is wrong. Splitting them here is
// itself a test of that boundary, not just a display grouping.
type doctorCheck struct {
	name string
	run  func(ctx context.Context) (ok bool, detail string, fix string)
}

type shardNodeDoctorFlags struct {
	*baseFlags
	keyConfFlags
	trustBaseFlags
	shardConfFlags
	p2pFlags

	Executor  string
	EngineURL string
	EthURL    string
	JWTSecret string

	DialTimeout time.Duration
}

func shardNodeDoctorCmd(baseFlags *baseFlags) *cobra.Command {
	flags := &shardNodeDoctorFlags{baseFlags: baseFlags}
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Preflight checks for a shard node — catches the silent-stall class before it happens",
		Long: `Runs the same checks that, left unchecked, tend to produce the identical symptom:
rounds stop certifying and the logs show repeat UCs. See docs/engine-api-adapter-plan.md §8.

Framework checks always run. Adapter checks run only for --executor engine-api, since
they're specific to what that executor needs (an Engine API endpoint to reach).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return shardNodeDoctor(cmd.Context(), flags)
		},
	}
	flags.addKeyConfFlags(cmd, false)
	flags.addTrustBaseFlags(cmd)
	flags.addShardConfFlags(cmd, false)
	flags.addP2PFlags(cmd)
	cmd.Flags().StringVar(&flags.Executor, "executor", "fake", "which executor this node runs — adapter checks only run for \"engine-api\"")
	cmd.Flags().StringVar(&flags.EngineURL, "engine-url", "http://127.0.0.1:8551", "engine-api executor only: Engine API endpoint")
	cmd.Flags().StringVar(&flags.EthURL, "eth-url", "http://127.0.0.1:8545", "engine-api executor only: eth_* endpoint")
	cmd.Flags().StringVar(&flags.JWTSecret, "jwt-secret", "", "engine-api executor only: path to the JWT secret (default: $UBFT_HOME/jwt.hex)")
	cmd.Flags().DurationVar(&flags.DialTimeout, "dial-timeout", 5*time.Second, "timeout for network-reachability checks")
	return cmd
}

func shardNodeDoctor(ctx context.Context, flags *shardNodeDoctorFlags) error {
	checks := frameworkChecks(flags)
	if flags.Executor == "engine-api" {
		checks = append(checks, adapterChecks(flags)...)
	}

	failed := 0
	for _, c := range checks {
		checkCtx, cancel := context.WithTimeout(ctx, flags.DialTimeout)
		ok, detail, fix := c.run(checkCtx)
		cancel()

		status := "PASS"
		if !ok {
			status = "FAIL"
			failed++
		}
		fmt.Printf("[%s] %-22s %s\n", status, c.name, detail)
		if !ok && fix != "" {
			fmt.Printf("       fix: %s\n", fix)
		}
	}

	fmt.Println()
	if failed > 0 {
		return fmt.Errorf("%d of %d checks failed", failed, len(checks))
	}
	fmt.Printf("all %d checks passed\n", len(checks))
	return nil
}

func frameworkChecks(flags *shardNodeDoctorFlags) []doctorCheck {
	return []doctorCheck{
		{
			name: "identity",
			run: func(ctx context.Context) (bool, string, string) {
				keyConf, err := flags.loadKeyConf(flags.baseFlags, false)
				if err != nil {
					return false, err.Error(), "run 'ubft shard-node init -g' to generate keys.json"
				}
				nodeID, err := keyConf.NodeID()
				if err != nil {
					return false, err.Error(), ""
				}
				shardConf, err := loadOneShardConf(flags)
				if err != nil {
					return false, err.Error(), ""
				}
				for _, v := range shardConf.Validators {
					if v.NodeID == nodeID.String() {
						return true, fmt.Sprintf("%s is in the shard's validator list", nodeID), ""
					}
				}
				return false, fmt.Sprintf("%s is NOT in the shard conf's validator list", nodeID),
					"regenerate the shard conf with this node's node-info.json included, or check --key-conf points at the right keys"
			},
		},
		{
			name: "trust base",
			run: func(ctx context.Context) (bool, string, string) {
				trustBases, err := flags.loadTrustBases(flags.baseFlags)
				if err != nil {
					return false, err.Error(), "check --trust-base points at a valid trust-base.json"
				}
				if len(trustBases) != 1 {
					return false, fmt.Sprintf("expected exactly one trust base, got %d", len(trustBases)), ""
				}
				tb := trustBases[0]
				shardConf, err := loadOneShardConf(flags)
				if err != nil {
					return false, err.Error(), ""
				}
				if tb.GetNetworkID() != shardConf.NetworkID {
					return false, fmt.Sprintf("trust base network id %d != shard conf network id %d", tb.GetNetworkID(), shardConf.NetworkID),
						"the trust base and shard conf were generated for different networks — regenerate one of them"
				}
				return true, fmt.Sprintf("epoch %d, %d root node(s), network id %d", tb.GetEpoch(), len(tb.GetRootNodes()), tb.GetNetworkID()), ""
			},
		},
		{
			name: "root reachability",
			run: func(ctx context.Context) (bool, string, string) {
				bootNodes, err := getBootStrapNodes(flags.BootstrapAddresses)
				if err != nil {
					return false, err.Error(), ""
				}
				if len(bootNodes) == 0 {
					return false, "no --bootnodes given", "pass at least one root node's multiaddress via --bootnodes so this node can find the root chain"
				}
				keyConf, err := flags.loadKeyConf(flags.baseFlags, false)
				if err != nil {
					return false, err.Error(), ""
				}
				authKeyPair, err := keyConf.AuthKeyPair()
				if err != nil {
					return false, err.Error(), ""
				}
				peerConf, err := network.NewPeerConfiguration("/ip4/127.0.0.1/tcp/0", nil, authKeyPair, bootNodes, &network.BootstrapConnectRetry{Count: 1, Delay: 1})
				if err != nil {
					return false, err.Error(), ""
				}
				p, err := network.NewPeer(ctx, peerConf, flags.observe.Logger(), nil)
				if err != nil {
					return false, err.Error(), ""
				}
				defer func() { _ = p.Close() }()
				if err := p.BootstrapConnect(ctx, flags.observe.Logger()); err != nil {
					return false, err.Error(), "check the root node is running and --bootnodes has the right address and peer id"
				}
				return true, fmt.Sprintf("dialed %d bootstrap node(s)", len(bootNodes)), ""
			},
		},
		{
			name: "timing sanity",
			run: func(ctx context.Context) (bool, string, string) {
				shardConf, err := loadOneShardConf(flags)
				if err != nil {
					return false, err.Error(), ""
				}
				margin := shardConf.T2Timeout - consensus.BlockRate*time.Millisecond
				if margin <= 0 {
					return false, fmt.Sprintf("T2 (%s) does not exceed the root block rate (%dms)", shardConf.T2Timeout, consensus.BlockRate),
						"regenerate the shard conf with a larger --t2-timeout"
				}
				return true, fmt.Sprintf("T2=%s, root block rate=%dms, margin=%s", shardConf.T2Timeout, consensus.BlockRate, margin), ""
			},
		},
	}
}

func adapterChecks(flags *shardNodeDoctorFlags) []doctorCheck {
	newAdapter := func() (*engineapi.Adapter, error) {
		secret, err := loadJWTSecret(flags)
		if err != nil {
			return nil, err
		}
		adapter := engineapi.NewAdapter(engineapi.Config{EngineURL: flags.EngineURL, EthURL: flags.EthURL, Secret: secret}, nil)
		adapter.RequireSealCapabilities()
		return adapter, nil
	}

	return []doctorCheck{
		{
			name: "engine link",
			run: func(ctx context.Context) (bool, string, string) {
				a, err := newAdapter()
				if err != nil {
					return false, err.Error(), ""
				}
				if err := a.CheckCapabilities(ctx); err != nil {
					return false, err.Error(), "check --engine-url and --jwt-secret point at a running execution client's authenticated endpoint"
				}
				return true, fmt.Sprintf("reachable at %s with the required seal capability set", flags.EngineURL), ""
			},
		},
		{
			name: "chain identity",
			run: func(ctx context.Context) (bool, string, string) {
				shardConf, err := loadOneShardConf(flags)
				if err != nil {
					return false, err.Error(), ""
				}
				wantChainID, ok := zkverifier.ParseChainIDFromParams(shardConf.PartitionParams)
				if !ok {
					return false, "shard conf has no chain_id partition param", ""
				}
				// Deliberately the same Adapter.CheckChainID that `shard-node run` enforces at
				// startup, so doctor cannot drift from what the node actually refuses to start
				// on — and called exactly ONCE.
				//
				// An earlier version queried eth_chainId itself for the report text and then
				// called CheckChainID, which queries again. Two requests can disagree: if the
				// second failed for any reason, doctor printed a mismatch message built from the
				// first response — reporting a chain-id mismatch even when the ids were equal.
				// The check's own error is now the report, so what doctor says and what the node
				// enforces cannot diverge (issue #89 item 4).
				a, err := newAdapter()
				if err != nil {
					return false, err.Error(), ""
				}
				if err := a.CheckChainID(ctx, wantChainID); err != nil {
					return false, err.Error(),
						"the wrong reth instance, a genesis.json generated for a different shard conf, " +
							"or --eth-url not pointing at a running execution client's plain RPC endpoint"
				}
				return true, fmt.Sprintf("chainId=%d, matches shard conf", wantChainID), ""
			},
		},
		{
			name: "genesis hash",
			run: func(ctx context.Context) (bool, string, string) {
				// The same Adapter.CheckEndpointsPaired that `shard-node run` enforces, so
				// doctor cannot drift from what the node refuses to start on. It reads block 0
				// over BOTH configured connections and requires them to agree, which is what
				// catches --engine-url and --eth-url addressing different execution clients
				// (issue #89 item 3).
				a, err := newAdapter()
				if err != nil {
					return false, err.Error(), ""
				}
				//
				// The reported hash is the one the check itself agreed on, not the result of a
				// third query. Re-reading for the report text is how #89 item 4's bug worked:
				// two requests can disagree, and a report built from a later one can describe a
				// state the check never saw.
				genesis, err := a.CheckEndpointsPaired(ctx)
				if err != nil {
					return false, err.Error(),
						"--engine-url and --eth-url must address the same execution client, and both must be reachable"
				}
				return true, fmt.Sprintf("block 0 hash=0x%x, agreed by both endpoints — compare this across every validator by hand; doctor runs per-node and cannot do that comparison itself", genesis), ""
			},
		},
		{
			name: "execution profile",
			run: func(ctx context.Context) (bool, string, string) {
				// The same Adapter.CheckExecutionProfile that `shard-node run` enforces, called
				// once, and the reported fork id is the one that call validated.
				shardConf, err := loadOneShardConf(flags)
				if err != nil {
					return false, err.Error(), ""
				}
				wantChainID, ok := zkverifier.ParseChainIDFromParams(shardConf.PartitionParams)
				if !ok {
					return false, "shard conf has no chain_id partition param", ""
				}
				a, err := newAdapter()
				if err != nil {
					return false, err.Error(), ""
				}
				profile, err := a.CheckExecutionProfile(ctx, wantChainID)
				if err != nil {
					return false, err.Error(),
						"start the execution client from a genesis.json generated by `ubft engine-api genesis`, unedited; " +
							"--eth-url must expose the eth namespace, which serves eth_config"
				}
				return true, fmt.Sprintf("%s (eth_config forkId=%s, read over --eth-url)", engineapi.PinnedProfileName, profile.ForkID), ""
			},
		},
	}
}

func loadOneShardConf(flags *shardNodeDoctorFlags) (*types.PartitionDescriptionRecord, error) {
	shardConfs, err := flags.loadShardConfs(flags.baseFlags)
	if err != nil {
		return nil, fmt.Errorf("loading shard conf: %w", err)
	}
	if len(shardConfs) != 1 {
		return nil, fmt.Errorf("expected exactly one --shard-conf, got %d", len(shardConfs))
	}
	return shardConfs[0], nil
}

func loadJWTSecret(flags *shardNodeDoctorFlags) (engineapi.Secret, error) {
	jwtPath := flags.PathWithDefault(flags.JWTSecret, "jwt.hex")
	data, err := os.ReadFile(jwtPath) // #nosec G304 -- operator-supplied config path, same trust level as keys.json
	if err != nil {
		return engineapi.Secret{}, fmt.Errorf("reading JWT secret %q: %w", jwtPath, err)
	}
	return engineapi.ParseSecret(strings.TrimSpace(string(data)))
}
