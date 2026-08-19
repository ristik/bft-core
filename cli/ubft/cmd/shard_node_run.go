package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ainvaltin/httpsrv"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
)

const lucStoreFileName = "shard-node-luc.json"

type shardNodeRunFlags struct {
	*baseFlags
	keyConfFlags
	trustBaseFlags
	shardConfFlags
	p2pFlags

	Executor string // "fake" or "engine-api"

	// engine-api executor only — see engineapi.Config.
	EngineURL string
	EthURL    string
	JWTSecret string

	LUCStoreFile string

	HandshakeNodes    int
	CertNodes         int
	HeartbeatInterval time.Duration
	InactivityTimeout time.Duration

	RPCServerAddress string // exposes /api/v1/metrics and /api/v1/health when set
}

func shardNodeRunCmd(baseFlags *baseFlags) *cobra.Command {
	flags := &shardNodeRunFlags{baseFlags: baseFlags}
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run a shard node",
		Long: `Run a shard node: an Engine API adapter or other executor, certifying state-root
transitions against the BFT Core root chain. See docs/shard-protocol.md for the round
protocol and docs/engine-api-adapter-plan.md for how this command's pieces fit together.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return shardNodeRun(cmd.Context(), flags)
		},
	}

	flags.addKeyConfFlags(cmd, false)
	flags.addTrustBaseFlags(cmd)
	flags.addShardConfFlags(cmd, false)
	flags.addP2PFlags(cmd)

	cmd.Flags().StringVar(&flags.Executor, "executor", "fake",
		"which Executor to run: \"fake\" (deterministic in-memory, no external process) or \"engine-api\" (drives an Ethereum execution client)")
	cmd.Flags().StringVar(&flags.EngineURL, "engine-url", "http://127.0.0.1:8551",
		"engine-api executor only: URL of the execution client's authenticated Engine API endpoint")
	cmd.Flags().StringVar(&flags.EthURL, "eth-url", "http://127.0.0.1:8545",
		"engine-api executor only: URL of the execution client's plain eth_* JSON-RPC endpoint")
	cmd.Flags().StringVar(&flags.JWTSecret, "jwt-secret", "",
		"engine-api executor only: path to the 32-byte hex JWT secret shared with the execution client (default: $UBFT_HOME/jwt.hex)")
	cmd.Flags().StringVar(&flags.LUCStoreFile, "luc-store", "",
		fmt.Sprintf("path to the last-certificate store, for restart recovery (default: %s)", filepath.Join("$UBFT_HOME", lucStoreFileName)))
	cmd.Flags().IntVar(&flags.HandshakeNodes, "handshake-nodes", shardnode.DefaultBFTClientOptions.HandshakeNodes, "number of root nodes to handshake with")
	cmd.Flags().IntVar(&flags.CertNodes, "cert-nodes", shardnode.DefaultBFTClientOptions.CertNodes, "number of root nodes to submit each certification request to")
	cmd.Flags().DurationVar(&flags.HeartbeatInterval, "heartbeat-interval", shardnode.DefaultBFTClientOptions.HeartbeatInterval, "how often to check for root-chain inactivity")
	cmd.Flags().DurationVar(&flags.InactivityTimeout, "inactivity-timeout", shardnode.DefaultBFTClientOptions.InactivityTimeout, "re-handshake if no certificate has been received for this long")
	cmd.Flags().StringVar(&flags.RPCServerAddress, "rpc-server-address", "",
		`address for the metrics/health HTTP server, in the form "host:port". Not started if empty.`)

	return cmd
}

func shardNodeRun(ctx context.Context, flags *shardNodeRunFlags) error {
	keyConf, err := flags.loadKeyConf(flags.baseFlags, false)
	if err != nil {
		return fmt.Errorf("loading key configuration: %w", err)
	}
	signer, err := keyConf.Signer()
	if err != nil {
		return fmt.Errorf("creating signer: %w", err)
	}
	authKeyPair, err := keyConf.AuthKeyPair()
	if err != nil {
		return fmt.Errorf("creating auth key pair: %w", err)
	}

	shardConfs, err := flags.loadShardConfs(flags.baseFlags)
	if err != nil {
		return fmt.Errorf("loading shard configuration: %w", err)
	}
	if len(shardConfs) != 1 {
		return fmt.Errorf("shard-node run requires exactly one --shard-conf, got %d", len(shardConfs))
	}
	shardConf := shardConfs[0]

	trustBases, err := flags.loadTrustBases(flags.baseFlags)
	if err != nil {
		return fmt.Errorf("loading trust base: %w", err)
	}
	if len(trustBases) != 1 {
		return fmt.Errorf("shard-node run requires exactly one --trust-base, got %d", len(trustBases))
	}
	trustBaseStore, err := shardnode.NewFileTrustBaseStore(trustBases[0], flags.observe.Logger())
	if err != nil {
		return fmt.Errorf("creating trust base store: %w", err)
	}

	bootNodes, err := getBootStrapNodes(flags.BootstrapAddresses)
	if err != nil {
		return fmt.Errorf("boot nodes parameter error: %w", err)
	}
	bootstrapConnectRetry := &network.BootstrapConnectRetry{
		Count: flags.BootstrapConnectRetryCount,
		Delay: flags.BootstrapConnectRetryDelay,
	}
	peerConf, err := network.NewPeerConfiguration(flags.Address, flags.AnnounceAddresses, authKeyPair, bootNodes, bootstrapConnectRetry)
	if err != nil {
		return fmt.Errorf("creating peer configuration: %w", err)
	}
	peer, err := network.NewPeer(ctx, peerConf, flags.observe.Logger(), flags.observe.PrometheusRegisterer())
	if err != nil {
		return fmt.Errorf("creating peer: %w", err)
	}

	shardNet, err := network.NewShardNetwork(peer, flags.observe, network.DefaultShardNetworkOptions)
	if err != nil {
		return fmt.Errorf("creating shard network: %w", err)
	}

	executor, err := buildExecutor(ctx, flags)
	if err != nil {
		return err
	}

	disseminator, err := buildDisseminator(peer, flags.observe, shardConf.Validators)
	if err != nil {
		return fmt.Errorf("creating dissemination transport: %w", err)
	}

	lucStorePath := flags.PathWithDefault(flags.LUCStoreFile, lucStoreFileName)
	store := shardnode.NewFileStore(lucStorePath)

	node, err := shardnode.New(
		peer,
		shardNet,
		signer,
		shardConf.PartitionID,
		shardConf.ShardID,
		trustBaseStore,
		executor,
		disseminator,
		store,
		flags.observe.Logger(),
		shardnode.BFTClientOptions{
			HandshakeNodes:    flags.HandshakeNodes,
			CertNodes:         flags.CertNodes,
			HeartbeatInterval: flags.HeartbeatInterval,
			InactivityTimeout: flags.InactivityTimeout,
		},
	)
	if err != nil {
		return fmt.Errorf("creating shard node: %w", err)
	}

	metrics, err := shardnode.NewMetrics(flags.observe.Meter("shardnode"))
	if err != nil {
		return fmt.Errorf("creating metrics: %w", err)
	}
	node.SetMetrics(metrics)

	if err := peer.BootstrapConnect(ctx, flags.observe.Logger()); err != nil {
		return fmt.Errorf("bootstrap connect: %w", err)
	}

	flags.observe.Logger().Info("shard node starting",
		"nodeID", peer.ID().String(), "partitionID", shardConf.PartitionID, "executor", flags.Executor)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return node.Run(gctx) })
	g.Go(func() error { return serveShardNodeRPC(gctx, flags, node) })
	return g.Wait()
}

// serveShardNodeRPC exposes /api/v1/metrics (Prometheus, when --metrics
// prometheus is set) and /api/v1/health (JSON, always) — see
// docs/engine-api-adapter-plan.md C3.2/C3.4. Mirrors root_node.go's own
// RPC server construction.
func serveShardNodeRPC(ctx context.Context, flags *shardNodeRunFlags, node *shardnode.Node) error {
	if flags.RPCServerAddress == "" {
		return nil // do not kill the errgroup
	}

	mux := http.NewServeMux()
	if pr := flags.observe.PrometheusRegisterer(); pr != nil {
		mux.Handle("/api/v1/metrics", promhttp.HandlerFor(pr.(prometheus.Gatherer), promhttp.HandlerOpts{MaxRequestsInFlight: 1}))
	}
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(node.Health().Snapshot())
	})

	return httpsrv.Run(ctx,
		&http.Server{
			Addr:              flags.RPCServerAddress,
			Handler:           mux,
			ReadTimeout:       3 * time.Second,
			ReadHeaderTimeout: time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       30 * time.Second,
		})
}

// buildDisseminator picks the transport based on how many validators the
// shard conf actually names. One validator (the common single-node dev
// case, and A2/A3's own test topology) needs nothing over the network —
// LoopbackDisseminator costs nothing and is never called. Two or more means
// a real multi-validator shard (C2), which needs NetDisseminator's actual
// libp2p connection to the others.
func buildDisseminator(p *network.Peer, obs Observability, validators []*types.NodeInfo) (shardnode.Disseminator, error) {
	selfID := p.ID().String()
	var peers []peer.ID
	for _, v := range validators {
		if v.NodeID == selfID {
			continue
		}
		id, err := peer.Decode(v.NodeID)
		if err != nil {
			return nil, fmt.Errorf("invalid validator node id %q in shard conf: %w", v.NodeID, err)
		}
		peers = append(peers, id)
	}
	if len(peers) == 0 {
		return shardnode.NewLoopbackDisseminator(), nil
	}
	return shardnode.NewNetDisseminator(p, obs, peers)
}

func buildExecutor(ctx context.Context, flags *shardNodeRunFlags) (shardnode.Executor, error) {
	switch flags.Executor {
	case "fake":
		return executortest.New(), nil

	case "engine-api":
		jwtPath := flags.PathWithDefault(flags.JWTSecret, "jwt.hex")
		hexStr, err := os.ReadFile(jwtPath) // #nosec G304 -- operator-supplied config path, same trust level as keys.json
		if err != nil {
			return nil, fmt.Errorf("reading JWT secret %q: %w", jwtPath, err)
		}
		secret, err := engineapi.ParseSecret(string(hexStr))
		if err != nil {
			return nil, fmt.Errorf("parsing JWT secret %q: %w", jwtPath, err)
		}

		adapter := engineapi.NewAdapter(engineapi.Config{
			EngineURL: flags.EngineURL,
			EthURL:    flags.EthURL,
			Secret:    secret,
		}, flags.observe.Logger())

		// Fail closed at startup rather than on the first round — see
		// docs/adr/0001-executor-boundary.md decision 3: capability
		// exchange alone doesn't guarantee the chain spec's fork schedule
		// matches what this adapter speaks, but it does catch the more
		// basic "wrong URL, wrong JWT, wrong reth build" failures before
		// they show up as a mysteriously stalled first round.
		if err := adapter.CheckCapabilities(ctx); err != nil {
			return nil, fmt.Errorf("engine-api executor failed its startup capability check: %w", err)
		}
		return adapter, nil

	default:
		return nil, fmt.Errorf("unknown --executor %q, expected \"fake\" or \"engine-api\"", flags.Executor)
	}
}
