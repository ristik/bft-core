package cmd

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/ainvaltin/httpsrv"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/logger"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/observability"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3delivery"
	"github.com/unicitynetwork/bft-core/recordsfeed"
	"github.com/unicitynetwork/bft-core/rootchain"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontiertransport"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-core/rootchain/poswitness"
	"github.com/unicitynetwork/bft-core/rootrecords"
	"github.com/unicitynetwork/bft-core/trustactivation"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
)

const (
	rootDBFileName             = "rootchain.db"
	trustBaseDBFileName        = "trustbase.db"
	orchestrationDBFileName    = "orchestration.db"
	rootTrustHistoryDBFileName = "root-trust-history.db"
	defaultNetworkTimeout      = 300 * time.Millisecond
)

type (
	rootNodeRunFlags struct {
		*baseFlags
		keyConfFlags
		trustBaseFlags
		shardConfFlags
		p2pFlags

		RootDBFile            string // path to Bolt storage file
		TrustBaseDBFile       string
		OrchestrationDBFile   string
		GenesisIdentitiesFile string
		PosDeploymentFile     string
		TrustHistoryDBFile    string
		Profile2              bool
		InstallHandoffEpoch   uint64
		Q3Lane                bool // the Q3 acceptance lane: a verified Q3 history, the install journal and the V3 handoff pipeline
		Q3JournalDBFile       string

		BlockRate        uint32
		MaxRequests      uint   // certification request channel capacity
		RPCServerAddress string // address on which http server is exposed with metrics endpoint
	}
)

func newRootNodeCmd(baseFlags *baseFlags) *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "root-node",
		Short: "Tools to run a root node",
	}

	cmd.AddCommand(rootNodeInitCmd(baseFlags))
	cmd.AddCommand(rootNodeRunCmd(baseFlags))
	return cmd
}

func rootNodeInitCmd(baseFlags *baseFlags) *cobra.Command {
	// Currently root node init is the same as shard node init
	flags := &shardNodeInitFlags{baseFlags: baseFlags}

	var cmd = &cobra.Command{
		Use:   "init",
		Short: "Generate node keys and a public node info file",
		RunE: func(cmd *cobra.Command, args []string) error {
			return shardNodeInit(cmd.Context(), flags)
		},
	}

	flags.addKeyConfFlags(cmd, true)
	return cmd
}

func rootNodeRunCmd(baseFlags *baseFlags) *cobra.Command {
	flags := &rootNodeRunFlags{baseFlags: baseFlags}
	var cmd = &cobra.Command{
		Use:   "run",
		Short: "Run a node",
		RunE: func(cmd *cobra.Command, args []string) error {
			return rootNodeRun(cmd.Context(), flags)
		},
	}

	flags.addKeyConfFlags(cmd, false)
	flags.addTrustBaseFlags(cmd)
	flags.addShardConfFlags(cmd, true)
	flags.addP2PFlags(cmd)

	cmd.Flags().UintVar(&flags.MaxRequests, "max-requests", 1000, "request buffer capacity")
	cmd.Flags().StringVar(&flags.RPCServerAddress, "rpc-server-address", "",
		`Specifies the TCP address for the RPC server to listen on, in the form "host:port". RPC server isn't initialised if address is empty.`)

	cmd.Flags().StringVar(&flags.RootDBFile, "root-db", "",
		fmt.Sprintf("path to the root database (default: %s)", filepath.Join("$UBFT_HOME", rootDBFileName)))
	cmd.Flags().StringVar(&flags.TrustBaseDBFile, "trust-base-db", "",
		fmt.Sprintf("path to the trust base database (default: %s)", filepath.Join("$UBFT_HOME", trustBaseDBFileName)))
	cmd.Flags().StringVar(&flags.GenesisIdentitiesFile, "genesis-identities", "",
		"proof-of-authority genesis: JSON identity records of the genesis committee of the coupled EVM shard (`ubft genesis-identities generate`), recorded once as the incumbent baseline that the first coupled handoff's authorization names as K; a different set than the recorded one is refused")
	cmd.Flags().StringVar(&flags.PosDeploymentFile, "pos-deployment", "",
		"proof-of-stake: JSON pinning the custody deployment (networkWord, chainId, custody). Turns on the P85 control executor and the mandatory CloseLiability duty (profile 2 only); refused together with --genesis-identities")
	cmd.Flags().StringVar(&flags.OrchestrationDBFile, "orchestration-db", "",
		fmt.Sprintf("path to the orchestration database (default: %s)", filepath.Join("$UBFT_HOME", orchestrationDBFileName)))
	cmd.Flags().BoolVar(&flags.Profile2, "profile-2", false, "run the version-2 root handoff network profile")
	cmd.Flags().Uint64Var(&flags.InstallHandoffEpoch, "install-handoff-epoch", 0, "fetch and verify this successor epoch before starting profile-2 consensus")
	cmd.Flags().BoolVar(&flags.Q3Lane, "q3-lane", false, "run the Q3 acceptance lane: verified Q3 history, install journal and V3 handoffs (requires --profile-2)")
	cmd.Flags().StringVar(&flags.Q3JournalDBFile, "q3-journal-db", "",
		fmt.Sprintf("Q3 install journal database (default: %s)", filepath.Join("$UBFT_HOME", q3JournalDBFileName)))
	cmd.Flags().StringVar(&flags.TrustHistoryDBFile, "trust-history-db", "",
		fmt.Sprintf("profile-2 trust history database (default: %s)", filepath.Join("$UBFT_HOME", rootTrustHistoryDBFileName)))

	cmd.Flags().Uint32Var(&flags.BlockRate, "block-rate", consensus.BlockRate, "block rate (consensus parameter)")

	hideFlags(cmd, "block-rate", "q3-lane", "q3-journal-db")
	return cmd
}

func getBootStrapNodes(bootNodesStr []string) ([]peer.AddrInfo, error) {
	bootNodes := make([]peer.AddrInfo, len(bootNodesStr))
	for i, str := range bootNodesStr {
		addrInfo, err := peer.AddrInfoFromString(str)
		if err != nil {
			return nil, fmt.Errorf("invalid bootstrap node parameter: %w", err)
		}
		bootNodes[i] = *addrInfo
	}
	return bootNodes, nil
}

func rootNodeRun(ctx context.Context, flags *rootNodeRunFlags) error {
	keyConf, err := flags.loadKeyConf(flags.baseFlags, false)
	if err != nil {
		return err
	}

	nodeID, err := keyConf.NodeID()
	if err != nil {
		return fmt.Errorf("failed to calculate nodeID: %w", err)
	}
	log := flags.observe.Logger().With(logger.NodeID(nodeID))
	obs := observability.WithLogger(flags.observe, log)

	host, err := createHost(ctx, keyConf, flags, obs)
	if err != nil {
		return fmt.Errorf("creating host: %w", err)
	}
	partitionNet, err := network.NewLibP2PRootChainNetwork(host, flags.MaxRequests, defaultNetworkTimeout, obs)
	if err != nil {
		return fmt.Errorf("partition network initialization failed: %w", err)
	}

	rootStore, err := storage.NewBoltStorage(flags.PathWithDefault(flags.RootDBFile, rootDBFileName))
	if err != nil {
		return err
	}

	trustBases, err := flags.loadTrustBases(flags.baseFlags)
	if err != nil {
		return err
	}

	trustBaseDB, err := flags.initDB(flags.TrustBaseDBFile, trustBaseDBFileName)
	if err != nil {
		return err
	}
	trustBaseStore, err := trustbase.NewTrustBaseStore(trustBaseDB, log)
	if err != nil {
		return err
	}

	for _, trustBase := range trustBases {
		if err := trustBaseStore.Store(trustBase); err != nil {
			if !errors.Is(err, trustbase.ErrAlreadyExists) {
				return fmt.Errorf("failed to store trust base: %w", err)
			}
			log.Warn(fmt.Sprintf("trust base already exists for epoch %d, not overwriting it", trustBase.Epoch))
		}
	}

	trustBase, err := trustBaseStore.LoadFirst()
	if err != nil {
		return err
	}

	orchestrationStorePath := flags.PathWithDefault(flags.OrchestrationDBFile, orchestrationDBFileName)
	orchestration, err := partitions.NewOrchestration(trustBase.GetNetworkID(), orchestrationStorePath, log)
	if err != nil {
		return fmt.Errorf("creating orchestration: %w", err)
	}

	shardConfs, err := flags.loadShardConfs(flags.baseFlags)
	if err != nil {
		return fmt.Errorf("failed to load shard confs: %w", err)
	}
	if err := loadShardConfs(orchestration, flags.Profile2, shardConfs); err != nil {
		return err
	}
	if flags.GenesisIdentitiesFile != "" {
		if err := seedGenesisIdentities(orchestration, trustBase, shardConfs, flags.GenesisIdentitiesFile); err != nil {
			return fmt.Errorf("recording the genesis committee identities: %w", err)
		}
	}

	signer, err := keyConf.Signer()
	if err != nil {
		return err
	}

	libp2pNet, err := network.NewLibP2RootConsensusNetwork(host, flags.MaxRequests, defaultNetworkTimeout, obs)
	if err != nil {
		return fmt.Errorf("failed initiate root network, %w", err)
	}
	// a build without the q4shim tag returns the network itself
	rootNet, stopShim, err := wrapRootNet(ctx, libp2pNet, host.ID(), signer, trustBaseStore.SigningConfig, log)
	if err != nil {
		return err
	}
	defer stopShim()

	consensusParams := consensus.NewConsensusParams()
	consensusParams.BlockRate = time.Duration(flags.BlockRate) * time.Millisecond
	var options []consensus.Option
	if flags.Q3Lane && !flags.Profile2 {
		return errors.New("q3-lane requires profile 2")
	}
	var q3rt *q3active.Runtime
	if flags.Q3Lane {
		journalDB, openErr := flags.initDB(flags.Q3JournalDBFile, q3JournalDBFileName)
		if openErr != nil {
			return openErr
		}
		if closer, ok := journalDB.(io.Closer); ok {
			defer closer.Close()
		}
		if q3rt, err = newRootQ3Runtime(journalDB, trustBase); err != nil {
			return err
		}
		// the first trust base is the pinned genesis the verified history is rooted in; the store accepts a V3 epoch's projection only
		// for a configuration that history holds
		if err = trustBaseStore.BindSigningAuthority(q3rt); err != nil {
			return fmt.Errorf("q3 runtime: %w", err)
		}
		options = append(options, consensus.WithQ3(q3rt))
	}
	if flags.Profile2 {
		consensusParams.NetworkProfileVersion = storage.ProfileHandoff
		rootHistoryDB, openErr := flags.initDB(flags.TrustHistoryDBFile, rootTrustHistoryDBFileName)
		if openErr != nil {
			return openErr
		}
		if closer, ok := rootHistoryDB.(io.Closer); ok {
			defer closer.Close()
		}
		anchorHash, hashErr := trustBase.Hash(crypto.SHA256)
		if hashErr != nil {
			return hashErr
		}
		identity := sha256.Sum256(append([]byte("unicity/root-profile-2/history/1"), anchorHash...))
		history, openErr := trusthistorystore.Open(ctx, rootHistoryDB, trustBase, identity, trustactivation.Verifier{Signing: trustBaseStore.SigningConfig})
		if openErr != nil {
			return fmt.Errorf("opening root profile-2 history: %w", openErr)
		}
		options = append(options, consensus.WithRecoveryProfile2(history))
	}

	// The root serves the automatic bootstrap-freshness protocol (F6f, #350) in default
	// startup. A trust base outside its fixed profile cannot serve it: say so and run
	// without, so replacement shard validators stay unready rather than the root failing.
	frontierServing := false
	if profileErr := consensus.ValidateFrontierProfile(trustBase); profileErr != nil {
		log.Warn("root frontier service disabled: the trust base is outside the bootstrap-freshness profile", "error", profileErr)
	} else if signerErr := consensus.ValidateFrontierSigner(trustBase, nodeID.String(), signer); signerErr != nil {
		// A root that joined at a successor epoch is not in the first trust base the service is pinned to.
		log.Warn("root frontier service disabled: this root cannot sign under the pinned trust base", "error", signerErr)
	} else {
		frontierServing = true
		options = append(options, consensus.WithFrontierSampler(consensus.DefaultFrontierSamplerConfig(trustBase)), consensus.WithFrontierSigning())
	}

	if flags.PosDeploymentFile != "" {
		// the witnesses of a block's controls are fetched by hash from the other root nodes before the block is executed
		options = append(options, consensus.WithWitnessFetcher(func(ctx context.Context, hash [32]byte, peers []peer.ID, maxBytes int) ([]byte, error) {
			return poswitness.Fetch(ctx, poswitness.FromLibp2p(host), peers, hash, maxBytes)
		}))
	}
	cm, err := consensus.NewConsensusManager(
		host.ID(),
		trustBaseStore,
		orchestration,
		rootNet,
		signer,
		rootStore,
		obs,
		append(options, consensus.WithConsensusParams(*consensusParams))...,
	)
	if err != nil {
		return fmt.Errorf("failed initiate distributed consensus manager: %w", err)
	}
	if flags.PosDeploymentFile != "" {
		if !flags.Profile2 {
			return fmt.Errorf("%w: --pos-deployment needs --profile-2", ErrPosDeployment)
		}
		if err = enablePosClosure(cm, orchestration, trustBaseStore, trustBase, shardConfs, flags.PosDeploymentFile, flags.GenesisIdentitiesFile != ""); err != nil {
			return err
		}
		stopWitnesses := serveWitnesses(host, cm)
		defer stopWitnesses()
	}
	if q3rt != nil {
		if err = attachRootQ3(ctx, q3rt, cm); err != nil {
			return err
		}
		server, srvErr := q3delivery.NewServer(q3BundleProvider{cm: cm, rt: q3rt})
		if srvErr != nil {
			return srvErr
		}
		server.Register(host)
	}
	if frontierServing {
		stopFrontier, serveErr := serveRootFrontier(ctx, log, host, cm, shardConfs)
		if serveErr != nil {
			return serveErr
		}
		defer stopFrontier()
	}
	if flags.Profile2 {
		stopRecords, recErr := serveRootRecords(log, host, cm, shardConfs)
		if recErr != nil {
			return recErr
		}
		defer stopRecords()
	}
	if flags.Profile2 {
		server, err := handoffdelivery.NewServer(cm)
		if err != nil {
			return err
		}
		server.Register(host)
	}
	if err = host.BootstrapConnect(ctx, log); err != nil {
		return err
	}
	if flags.InstallHandoffEpoch != 0 {
		if !flags.Profile2 || flags.InstallHandoffEpoch < 2 {
			return fmt.Errorf("install-handoff-epoch requires profile 2 and epoch >= 2")
		}
		if flags.InstallHandoffEpoch < cm.InstalledRootEpoch() {
			return fmt.Errorf("requested handoff epoch %d is older than installed epoch %d", flags.InstallHandoffEpoch, cm.InstalledRootEpoch())
		}
		peers, err := getBootStrapNodes(flags.BootstrapAddresses)
		if err != nil {
			return err
		}
		if q3rt != nil {
			if err := installQ3Epochs(ctx, host, peers, q3rt, cm, flags.InstallHandoffEpoch); err != nil {
				return err
			}
		}
		for epoch := cm.InstalledRootEpoch() + 1; q3rt == nil && epoch <= flags.InstallHandoffEpoch; epoch++ {
			bundle, fetchErr := fetchFromRootPeers(peers, func(id peer.ID) (handoffdelivery.Bundle, error) {
				return handoffdelivery.Request(ctx, host, id, epoch)
			})
			if fetchErr != nil {
				return fmt.Errorf("no root peer served verified handoff epoch %d: %w", epoch, fetchErr)
			}
			if _, installErr := cm.InstallEpochBundle(bundle); installErr != nil {
				return fmt.Errorf("install handoff epoch %d: %w", epoch, installErr)
			}
		}
	}

	if q3rt != nil {
		// after the activations this process installed: a root that installs epoch 2 at this very start holds its first activation only now
		if err = selectRootQ3RequestHistory(q3rt, cm, orchestration, uint64(trustBase.GetNetworkID())); err != nil {
			return err
		}
	}

	node, err := rootchain.New(
		host,
		partitionNet,
		cm,
		obs,
	)
	if err != nil {
		return fmt.Errorf("failed initiate root node: %w", err)
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return node.Run(ctx) })

	g.Go(func() error {
		if flags.RPCServerAddress == "" {
			return nil // do not kill the group!
		}

		mux := http.NewServeMux()
		if pr := flags.observe.PrometheusRegisterer(); pr != nil {
			mux.Handle("/api/v1/metrics", promhttp.HandlerFor(pr.(prometheus.Gatherer), promhttp.HandlerOpts{MaxRequestsInFlight: 1}))
		}
		mux.HandleFunc("PUT /api/v1/configurations", configurationsHandler(flags.Profile2, orchestration.AddShardConfig))
		mux.HandleFunc("PUT /api/v1/trustbases", putTrustBaseHandler(trustBaseStore.Store))
		mux.HandleFunc("GET /api/v1/trustbases", getTrustBaseHandler(trustBaseStore, obs))
		mux.HandleFunc("GET /api/v1/roundInfo", getRoundInfoHandler(cm.GetState, obs))
		if flags.Profile2 {
			mux.HandleFunc("POST /api/v1/handoff/plan", rootHandoffPlanHandler(cm))
			mux.HandleFunc("POST /api/v1/handoff/intent", rootHandoffIntentHandler(cm))
			mux.HandleFunc("POST /api/v1/handoff/endorse", rootHandoffEndorseHandler(cm))
			mux.HandleFunc("POST /api/v1/handoff/evm-assignment/context", rootHandoffEVMContextHandler(cm))
			if q3rt != nil {
				mux.HandleFunc("POST /api/v1/handoff/q3-candidate", rootQ3CandidateHandler(cm))
				mux.HandleFunc("POST /api/v1/handoff/q3-stage", rootQ3StageHandler(cm))
				rootQ3API{Status: cm.Q3Status, Rt: q3rt, Bundle: q3BundleProvider{cm: cm, rt: q3rt}.Q3Bundle, State: cm.GetState,
					Trust: func(epoch uint64) (*types.RootTrustBaseV1, error) { return trustBaseStore.GetByEpoch(epoch) }}.register(mux)
			}
			if flags.PosDeploymentFile != "" {
				mux.HandleFunc("POST /api/v1/pos/control", rootPosControlHandler(cm))
			}
			mux.HandleFunc("POST /api/v1/handoff/abort", rootHandoffAbortHandler(cm))
			mux.HandleFunc("POST /api/v1/handoff/abort/status", rootHandoffAbortStatusHandler(cm))
		}
		return httpsrv.Run(ctx,
			&http.Server{
				Addr:              flags.RPCServerAddress,
				Handler:           mux,
				ReadTimeout:       3 * time.Second,
				ReadHeaderTimeout: time.Second,
				WriteTimeout:      5 * time.Second,
				IdleTimeout:       30 * time.Second,
			})
	})

	return g.Wait()
}

func createHost(ctx context.Context, keyConf *KeyConf, flags *rootNodeRunFlags, obs Observability) (*network.Peer, error) {
	bootNodes, err := getBootStrapNodes(flags.BootstrapAddresses)
	if err != nil {
		return nil, fmt.Errorf("boot nodes parameter error: %w", err)
	}
	authKeyPair, err := keyConf.AuthKeyPair()
	if err != nil {
		return nil, fmt.Errorf("invalid authentication key: %w", err)
	}
	bootstrapConnectRetry := &network.BootstrapConnectRetry{
		Count: flags.BootstrapConnectRetryCount,
		Delay: flags.BootstrapConnectRetryDelay,
	}
	peerConf, err := network.NewPeerConfiguration(flags.Address, flags.AnnounceAddresses, authKeyPair, bootNodes, bootstrapConnectRetry)
	if err != nil {
		return nil, err
	}
	return network.NewPeer(ctx, peerConf, obs.Logger(), obs.PrometheusRegisterer())
}

type TrustBasesResponse struct {
	_          struct{} `cbor:",toarray"`
	TrustBases []*types.RootTrustBaseV1
}

func getTrustBaseHandler(trustBaseStore *trustbase.TrustBaseStore, obs Observability) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// return trust base records for the epochs from <epoch1> to <epoch2>, inclusively.
		// Both parameters are optional and default to the latest epoch.
		// parameters are uint64 (0 value is not allowed by business rules)
		lastTrustBase, err := trustBaseStore.LoadLast()
		if err != nil {
			obs.Logger().Error(fmt.Sprintf("GET trustbases request: failed to load latest active epoch: %v", err))
			http.Error(w, "failed to load latest trust base", http.StatusInternalServerError)
			return
		}

		epoch1, epoch2, err := validateQueryParams(r, lastTrustBase.Epoch)
		if err != nil {
			obs.Logger().Warn(fmt.Sprintf("GET trustbases request: %v", err))
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		trustBases, err := fetchTrustBases(trustBaseStore, epoch1, epoch2)
		if err != nil {
			obs.Logger().Warn(fmt.Sprintf("GET trustbases request: %v", err))
			http.Error(w, "failed to load trust base", http.StatusInternalServerError)
			return
		}

		result := &TrustBasesResponse{TrustBases: trustBases}
		if err := writeCborResponse(w, result); err != nil {
			obs.Logger().Error(fmt.Sprintf("failed to write response: %v", err))
		}
	}
}

func fetchTrustBases(store *trustbase.TrustBaseStore, epoch1, epoch2 uint64) ([]*types.RootTrustBaseV1, error) {
	var trustBases []*types.RootTrustBaseV1
	for i := epoch1; i <= epoch2; i++ {
		tb, err := store.GetByEpoch(i)
		if err != nil {
			return nil, fmt.Errorf("failed to load trust base for epoch %d: %w", i, err)
		}
		trustBases = append(trustBases, tb)
	}
	return trustBases, nil
}

func writeCborResponse(w http.ResponseWriter, response any) error {
	w.Header().Set("Content-Type", "application/cbor")
	encoder, err := types.Cbor.GetEncoder(w)
	if err != nil {
		return fmt.Errorf("failed to create cbor encoder: %w", err)
	}
	if err := encoder.Encode(response); err != nil {
		return fmt.Errorf("failed to encode response: %w", err)
	}
	return nil
}

func validateQueryParams(r *http.Request, lastEpoch uint64) (uint64, uint64, error) {
	q := r.URL.Query()

	epoch1, err := parseUint64WithDefault(q, "from", lastEpoch)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse from query param: %v", err)
	}
	epoch2, err := parseUint64WithDefault(q, "to", lastEpoch)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse to query param: %v", err)
	}

	if epoch1 == 0 || epoch2 == 0 {
		return 0, 0, fmt.Errorf("from and to should be greater than 0")
	}
	if epoch1 > epoch2 {
		return 0, 0, fmt.Errorf("to must be greater than or equal to from")
	}
	if epoch1 > lastEpoch || epoch2 > lastEpoch {
		return 0, 0, fmt.Errorf("from and to cannot be greater than latest epoch")
	}
	return epoch1, epoch2, nil
}

func parseUint64WithDefault(q url.Values, key string, defaultValue uint64) (uint64, error) {
	valStr := q.Get(key)
	if valStr == "" {
		return defaultValue, nil
	}

	v, err := strconv.ParseUint(valStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", key, err)
	}

	return v, nil
}

func putTrustBaseHandler(addTrustBaseFn func(trustBase types.RootTrustBase) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		trustBase, err := parseTrustBase(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "parsing request body: %v", err)
			return
		}

		if err := addTrustBaseFn(trustBase); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "registering trust base: %v", err)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

// configurationsHandler serves PUT /api/v1/configurations. Under the unified (handoff) profile it refuses every write:
// configurations are ordered by root consensus in the handoff and rebuilt from committed history, never written per node.
func configurationsHandler(handoffProfile bool, add func(*types.PartitionDescriptionRecord) error) http.HandlerFunc {
	if handoffProfile {
		return func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "shard configurations change only through a committed root handoff", http.StatusForbidden)
		}
	}
	return putShardConfigHandler(add)
}

func putShardConfigHandler(addShardConfFn func(shardConf *types.PartitionDescriptionRecord) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		shardConf, err := parseShardConf(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "parsing request body: %v", err)
			return
		}

		if err := addShardConfFn(shardConf); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "registering shard conf: %v", err)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func parseTrustBase(r io.ReadCloser) (types.RootTrustBase, error) {
	defer r.Close()
	var trustBase *types.RootTrustBaseV1
	if err := json.NewDecoder(r).Decode(&trustBase); err != nil {
		return nil, fmt.Errorf("decoding trust base json: %w", err)
	}
	return trustBase, nil
}

func parseShardConf(r io.ReadCloser) (*types.PartitionDescriptionRecord, error) {
	defer r.Close()
	var shardConf *types.PartitionDescriptionRecord
	if err := json.NewDecoder(r).Decode(&shardConf); err != nil {
		return nil, fmt.Errorf("decoding shard conf json: %w", err)
	}
	return shardConf, nil
}

type (
	shardInfo struct {
		PartitionID types.PartitionID `json:"partitionId"`
		ShardID     types.ShardID     `json:"shardId"`
		RoundNumber uint64            `json:"roundNumber,string"`
		EpochNumber uint64            `json:"epochNumber,string"`
		TRRound     uint64            `json:"trRound,string"`
		TRLeader    string            `json:"trLeader"`
		StateRoot   string            `json:"stateRoot"`
	}
	roundInfoResponse struct {
		RoundNumber     uint64      `json:"roundNumber,string"`
		EpochNumber     uint64      `json:"epochNumber,string"`
		PartitionShards []shardInfo `json:"partitionShards"`
	}
)

func getRoundInfoHandler(getState func() (*abdrc.StateMsg, error), obs Observability) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := getState()
		if err != nil {
			obs.Logger().Warn(fmt.Sprintf("GET roundInfo request: failed to load state: %v", err))
			http.Error(w, "failed to load state", http.StatusInternalServerError)
			return
		}

		partitionShards := make([]shardInfo, 0, len(state.CommittedHead.ShardInfo))
		for _, si := range state.CommittedHead.ShardInfo {
			partitionShards = append(partitionShards, shardInfo{
				PartitionID: si.Partition,
				ShardID:     si.Shard,
				RoundNumber: si.IR.RoundNumber,
				EpochNumber: si.IR.Epoch,
				TRRound:     si.IRTR.Round,
				TRLeader:    si.IRTR.Leader,
				StateRoot:   "0x" + hex.EncodeToString(si.IR.Hash),
			})
		}
		response := roundInfoResponse{
			RoundNumber:     state.CommittedHead.Block.Round,
			EpochNumber:     state.CommittedHead.Block.Epoch,
			PartitionShards: partitionShards,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			obs.Logger().Warn(fmt.Sprintf("GET roundInfo request: failed to write response: %v", err))
		}
	}
}

// loadShardConfs installs the locally configured shard configurations. Under the handoff profile the profile's guards
// must already be on: they are the only thing refusing a local EVM entry that differs from the stored genesis one (a
// wrong-key file would otherwise silently replace the history every derived assignment extends).
func loadShardConfs(orchestration *partitions.Orchestration, handoffProfile bool, shardConfs []*types.PartitionDescriptionRecord) error {
	if handoffProfile {
		orchestration.EnableHandoffProfile()
		// Atomically: into an empty orchestration the genesis set; afterwards only an identical reload.
		if err := orchestration.InitGenesisShardConfigs(shardConfs...); err != nil {
			return fmt.Errorf("failed to load the genesis shard confs: %w", err)
		}
		return nil
	}
	for _, shardConf := range shardConfs {
		if err := orchestration.AddShardConfig(shardConf); err != nil {
			return fmt.Errorf("failed to add shard conf for partition: %d, %w", shardConf.PartitionID, err)
		}
	}
	return nil
}

// frontierEligiblePeers is the distinct set of shard validators allowed to query the root's frontier service.
func frontierEligiblePeers(shardConfs []*types.PartitionDescriptionRecord) ([]peer.ID, error) {
	seen := map[peer.ID]struct{}{}
	var eligible []peer.ID
	for _, conf := range shardConfs {
		for _, v := range conf.Validators {
			id, err := peer.Decode(v.NodeID)
			if err != nil {
				return nil, fmt.Errorf("frontier service: shard validator %q is not a peer ID: %w", v.NodeID, err)
			}
			if _, dup := seen[id]; !dup {
				seen[id] = struct{}{}
				eligible = append(eligible, id)
			}
		}
	}
	return eligible, nil
}

// serveRootFrontier registers the root-bootstrap frontier and cut protocols for the validators of
// the shards this root was configured with. The eligible set is fixed when the root starts: a shard
// configuration added later through the RPC server is served after the next restart.
func serveRootFrontier(ctx context.Context, log *slog.Logger, host *network.Peer, cm *consensus.ConsensusManager, shardConfs []*types.PartitionDescriptionRecord) (func(), error) {
	limits := consensus.DefaultFrontierServerLimits()
	eligible, err := frontierEligiblePeers(shardConfs)
	if err != nil {
		return nil, err
	}
	if len(eligible) == 0 || len(eligible) > limits.MaxEligiblePeers {
		log.Warn("root frontier service disabled: the configured shards have no usable validator set", "validators", len(eligible))
		return func() {}, nil
	}
	handlers, err := cm.FrontierHandlers()
	if err != nil {
		return nil, err
	}
	server, err := frontiertransport.NewServer(ctx, eligible, limits, handlers)
	if err != nil {
		return nil, fmt.Errorf("frontier service: %w", err)
	}
	host.RegisterProtocolHandler(frontiertransport.FrontierProtocolID, server.FrontierHandler)
	host.RegisterProtocolHandler(frontiertransport.CutProtocolID, server.CutHandler)
	log.Info("root frontier service enabled", "validators", len(eligible))
	return func() {
		host.RemoveProtocolHandler(frontiertransport.FrontierProtocolID)
		host.RemoveProtocolHandler(frontiertransport.CutProtocolID)
		server.Close()
	}, nil
}

// serveWitnesses serves the retained control witnesses to the other root nodes of the current trust base.
func serveWitnesses(host *network.Peer, cm *consensus.ConsensusManager) func() {
	server := poswitness.NewServer(cm, func(id peer.ID) bool { return slices.Contains(cm.Validators(), id) })
	host.RegisterProtocolHandler(poswitness.ProtocolID, server.Handler)
	return func() { host.RemoveProtocolHandler(poswitness.ProtocolID) }
}

// rootRecordFetcher fetches source-log records from the other roots of the current trust base, in the order the trust base lists them.
type rootRecordFetcher struct {
	host *network.Peer
	cm   *consensus.ConsensusManager
}

func (f rootRecordFetcher) Records(ctx context.Context, from uint64, max int) ([]rootrecords.Record, error) {
	var others []peer.ID
	for _, id := range f.cm.Validators() {
		if id != f.host.ID() {
			others = append(others, id)
		}
	}
	return recordsfeed.P2PRemote{Opener: recordsfeed.FromLibp2p(f.host), Roots: others}.Records(ctx, from, max)
}

// recordsSource adapts the consensus manager to the records feed's server.
type recordsSource struct{ cm *consensus.ConsensusManager }

func (s recordsSource) ControlCut(key recordsfeed.CutKey) (recordsfeed.Cut, error) {
	cut, err := s.cm.ControlCut(storage.CutKey{Network: key.Network, Epoch: key.Epoch, Round: key.Round, TreeRoot: key.TreeRoot})
	if err != nil {
		return recordsfeed.Cut{}, err
	}
	return recordsfeed.Cut{Control: cut.Control, Path: cut.Path}, nil
}

func (s recordsSource) Records(from uint64, max int) ([]rootrecords.Record, error) {
	return s.cm.Records(from, max)
}

// serveRootRecords serves the root's source-log cuts and records to the validators of the shards this root was configured with. The
// shard pairs an EVM with the root and derives the next prefix of the log from them, verifying everything against the unicity tree
// root of its certificate, so the service needs no trust in the node it asks.
func serveRootRecords(log *slog.Logger, host *network.Peer, cm *consensus.ConsensusManager, shardConfs []*types.PartitionDescriptionRecord) (func(), error) {
	eligible, err := frontierEligiblePeers(shardConfs)
	if err != nil {
		return nil, err
	}
	if len(eligible) == 0 {
		log.Warn("the configured shards have no usable validator set: the records feed serves the other roots only")
	}
	allowed := make(map[peer.ID]struct{}, len(eligible))
	for _, id := range eligible {
		allowed[id] = struct{}{}
	}
	// The other roots of the trust base are served too: a root that installs an epoch checkpoint without the source log it commits
	// fetches the missing prefix from them (storage.BlockStore.SetRecordFetcher), verifying every record against the checkpoint.
	server := recordsfeed.NewServer(recordsSource{cm}, func(id peer.ID) bool {
		if _, ok := allowed[id]; ok {
			return true
		}
		return slices.Contains(cm.Validators(), id)
	})
	host.RegisterProtocolHandler(recordsfeed.ProtocolID, server.Handler)
	cm.SetRecordFetcher(rootRecordFetcher{host: host, cm: cm})
	log.Info("root records feed enabled", "validators", len(eligible))
	return func() { host.RemoveProtocolHandler(recordsfeed.ProtocolID) }, nil
}
