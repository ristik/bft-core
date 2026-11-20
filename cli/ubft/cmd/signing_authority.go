package cmd

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/unicitynetwork/bft-core/vrrules"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"

	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/signingauthority/service"
	"github.com/unicitynetwork/bft-core/vrschema"
)

/*
The signing authority commands (#105, docs/design/f6c-signing-state-contract.md).

`run` is the authority process. The other commands are the operator's control plane, and reach the
authority only through its operator socket with the operator credential. None of them reads or
writes a signing key: the authority generates its key when it starts, and nothing here can supply,
export or restore one.
*/

func newSigningAuthorityCmd(baseFlags *baseFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signing-authority",
		Short: "Run and operate an independent signing authority for one shard validator (#105)",
		Long: `A signing authority holds one shard validator's signing key and signs that validator's
certification requests under a record that refuses a second, different request for a round it has
already reserved. The shard node reaches it over a Unix socket with a client credential, and holds
no signing key itself.

The key is generated when the authority starts and exists only in its memory. There is no key import,
export or backup. Stopping the authority, for any reason, loses the key: a restarted authority has a
different key, which the existing shard configuration does not name, and returning that validator
to service needs a separately authorized configuration. Run it outside the shard node's backup,
snapshot and process-cloning domains (design §3).

Deployment order:
  1. signing-authority credential --out operator.cred
  2. signing-authority run ...                        (the enrollment is pending)
  3. signing-authority node-info --out authority-node-info.json
  4. shard-conf generate --node-info authority-node-info.json ...   (and register it with the root chain)
  5. signing-authority complete-enrollment --shard-conf shard-conf.json
  6. signing-authority replace-session --out client.cred
  7. shard-node run ... --signing-authority-socket client.sock --signing-authority-credential client.cred`,
	}
	cmd.AddCommand(signingAuthorityRunCmd(baseFlags))
	cmd.AddCommand(signingAuthorityCredentialCmd(baseFlags))
	cmd.AddCommand(signingAuthorityNodeInfoCmd(baseFlags))
	cmd.AddCommand(signingAuthorityCompleteEnrollmentCmd(baseFlags))
	cmd.AddCommand(signingAuthorityAdvanceEpochCmd(baseFlags))
	cmd.AddCommand(signingAuthorityAdvanceWithProofCmd(baseFlags))
	cmd.AddCommand(signingAuthorityReplaceSessionCmd(baseFlags))
	cmd.AddCommand(signingAuthorityStatusCmd(baseFlags))
	cmd.AddCommand(signingAuthorityRegistrationPolicyCmd(baseFlags))
	cmd.AddCommand(signingAuthorityPosPolicyCmd(baseFlags))
	return cmd
}

type signingAuthorityRunFlags struct {
	*baseFlags
	trustBaseFlags

	ActivationSourceURL  string
	VRGeneration         bool
	FenceProvisionFile   string
	B1Profile            string
	ExecutionGenesisHash string
	VRNetworkWord        string
	VRRegistryCodeHash   string
	ClientSocket         string
	OperatorSocket       string
	OperatorCredential   string
	// the automated root member's narrow channel: the handoff possession proof only (VT-09); both or neither
	PoPSocket     string
	PoPCredential string
	// MetricsAddress, when set, serves the authority's read-only status gauges (unicity_authority_*) as Prometheus metrics on a loopback address
	MetricsAddress string

	// the registrations this authority may sign (VT-10); empty: none
	RegistrationPolicy string
	// the P85 election this authority may sign possession proofs for (#1216); empty: pinned later by `signing-authority pos-policy`, or never
	PosPolicies []string
	// RequirePosPolicy refuses every P85 possession signature until the pin is set (the production profile: give --pos-policy at startup)
	RequirePosPolicy bool
	// LatePosPolicy lets `signing-authority pos-policy` pin the election on the running authority: development only
	LatePosPolicy bool

	AuthorityID string
	NodeID      string
	NetworkID   uint16
	PartitionID uint32
	ShardID     string
	ShardEpoch  uint64
	RootEpoch   uint64

	// the lineage pin of the proof-verified advance (#1085)
	LineageGenesis   string
	LineageUTB       bool
	UncheckedAdvance bool
}

func signingAuthorityRunCmd(baseFlags *baseFlags) *cobra.Command {
	flags := &signingAuthorityRunFlags{baseFlags: baseFlags}
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run a signing authority: generate its key and serve the client and operator sockets",
		Long: `Start an authority for one validator. The enrollment named by the flags is fixed for the
process lifetime, except the shard configuration, which cannot name the authority's key until the
key exists: the authority starts pending and admits no client until complete-enrollment.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return signingAuthorityRun(cmd.Context(), flags)
		},
	}
	flags.addTrustBaseFlags(cmd)
	cmd.Flags().StringVar(&flags.ClientSocket, "client-socket", "", "Unix socket the shard node connects to; its directory is restricted to the owner")
	cmd.Flags().StringVar(&flags.OperatorSocket, "operator-socket", "", "Unix socket for the operator commands; its directory is restricted to the owner")
	cmd.Flags().StringVar(&flags.OperatorCredential, "operator-credential", "", "path to the operator credential (see `signing-authority credential`)")
	cmd.Flags().StringVar(&flags.PoPSocket, "pop-socket", "", "Unix socket of the automated root member (`root-node run --vr-evm-authority-socket`): it serves the handoff possession proof and nothing else; with --pop-credential")
	cmd.Flags().StringVar(&flags.PoPCredential, "pop-credential", "", "path to the member's credential (see `signing-authority credential`); a credential of its own, not the operator's. The root process must run as the authority's uid to reach the socket (its directory is 0700), so keep the operator credential file unreadable by the root process: the member credential is then the only thing it can use")
	cmd.Flags().StringVar(&flags.MetricsAddress, "metrics-address", "", "serve the authority's read-only status (enrolled, faulted, retired, session, signatures, epochs) as Prometheus metrics (unicity_authority_*) on this loopback host:port; no key, request or response bytes are in it. Off by default")
	cmd.Flags().StringVar(&flags.RegistrationPolicy, "registration-policy", "", "JSON file pinning the VR deployment and listing the registrations this authority may sign for its EVM key (VT-10): without it the authority signs none. Fixed for the authority's lifetime")
	cmd.Flags().StringArrayVar(&flags.PosPolicies, "pos-policy", nil, "JSON file pinning the P85 election (network word, chain id, ElectionPolicy address) and the identity ids this authority's EVM key may sign possession proofs for (#1216): without a pin the authority signs no P85 assignment possession. Fixed for the authority's lifetime; `signing-authority pos-policy` pins it once on a running authority")
	cmd.Flags().BoolVar(&flags.RequirePosPolicy, "require-pos-policy", false, "refuse every P85 possession signature (election, delegation, assignment) until the P85 pin is set; with --pos-policy the pin is fixed from startup")
	cmd.Flags().BoolVar(&flags.LatePosPolicy, "dev-allow-late-pos-policy", false, "DEVELOPMENT ONLY: let `signing-authority pos-policy` pin the P85 election on this running authority. The pin then comes from the operator credential that also asks for signatures, so it restricts nothing against a compromised credential; production gives --pos-policy at startup")
	cmd.Flags().StringVar(&flags.ActivationSourceURL, "activation-source-url", "", activationSourceUsage)
	cmd.Flags().BoolVar(&flags.VRGeneration, "vr-generation", false, "force the VR-generation requirements (it cannot disable them): a b1 profile with the VR measurement, or a VR registration/P85 policy, already requires --activation-source-url and the generation pins, and the authority refuses to start without them")
	cmd.Flags().StringVar(&flags.FenceProvisionFile, "fence-provision-file", "", "on a VR generation whose fence inputs are not known at start (the authority is started first to provide its key): start in the pre-genesis enrollment mode, signing and advancing nothing, and enable signing when this JSON file {b1Profile, activationSourceUrl, executionGenesisHash} appears. Provision the genesis hash from the generation's own genesis artifacts, not from the endpoint it checks")
	cmd.Flags().StringVar(&flags.B1Profile, "b1-profile", "", "the deployment's b1 profile (as the shard node's): on a VR generation it supplies the registry code hash pin and makes the activation fence mandatory")
	cmd.Flags().StringVar(&flags.ExecutionGenesisHash, "execution-genesis-hash", "", "0x-prefixed hash of the deployment's execution genesis block: the generation the activation source must be (mandatory on a VR generation)")
	cmd.Flags().StringVar(&flags.VRNetworkWord, "vr-network-word", "", "optional 0x-prefixed VR network word the activation source's registry must report")
	cmd.Flags().StringVar(&flags.VRRegistryCodeHash, "vr-registry-code-hash", "", "0x-prefixed runtime code hash of the pinned VR core (the b1 profile's VR measurement) that the activation source's registry must have")
	cmd.Flags().StringVar(&flags.AuthorityID, "authority-id", "", "operator-assigned name for this authority lifetime, for diagnostics")
	cmd.Flags().StringVar(&flags.NodeID, "node-id", "", "the shard validator this authority signs for (`ubft node-id` on the shard node's key configuration)")
	cmd.Flags().Uint16Var(&flags.NetworkID, "network-id", 0, "network identifier")
	cmd.Flags().Uint32Var(&flags.PartitionID, "partition-id", 0, "partition identifier")
	cmd.Flags().StringVar(&flags.ShardID, "shard-id", "0x80", "the shard id in hex format with 0x prefix")
	cmd.Flags().Uint64Var(&flags.ShardEpoch, "shard-epoch", 0, "the shard configuration epoch this authority signs for; a later epoch is refused, not followed")
	cmd.Flags().Uint64Var(&flags.RootEpoch, "root-epoch", 0, "the root trust epoch this authority signs for; a later epoch is refused, not followed")
	cmd.Flags().StringVar(&flags.LineageGenesis, "lineage-genesis-trust-base", "", "the deployment's genesis root trust base (epoch 1): the pin this "+
		"authority verifies every activation from (advance-with-proof). Without it the authority advances only by the operator-trusted advance-epoch")
	cmd.Flags().BoolVar(&flags.LineageUTB, "lineage-utb-genesis", false, "with --lineage-genesis-trust-base: the chain is a UTB chain (its genesis epoch endorses the signed trust-base entry)")
	cmd.Flags().BoolVar(&flags.UncheckedAdvance, "recovery-unchecked-advance", false, "with --lineage-genesis-trust-base: also admit the operator-trusted "+
		"advance-epoch, a recovery policy (it installs the operator's trust and configuration with structural checks only)")
	for _, name := range []string{"client-socket", "operator-socket", "operator-credential", "authority-id", "node-id", "network-id", "partition-id", "shard-epoch", "root-epoch", "trust-base"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}
	return cmd
}

func signingAuthorityRun(ctx context.Context, flags *signingAuthorityRunFlags) error {
	log := flags.observe.Logger()
	operatorCredential, err := readCredentialFile(flags.OperatorCredential)
	if err != nil {
		return fmt.Errorf("loading the operator credential: %w", err)
	}
	if (flags.PoPSocket == "") != (flags.PoPCredential == "") {
		return errors.New("--pop-socket and --pop-credential go together")
	}
	var popCredential []byte
	if flags.PoPCredential != "" {
		if popCredential, err = readCredentialFile(flags.PoPCredential); err != nil {
			return fmt.Errorf("loading the possession-proof credential: %w", err)
		}
	}
	trustBases, err := flags.loadTrustBases(flags.baseFlags)
	if err != nil {
		return fmt.Errorf("loading trust base: %w", err)
	}
	if len(trustBases) != 1 {
		return fmt.Errorf("signing-authority run requires exactly one --trust-base, got %d", len(trustBases))
	}
	tb := trustBases[0]
	// Both are enrollment context the authority freezes. A trust base that does not match them would
	// refuse every certificate later; saying so now is the same outcome with a useful message.
	if tb.GetNetworkID() != types.NetworkID(flags.NetworkID) {
		return fmt.Errorf("the trust base is for network %d, the authority is enrolled for %d", tb.GetNetworkID(), flags.NetworkID)
	}
	if tb.GetEpoch() != flags.RootEpoch {
		return fmt.Errorf("the trust base is for root epoch %d, the authority is enrolled for %d", tb.GetEpoch(), flags.RootEpoch)
	}
	trust, err := shardnode.NewFileTrustBaseStore(tb, log)
	if err != nil {
		return fmt.Errorf("creating trust base store: %w", err)
	}
	shardID := types.ShardID{}
	if err := shardID.UnmarshalText([]byte(flags.ShardID)); err != nil {
		return fmt.Errorf("failed to parse shard id: %w", err)
	}

	opts, err := flags.lineageOptions(log)
	if err != nil {
		return err
	}
	var policyNetwork *[32]byte // the VR network word the registration policy pins: the generation this authority belongs to
	if flags.RegistrationPolicy != "" {
		policy, err := readRegistrationPolicy(flags.RegistrationPolicy)
		if err != nil {
			return err
		}
		opts = append(opts, signingauthority.WithRegistrationPolicy(policy))
		nw := [32]byte(policy.Deployment.Network)
		policyNetwork = &nw
	}
	if len(flags.PosPolicies) > 1 {
		return fmt.Errorf("--pos-policy is given once: %d policies named", len(flags.PosPolicies))
	}
	if len(flags.PosPolicies) == 1 {
		pin, err := readPosPolicy(flags.PosPolicies[0])
		if err != nil {
			return err
		}
		opts = append(opts, signingauthority.WithPosPolicy(pin))
	}
	if flags.LatePosPolicy {
		opts = append(opts, signingauthority.WithLatePosPolicy())
	}
	if flags.RequirePosPolicy {
		opts = append(opts, signingauthority.WithRequirePosPolicy())
	}
	// Whether this deployment is a VR generation comes from trusted enrollment data, never from an opt-in: the enrolled b1 profile carries
	// the VR hook measurement (as the shard node's does), or the authority is given a VR registration policy (not a P85 --pos-policy). On a VR generation the
	// fence is mandatory and the authority refuses to start without its activation source and generation pins. --vr-generation can only add
	// to that (it cannot disable it).
	fenceGen := vrFence{VR: flags.VRGeneration || flags.RegistrationPolicy != ""} // never from --pos-policy: that also pins the standalone P85 election of a pre-VR generation
	if flags.B1Profile != "" {
		_, pf, perr := readB1ProfileFile(flags.B1Profile)
		if perr != nil {
			return fmt.Errorf("loading the b1 profile: %w", perr)
		}
		if pf.VRHookMeasurement != nil {
			fenceGen.VR = true
			fenceGen.CodeHash = &pf.VRHookMeasurement.RegistryCodeHash
		}
	}
	if flags.VRRegistryCodeHash != "" {
		if fenceGen.CodeHash, err = parseCodeHash(flags.VRRegistryCodeHash); err != nil {
			return err
		}
	}
	if flags.ExecutionGenesisHash != "" {
		if fenceGen.GenesisHash, err = parseCodeHash(flags.ExecutionGenesisHash); err != nil {
			return err
		}
	}
	if flags.VRNetworkWord != "" {
		if fenceGen.NetworkWord, err = parseCodeHash(flags.VRNetworkWord); err != nil {
			return err
		}
	}
	if fenceGen.NetworkWord == nil {
		fenceGen.NetworkWord = policyNetwork
	}
	if fenceGen.VR && flags.LineageGenesis == "" {
		// the schedule for an epoch is decided from the checkpoint of the activation proof the authority verifies itself: an authority that
		// advances on the operator's word alone has no authenticated evidence for the epochs it installs
		return fmt.Errorf("%w: a VR generation advances by advance-with-proof, so --lineage-genesis-trust-base is mandatory", errVRFenceRequired)
	}
	// On a VR generation whose fence inputs are not known yet (the authority is started to provide its key, from which the shard
	// configuration and the genesis are generated), --fence-provision-file starts it in the pre-genesis enrollment mode: it signs and
	// advances nothing until that file supplies the b1 profile, the execution genesis hash and the activation source.
	pending := fenceGen.VR && flags.FenceProvisionFile != "" && (flags.ActivationSourceURL == "" || fenceGen.CodeHash == nil || fenceGen.GenesisHash == nil)
	var activationGate *vrrules.Gate
	closeGate := func() {}
	if pending {
		opts = append(opts, signingauthority.WithFencePending())
		log.Warn("signing authority in pre-genesis enrollment mode: it signs nothing until its activation fence is provisioned", "file", flags.FenceProvisionFile)
	} else {
		var gerr error
		activationGate, closeGate, gerr = newActivationGate(ctx, log, flags.ActivationSourceURL, fenceGen)
		if gerr != nil {
			return gerr
		}
		defer closeGate()
		if activationGate != nil {
			opts = append(opts, signingauthority.WithFence(activationGate))
			if err := activationGate.RegisterMetric(flags.observe.Meter("signingauthority")); err != nil {
				return fmt.Errorf("creating the upgrade metric: %w", err)
			}
			go activationGate.Watch(ctx, activationWatchInterval, func() uint64 { return flags.RootEpoch })
		}
	}
	// The key is generated here. The enrollment has no configuration hash yet, on purpose.
	authority, err := signingauthority.New(signingauthority.Enrollment{
		AuthorityID: flags.AuthorityID, NodeID: flags.NodeID, NetworkID: types.NetworkID(flags.NetworkID),
		PartitionID: types.PartitionID(flags.PartitionID), ShardID: shardID, ShardEpoch: flags.ShardEpoch,
		RootEpoch: signingauthority.PinRootEpoch(flags.RootEpoch), Profile: signingauthority.ProfileLegacyBCRv1,
	}, trust, opts...)
	if err != nil {
		return err
	}
	defer authority.Close()
	if pending {
		go provisionFenceWhenReady(ctx, log, flags.FenceProvisionFile, fenceGen, flags.ActivationSourceURL, authority, flags.observe.Meter("signingauthority"), func() uint64 { return flags.RootEpoch })
	}

	server, err := service.NewServer(authority, service.Config{OperatorCredential: operatorCredential, PoPCredential: popCredential, Log: log})
	if err != nil {
		return err
	}
	clientListener, err := service.ListenUnix(flags.ClientSocket)
	if err != nil {
		return fmt.Errorf("client socket: %w", err)
	}
	defer func() { _ = clientListener.Close() }()
	operatorListener, err := service.ListenUnix(flags.OperatorSocket)
	if err != nil {
		return fmt.Errorf("operator socket: %w", err)
	}
	defer func() { _ = operatorListener.Close() }()

	var popListener net.Listener
	if flags.PoPSocket != "" {
		if popListener, err = service.ListenUnix(flags.PoPSocket); err != nil {
			return fmt.Errorf("possession-proof socket: %w", err)
		}
		defer func() { _ = popListener.Close() }()
	}

	publicKey, err := authority.SigningPublicKey()
	if err != nil {
		return err
	}
	log.Info("signing authority running; its enrollment is pending until complete-enrollment, and the key is lost when this process stops",
		"authorityID", flags.AuthorityID, "nodeID", flags.NodeID, "partitionID", flags.PartitionID,
		"signingKey", hex.EncodeToString(publicKey), "signingKeyFingerprint", hex.EncodeToString(authority.Enrollment().SigningKeyFingerprint),
		"clientSocket", flags.ClientSocket, "operatorSocket", flags.OperatorSocket)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return server.Serve(clientListener, service.ClientEndpoint) })
	g.Go(func() error { return server.Serve(operatorListener, service.OperatorEndpoint) })
	if popListener != nil {
		g.Go(func() error { return server.Serve(popListener, service.PoPEndpoint) })
	}
	if flags.MetricsAddress != "" {
		if err := checkAuthorityMetricsAddress(flags.MetricsAddress); err != nil {
			return err
		}
		g.Go(func() error { return serveAuthorityMetrics(gctx, log, flags.MetricsAddress, authority) })
	}
	g.Go(func() error {
		<-gctx.Done()
		server.Close()
		_ = clientListener.Close()
		_ = operatorListener.Close()
		if popListener != nil {
			_ = popListener.Close()
		}
		return nil
	})
	return g.Wait()
}

// lineageOptions are the authority options of the lineage flags: the pinned genesis (#1085) and the explicit recovery policy.
func (flags *signingAuthorityRunFlags) lineageOptions(log interface {
	Info(string, ...any)
	Warn(string, ...any)
}) ([]signingauthority.Option, error) {
	if flags.LineageGenesis == "" {
		if flags.LineageUTB || flags.UncheckedAdvance {
			return nil, errors.New("--lineage-utb-genesis and --recovery-unchecked-advance need --lineage-genesis-trust-base")
		}
		log.Warn("signing authority without a lineage pin: it advances only by the operator-trusted advance-epoch (pass --lineage-genesis-trust-base)")
		return nil, nil
	}
	genesis, err := util.ReadJsonFile(flags.LineageGenesis, &types.RootTrustBaseV1{})
	if err != nil {
		return nil, fmt.Errorf("loading the lineage genesis trust base: %w", err)
	}
	id, err := genesis.Hash(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("hashing the lineage genesis trust base: %w", err)
	}
	// what the lineage starts from, stated at start: a UTB chain's first activation extends only a lineage pinned with --lineage-utb-genesis (#1091)
	log.Info("signing authority lineage pinned", "genesis", hex.EncodeToString(id), "network", genesis.NetworkID, "utbGenesis", flags.LineageUTB)
	opts := []signingauthority.Option{signingauthority.WithLineage(genesis, flags.LineageUTB)}
	if flags.UncheckedAdvance {
		log.Warn("signing authority admits the operator-trusted advance-epoch (--recovery-unchecked-advance): a recovery policy")
		opts = append(opts, signingauthority.WithUncheckedAdvance())
	}
	return opts, nil
}

type signingAuthorityOperatorFlags struct {
	*baseFlags
	OperatorSocket     string
	OperatorCredential string
	Timeout            time.Duration
}

func (f *signingAuthorityOperatorFlags) addOperatorFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.OperatorSocket, "operator-socket", "", "the authority's operator socket")
	cmd.Flags().StringVar(&f.OperatorCredential, "operator-credential", "", "path to the operator credential")
	cmd.Flags().DurationVar(&f.Timeout, "timeout", 10*time.Second, "bound on the operation")
	for _, name := range []string{"operator-socket", "operator-credential"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}
}

func (f *signingAuthorityOperatorFlags) operator() (*service.OperatorClient, error) {
	credential, err := readCredentialFile(f.OperatorCredential)
	if err != nil {
		return nil, fmt.Errorf("loading the operator credential: %w", err)
	}
	return service.NewOperatorClient(service.ClientConfig{
		Dial: service.UnixDialer(f.OperatorSocket), Credential: credential, Timeout: f.Timeout,
	})
}

func signingAuthorityCredentialCmd(baseFlags *baseFlags) *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "credential",
		Short: "Generate an operator credential file for `signing-authority run`",
		RunE: func(cmd *cobra.Command, args []string) error {
			credential, err := service.NewCredential()
			if err != nil {
				return err
			}
			return writeCredentialFile(out, credential, false)
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "path of the credential file to create; an existing file is not overwritten")
	if err := cmd.MarkFlagRequired("out"); err != nil {
		panic(err)
	}
	return cmd
}

func signingAuthorityNodeInfoCmd(baseFlags *baseFlags) *cobra.Command {
	flags := &signingAuthorityOperatorFlags{baseFlags: baseFlags}
	var out string
	cmd := &cobra.Command{
		Use:   "node-info",
		Short: "Write the node info naming the authority's signing key, for `shard-conf generate --node-info`",
		Long: `Write the enrolled node's identifier with the public key this authority generated. This is
the node info a shard configuration must be generated from for this validator. The node info written
by shard-node init names the key in the shard node's key configuration instead, which the authority
does not hold and cannot sign for.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if util.FileExists(out) {
				return fmt.Errorf("node info %q already exists; an earlier authority lifetime's key is not this authority's key", out)
			}
			operator, err := flags.operator()
			if err != nil {
				return err
			}
			defer func() { _ = operator.Close() }()
			enrollment, publicKey, err := operator.Enrollment(cmd.Context())
			if err != nil {
				return err
			}
			return util.WriteJsonFile(out, &types.NodeInfo{NodeID: enrollment.NodeID, SigKey: publicKey, Stake: 1})
		},
	}
	flags.addOperatorFlags(cmd)
	cmd.Flags().StringVar(&out, "out", "", "path of the node info file to create")
	if err := cmd.MarkFlagRequired("out"); err != nil {
		panic(err)
	}
	return cmd
}

func signingAuthorityCompleteEnrollmentCmd(baseFlags *baseFlags) *cobra.Command {
	flags := &signingAuthorityOperatorFlags{baseFlags: baseFlags}
	var shardConfFile string
	cmd := &cobra.Command{
		Use:   "complete-enrollment",
		Short: "State a pending authority's shard configuration, once",
		Long: `Send the shard configuration to the authority. The authority checks that it names the
enrolled node with the authority's own signing key, for the enrolled network, partition, shard and
shard epoch, and then fixes its hash for the rest of its lifetime. A second completion is refused.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := util.ReadJsonFile(shardConfFile, &types.PartitionDescriptionRecord{})
			if err != nil {
				return fmt.Errorf("failed to load %q: %w", shardConfFile, err)
			}
			operator, err := flags.operator()
			if err != nil {
				return err
			}
			defer func() { _ = operator.Close() }()
			if err := operator.CompleteEnrollment(cmd.Context(), conf); err != nil {
				if errors.Is(err, signingauthority.ErrContextMismatch) {
					return fmt.Errorf("the authority refused the shard configuration (%w); its log names the check that failed", err)
				}
				return err
			}
			return nil
		},
	}
	flags.addOperatorFlags(cmd)
	cmd.Flags().StringVar(&shardConfFile, "shard-conf", "", "path to the shard configuration naming this authority's key")
	if err := cmd.MarkFlagRequired("shard-conf"); err != nil {
		panic(err)
	}
	return cmd
}

func signingAuthorityAdvanceEpochCmd(baseFlags *baseFlags) *cobra.Command {
	flags := &signingAuthorityOperatorFlags{baseFlags: baseFlags}
	var confFile, trustFile string
	cmd := &cobra.Command{
		Use:   "advance-epoch",
		Short: "Advance a surviving authority to operator-provisioned successor trust and shard configuration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conf, err := util.ReadJsonFile(confFile, &types.PartitionDescriptionRecord{})
			if err != nil {
				return fmt.Errorf("loading successor shard configuration: %w", err)
			}
			trust, err := util.ReadJsonFile(trustFile, &types.RootTrustBaseV1{})
			if err != nil {
				return fmt.Errorf("loading successor root trust: %w", err)
			}
			operator, err := flags.operator()
			if err != nil {
				return err
			}
			defer func() { _ = operator.Close() }()
			return operator.AdvanceEpoch(cmd.Context(), conf, trust)
		},
	}
	flags.addOperatorFlags(cmd)
	cmd.Flags().StringVar(&confFile, "shard-conf", "", "successor shard configuration naming this authority's key")
	cmd.Flags().StringVar(&trustFile, "trust-base", "", "operator-provisioned successor root trust base")
	_ = cmd.MarkFlagRequired("shard-conf")
	_ = cmd.MarkFlagRequired("trust-base")
	return cmd
}

/*
advance-with-proof is the operator's one local operation per entity (#1085): it hands the authority the root activation bundles, one call
each in epoch order, and the authority verifies each against its own lineage before it changes anything; then, when the scope changed or
no session has been issued since it last changed, it replaces the session and writes the new client credential. Rerunning it with the
same bundles is a no-op that only repairs a missing credential, so a crash between the advance and the credential is repaired by a rerun.
*/
func signingAuthorityAdvanceWithProofCmd(baseFlags *baseFlags) *cobra.Command {
	flags := &signingAuthorityOperatorFlags{baseFlags: baseFlags}
	var proofs []string
	var out, clientSocket string
	cmd := &cobra.Command{
		Use:   "advance-with-proof",
		Short: "Advance the authority by root activation bundles it verifies itself, then issue the next client credential",
		RunE: func(cmd *cobra.Command, _ []string) error {
			operator, err := flags.operator()
			if err != nil {
				return err
			}
			defer func() { _ = operator.Close() }()
			current := func(ctx context.Context) error { return checkClientCredential(ctx, clientSocket, out, flags.Timeout) }
			report, err := advanceWithProof(cmd.Context(), operator, proofs, out, current)
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(report)
		},
	}
	flags.addOperatorFlags(cmd)
	cmd.Flags().StringArrayVar(&proofs, "proof", nil, "a root activation bundle file (the q3/bundle encoding), repeated in epoch order")
	cmd.Flags().StringVar(&out, "out", "", "path of the client credential file written when a session is issued; an existing file is replaced")
	cmd.Flags().StringVar(&clientSocket, "client-socket", "", "the authority's client socket: a session already issued is checked with the credential in --out, "+
		"and replaced when that credential is fenced or missing (a lost replacement answer, or a crash before the credential was written)")
	_ = cmd.MarkFlagRequired("proof")
	_ = cmd.MarkFlagRequired("client-socket")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

// advanceWithProofReport is what advance-with-proof prints.
type advanceWithProofReport struct {
	Steps         []signingauthority.AdvanceResult `json:"steps"`
	Advanced      bool                             `json:"advanced"`
	Retired       bool                             `json:"retired"`
	SessionIssued bool                             `json:"sessionIssued"`
	RootEpoch     uint64                           `json:"rootEpoch"`
	ShardEpoch    uint64                           `json:"shardEpoch"`
	LineageEpoch  uint64                           `json:"lineageEpoch"`
}

// advanceOperator is the part of the operator client advance-with-proof uses.
type advanceOperator interface {
	AdvanceWithProof(ctx context.Context, bundle []byte) (signingauthority.AdvanceResult, error)
	Status(ctx context.Context) (signingauthority.Status, error)
	ReplaceSession(ctx context.Context) ([]byte, error)
}

// checkClientCredential asks the authority's client socket for its status with the credential in path: nil when that credential is the
// admitted one.
func checkClientCredential(ctx context.Context, socket, path string, timeout time.Duration) error {
	credential, err := readCredentialFile(path)
	if err != nil {
		return err
	}
	client, err := service.NewClient(service.ClientConfig{Dial: service.UnixDialer(socket), Credential: credential, Timeout: timeout})
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	_, err = client.RestoreStatus(ctx)
	return err
}

func advanceWithProof(ctx context.Context, operator advanceOperator, proofs []string, out string, current func(context.Context) error) (advanceWithProofReport, error) {
	var report advanceWithProofReport
	status, err := operator.Status(ctx)
	if err != nil {
		return report, err
	}
	if len(proofs) == 0 {
		return report, errors.New("no activation bundle: pass at least the target epoch's (a resume replays it)")
	}
	if current == nil {
		return report, errors.New("no check of the current client credential")
	}
	for _, path := range proofs {
		info, err := os.Stat(path)
		if err != nil {
			return report, err
		}
		if info.Size() > service.MaxAdvanceProofBytes {
			return report, fmt.Errorf("%s: %d bytes, an activation proof is at most %d", path, info.Size(), service.MaxAdvanceProofBytes)
		}
		raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied proof path
		if err != nil {
			return report, err
		}
		res, err := operator.AdvanceWithProof(ctx, raw)
		if err != nil {
			return report, fmt.Errorf("%s: %w", path, err)
		}
		report.Steps = append(report.Steps, res)
		report.Advanced = report.Advanced || res.Advanced
	}
	if status, err = operator.Status(ctx); err != nil {
		return report, err
	}
	report.Retired, report.RootEpoch, report.ShardEpoch, report.LineageEpoch = status.Retired, status.RootEpoch, status.ShardEpoch, status.LineageEpoch
	// the session is issued when none was since the scope last changed, or when the one issued is not the credential in --out (its
	// answer was lost, or the file was never written): success is never reported without --out holding the admitted credential
	issue := !status.Retired && !status.SessionIssued
	if !issue && !status.Retired {
		if err := current(ctx); err != nil {
			if !errors.Is(err, signingauthority.ErrFenced) && !errors.Is(err, os.ErrNotExist) {
				return report, fmt.Errorf("checking the current client credential: %w", err)
			}
			issue = true // issued, but its credential never reached the file
		}
	}
	if issue {
		credential, err := operator.ReplaceSession(ctx)
		if err != nil {
			return report, err
		}
		if err := writeCredentialFile(out, credential, true); err != nil {
			return report, fmt.Errorf("the session was replaced, so the previous credential is fenced, but the new one could not be written (run again): %w", err)
		}
		report.SessionIssued = true
	}
	if !status.Retired {
		if err := current(ctx); err != nil {
			return report, fmt.Errorf("the credential in %s is not the admitted one: %w", out, err)
		}
	}
	return report, nil
}

func signingAuthorityReplaceSessionCmd(baseFlags *baseFlags) *cobra.Command {
	flags := &signingAuthorityOperatorFlags{baseFlags: baseFlags}
	var out string
	cmd := &cobra.Command{
		Use:   "replace-session",
		Short: "Fence the current shard client and write the credential for the next one",
		Long: `Advance the authority's client generation and write the new client credential. The
credential previously issued stops being admitted in the same step, so a shard node still holding it
abstains. The authority keeps its signing record: the new client inherits it. The credential is
returned once and cannot be read back; losing it means replacing the session again.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			operator, err := flags.operator()
			if err != nil {
				return err
			}
			defer func() { _ = operator.Close() }()
			credential, err := operator.ReplaceSession(cmd.Context())
			if err != nil {
				return err
			}
			if err := writeCredentialFile(out, credential, true); err != nil {
				return fmt.Errorf("the session was replaced, so the previous credential is fenced, but the new one could not be written (replace the session again): %w", err)
			}
			return nil
		},
	}
	flags.addOperatorFlags(cmd)
	cmd.Flags().StringVar(&out, "out", "", "path of the client credential file; an existing file is replaced")
	if err := cmd.MarkFlagRequired("out"); err != nil {
		panic(err)
	}
	return cmd
}

// signingAuthorityStatus is what `signing-authority status` prints. It carries no request bytes, no
// response and no credential.
type signingAuthorityStatus struct {
	AuthorityID           string `json:"authorityId"`
	NodeID                string `json:"nodeId"`
	NetworkID             uint16 `json:"networkId"`
	PartitionID           uint32 `json:"partitionId"`
	ShardID               string `json:"shardId"`
	ShardEpoch            uint64 `json:"shardEpoch"`
	RootEpoch             uint64 `json:"rootEpoch"`
	EnrollmentComplete    bool   `json:"enrollmentComplete"`
	ShardConfHash         string `json:"shardConfHash,omitempty"`
	SigningKeyFingerprint string `json:"signingKeyFingerprint"`
	Generation            uint64 `json:"generation"`
	HasReservation        bool   `json:"hasReservation"`
	ReservedRound         uint64 `json:"reservedRound"`
	ResponseRetained      bool   `json:"responseRetained"`
	Faulted               bool   `json:"faulted"`
	KeyLost               bool   `json:"keyLost"`
	LineagePinned         bool   `json:"lineagePinned"`
	LineageEpoch          uint64 `json:"lineageEpoch"`
	Retired               bool   `json:"retired"`
	SessionIssued         bool   `json:"sessionIssued"`
}

func signingAuthorityStatusCmd(baseFlags *baseFlags) *cobra.Command {
	flags := &signingAuthorityOperatorFlags{baseFlags: baseFlags}
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Print the authority's enrollment and what it is holding",
		RunE: func(cmd *cobra.Command, args []string) error {
			operator, err := flags.operator()
			if err != nil {
				return err
			}
			defer func() { _ = operator.Close() }()
			enrollment, publicKey, err := operator.Enrollment(cmd.Context())
			if err != nil {
				return err
			}
			status, err := operator.Status(cmd.Context())
			if err != nil {
				return err
			}
			fingerprint := sha256.Sum256(publicKey)
			out := signingAuthorityStatus{
				AuthorityID: enrollment.AuthorityID, NodeID: enrollment.NodeID,
				NetworkID: uint16(enrollment.NetworkID), PartitionID: uint32(enrollment.PartitionID),
				ShardID: enrollment.ShardID.String(), ShardEpoch: enrollment.ShardEpoch,
				EnrollmentComplete: len(enrollment.ShardConfHash) != 0, ShardConfHash: hex.EncodeToString(enrollment.ShardConfHash),
				SigningKeyFingerprint: hex.EncodeToString(fingerprint[:]),
				Generation:            status.Generation, HasReservation: status.HasReservation, ReservedRound: status.ReservedRound,
				ResponseRetained: status.ResponseRetained, Faulted: status.Faulted, KeyLost: status.KeyLost,
				LineagePinned: status.LineagePinned, LineageEpoch: status.LineageEpoch, Retired: status.Retired, SessionIssued: status.SessionIssued,
			}
			if enrollment.RootEpoch != nil {
				out.RootEpoch = *enrollment.RootEpoch
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(out)
		},
	}
	flags.addOperatorFlags(cmd)
	return cmd
}

/*
readCredentialFile loads a client or operator credential: hex text of exactly CredentialBytes.

A credential is a bearer secret, so a file other users can read is refused rather than used. The
check is on the file's mode only; the socket directories and host separation are what keep the
credential's holder the intended one.
*/
func readCredentialFile(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("no credential file")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is accessible to other users (mode %04o); a credential file must be readable by its owner only", path, info.Mode().Perm())
	}
	text, err := os.ReadFile(path) // #nosec G304 -- operator-supplied credential path
	if err != nil {
		return nil, err
	}
	credential, err := hex.DecodeString(strings.TrimSpace(string(text)))
	if err != nil {
		return nil, fmt.Errorf("%s is not a hex credential: %w", path, err)
	}
	if len(credential) != service.CredentialBytes {
		return nil, fmt.Errorf("%s holds a %d-byte credential, expected %d", path, len(credential), service.CredentialBytes)
	}
	return credential, nil
}

// writeCredentialFile writes a credential readable by its owner only. Without replace an existing
// file is an error. With replace the new file is written beside the old one and renamed over it, so
// a reader sees the old credential or the new one and never a partial file.
func writeCredentialFile(path string, credential []byte, replace bool) error {
	if path == "" {
		return errors.New("no credential file")
	}
	content := []byte(hex.EncodeToString(credential) + "\n")
	if !replace {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-supplied credential path
		if err != nil {
			return err
		}
		if _, err := f.Write(content); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".credential-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func signingAuthorityRegistrationPolicyCmd(baseFlags *baseFlags) *cobra.Command {
	flags := &signingAuthorityOperatorFlags{baseFlags: baseFlags}
	var file string
	cmd := &cobra.Command{
		Use:   "registration-policy",
		Short: "Replace the registrations a running authority may sign (VT-10)",
		Long: `Replace the authorized registrations of the running authority with those of the policy file. The identity id is allocated by VR at
registration and a later payee or root key is not known when the authority starts, so the operator authorizes them here, on the
operator channel. The deployment pin the authority started with, its key and its signing record are untouched: the file's deployment
must equal the authority's pin (a policy for another deployment is refused), and an authority started without --registration-policy refuses the reload. The list replaces the old one.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			policy, err := readRegistrationPolicy(file)
			if err != nil {
				return err
			}
			operator, err := flags.operator()
			if err != nil {
				return err
			}
			defer func() { _ = operator.Close() }()
			ctx, cancel := context.WithTimeout(cmd.Context(), flags.Timeout)
			defer cancel()
			if err := operator.ReloadRegistrationPolicy(ctx, policy.Deployment, policy.Authorized); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "registration policy reloaded: %d authorized\n", len(policy.Authorized))
			return nil
		},
	}
	flags.addOperatorFlags(cmd)
	cmd.Flags().StringVar(&file, "policy", "", "the registration policy file (the format of `signing-authority run --registration-policy`)")
	if err := cmd.MarkFlagRequired("policy"); err != nil {
		panic(err)
	}
	return cmd
}

// posPolicyFile is the JSON of `signing-authority run --pos-policy` and `signing-authority pos-policy`.
type posPolicyFile struct {
	Network  string   `json:"network"`
	ChainID  uint64   `json:"chainId"`
	Election string   `json:"election"`
	IDs      []uint64 `json:"ids"`
}

func readPosPolicy(path string) (signingauthority.PosPolicy, error) {
	var p signingauthority.PosPolicy
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return p, err
	}
	var f posPolicyFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return p, fmt.Errorf("P85 pin %s: %w", path, err)
	}
	if dec.More() {
		return p, fmt.Errorf("P85 pin %s: trailing data after the pin object", path)
	}
	nw, err := hexutil.Decode(f.Network)
	if err != nil || len(nw) != 32 || !common.IsHexAddress(f.Election) || f.ChainID == 0 {
		return p, fmt.Errorf("P85 pin %s: network is 32 bytes of 0x-hex, chainId nonzero and election an address", path)
	}
	copy(p.Network[:], nw)
	p.ChainID = vrschema.U64(f.ChainID)
	p.Election = common.HexToAddress(f.Election)
	p.IDs = f.IDs
	return p, nil
}

func signingAuthorityPosPolicyCmd(baseFlags *baseFlags) *cobra.Command {
	flags := &signingAuthorityOperatorFlags{baseFlags: baseFlags}
	var file string
	cmd := &cobra.Command{
		Use:   "pos-policy",
		Short: "Pin the P85 election a running authority may sign possession proofs for (#1216)",
		Long: `Pin, once, the scope of the P85 possession signatures of the running authority: the election's network word, the chain id, the
ElectionPolicy address and the identity ids its EVM key may prove for. The election is deployed in the generation's genesis, after the
authority started, so the operator states it here on the operator channel. The pin cannot be changed in the authority's lifetime: the same
pin again is a no-op, another is refused. Until pinned, the authority signs no P85 assignment possession.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pin, err := readPosPolicy(file)
			if err != nil {
				return err
			}
			operator, err := flags.operator()
			if err != nil {
				return err
			}
			defer func() { _ = operator.Close() }()
			ctx, cancel := context.WithTimeout(cmd.Context(), flags.Timeout)
			defer cancel()
			if err := operator.SetPosPolicy(ctx, pin); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "P85 election pinned: %s, identities %v\n", common.Address(pin.Election).Hex(), pin.IDs)
			return nil
		},
	}
	flags.addOperatorFlags(cmd)
	cmd.Flags().StringVar(&file, "policy", "", "the P85 pin file: {\"network\":\"0x..\",\"chainId\":N,\"election\":\"0x..\",\"ids\":[..]}")
	if err := cmd.MarkFlagRequired("policy"); err != nil {
		panic(err)
	}
	return cmd
}
