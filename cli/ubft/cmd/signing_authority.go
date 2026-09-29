package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"

	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/signingauthority/service"
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
	cmd.AddCommand(signingAuthorityReplaceSessionCmd(baseFlags))
	cmd.AddCommand(signingAuthorityStatusCmd(baseFlags))
	return cmd
}

type signingAuthorityRunFlags struct {
	*baseFlags
	trustBaseFlags

	ClientSocket       string
	OperatorSocket     string
	OperatorCredential string

	AuthorityID string
	NodeID      string
	NetworkID   uint16
	PartitionID uint32
	ShardID     string
	ShardEpoch  uint64
	RootEpoch   uint64
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
	cmd.Flags().StringVar(&flags.AuthorityID, "authority-id", "", "operator-assigned name for this authority lifetime, for diagnostics")
	cmd.Flags().StringVar(&flags.NodeID, "node-id", "", "the shard validator this authority signs for (`ubft node-id` on the shard node's key configuration)")
	cmd.Flags().Uint16Var(&flags.NetworkID, "network-id", 0, "network identifier")
	cmd.Flags().Uint32Var(&flags.PartitionID, "partition-id", 0, "partition identifier")
	cmd.Flags().StringVar(&flags.ShardID, "shard-id", "0x80", "the shard id in hex format with 0x prefix")
	cmd.Flags().Uint64Var(&flags.ShardEpoch, "shard-epoch", 0, "the shard configuration epoch this authority signs for; a later epoch is refused, not followed")
	cmd.Flags().Uint64Var(&flags.RootEpoch, "root-epoch", 0, "the root trust epoch this authority signs for; a later epoch is refused, not followed")
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

	// The key is generated here. The enrollment has no configuration hash yet, on purpose.
	authority, err := signingauthority.New(signingauthority.Enrollment{
		AuthorityID: flags.AuthorityID, NodeID: flags.NodeID, NetworkID: types.NetworkID(flags.NetworkID),
		PartitionID: types.PartitionID(flags.PartitionID), ShardID: shardID, ShardEpoch: flags.ShardEpoch,
		RootEpoch: signingauthority.PinRootEpoch(flags.RootEpoch), Profile: signingauthority.ProfileLegacyBCRv1,
	}, trust)
	if err != nil {
		return err
	}
	defer authority.Close()

	server, err := service.NewServer(authority, service.Config{OperatorCredential: operatorCredential, Log: log})
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
	g.Go(func() error {
		<-gctx.Done()
		server.Close()
		_ = clientListener.Close()
		_ = operatorListener.Close()
		return nil
	})
	return g.Wait()
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
