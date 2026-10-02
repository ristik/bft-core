package cmd

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ainvaltin/httpsrv"
	"github.com/ethereum/go-ethereum/common"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier"

	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/archivewiring"
	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/configuredadmission"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/keyvaluedb/boltdb"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
	"github.com/unicitynetwork/bft-core/signingauthority"
)

const lucStoreFileName = "shard-node-luc.json"

// ErrRestoreTrustAnchorEpoch is returned when a restore is started with a --trust-base whose epoch is not the genesis root epoch. The
// restore replays every archived block from block 1, so it must verify forward from the genesis-epoch trust base through every missed
// handoff; a later anchor leaves the earlier epochs' trust, assignment transitions and shard configurations uninstalled.
var ErrRestoreTrustAnchorEpoch = errors.New("restore trust anchor is not the genesis root epoch")

// requireRestoreTrustAnchor refuses a restore whose CLI trust base is not at the genesis root epoch. It reads only the checked origin and
// the trust epoch, so it can run before anything is constructed or written. Ordinary runs are not restricted: a later trust base remains
// valid for a node that has its own history. A restore without a checked origin is refused later by the journal requirements.
func requireRestoreTrustAnchor(restore bool, origin registrygenesis.GenesisOrigin, trustEpoch uint64) error {
	if !restore || !origin.Valid() {
		return nil
	}
	if genesisEpoch := origin.Record().RootEpoch; trustEpoch != genesisEpoch {
		return fmt.Errorf("%w: --trust-base is at root epoch %d but the genesis was generated at root epoch %d; supply the genesis-epoch trust base to --trust-base (the current trust base is pinned separately by --trust-body-id)",
			ErrRestoreTrustAnchorEpoch, trustEpoch, genesisEpoch)
	}
	return nil
}

type handoffTerminalCertificate struct {
	uc *types.UnicityCertificate
	tr *certification.TechnicalRecord
}

type handoffObservationBackfiller interface {
	BackfillJournalObservation(context.Context, configuredprogress.Context, configuredprogress.JournalLimits, *types.UnicityCertificate, *certification.TechnicalRecord) error
}

type handoffArchiveReader interface {
	Get(archive.Request) (*archive.Record, error)
}

type handoffHistoricalCandidateWriter interface {
	PutHistoricalCertifiedJournalCandidate(context.Context, configuredprogress.Context, configuredprogress.JournalLimits,
		configuredprogress.JournalCandidate, *types.UnicityCertificate, *certification.TechnicalRecord) error
}

// runProfile2JournalStartup is the startup boundary for proof-aware journal
// replay. Keep the verified lineage restore ahead of Initialize: Initialize
// replays observations using the active epoch from that lineage.
func runProfile2JournalStartup(ctx context.Context, restore, initialize, enable, repair func(context.Context) error) error {
	if restore != nil {
		if err := restore(ctx); err != nil {
			return fmt.Errorf("restoring handoff lineage: %w", err)
		}
	}
	if err := initialize(ctx); err != nil {
		return fmt.Errorf("initializing execution journal: %w", err)
	}
	if err := enable(ctx); err != nil {
		return fmt.Errorf("activating execution journal: %w", err)
	}
	if repair != nil {
		if err := repair(ctx); err != nil {
			return fmt.Errorf("repairing saved handoff observations: %w", err)
		}
	}
	return nil
}

// handoffArchiveRefusal names an archive replica's refusal of this node (it has not installed the assignment step that admits it yet)
// as the follower's retryable sentinel; every other error passes through unchanged.
func handoffArchiveRefusal(err error) error {
	if errors.Is(err, archivewiring.ErrPeerNotAllowed) {
		return fmt.Errorf("%w: %w", shardnode.ErrHandoffPeerNotReady, err)
	}
	return err
}

// runProfile2ArchiveRestore keeps verified handoff installation ahead of
// archive replay, then repairs any terminal observations saved during catch-up. The catch-up step also validates the configured archive
// replicas against the installed set; the archive setup (frontier enablement) follows it and precedes the replay.
func runProfile2ArchiveRestore(ctx context.Context, catchUp, setupArchive, restore, repair func(context.Context) error) error {
	if catchUp != nil {
		if err := catchUp(ctx); err != nil {
			return fmt.Errorf("restoring handoff history: %w", err)
		}
	}
	if setupArchive != nil {
		if err := setupArchive(ctx); err != nil {
			return fmt.Errorf("setting up the archive: %w", err)
		}
	}
	if restore != nil {
		if err := restore(ctx); err != nil {
			return fmt.Errorf("restoring from certified archive: %w", err)
		}
	}
	if repair != nil {
		if err := repair(ctx); err != nil {
			return fmt.Errorf("repairing restored handoff observations: %w", err)
		}
	}
	return nil
}

func reapplyHandoffTerminalCertificates(ctx context.Context, store handoffObservationBackfiller, journalCtx configuredprogress.Context,
	limits configuredprogress.JournalLimits, terminals []handoffTerminalCertificate) error {
	for _, terminal := range terminals {
		if terminal.uc == nil || terminal.tr == nil {
			return configuredprogress.ErrUntrusted
		}
		if err := store.BackfillJournalObservation(ctx, journalCtx, limits, terminal.uc, terminal.tr); err != nil {
			return fmt.Errorf("backfilling handoff terminal certificate at root epoch %d round %d: %w",
				terminal.uc.GetRootEpoch(), terminal.uc.GetRoundNumber(), err)
		}
	}
	return nil
}

func reapplyHandoffTerminalCertificatesWithArchive(ctx context.Context, store handoffObservationBackfiller,
	candidateWriter handoffHistoricalCandidateWriter, localArchive handoffArchiveReader, archiveContext archive.Context,
	journalCtx configuredprogress.Context, limits configuredprogress.JournalLimits, terminals []handoffTerminalCertificate) error {
	for _, terminal := range terminals {
		if terminal.uc == nil || terminal.tr == nil || terminal.uc.InputRecord == nil || len(terminal.uc.InputRecord.BlockHash) != 32 ||
			len(terminal.uc.InputRecord.PreviousHash) != 32 {
			return configuredprogress.ErrUntrusted
		}
		err := store.BackfillJournalObservation(ctx, journalCtx, limits, terminal.uc, terminal.tr)
		if err == nil {
			continue
		}
		if !errors.Is(err, configuredprogress.ErrUnavailable) || localArchive == nil || candidateWriter == nil {
			return fmt.Errorf("backfilling handoff terminal certificate at root epoch %d round %d: %w",
				terminal.uc.GetRootEpoch(), terminal.uc.GetRoundNumber(), err)
		}
		var q archive.Request
		q.Context = archiveContext
		copy(q.BlockHash[:], terminal.uc.InputRecord.BlockHash)
		record, archiveErr := localArchive.Get(q)
		if errors.Is(archiveErr, archive.ErrUnavailable) {
			return fmt.Errorf("%w: handoff terminal body %x is unavailable in both journal and archive",
				configuredprogress.ErrUnavailable, q.BlockHash)
		}
		if archiveErr != nil {
			return fmt.Errorf("loading handoff terminal body %x from archive: %w", q.BlockHash, archiveErr)
		}
		var originalUC types.UnicityCertificate
		var originalTR certification.TechnicalRecord
		var resultingUC types.UnicityCertificate
		var resultingTR certification.TechnicalRecord
		if record == nil || types.Cbor.Unmarshal(record.OriginalUC, &originalUC) != nil || types.Cbor.Unmarshal(record.OriginalTR, &originalTR) != nil ||
			types.Cbor.Unmarshal(record.ResultingUC, &resultingUC) != nil || types.Cbor.Unmarshal(record.ResultingTR, &resultingTR) != nil {
			return fmt.Errorf("%w: archived handoff terminal body has invalid certificate binding", configuredprogress.ErrUntrusted)
		}
		block, blockErr := engineapi.BlockFromArchive(q, record, originalUC.GetRootRoundNumber(), terminal.uc.InputRecord.RoundNumber)
		if blockErr != nil {
			return fmt.Errorf("verifying archived handoff terminal body %x: %w", q.BlockHash, blockErr)
		}
		if block.Number == 0 || !bytes.Equal(block.Hash, terminal.uc.InputRecord.BlockHash) || !bytes.Equal(block.StateRoot, terminal.uc.InputRecord.Hash) {
			return fmt.Errorf("%w: archived handoff terminal body differs from its verified certificate",
				configuredprogress.ErrUntrusted)
		}
		candidate := configuredprogress.JournalCandidate{
			Round: terminal.uc.InputRecord.RoundNumber, Number: block.Number, ParentNumber: block.Number - 1,
			Hash: bytes.Clone(block.Hash), StateRoot: bytes.Clone(block.StateRoot), ParentHash: bytes.Clone(block.ParentHash),
			ParentState: bytes.Clone(terminal.uc.InputRecord.PreviousHash),
			Raw:         bytes.Clone(block.Raw), BlockSize: block.BlockSize, StateSize: block.StateSize,
			AuthorizingUC: &originalUC, AuthorizingTR: &originalTR,
		}
		if err := candidateWriter.PutHistoricalCertifiedJournalCandidate(ctx, journalCtx, limits, candidate, &resultingUC, &resultingTR); err != nil {
			return fmt.Errorf("retaining verified archived handoff terminal body %x: %w", q.BlockHash, err)
		}
		if err := store.BackfillJournalObservation(ctx, journalCtx, limits, terminal.uc, terminal.tr); err != nil {
			return fmt.Errorf("backfilling handoff terminal certificate at root epoch %d round %d after archive recovery: %w",
				terminal.uc.GetRootEpoch(), terminal.uc.GetRoundNumber(), err)
		}
	}
	return nil
}

type shardNodeRunFlags struct {
	*baseFlags
	keyConfFlags
	trustBaseFlags
	shardConfFlags
	p2pFlags

	Executor string // "fake" or "engine-api"

	// engine-api executor only — see engineapi.Config.
	EngineURL           string
	EthURL              string
	JWTSecret           string
	EngineFeeCollector  string
	ExpectedGenesisHash string

	// The two files `ubft engine-api genesis` emits. They are required together: when given, the node
	// runs on the full shard configuration and configures a checked genesis origin plus its bootstrap
	// snapshot for the v2 derivation. Without them, the v2 build path refuses to derive.
	GenesisFile            string
	FullShardConf          string
	ExpectedOriginIdentity string
	EVMTransitionFile      string
	// RegistryLayout is the layout of the deployment's SealRegistry (1 or 2); it must be the one the genesis
	// was generated with, because G commits to it.
	RegistryLayout uint64

	LUCStoreFile         string
	ExecutionJournal     string
	JournalCandidates    int
	JournalObservations  int
	JournalBytes         int64
	ArchiveStore         string
	ArchiveReplicas      []string
	ArchivePrune         bool
	TrustHistoryProfile2 bool
	Restore              bool
	RestoreTipUC         string
	RestoreTipTR         string
	RestoreTrustBodyID   string

	// CertifiedRecordStore enables the certified-block record store (#14) at this path. Empty, the default,
	// constructs nothing, and the node runs exactly as before. See startCertifiedRecord.
	CertifiedRecordStore  string
	CertifiedRecordRetain int
	// CertifiedRecordGate withholds leadership and the signature while the durable record cannot prove
	// readiness for the held certificate's child (#14 W3b-1). It requires CertifiedRecordStore; set alone
	// it stops startup. Off by default so asking for a store does not silently change voting.
	CertifiedRecordGate bool
	// CertifiedRecordCaptureTimeout bounds one witness acquisition over --eth-url.
	CertifiedRecordCaptureTimeout time.Duration
	// The EVM genesis parameters the SealRegistry deployment was generated with, used only with
	// CertifiedRecordStore.
	RegistryEVMGasLimit  uint64
	RegistryEVMCoinbase  string
	RegistryEVMExtraData string

	HandshakeNodes           int
	CertNodes                int
	HeartbeatInterval        time.Duration
	StartupHandshakeInterval time.Duration
	InactivityTimeout        time.Duration

	// EvidenceServe / EvidenceRecover switch the two halves of authenticated-evidence anchor
	// recovery (#92) independently — see the flag help and shardnode.RecoveryOptions.
	EvidenceServe   bool
	EvidenceRecover bool

	RPCServerAddress string // exposes /api/v1/metrics and /api/v1/health when set

	shardNodeSigningFlags
}

func shardNodeRunCmd(baseFlags *baseFlags) *cobra.Command {
	return shardNodeExecutionCmd(baseFlags, false)
}

func shardNodeRestoreCmd(baseFlags *baseFlags) *cobra.Command {
	return shardNodeExecutionCmd(baseFlags, true)
}

func shardNodeExecutionCmd(baseFlags *baseFlags, restore bool) *cobra.Command {
	flags := &shardNodeRunFlags{baseFlags: baseFlags}
	flags.Restore = restore
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run a shard node",
		Long: `Run a shard node: an Engine API adapter or other executor, certifying state-root
transitions against the BFT Core root chain. See docs/shard-protocol.md for the round
protocol and docs/engine-api-adapter-plan.md for how this command's pieces fit together.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return shardNodeRun(cmd.Context(), flags, cmd.Flags().Changed)
		},
	}
	if restore {
		cmd.Use = "restore"
		cmd.Short = "Restore an empty shard node from certified archive records and verified handoffs, then run"
		cmd.Flags().StringVar(&flags.RestoreTipUC, "tip-uc", "", "canonical CBOR file containing the operator-pinned latest certified UC")
		cmd.Flags().StringVar(&flags.RestoreTipTR, "tip-tr", "", "canonical CBOR file containing that UC's technical record")
		cmd.Flags().StringVar(&flags.RestoreTrustBodyID, "trust-body-id", "", "0x-prefixed BodyID of the pinned current trust base")
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
	cmd.Flags().StringVar(&flags.EngineFeeCollector, "engine-fee-collector", "0x0000000000000000000000000000000000000000",
		"engine-api executor only: configured fee collector address, which must match the execution client's --unicity.fee-collector")
	cmd.Flags().StringVar(&flags.ExpectedGenesisHash, "expected-genesis-hash", "",
		"engine-api executor only: the execution client's expected genesis block hash (0x-prefixed). "+
			"Operator-configured; when set it is verified before the node can vote. A chain id does not "+
			"establish genesis identity, and a matching genesis does not establish agreement on future forks")
	cmd.Flags().StringVar(&flags.EVMTransitionFile, "engine-epoch-transition", "",
		"engine-api executor only: path to the canonical transition emitted by the installed root handoff; sent while the authenticated parent is in the old epoch")
	cmd.Flags().StringVar(&flags.GenesisFile, "genesis", "",
		"path to the finalized genesis JSON emitted by `ubft engine-api genesis`; with --full-shard-conf it "+
			"configures a checked genesis origin and bootstrap snapshot, and the client's block 0 is required to match it")
	cmd.Flags().StringVar(&flags.FullShardConf, "full-shard-conf", "",
		"path to the full shard configuration emitted by `ubft engine-api genesis` (the base conf plus "+
			"seal_registry_genesis). The node runs on this configuration, because the v2 derivation requires the "+
			"observation's shard configuration hash to equal the genesis origin's full configuration hash")
	cmd.Flags().Uint64Var(&flags.RegistryLayout, "registry-layout", 1,
		"SealRegistry layout the genesis was generated with: 1 (sealRegistry/v1) or 2 (assignment-aware sealRegistry/v2)")
	cmd.Flags().StringVar(&flags.ExpectedOriginIdentity, "expected-origin-identity", "",
		"optional 0x-prefixed 32-byte expected genesis origin identity; when set, startup refuses a mismatch")
	cmd.Flags().StringVar(&flags.JWTSecret, "jwt-secret", "",
		"engine-api executor only: path to the 32-byte hex JWT secret shared with the execution client (default: $UBFT_HOME/jwt.hex)")
	cmd.Flags().StringVar(&flags.LUCStoreFile, "luc-store", "",
		fmt.Sprintf("path to the last-certificate store, for restart recovery (default: %s)", filepath.Join("$UBFT_HOME", lucStoreFileName)))
	cmd.Flags().StringVar(&flags.ExecutionJournal, "execution-journal", "",
		"path to the configured-origin v2 full-history proposal and certification journal (fresh D2 lane state required)")
	cmd.Flags().IntVar(&flags.JournalCandidates, "journal-candidates", 256,
		"maximum retained candidate bodies with --execution-journal; admission stops at capacity")
	cmd.Flags().IntVar(&flags.JournalObservations, "journal-observations", 512,
		"maximum retained certificate observations with --execution-journal; admission stops at capacity")
	cmd.Flags().Int64Var(&flags.JournalBytes, "journal-bytes", 64<<20,
		"maximum retained hot journal bytes with --execution-journal; pruning requires --archive-prune")
	cmd.Flags().StringVar(&flags.ArchiveStore, "archive-store", "",
		"local certified archive directory; requires --execution-journal and exactly two --archive-replica peer IDs")
	cmd.Flags().StringSliceVar(&flags.ArchiveReplicas, "archive-replica", nil,
		"configured replica peer ID; set exactly twice with --archive-store")
	cmd.Flags().BoolVar(&flags.ArchivePrune, "archive-prune", false,
		"advance the certified frontier and prune acknowledged journal history; requires --archive-store")
	cmd.Flags().BoolVar(&flags.TrustHistoryProfile2, "trust-history-profile-2", false,
		"verify old-set handoff commit proofs before admitting successor trust epochs; requires --execution-journal")
	cmd.Flags().StringVar(&flags.CertifiedRecordStore, "certified-record-store", "",
		"path of the certified-block record store (#14); empty leaves it off. Requires --executor engine-api and a SealRegistry shard configuration. The record is reloaded and reported at startup, and the witness of every block the round commits is captured over --eth-url and published; none of it changes voting")
	cmd.Flags().IntVar(&flags.CertifiedRecordRetain, "certified-record-retain", defaultCertifiedRecordRetain,
		"non-genesis certified records to retain, counting the newest")
	cmd.Flags().BoolVar(&flags.CertifiedRecordGate, "certified-record-gate", false,
		"withhold leadership and the signature while the certified-block record cannot prove readiness for the held certificate's child (#14 W3b-1); requires --certified-record-store")
	cmd.Flags().DurationVar(&flags.CertifiedRecordCaptureTimeout, "certified-record-capture-timeout", recordwiringDefaultAcquireTimeout,
		"bound on one witness acquisition over --eth-url (with --certified-record-store)")
	cmd.Flags().Uint64Var(&flags.RegistryEVMGasLimit, "registry-evm-gas-limit", defaultGasLimit,
		"EVM genesis gas limit the SealRegistry deployment was generated with (with --certified-record-store)")
	cmd.Flags().StringVar(&flags.RegistryEVMCoinbase, "registry-evm-coinbase", "0x0000000000000000000000000000000000000000",
		"EVM genesis coinbase the SealRegistry deployment was generated with (with --certified-record-store)")
	cmd.Flags().StringVar(&flags.RegistryEVMExtraData, "registry-evm-extra-data", "0x",
		"EVM genesis extraData the SealRegistry deployment was generated with, 0x-prefixed hex (with --certified-record-store)")
	cmd.Flags().IntVar(&flags.HandshakeNodes, "handshake-nodes", shardnode.DefaultBFTClientOptions.HandshakeNodes, "number of root nodes to handshake with")
	cmd.Flags().IntVar(&flags.CertNodes, "cert-nodes", shardnode.DefaultBFTClientOptions.CertNodes, "number of root nodes to submit each certification request to")
	cmd.Flags().DurationVar(&flags.HeartbeatInterval, "heartbeat-interval", shardnode.DefaultBFTClientOptions.HeartbeatInterval, "how often to check for root-chain inactivity")
	cmd.Flags().DurationVar(&flags.StartupHandshakeInterval, "startup-handshake-interval", shardnode.DefaultBFTClientOptions.StartupHandshakeInterval, "re-send the handshake this often (with backoff, capped at the inactivity timeout) until the first certificate arrives; zero disables")
	cmd.Flags().DurationVar(&flags.InactivityTimeout, "inactivity-timeout", shardnode.DefaultBFTClientOptions.InactivityTimeout, "re-handshake if no certificate has been received for this long")
	cmd.Flags().BoolVar(&flags.EvidenceServe, "evidence-serve", true,
		"retain observed certificates and answer other validators' requests for anchor evidence (#92)")
	cmd.Flags().BoolVar(&flags.EvidenceRecover, "evidence-recover", false,
		"obtain and apply authenticated evidence for this node's own missing execution anchor (#92); off by default — it depends on peers answering and ends in a finality-changing executor call")
	cmd.Flags().StringVar(&flags.RPCServerAddress, "rpc-server-address", "",
		`address for the metrics/health HTTP server, in the form "host:port". Not started if empty.`)
	flags.addSigningAuthorityFlags(cmd)

	return cmd
}

func shardNodeRun(ctx context.Context, flags *shardNodeRunFlags, changed func(string) bool) error {
	var readOperatorStatus func(context.Context) (archivewiring.OperatorStatus, error)
	if flags.Restore {
		if flags.Executor != "engine-api" || flags.ExecutionJournal == "" || flags.ArchiveStore == "" || !flags.ArchivePrune ||
			flags.SigningAuthoritySocket == "" || flags.RestoreTipUC == "" || flags.RestoreTipTR == "" || flags.RestoreTrustBodyID == "" {
			return errors.New("restore requires --executor engine-api, --execution-journal, --archive-store, --archive-prune, a surviving --signing-authority-socket, --tip-uc, --tip-tr and --trust-body-id; local-key restore is refused")
		}
		for _, path := range []string{flags.ExecutionJournal, flags.ExecutionJournal + ".trust", flags.ExecutionJournal + ".handoffs", flags.PathWithDefault(flags.LUCStoreFile, lucStoreFileName)} {
			if _, err := os.Lstat(path); err == nil {
				return fmt.Errorf("restore requires a fresh BFT data directory: %s already exists", path)
			} else if !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("checking fresh BFT path %s: %w", path, err)
			}
		}
	}
	if flags.TrustHistoryProfile2 && flags.ExecutionJournal == "" {
		return errors.New("--trust-history-profile-2 requires --execution-journal")
	}
	if flags.EVMTransitionFile != "" && flags.Executor != "engine-api" {
		return errors.New("--engine-epoch-transition requires --executor=engine-api")
	}
	if flags.ArchiveStore != "" && (flags.ExecutionJournal == "" || len(flags.ArchiveReplicas) != 2) || flags.ArchiveStore == "" && len(flags.ArchiveReplicas) != 0 {
		return archivewiring.ErrConfig
	}
	if flags.ArchivePrune && flags.ArchiveStore == "" {
		return archivewiring.ErrConfig
	}
	if flags.ExecutionJournal != "" && flags.EvidenceRecover {
		return errors.New("--evidence-recover cannot be combined with --execution-journal: evidence recovery bypasses durable journal admission")
	}
	// The record gate needs the store it reads. Checked before anything is built so the refusal is the
	// operator's configuration, not a downstream symptom of a node running without the record it was
	// asked to consult.
	if err := validateCertifiedRecordFlags(flags.CertifiedRecordStore, flags.CertifiedRecordGate); err != nil {
		return err
	}

	keyConf, err := flags.loadKeyConf(flags.baseFlags, false)
	if err != nil {
		return fmt.Errorf("loading key configuration: %w", err)
	}
	authKeyPair, err := keyConf.AuthKeyPair()
	if err != nil {
		return fmt.Errorf("creating auth key pair: %w", err)
	}

	shardConf, err := loadRunShardConf(flags, changed)
	if err != nil {
		return err
	}

	// How certification requests are signed is decided once, here, before anything is built: with the
	// key configuration's signing key as before, or through a signing authority when one is configured
	// (#105). In the second case no local signer is kept or passed to the round.
	signing, err := buildCertificationSigning(&flags.shardNodeSigningFlags, keyConf, shardConf, flags.Restore || flags.TrustHistoryProfile2)
	if err != nil {
		return fmt.Errorf("configuring certification signing: %w", err)
	}
	defer signing.close()
	if flags.Restore {
		guard, ok := signing.authority.(interface {
			RestoreReadiness(context.Context, uint64) error
		})
		if !ok {
			return errors.New("restore requires a signing authority with a surviving high-water record")
		}
		if err := guard.RestoreReadiness(ctx, 0); err != nil {
			return fmt.Errorf("restore signing authority is not ready: %w", err)
		}
	}

	trustBases, err := flags.loadTrustBases(flags.baseFlags)
	if err != nil {
		return fmt.Errorf("loading trust base: %w", err)
	}
	if len(trustBases) != 1 {
		return fmt.Errorf("shard-node run requires exactly one --trust-base, got %d", len(trustBases))
	}
	if flags.Restore && !flags.TrustHistoryProfile2 {
		expected, parseErr := hexToHash(flags.RestoreTrustBodyID)
		actual, hashErr := trustBases[0].Hash(crypto.SHA256)
		if parseErr != nil || hashErr != nil || !bytes.Equal(expected, actual) {
			return fmt.Errorf("restore trust BodyID differs from configured trust base: parse=%v hash=%v", parseErr, hashErr)
		}
	}
	initialTrustStore, err := shardnode.NewFileTrustBaseStore(trustBases[0], flags.observe.Logger())
	if err != nil {
		return fmt.Errorf("creating trust base store: %w", err)
	}
	var trustBaseStore shardnode.TrustBaseStore = initialTrustStore
	var historicalTrust *shardnode.HistoricalTrustBaseStore

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

	// The configuration THIS node was started with, hashed the way certificates commit to it. Every
	// certificate this node accepts — live, restored from disk, or recovered as evidence — must name
	// it (#134), so it is computed once here, for every deployment, not only when recovery is on.
	//
	// Computed BEFORE the executor so the engine-api adapter can take it as part of its derivation
	// context: a seal build derives the canonical root input from a certificate authenticated
	// against THIS node's configuration, never the certificate's own (F2c §3). It used to be
	// computed after buildExecutor, which would have meant either recomputing it or deriving against
	// an unauthenticated configuration.
	confHash, err := shardConf.Hash(crypto.SHA256)
	if err != nil {
		return fmt.Errorf("hashing the shard configuration: %w", err)
	}

	// The checked genesis origin and its bootstrap snapshot, when the node was configured with the two
	// artifacts `ubft engine-api genesis` emits. The origin is re-derived from the finalized JSON
	// against this node's own full shard configuration and pinned artifact, so it is this node's only
	// chance to notice it was handed the wrong genesis; the operator's expected identity, when set, is
	// checked against it. The adapter uses this snapshot for v2 block-1 derivation.
	var origin registrygenesis.GenesisOrigin
	var bootstrap registryproof.Snapshot
	if flags.GenesisFile != "" {
		// M1 pins one root epoch from trustBases[0]. H1/H2 multi-epoch trust bases must
		// select the epoch bound to the genesis record instead of assuming the first.
		origin, bootstrap, err = loadGenesisOriginLayout(shardConf, flags.GenesisFile, flags.ExpectedOriginIdentity, trustBases[0].GetEpoch(), flags.RegistryLayout)
		if err != nil {
			return err
		}
	}
	if err := requireRestoreTrustAnchor(flags.Restore, origin, trustBases[0].GetEpoch()); err != nil {
		return err
	}
	if err := validateExecutionJournalFlags(flags, origin); err != nil {
		return err
	}
	evmTransition, err := loadEngineEpochTransition(flags.EVMTransitionFile, trustBases[0].GetEpoch())
	if err != nil {
		return err
	}

	verifierContext := &engineapi.VerifierContext{
		NetworkID:     shardConf.NetworkID,
		PartitionID:   shardConf.PartitionID,
		ShardID:       shardConf.ShardID,
		ShardConfHash: confHash,
		RootEpoch:     trustBases[0].GetEpoch(),
		TrustBases:    trustBaseStore,
		Transition:    evmTransition,
		// Kept for compatibility with callers of the former v1 adapter. The live v2 path reads the
		// applied root round from the verified parent registry snapshot instead.
		Cursor: engineapi.CursorNotActivated(),

		// The checked execution genesis and its bootstrap snapshot, when configured. They are
		// verifier-owned and consumed by the v2 bootstrap derivation.
		GenesisOrigin:     origin,
		BootstrapSnapshot: bootstrap,
	}
	executor, err := buildExecutor(ctx, flags, shardConf, verifierContext)
	if err != nil {
		return err
	}
	if closer, ok := executor.(interface{ Close() }); ok {
		defer closer.Close()
	}
	var executionID [32]byte
	var handoffFollower *shardnode.HandoffFollower
	if flags.ExecutionJournal != "" {
		adapter, ok := executor.(*engineapi.Adapter)
		if !ok || !origin.Valid() {
			return errors.New("execution journal requires a checked engine-api executor and genesis origin")
		}
		executionID, err = adapter.CheckedExecutionConfigIdentity(ctx, [32]byte(origin.ExecutionConfigIdentity()))
		if err != nil {
			return fmt.Errorf("binding checked companion execution identity: %w", err)
		}
		historyDB, openErr := boltdb.New(flags.ExecutionJournal + ".trust")
		if openErr != nil {
			return fmt.Errorf("opening historical trust store: %w", openErr)
		}
		defer historyDB.Close()
		historical, openErr := shardnode.NewHistoricalTrustBaseStore(ctx, historyDB, trustBases[0], executionID, flags.TrustHistoryProfile2)
		if openErr != nil {
			return fmt.Errorf("verifying historical trust store: %w", openErr)
		}
		trustBaseStore = historical
		historicalTrust = historical
		verifierContext.TrustBases = historical
		if flags.TrustHistoryProfile2 {
			verifierContext.EpochAuthority = historical
		}
	}
	if origin.Valid() && flags.Executor == "engine-api" {
		// The agreed genesis hash: buildExecutor has just required the paired client's block 0 to equal
		// origin.BlockHash(), so this line reports a value the configuration and the client agree on.
		flags.observe.Logger().Info("configured genesis origin",
			"originIdentity", origin.Identity().Hex(),
			"genesisBlockHash", origin.BlockHash().Hex(),
			"stateRoot", origin.StateRoot().Hex(),
			"fullShardConfHash", origin.FullShardConfHash().Hex())
	}

	activePeers, err := shardnode.NewActivePeers(peer.ID(), shardConf.Validators)
	if err != nil {
		return fmt.Errorf("deriving the shard peers: %w", err)
	}
	// Every shard-membership consumer (block dissemination, the archive and journal servers, the journal suffix and evidence providers)
	// follows this set: the genesis validators until a verified assignment step is installed, then the active assignment's.
	disseminator, err := buildDisseminator(peer, flags.observe, shardConf.Validators, activePeers, flags.TrustHistoryProfile2)
	if err != nil {
		return fmt.Errorf("creating dissemination transport: %w", err)
	}

	lucStorePath := flags.PathWithDefault(flags.LUCStoreFile, lucStoreFileName)
	store := shardnode.NewFileStore(lucStorePath)
	if flags.ExecutionJournal != "" {
		if flags.Executor != "engine-api" || !origin.Valid() {
			return errors.New("--execution-journal requires --executor engine-api and a checked --genesis/--full-shard-conf origin")
		}
		if flags.CertifiedRecordStore != "" {
			return errors.New("--execution-journal cannot share authority with the legacy --certified-record-store; v2 record/readiness wiring belongs to D2-B")
		}
		if _, statErr := os.Stat(lucStorePath); statErr == nil {
			return fmt.Errorf("execution journal requires fresh D2 lane state: legacy LUC checkpoint exists at %s; no automatic migration", lucStorePath)
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			return fmt.Errorf("checking legacy LUC checkpoint: %w", statErr)
		}
		store = nil
	}

	if flags.TrustHistoryProfile2 && flags.ExecutionJournal != "" {
		// The archive server authorizes peers from this set. It is created from the genesis validators and rebuilt from the persisted
		// verified assignment steps further down (handoff follower Restore, or CatchUp for a restoring node); until that is done it
		// authorizes nobody instead of a genesis set that a persisted step may have retired. Released right after the replay.
		activePeers.Hold()
	}
	node, err := shardnode.New(
		peer,
		shardNet,
		signing.local,
		shardConf.PartitionID,
		shardConf.ShardID,
		confHash,
		trustBaseStore,
		executor,
		disseminator,
		store,
		flags.observe.Logger(),
		shardnode.BFTClientOptions{
			HandshakeNodes:           flags.HandshakeNodes,
			CertNodes:                flags.CertNodes,
			HeartbeatInterval:        flags.HeartbeatInterval,
			InactivityTimeout:        flags.InactivityTimeout,
			StartupHandshakeInterval: flags.StartupHandshakeInterval,
		},
	)
	if err != nil {
		return fmt.Errorf("creating shard node: %w", err)
	}
	// The adapter authenticates certificates under the same per-epoch configuration set as the admission, not under a scan of every
	// installed assignment. Set before Run.
	verifierContext.SetConfForEpoch(node.ShardConfForEpoch)
	if signing.authority != nil {
		// Before Run, and before anything else is attached. P-id still applies ahead of this signer. A
		// node resumed from its checkpoint signs only through this signer's authority record; with the
		// local key it stays non-voting (#105 step 4).
		node.SetCertificationSigner(signing.authority)
	}
	if flags.ExecutionJournal != "" {
		limits := configuredprogress.JournalLimits{Candidates: flags.JournalCandidates, Observations: flags.JournalObservations, Bytes: flags.JournalBytes}
		journalPath := flags.ExecutionJournal
		journalStore, openErr := configuredprogress.OpenConfiguredV2(journalPath, configuredprogress.Settings{Retain: 128})
		if openErr != nil {
			return fmt.Errorf("opening execution journal: %w", openErr)
		}
		defer journalStore.Close()
		recordCtx := certifiedstore.Context{NetworkID: shardConf.NetworkID, PartitionID: shardConf.PartitionID, ShardID: shardConf.ShardID, FullShardConfHash: confHash, Registry: origin.ProofContext(), TrustBases: trustBaseStore}
		journalCtx := configuredprogress.Context{Origin: origin, ExecutionConfigV2: executionID, Observation: rootinput.ObservationContextV2{NetworkID: shardConf.NetworkID, PartitionID: shardConf.PartitionID, ShardID: shardConf.ShardID, ShardConfHash: confHash, ConfForEpoch: node.ShardConfForEpoch, RootEpoch: trustBases[0].GetEpoch(), TrustBases: trustBaseStore}, Record: recordCtx}
		if flags.TrustHistoryProfile2 {
			journalCtx.Observation.EpochAuthority = historicalTrust
			journalCtx.Record.EpochAuthority = historicalTrust
		}
		var archiveLocal *archive.Store
		var archiveSubject archive.Context
		var archiveHost shardnode.EvidenceHost
		var archiveReplicas [2]libp2ppeer.ID
		var archiveAllowed []libp2ppeer.ID
		var publisher *archivewiring.Publisher
		archiveTransportLimits := archivewiring.DefaultLimits()
		if flags.ArchiveStore != "" {
			if flags.Restore {
				entries, readErr := os.ReadDir(flags.ArchiveStore)
				if readErr == nil && len(entries) != 0 {
					return fmt.Errorf("restore archive directory %s is not empty; supply a fresh directory", flags.ArchiveStore)
				}
				if readErr != nil && !errors.Is(readErr, fs.ErrNotExist) {
					return fmt.Errorf("checking restore archive directory: %w", readErr)
				}
			}
			adapter, ok := executor.(*engineapi.Adapter)
			if !ok || !origin.Valid() {
				return archivewiring.ErrConfig
			}
			identity, e := adapter.CheckedExecutionConfigBytes(ctx, [32]byte(origin.ExecutionConfigIdentity()))
			if e != nil {
				return fmt.Errorf("checking archive execution identity: %w", e)
			}
			archiveSubject, e = archivewiring.ContextFrom(journalCtx, identity)
			if e != nil {
				return fmt.Errorf("checking archive subject: %w", e)
			}
			archiveLocal, e = archive.Open(flags.ArchiveStore)
			if e != nil {
				return fmt.Errorf("opening archive: %w", e)
			}
			archiveAllowed, e = shardPeers(peer, shardConf.Validators)
			if e != nil {
				return e
			}
			// Structure only: membership is checked against the installed set after the replay (admitArchivePeers).
			archiveReplicas, e = parseArchiveReplicas(flags.ArchiveReplicas, peer.ID())
			if e != nil {
				return e
			}
			archiveHost, e = archivewiring.NewPeerGatedHost(peer, archiveTransportLimits.PerPeer)
			if e != nil {
				return e
			}
			receiptSource, ok := executor.(*engineapi.Adapter)
			if !ok {
				return errors.New("receipt-complete archive requires an EVM adapter")
			}
			archiveServer, e := archivewiring.NewServer(archiveLocal, archiveSubject, archivewiring.JournalVerifier(journalStore, journalCtx, limits, archiveSubject, receiptSource), archiveAllowed, archiveTransportLimits)
			if e != nil {
				return fmt.Errorf("starting archive replica: %w", e)
			}
			if flags.TrustHistoryProfile2 {
				archiveServer.SetBundleVerifier(archivewiring.BundleAdmission(historicalTrust, node.ShardConfForEpoch))
			}
			// Who may fetch from and publish to this node's archive is the validator set of the ACTIVE assignment, not the genesis one:
			// a joiner must be able to restore before it can acknowledge, and a retired validator must not keep access.
			archiveServer.SetPeerAuthorizer(activePeers.Allowed)
			archiveServer.SetLogger(flags.observe.Logger())
			archiveServer.Register(ctx, peer)
		}
		restoringHandoffHistory := flags.TrustHistoryProfile2
		var restoredHandoffTerminals []handoffTerminalCertificate
		if flags.TrustHistoryProfile2 {
			currentRoots := make([]libp2ppeer.ID, 0, len(bootNodes))
			for _, root := range bootNodes {
				currentRoots = append(currentRoots, root.ID)
			}
			handoffFollower = &shardnode.HandoffFollower{Host: peer, History: historicalTrust, Partition: shardConf.PartitionID, Shard: shardConf.ShardID,
				ConfHash: confHash, AnchorEpoch: trustBases[0].GetEpoch(), Directory: flags.ExecutionJournal + ".handoffs", CurrentRoots: currentRoots,
				ArchiveReplicas: archiveReplicas[:],
				OnInstalled: func(ctx context.Context, bundle handoffdelivery.Bundle, verified handoffdelivery.Verified) error {
					if verified.Shard.UC == nil || verified.Shard.UC.InputRecord == nil || verified.Shard.TR == nil || verified.Shard.IR == nil ||
						!bytes.Equal(verified.Shard.IR.BlockHash, bundle.Proof.Control.FrozenParent) ||
						!bytes.Equal(verified.Shard.UC.InputRecord.BlockHash, verified.Shard.IR.BlockHash) ||
						verified.Shard.UC.GetRoundNumber() != verified.Shard.IR.RoundNumber {
						return errors.New("verified handoff lacks the terminal shard certificate")
					}
					// The terminal certificate belongs to the epoch this handoff ends, whose configuration is the one the
					// verified snapshot carries (checked against the followed assignment), not the genesis configuration. The store
					// stays bound to the genesis origin; the per-epoch resolver adds the certificate's own shard epoch to the installed set
					// (the store's other durable state sits at other epochs) and refuses a conflict with an installed configuration.
					terminalCtx, err := configuredprogress.TerminalContext(journalCtx, verified.Shard.ShardConfHash, verified.Shard.TR.Epoch)
					if err != nil {
						return fmt.Errorf("handoff terminal certificate context: %w", err)
					}
					terminal, err := rootinput.AuthenticateObservationV2(ctx, terminalCtx.Observation, verified.Shard.UC, verified.Shard.TR)
					if err != nil {
						return fmt.Errorf("authenticating handoff terminal certificate: %w", err)
					}
					if restoringHandoffHistory {
						uc := *verified.Shard.UC
						tr := *verified.Shard.TR
						restoredHandoffTerminals = append(restoredHandoffTerminals, handoffTerminalCertificate{uc: &uc, tr: &tr})
					} else {
						prepared, _, err := journalStore.PrepareObservation(ctx, terminalCtx, terminal)
						if err != nil {
							return fmt.Errorf("preparing handoff terminal certificate: %w", err)
						}
						if _, _, err := journalStore.CommitObservation(prepared); err != nil {
							return fmt.Errorf("persisting handoff terminal certificate: %w", err)
						}
					}
					if err := verifierContext.InstallHandoffTransition(bundle, verified); err != nil {
						return err
					}
					old, err := historicalTrust.GetByEpoch(ctx, bundle.Proof.Record.Epoch)
					if err != nil {
						return err
					}
					anchor := &rctypes.EpochAnchor{GenesisID: verified.Genesis.ID(), Epoch: verified.Genesis.Epoch,
						Slot: verified.Genesis.Start - 1, StateRoot: verified.Record.StateRoot[:]}
					step, err := handoffdelivery.AssignmentStepOf(bundle, verified)
					if err != nil {
						return err
					}
					// The step is verified (the bundle's candidate must replace the checkpoint's installed assignment): it is the only
					// source of the shard configuration hashes the client will accept per shard epoch. Installed before the handoff is
					// activated, so no certificate of the new root epoch can be verifiable while its configuration is still unknown; and
					// again from every persisted bundle on restart, which rebuilds the set from genesis plus the verified history.
					if err := installVerifiedAssignment(node, activePeers, bundle, step); err != nil {
						return err
					}
					if err := noteJoinerStep(signing, bundle, step, node.ShardConfForEpoch); err != nil {
						return err
					}
					transition, err := handoff.TransitionFromInstalledAnchor(bundle.Proof, old, bundle.Body, anchor, verified.Shard.IRTR, step)
					if err != nil {
						return err
					}
					rawTransition, err := transition.Encode()
					if err != nil {
						return err
					}
					if err := executor.(*engineapi.Adapter).InstallEpochTransition(rawTransition); err != nil {
						return err
					}
					if archiveLocal != nil {
						raw, err := handoffdelivery.EncodeBundle(bundle)
						if err != nil {
							return err
						}
						// The archive copy is availability for others: a second, conflicting or unverifiable copy never stops this node's own
						// activation (only a fault of the local store does).
						if err := archivewiring.RetainActivatedBundle(ctx, archiveLocal, archive.BundleRequest{Context: archiveSubject, Epoch: bundle.Body.Epoch}, raw,
							archivewiring.BundleAdmission(historicalTrust, node.ShardConfForEpoch), flags.observe.Logger()); err != nil {
							return err
						}
					}
					if err := historicalTrust.ActivateHandoff(bundle.Body.Epoch); err != nil {
						return err
					}
					flags.observe.Logger().Info("handoff activated", "rootEpoch", bundle.Body.Epoch)
					return nil
				}}
			if archiveLocal != nil {
				handoffFollower.FetchArchive = func(ctx context.Context, id libp2ppeer.ID, epoch uint64) (handoffdelivery.Bundle, error) {
					raw, err := archivewiring.FetchBundle(ctx, archiveHost, id, archive.BundleRequest{Context: archiveSubject, Epoch: epoch}, archiveTransportLimits)
					err = handoffArchiveRefusal(err)
					var bundle handoffdelivery.Bundle
					if err == nil {
						bundle, err = handoffdelivery.DecodeBundle(raw)
					}
					return bundle, err
				}
			}
		}
		var restoreLineage func(context.Context) error
		if handoffFollower != nil {
			restoreLineage = func(ctx context.Context) error {
				if err := handoffFollower.Restore(ctx); err != nil {
					return err
				}
				if !flags.Restore {
					restoringHandoffHistory = false
				}
				return nil
			}
		}
		if startupErr := runProfile2JournalStartup(ctx, restoreLineage,
			func(ctx context.Context) error {
				_, _, err := journalStore.Initialize(ctx, journalCtx)
				return err
			},
			func(ctx context.Context) error { return journalStore.EnableJournal(ctx, journalCtx, limits) },
			func(ctx context.Context) error {
				return reapplyHandoffTerminalCertificatesWithArchive(ctx, journalStore, journalStore, archiveLocal,
					archiveSubject, journalCtx, limits, restoredHandoffTerminals)
			}); startupErr != nil {
			flags.observe.Logger().Error("profile2 handoff terminal repair failed", "error", startupErr)
			return startupErr
		}
		// A plain restart of a joiner: the persisted verified steps were replayed above; bind the key of the latest one that names this
		// node, or refuse. (A restore does the same after its catch-up, below.)
		if !flags.Restore {
			if err := finishJoinerKey(signing); err != nil {
				return err
			}
		}
		// Frontier enablement is part of the archive setup that follows the replica validation: it runs from this one action after the
		// persisted replay on a plain run, and after CatchUp and before the archive replay on a restore.
		enableArchiveFrontier := func(ctx context.Context) error {
			if archiveLocal == nil || !flags.ArchivePrune {
				return nil
			}
			policy := frontier.Policy{Context: archiveSubject, Replicas: [2]string{archiveReplicas[0].String(), archiveReplicas[1].String()}, Binding: archivewiring.CertifiedBinding{Context: journalCtx, Subject: archiveSubject}, Availability: archivewiring.ReplicaAvailability{Context: ctx, Host: archiveHost, Replicas: archiveReplicas, Limits: archiveTransportLimits}}
			journalStore.SetLogger(flags.observe.Logger())
			if e := journalStore.EnableFrontier(ctx, journalCtx, limits, policy); e != nil {
				return fmt.Errorf("authenticating certified frontier: %w", e)
			}
			return nil
		}
		if !flags.Restore {
			// The persisted verified steps are replayed into the set (OnInstalled): the configured replicas are validated against the
			// rebuilt set, and only then may serving start (the hold ends) and the frontier use them.
			if err := admitArchivePeers(activePeers, archiveReplicas, archiveLocal != nil, flags.TrustHistoryProfile2); err != nil {
				return err
			}
			if err := enableArchiveFrontier(ctx); err != nil {
				return err
			}
		}
		if flags.Restore {
			uc, tr, pinErr := loadRestorePin(flags.RestoreTipUC, flags.RestoreTipTR)
			if pinErr != nil {
				return pinErr
			}
			catchUpHistory := func(ctx context.Context) error {
				if !flags.TrustHistoryProfile2 {
					// No handoff history to install: the installed set is the genesis one, and the replicas are validated against it
					// before the archive replay.
					return admitArchivePeers(activePeers, archiveReplicas, archiveLocal != nil, false)
				}
				if err := peer.BootstrapConnect(ctx, flags.observe.Logger()); err != nil {
					return fmt.Errorf("restore bootstrap connect: %w", err)
				}
				if _, err := handoffFollower.CatchUp(ctx, uc.GetRootEpoch()); err != nil {
					return err
				}
				// Every step up to the pinned epoch is verified and installed: the set is rebuilt. The configured replicas are validated
				// against it before the hold ends; a failed catch-up or validation never releases the hold.
				if err := admitArchivePeers(activePeers, archiveReplicas, archiveLocal != nil, true); err != nil {
					return err
				}
				if err := finishJoinerKey(signing); err != nil {
					return err
				}
				pin, err := hexToHash(flags.RestoreTrustBodyID)
				if err != nil {
					return err
				}
				bodyID, err := historicalTrust.BodyID(uc.GetRootEpoch())
				if err != nil || !bytes.Equal(pin, bodyID[:]) {
					return fmt.Errorf("restore trust BodyID differs from verified current history: %v", err)
				}
				return nil
			}
			restoreArchive := func(ctx context.Context) error {
				genesis, genesisErr := executor.GenesisBlock(ctx)
				if genesisErr != nil {
					return fmt.Errorf("reading restore genesis identity: %w", genesisErr)
				}
				restorer := &archivewiring.ArchiveRestore{Journal: journalStore, Context: journalCtx, JournalLimits: limits,
					Archive: archiveLocal, Subject: archiveSubject, Replicas: archiveReplicas, Host: archiveHost,
					Limits: archiveTransportLimits, Adapter: executor.(*engineapi.Adapter), Genesis: genesis, TipUC: uc, TipTR: tr}
				return restorer.Restore(ctx)
			}
			var repairRestoredHandoffs func(context.Context) error
			if flags.TrustHistoryProfile2 {
				repairRestoredHandoffs = func(ctx context.Context) error {
					restoringHandoffHistory = false
					return reapplyHandoffTerminalCertificatesWithArchive(ctx, journalStore, journalStore, archiveLocal,
						archiveSubject, journalCtx, limits, restoredHandoffTerminals)
				}
			}
			if restoreErr := runProfile2ArchiveRestore(ctx, catchUpHistory, enableArchiveFrontier, restoreArchive, repairRestoredHandoffs); restoreErr != nil {
				flags.observe.Logger().Error("profile2 archive restore failed", "error", restoreErr)
				return restoreErr
			}
		}
		journalImage, loadErr := journalStore.LoadJournal(ctx, journalCtx, limits)
		if loadErr != nil {
			return fmt.Errorf("verifying execution journal: %w", loadErr)
		}
		progress, _, loadErr := journalStore.Load(ctx, journalCtx)
		if loadErr != nil {
			return fmt.Errorf("loading execution progress: %w", loadErr)
		}
		if observed, ok := progress.Observed(); ok {
			node.MarkJournalRestored(observed.Certificate().GetRoundNumber())
			cert := observed.Certificate()
			var height uint64
			for _, entry := range journalImage.Candidates {
				if entry.Certified && entry.ResultingUC != nil && entry.ResultingUC.GetRootRoundNumber() == cert.GetRootRoundNumber() && bytes.Equal(entry.Candidate.Hash, cert.InputRecord.BlockHash) {
					height = entry.Candidate.Number
					break
				}
			}
			flags.observe.Logger().Info("execution journal restored", "block", fmt.Sprintf("%x", cert.InputRecord.BlockHash), "height", height, "round", cert.GetRoundNumber(), "rootRound", cert.GetRootRoundNumber())
		}
		node.SetProposalJournal(configuredadmission.ProposalJournal{Store: journalStore, Context: journalCtx, Limits: limits})
		recoveryExecutor, ok := executor.(configuredadmission.RecoveryExecutor)
		if !ok {
			return errors.New("execution journal needs an executor with finalized identity and recovery forkchoice")
		}
		genesis, genesisErr := executor.GenesisBlock(ctx)
		if genesisErr != nil {
			return fmt.Errorf("reading recovery genesis identity: %w", genesisErr)
		}
		coordinator := &configuredadmission.ExecutionRecovery{Store: journalStore, Context: journalCtx, JournalLimits: limits, Executor: recoveryExecutor, Gate: node.FinalityGate(), Log: flags.observe.Logger(), Genesis: genesis, Limits: configuredadmission.DefaultRecoveryLimits()}
		server, serverErr := shardnode.NewJournalServer(configuredadmission.JournalProvider{Store: journalStore, Context: journalCtx, Limits: limits}, shardnode.DefaultJournalTransportLimits())
		if serverErr != nil {
			return fmt.Errorf("starting journal suffix server: %w", serverErr)
		}
		// Who may fetch from this node's journal and whom it asks follow the active assignment (held until the persisted steps are replayed).
		server.SetPeerAuthorizer(activePeers.Allowed)
		server.Register(peer)
		coordinator.Host, coordinator.ProviderSource, coordinator.TransportLimits = peer, activePeers, shardnode.DefaultJournalTransportLimits()
		if archiveLocal != nil {
			source := &archivewiring.RecoverySource{Context: journalCtx, Subject: archiveSubject, Local: archiveLocal, Host: archiveHost,
				Replicas: archiveReplicas, Limits: archiveTransportLimits, MaxBlocks: configuredadmission.DefaultRecoveryLimits().Blocks, Log: flags.observe.Logger()}
			coordinator.FetchArchive = func(ctx context.Context, after shardnode.BlockRef, target []byte) ([]shardnode.JournalFetchEntry, error) {
				entries, fetchErr := source.FetchSuffix(ctx, after, target)
				if errors.Is(fetchErr, archivewiring.ErrArchiveRecoveryInvalid) {
					return nil, fmt.Errorf("%w: %w", configuredadmission.ErrRecoveryInvalid, fetchErr)
				}
				if errors.Is(fetchErr, archivewiring.ErrArchiveRecoveryUnavailable) {
					return nil, fmt.Errorf("%w: %w", configuredadmission.ErrRecoveryUnavailable, fetchErr)
				}
				return entries, fetchErr
			}
		}
		node.SetJournalRecovery(coordinator, coordinator)
		if openErr = node.SetJournalAdmission(configuredadmission.JournalFactory{Store: journalStore, Origin: origin, ExecutionConfigV2: executionID, Limits: limits, CatchUp: coordinator.AcquireForCertificate, OnStop: node.ReportJournalStop, Logger: flags.observe.Logger(), EpochAuthority: journalCtx.Observation.EpochAuthority}); openErr != nil {
			return fmt.Errorf("enabling journal certification admission: %w", openErr)
		}
		flags.observe.Logger().Info("execution journal verified", "candidates", len(journalImage.Candidates), "observations", len(journalImage.Observations), "bytes", journalImage.Bytes)
		if flags.ArchiveStore != "" {
			metrics, e := archivewiring.NewMetrics(flags.observe.Meter("archive"))
			if e != nil {
				return e
			}
			publisher = &archivewiring.Publisher{Journal: journalStore, Context: journalCtx, JournalLimits: limits, Archive: archiveLocal, Subject: archiveSubject, Host: archiveHost, Replicas: archiveReplicas, Limits: archiveTransportLimits, Log: flags.observe.Logger(), Metrics: metrics, ReceiptSource: executor.(*engineapi.Adapter)}
			if flags.TrustHistoryProfile2 {
				publisher.BundleVerifier = archivewiring.BundleAdmission(historicalTrust, node.ShardConfForEpoch)
			}
			if e := publisher.Validate(); e != nil {
				_ = metrics.Close()
				return e
			}
			archiveCtx, cancelArchive := context.WithCancel(ctx)
			archiveDone := make(chan struct{})
			go func() { defer close(archiveDone); _ = publisher.Run(archiveCtx) }()
			defer func() { cancelArchive(); <-archiveDone; _ = metrics.Close() }()
			if flags.ArchivePrune {
				worker := &archivewiring.FrontierWorker{Journal: journalStore, Context: journalCtx, Limits: limits, Archive: archiveLocal, Subject: archiveSubject, Replicas: archiveReplicas, Host: archiveHost, TransportLimits: archiveTransportLimits, Log: flags.observe.Logger(), Finalized: recoveryExecutor.Finalized}
				pruneDone := make(chan struct{})
				go func() { defer close(pruneDone); _ = worker.Run(archiveCtx) }()
				defer func() { cancelArchive(); <-pruneDone }()
			}
		}
		readOperatorStatus = func(statusCtx context.Context) (archivewiring.OperatorStatus, error) {
			rootEpoch := trustBases[0].GetEpoch()
			var activated []uint64
			if historicalTrust != nil {
				if active, ok := historicalTrust.CurrentRootEpoch(); ok && active >= rootEpoch {
					rootEpoch = active
					for epoch := trustBases[0].GetEpoch() + 1; epoch <= active; epoch++ {
						activated = append(activated, epoch)
						if epoch == ^uint64(0) {
							break
						}
					}
				}
			}
			var progress [2]archivewiring.ReplicaProgress
			if publisher != nil {
				progress = publisher.ReplicaProgress()
			}
			var authority *archivewiring.AuthorityReport
			if probe, ok := signing.authority.(interface {
				RestoreStatus(context.Context) (signingauthority.Status, error)
			}); ok {
				probeCtx, cancel := context.WithTimeout(statusCtx, 1500*time.Millisecond)
				defer cancel()
				status, statusErr := probe.RestoreStatus(probeCtx)
				authority = &archivewiring.AuthorityReport{Reachable: statusErr == nil, Error: errorString(statusErr)}
				if statusErr == nil {
					authority.RootEpoch, authority.ShardEpoch, authority.ReservedRound = status.RootEpoch, status.ShardEpoch, status.ReservedRound
				}
			}
			return archivewiring.ReadOperatorStatus(statusCtx, journalStore, journalCtx, limits,
				archiveLocal, archiveSubject, archiveReplicas, rootEpoch, activated, progress, authority)
		}
	}

	// The follower's wait for the leader's block comes from the shard's own T2, never from a
	// framework default: a budget longer than T2 makes this node consume certificates more slowly
	// than the root chain issues them, so a silent leader leaves it permanently behind instead of
	// costing it one round. See shardnode.AwaitTimeoutForT2 — nothing configured this before, so
	// every deployment ran the 5s default whatever its T2 was.
	awaitTimeout := shardnode.AwaitTimeoutForT2(shardConf.T2Timeout)
	node.SetAwaitTimeout(awaitTimeout)

	// The certified-block record (#14): nothing is constructed unless a store path is configured, and then
	// the record is reloaded and reported without changing voting. See startCertifiedRecord.
	if flags.CertifiedRecordStore != "" {
		closeRecord, err := startCertifiedRecord(ctx, flags, shardConf, confHash, trustBaseStore, trustBases[0].GetEpoch(), executor, node)
		if err != nil {
			return err
		}
		defer closeRecord()
	}

	// Authenticated-evidence anchor recovery (#92, docs/design/f6b-quiet-tail-anchor-recovery.md).
	// Two switches, because they cost different things: serving retains certificates this node has
	// already authenticated and answers bounded requests from peers, taking no new dependency;
	// recovering depends on peers answering and ends in a finality-changing executor call.
	recoveryOpts := shardnode.DefaultRecoveryOptions()
	recoveryOpts.Serve = flags.EvidenceServe
	recoveryOpts.Recover = flags.EvidenceRecover
	if recoveryOpts.Recover {
		recoveryOpts.ProviderSource = activePeers
	}
	if err := node.EnableRecovery(recoveryOpts); err != nil {
		return fmt.Errorf("enabling anchor recovery: %w", err)
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
		"nodeID", peer.ID().String(), "partitionID", shardConf.PartitionID, "executor", flags.Executor,
		"t2Timeout", shardConf.T2Timeout, "leaderAwaitTimeout", awaitTimeout, "certificationSigning", signing.describe)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return node.Run(gctx) })
	g.Go(func() error { return serveShardNodeRPC(gctx, flags, node, readOperatorStatus) })
	if handoffFollower != nil {
		g.Go(func() error { return handoffFollower.Run(gctx) })
	}
	return g.Wait()
}

func validateExecutionJournalFlags(flags *shardNodeRunFlags, origin registrygenesis.GenesisOrigin) error {
	if flags.Executor == "engine-api" && origin.Valid() && flags.ExecutionJournal == "" {
		return errors.New("engine-api seal deployments require --execution-journal in M1; supply a path in fresh D2 state")
	}
	return nil
}

// serveShardNodeRPC exposes /api/v1/metrics (Prometheus, when --metrics
// prometheus is set) and /api/v1/health (JSON, always) — see
// docs/engine-api-adapter-plan.md C3.2/C3.4. Mirrors root_node.go's own
// RPC server construction.
func serveShardNodeRPC(ctx context.Context, flags *shardNodeRunFlags, node *shardnode.Node,
	readOperatorStatus func(context.Context) (archivewiring.OperatorStatus, error)) error {
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
	if readOperatorStatus != nil {
		mux.HandleFunc("GET /api/v1/operator/status", func(w http.ResponseWriter, r *http.Request) {
			writeOperatorStatus(w, r, readOperatorStatus)
		})
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
}

// buildDisseminator picks the transport based on how many validators the
// shard conf actually names. One validator (the common single-node dev
// case, and A2/A3's own test topology) needs nothing over the network —
// LoopbackDisseminator costs nothing and is never called. Two or more means
// a real multi-validator shard (C2), which needs NetDisseminator's actual
// libp2p connection to the others.
func buildDisseminator(p *network.Peer, obs Observability, validators []*types.NodeInfo, active shardnode.PeerLister, followsAssignments bool) (shardnode.Disseminator, error) {
	peers, err := shardPeers(p, validators)
	if err != nil {
		return nil, err
	}
	if len(peers) == 0 && !followsAssignments {
		return shardnode.NewLoopbackDisseminator(), nil
	}
	// The recipients are the active assignment's validators as of each publish, not the genesis ones: after a rotation the successor
	// quorum must be reachable.
	return shardnode.NewNetDisseminatorFrom(p, obs, active)
}

// parseArchiveReplicas is the structural half of the archive replica configuration: exactly two distinct, valid peer IDs, neither this
// node. It runs at startup, before the handoff follower is built, because the follower fetches its verified bundles from these replicas;
// they supply availability only, never the installed membership (their bytes pass the bundle verifier before anything is installed).
// Whether they are validators of the installed assignment is requireArchiveReplicasInstalled, which needs the replayed set.
func parseArchiveReplicas(raws []string, self libp2ppeer.ID) ([2]libp2ppeer.ID, error) {
	var out [2]libp2ppeer.ID
	if len(raws) != 2 {
		return out, archivewiring.ErrConfig
	}
	for i, raw := range raws {
		id, err := libp2ppeer.Decode(raw)
		if err != nil {
			return [2]libp2ppeer.ID{}, fmt.Errorf("%w: archive replica %d: %v", archivewiring.ErrConfig, i, err)
		}
		if id == self {
			return [2]libp2ppeer.ID{}, fmt.Errorf("%w: archive replica cannot be self", archivewiring.ErrConfig)
		}
		out[i] = id
	}
	if out[0] == out[1] {
		return [2]libp2ppeer.ID{}, fmt.Errorf("%w: the two archive replicas must be distinct", archivewiring.ErrConfig)
	}
	return out, nil
}

// requireArchiveReplicasInstalled is the membership half: both replicas must be validators of the INSTALLED assignment (installed is
// ActivePeers.Peers(), which reflects the replayed verified steps and never contains this node). Run it only after the persisted replay
// (plain run) or CatchUp (restore); against the genesis set it would refuse a replica that a later step installed.
func requireArchiveReplicasInstalled(replicas [2]libp2ppeer.ID, installed []libp2ppeer.ID) error {
	for _, replica := range replicas {
		found := false
		for _, candidate := range installed {
			found = found || candidate == replica
		}
		if !found {
			return fmt.Errorf("%w: archive replica %s is not a validator of the installed shard assignment", archivewiring.ErrConfig, replica)
		}
	}
	return nil
}

// admitArchivePeers validates the configured replicas against the installed set and only then ends the startup hold on the archive peer
// set (held: the node holds it, which is the profile-2 case). A refusal leaves the hold in place, so nobody is authorized from a set
// the node has just found inconsistent with its configuration. archived is whether an archive is configured at all.
func admitArchivePeers(peers *shardnode.ActivePeers, replicas [2]libp2ppeer.ID, archived, held bool) error {
	if archived {
		if err := requireArchiveReplicasInstalled(replicas, peers.Peers()); err != nil {
			return err
		}
	}
	if held {
		peers.Release()
	}
	return nil
}

// shardPeers is the shard's other validators from the shard conf, excluding this node. It is the
// set the leader disseminates blocks to and the set a returning node asks for anchor evidence —
// deliberately the same set, because both are "the validators of this shard" and a node that is
// trusted to send blocks is no more trusted to serve evidence: the evidence predicate authenticates
// everything against this node's own trust base regardless of who supplied it (§3).
func shardPeers(p *network.Peer, validators []*types.NodeInfo) ([]libp2ppeer.ID, error) {
	selfID := p.ID().String()
	var peers []libp2ppeer.ID
	for _, v := range validators {
		if v.NodeID == selfID {
			continue
		}
		id, err := libp2ppeer.Decode(v.NodeID)
		if err != nil {
			return nil, fmt.Errorf("invalid validator node id %q in shard conf: %w", v.NodeID, err)
		}
		peers = append(peers, id)
	}
	return peers, nil
}

// hexToHash parses a 0x-prefixed 32-byte hash from configuration.
func hexToHash(s string) (shardnode.Hash, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return nil, fmt.Errorf("not hex: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	return b, nil
}

// parseHash32 parses a 0x-prefixed 32-byte hash as a go-ethereum hash.
func parseHash32(s string) (common.Hash, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return common.Hash{}, fmt.Errorf("not hex: %w", err)
	}
	if len(b) != common.HashLength {
		return common.Hash{}, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	return common.BytesToHash(b), nil
}

// loadGenesisOrigin validates the finalized genesis artifact against the full shard configuration and
// the pinned artifact, checks the operator's expected identity when one is configured, and builds the
// bootstrap snapshot from the origin's own retained evidence (no RPC). It is the node's only chance to
// notice it was handed the wrong genesis: every value it uses is this node's own configuration or the
// pinned artifact, never a peer's.
func loadGenesisOrigin(shardConf *types.PartitionDescriptionRecord, genesisPath, expectedIdentity string, rootEpoch uint64) (registrygenesis.GenesisOrigin, registryproof.Snapshot, error) {
	return loadGenesisOriginLayout(shardConf, genesisPath, expectedIdentity, rootEpoch, 1)
}

// loadGenesisOriginLayout validates the finalized genesis. The root epoch it pins is the one the genesis was generated at, read from the
// genesis itself, not the epoch of the node's trust base: a node started after a root handoff (a restore above all) runs under a later
// trust base than the genesis was made at. trustBaseEpoch only bounds it: a genesis cannot be from a root epoch the node's own trust base
// has not reached. Reading the number authenticates nothing; the commitment re-derived with it and the predeployed registry account must
// reproduce exactly (below), and block 0 and the root-certified registry snapshots bind the genesis the node actually runs.
func loadGenesisOriginLayout(shardConf *types.PartitionDescriptionRecord, genesisPath, expectedIdentity string, trustBaseEpoch, layout uint64) (registrygenesis.GenesisOrigin, registryproof.Snapshot, error) {
	art, err := registrygenesis.PinnedArtifactForLayout(layout)
	if err != nil {
		return registrygenesis.GenesisOrigin{}, registryproof.Snapshot{}, fmt.Errorf("loading the pinned seal-registry artifact: %w", err)
	}
	pins := registrygenesis.Pins{
		RegistryCodeHash: art.CodeHash,
		SystemAddress:    registrygenesis.SystemAddress,
		RegistryAddress:  registryproof.RegistryAddress,
	}
	finalized, err := os.ReadFile(genesisPath) // #nosec G304 -- operator-supplied config path, same trust level as --shard-conf
	if err != nil {
		return registrygenesis.GenesisOrigin{}, registryproof.Snapshot{}, fmt.Errorf("reading the finalized genesis %q: %w", genesisPath, err)
	}
	rootEpoch, err := registrygenesis.RootEpochOf(finalized, layout, registrygenesis.DefaultGenesisJSONLimits())
	if err != nil {
		return registrygenesis.GenesisOrigin{}, registryproof.Snapshot{}, fmt.Errorf("reading the genesis root epoch: %w", err)
	}
	if rootEpoch == 0 || rootEpoch > trustBaseEpoch {
		return registrygenesis.GenesisOrigin{}, registryproof.Snapshot{}, fmt.Errorf("%w: the genesis is at root epoch %d, the node's trust base is at %d", registrygenesis.ErrGenesisRootEpoch, rootEpoch, trustBaseEpoch)
	}
	pins.RootEpoch = rootEpoch
	var expected *common.Hash
	if expectedIdentity != "" {
		h, err := parseHash32(expectedIdentity)
		if err != nil {
			return registrygenesis.GenesisOrigin{}, registryproof.Snapshot{}, fmt.Errorf("parsing --expected-origin-identity: %w", err)
		}
		expected = &h
	}
	origin, err := registrygenesis.ValidateFinalizedGenesisJSON(shardConf, pins, art, finalized, expected, registrygenesis.DefaultGenesisJSONLimits())
	if err != nil {
		return registrygenesis.GenesisOrigin{}, registryproof.Snapshot{}, fmt.Errorf("validating the finalized genesis against the full shard configuration: %w", err)
	}
	// The bootstrap snapshot comes from the origin's own retained evidence. It is the block-0 witness
	// the v2 derivation needs as the parent of the first payload.
	bootstrap, err := registryproof.Verify(origin.ProofContext(), origin.BlockHash(), origin.Evidence())
	if err != nil {
		return registrygenesis.GenesisOrigin{}, registryproof.Snapshot{}, fmt.Errorf("verifying the configured bootstrap snapshot: %w", err)
	}
	if !bootstrap.Valid() || !bootstrap.Genesis() || bootstrap.Number() != 0 || bootstrap.StateRoot() != origin.StateRoot() {
		return registrygenesis.GenesisOrigin{}, registryproof.Snapshot{}, fmt.Errorf("the configured bootstrap snapshot is not block 0 of the configured genesis origin")
	}
	return origin, bootstrap, nil
}

// loadRunShardConf returns the shard configuration the node runs on. With --full-shard-conf it is the
// full configuration `ubft engine-api genesis` emitted (the base conf plus seal_registry_genesis),
// which is what the v2 derivation requires the observation's shard configuration hash to equal;
// otherwise it is the ordinary --shard-conf. The two are mutually exclusive rather than merged,
// because they would be two sources for the node's identity and its configuration hash.
func loadRunShardConf(flags *shardNodeRunFlags, changed func(string) bool) (*types.PartitionDescriptionRecord, error) {
	if flags.GenesisFile == "" && flags.FullShardConf != "" {
		return nil, fmt.Errorf("--full-shard-conf requires --genesis")
	}
	if flags.GenesisFile == "" && flags.ExpectedOriginIdentity != "" {
		return nil, fmt.Errorf("--expected-origin-identity requires --genesis and --full-shard-conf")
	}
	if flags.GenesisFile != "" && flags.FullShardConf == "" {
		return nil, fmt.Errorf("--genesis requires --full-shard-conf: the finalized artifact is validated against the full shard configuration the node runs on")
	}
	if flags.FullShardConf == "" {
		shardConfs, err := flags.loadShardConfs(flags.baseFlags)
		if err != nil {
			return nil, fmt.Errorf("loading shard configuration: %w", err)
		}
		if len(shardConfs) != 1 {
			return nil, fmt.Errorf("shard-node run requires exactly one --shard-conf, got %d", len(shardConfs))
		}
		return shardConfs[0], nil
	}
	if changed("shard-conf") {
		return nil, fmt.Errorf("--full-shard-conf and --shard-conf both name the shard configuration; give only --full-shard-conf")
	}
	fullFlags := shardConfFlags{ShardConfFiles: []string{flags.FullShardConf}}
	shardConfs, err := fullFlags.loadShardConfs(flags.baseFlags)
	if err != nil {
		return nil, fmt.Errorf("loading full shard configuration: %w", err)
	}
	if len(shardConfs) != 1 {
		return nil, fmt.Errorf("loading full shard configuration: expected one configuration, got %d", len(shardConfs))
	}
	return shardConfs[0], nil
}

func buildExecutor(ctx context.Context, flags *shardNodeRunFlags, shardConf *types.PartitionDescriptionRecord, verifier *engineapi.VerifierContext) (shardnode.Executor, error) {
	switch flags.Executor {
	case "fake":
		return executortest.New(), nil

	case "engine-api":
		if !common.IsHexAddress(flags.EngineFeeCollector) {
			return nil, fmt.Errorf("--engine-fee-collector %q is not an address", flags.EngineFeeCollector)
		}
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
			EngineURL:    flags.EngineURL,
			EthURL:       flags.EthURL,
			Secret:       secret,
			FeeCollector: [20]byte(common.HexToAddress(flags.EngineFeeCollector)),
			Verifier:     verifier,
		}, flags.observe.Logger())

		// The build path now runs through the seal siblings, so a client that lacks them fails
		// startup rather than the first round. Opt-in at the client because the adapter itself is
		// still usable for non-seal work; this executor is not.
		adapter.RequireSealCapabilities()

		// Fail closed at startup rather than on the first round — see
		// docs/adr/0001-executor-boundary.md decision 3: capability
		// exchange alone doesn't guarantee the chain spec's fork schedule
		// matches what this adapter speaks, but it does catch the more
		// basic "wrong URL, wrong JWT, wrong reth build" failures before
		// they show up as a mysteriously stalled first round.
		if err := adapter.CheckCapabilities(ctx); err != nil {
			return nil, fmt.Errorf("engine-api executor failed its startup capability check: %w", err)
		}

		// Capability exchange cannot tell one chain from another — the V3 method set is
		// identical whatever chain the client is running — so a node pointed at the wrong
		// execution client would pass the check above and then certify against the wrong
		// state. `shard-node doctor` has always caught this, but doctor is an optional
		// preflight; F1 (#9) requires the node itself to refuse before it can vote.
		wantChainID, ok := zkverifier.ParseChainIDFromParams(shardConf.PartitionParams)
		if !ok {
			return nil, fmt.Errorf("engine-api executor requires a chain_id partition param in the shard conf, which has none")
		}
		if err := adapter.CheckChainID(ctx, wantChainID); err != nil {
			return nil, fmt.Errorf("engine-api executor failed its startup chain-identity check "+
				"(the wrong execution client, or a genesis generated for a different shard conf): %w", err)
		}

		// Endpoint pairing, unconditionally. The chain-id check above already refuses two
		// clients on different chains; this refuses two clients on the SAME chain id that
		// were started from different genesis states, without requiring the operator to have
		// configured an expected hash. If --expected-genesis-hash is set, CheckGenesisHash
		// below subsumes this — it is still run first so the diagnostic an operator sees for
		// a mispairing is the mispairing, not a genesis mismatch against one of the two.
		if _, err := adapter.CheckEndpointsPaired(ctx); err != nil {
			return nil, fmt.Errorf("engine-api executor failed its startup endpoint-pairing check "+
				"(--engine-url and --eth-url must address the same execution client): %w", err)
		}

		// Genesis binding, when the operator configured one. Chain id does not establish it: two
		// chains can share a chain id and differ in allocation or any other genesis field, which
		// is exactly what a genesis generated for a different deployment looks like. The expected
		// value must come from configuration, never from the client under test.
		if flags.ExpectedGenesisHash != "" {
			want, err := hexToHash(flags.ExpectedGenesisHash)
			if err != nil {
				return nil, fmt.Errorf("parsing --expected-genesis-hash: %w", err)
			}
			if err := adapter.CheckGenesisHash(ctx, want); err != nil {
				return nil, fmt.Errorf("engine-api executor failed its startup genesis check: %w", err)
			}
		}

		// And the checked genesis origin, when configured: the client's block 0 must be the block the
		// finalized artifact and this node's full shard configuration derive. A node whose
		// configuration and client disagree about genesis must not vote.
		if verifier != nil && verifier.GenesisOrigin.Valid() {
			if err := adapter.CheckGenesisHash(ctx, shardnode.Hash(verifier.GenesisOrigin.BlockHash().Bytes())); err != nil {
				return nil, fmt.Errorf("engine-api executor failed its startup genesis check against the configured origin: %w", err)
			}
		}

		// The loaded fork schedule, unconditionally. Neither chain id nor genesis binds it: a spec
		// that schedules Prague for a later timestamp has the same genesis block as one that
		// schedules nothing, and would pass every check above before requiring Engine methods this
		// adapter does not call. eth_config (EIP-7910) is the standard read for it. Last, so that a
		// mispairing or a wrong genesis is reported as that rather than as a profile difference.
		if _, err := adapter.CheckExecutionProfile(ctx, wantChainID); err != nil {
			return nil, fmt.Errorf("engine-api executor failed its startup execution-profile check "+
				"(the execution client's chain spec is not the pinned %s profile): %w", engineapi.PinnedProfileName, err)
		}
		if verifier != nil && verifier.GenesisOrigin.Valid() {
			budget := engineapi.DefaultParentWitnessBudget()
			if err := adapter.EnableParentWitness(ctx, budget); err != nil {
				return nil, fmt.Errorf("engine-api executor failed to enable local parent witness acquisition: %w", err)
			}
			flags.observe.Logger().Info("local parent witness acquisition enabled",
				"maxAttempts", budget.MaxAttempts, "overall", budget.Overall,
				"perAttempt", budget.PerAttempt, "maxDownloadedBytes", budget.MaxDownloadedBytes,
				"backoff", budget.Backoff)
		}
		return adapter, nil

	default:
		return nil, fmt.Errorf("unknown --executor %q, expected \"fake\" or \"engine-api\"", flags.Executor)
	}
}

func loadEngineEpochTransition(path string, oldEpoch uint64) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied trusted local handoff file
	if err != nil {
		return nil, fmt.Errorf("reading --engine-epoch-transition %q: %w", path, err)
	}
	transition, err := handoff.DecodeEVMTransition(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding --engine-epoch-transition %q: %w", path, err)
	}
	if transition.OldRootEpoch != oldEpoch {
		return nil, fmt.Errorf("--engine-epoch-transition starts at epoch %d, configured root trust base is epoch %d", transition.OldRootEpoch, oldEpoch)
	}
	return raw, nil
}

// shardConfInstaller is the node surface a verified assignment step is installed into.
type shardConfInstaller interface {
	InstallShardConf(epoch uint64, hash []byte) error
}

// installAssignmentStepConfs records the shard configuration hashes a VERIFIED assignment step names, the old epoch's before the new
// epoch's: the only production source of the node's per-epoch configuration set. A contradiction with what is installed is an error
// (the handoff is not activated).
func installAssignmentStepConfs(node shardConfInstaller, step handoff.AssignmentStep) error {
	if err := node.InstallShardConf(step.OldShardEpoch, step.OldActiveConfHash[:]); err != nil {
		return fmt.Errorf("installing the old shard configuration: %w", err)
	}
	if err := node.InstallShardConf(step.NewShardEpoch, step.NewActiveConfHash[:]); err != nil {
		return fmt.Errorf("installing the new shard configuration: %w", err)
	}
	return nil
}

// peerInstaller is the surface a verified assignment's validator set is installed into.
type peerInstaller interface {
	Install(epoch uint64, validators []*types.NodeInfo) error
}

// installAssignmentPeers makes the validators of the assignment a VERIFIED bundle installs the active peer set (who may use this node's
// archive), in the same install path as the shard configuration set. A root-only bundle changes nothing.
func installAssignmentPeers(peers peerInstaller, bundle handoffdelivery.Bundle) error {
	epoch, validators, ok, err := handoffdelivery.AssignmentValidators(bundle)
	if err != nil {
		return fmt.Errorf("reading the assignment's validators: %w", err)
	}
	if !ok {
		return nil
	}
	if err := peers.Install(epoch, validators); err != nil {
		return fmt.Errorf("installing the assignment's validators: %w", err)
	}
	return nil
}

// installVerifiedAssignment is everything a VERIFIED assignment step installs into the node before the handoff is activated: the shard
// configuration hashes (the certificate client, the admission and the bundle check follow them) and the validator set (who may use this
// node's archive). It is the single call the OnInstalled path makes; shard_node_install_wiring_test.go pins that it does.
func installVerifiedAssignment(conf shardConfInstaller, peers peerInstaller, bundle handoffdelivery.Bundle, step handoff.AssignmentStep) error {
	if err := installAssignmentStepConfs(conf, step); err != nil {
		return err
	}
	return installAssignmentPeers(peers, bundle)
}
