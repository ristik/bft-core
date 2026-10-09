package consensus

import (
	"bytes"
	"cmp"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/observability"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
)

type (
	RootNet interface {
		Send(ctx context.Context, msg any, receivers ...peer.ID) error
		ReceivedChannel() <-chan any
	}

	// Leader provides interface to different leader selection algorithms
	Leader interface {
		// GetLeaderForRound returns valid leader (node id) for round/view number
		GetLeaderForRound(round uint64) (peer.ID, error)

		// Update - what PaceMaker considers to be the current round at the time QC is processed.
		Update(qc *drctypes.QuorumCert, currentRound uint64, b leader.BlockLoader) error

		UpdateWithTrustBase(trustBase types.RootTrustBase, currentRound uint64) error
	}

	Observability interface {
		Meter(name string, opts ...metric.MeterOption) metric.Meter
		Tracer(name string, options ...trace.TracerOption) trace.Tracer
		Logger() *slog.Logger
		RoundLogger(curRound func() uint64) *slog.Logger
	}

	Orchestration interface {
		NetworkID() types.NetworkID
		ShardConfig(partitionID types.PartitionID, shardID types.ShardID, rootRound uint64) (*types.PartitionDescriptionRecord, error)
		ShardConfigs(rootRound uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error)
	}

	PersistentStore interface {
		SafetyStorage
		storage.PersistentStore
	}

	certRequest struct {
		ircr IRChangeRequest
		rsc  trace.SpanContext
	}

	ConsensusManager struct {
		// channel via which validator sends "certification requests" to CM
		certReqCh chan certRequest
		// channel via which CM sends "certification request" response to validator
		certResultCh chan *certification.CertificationResponse
		// internal buffer for "certification request" response to allow CM to
		// continue without waiting validator to consume the response
		ucSink         chan []*certification.CertificationResponse
		params         *Parameters
		id             peer.ID
		net            RootNet
		pacemaker      *Pacemaker
		leaderSelector Leader
		trustBase      atomic.Pointer[types.RootTrustBaseV1] // valid in current round
		trustBaseStore *trustbase.TrustBaseStore
		irReqBuffer    *IrReqBuffer
		safety         *SafetyModule
		blockStore     *storage.BlockStore
		orchestration  Orchestration
		irReqVerifier  *IRChangeReqVerifier
		t2Timeouts     *PartitionTimeoutGenerator
		// viewResolver selects the view-aware branch (Q2-C2) for leader admission, timeouts and payload generation. Production
		// leaves it nil: the legacy round-only dispatch stays selected.
		viewResolver ViewResolver
		// votes need to be buffered when CM will be the next leader (so other nodes
		// will send votes to it) but it hasn't got the proposal yet, so it can't process
		// the votes. voteBuffer maps author id to vote, so we do not buffer same vote
		// multiple times (votes are buffered for single round only)
		voteBuffer map[string]*abdrc.VoteMsg
		// whether the CM is in recovery mode, trying to get into the same state as other CMs
		recovery         *recoveryState
		frontier         *frontierSampler
		recoveryProfile2 bool
		recoveryHistory  *trusthistorystore.Store
		posPrefetching   atomic.Int32
		posQueue         posSubmissions              // submitted Retirement and RejectResult controls waiting for a leader
		witnesses        WitnessFetcher              // nil: control witnesses are only what the store already holds
		q3               Q3Authority                 // the verified Q3 history, nil when the binary does not know it
		v3Planned        atomic.Pointer[V3Candidate] // the last candidate PlanV3Candidate derived: the exact body the members declared readiness for
		q3Staged         atomic.Pointer[Q3Staged]    // the V3 candidate this validator last derived for its operator
		epochAnchor      *drctypes.EpochAnchor
		primaryWitness   atomic.Pointer[PrimaryWitnessSource] // the execution client's side of a primary candidate's EVM proof
		primaryCache     primaryCache
		// approvalSink and judgeHook are test seams: where a released parked approval goes, and the intake's proof judgement
		approvalSink func(*abdrc.HandoffApprovalMsg) error
		judgeHook    func(*abdrc.HandoffApprovalMsg) error
		handoffMu    sync.Mutex
		handoffPlans map[[32]byte]*pendingHandoff
		// handoffIntent is the operator plan this validator holds for the leader to order a Prepare for: unsigned, naming no parent.
		handoffIntent *abdrc.HandoffApprovalMsg
		handoffAborts map[handoffAbortKey]*pendingHandoffAbort

		log    *slog.Logger
		tracer trace.Tracer

		leaderCnt   metric.Int64Counter
		execMsgCnt  metric.Int64Counter
		execMsgDur  metric.Float64Histogram
		voteCnt     metric.Int64Counter
		proposedCR  metric.Int64Counter
		fwdIRCRCnt  metric.Int64Counter
		qcSize      metric.Int64Counter
		qcVoters    metric.Int64Counter
		susVotes    metric.Int64Counter
		recoveryReq metric.Int64Counter
		addBlockDur metric.Float64Histogram
	}
)

// NewConsensusManager creates new "Atomic Broadcast" protocol based distributed consensus manager
func NewConsensusManager(
	nodeID peer.ID,
	trustBaseStore *trustbase.TrustBaseStore,
	orchestration Orchestration,
	net RootNet,
	signer abcrypto.Signer,
	rcDB PersistentStore,
	observe Observability,
	opts ...Option,
) (*ConsensusManager, error) {
	// Sanity checks
	if net == nil {
		return nil, errors.New("network is nil")
	}
	if trustBaseStore == nil {
		return nil, errors.New("trust base store is nil")
	}
	// load options
	optional, err := LoadConf(opts)
	if err != nil {
		return nil, fmt.Errorf("loading optional configuration: %w", err)
	}
	if optional.RecoveryProfile2 && optional.RecoveryHistory == nil {
		return nil, errors.New("profile 2 recovery requires verified trust history")
	}

	cParams := optional.Params
	pm, err := NewPacemaker(cParams.BlockRate/2, cParams.LocalTimeout, observe)
	if err != nil {
		return nil, fmt.Errorf("creating Pacemaker: %w", err)
	}
	log := observe.RoundLogger(pm.GetCurrentRound)

	// The EVM shard's configuration is derived from committed handoff history.
	// Reconcile it before the block tree rebuilds trust bases, before the frontier
	// service starts and before this node can vote.
	if cParams.NetworkProfileVersion == storage.ProfileHandoff {
		if profileOrchestration, ok := orchestration.(interface{ EnableHandoffProfile() }); ok {
			profileOrchestration.EnableHandoffProfile()
		}
		if err := reconcileAssignmentHistory(rcDB, trustBaseStore, orchestration); err != nil {
			return nil, fmt.Errorf("reconciling committed EVM assignment history: %w", err)
		}
	}

	store := rcDB
	var frontier *frontierSampler
	if optional.FrontierSampler != nil {
		reader, ok := rcDB.(frontierSafetyReader)
		if !ok {
			return nil, errors.New("frontier sampler requires checked safety reader")
		}
		samplerConfig := *optional.FrontierSampler
		if samplerConfig.TrustBase != nil {
			// the covering QCs are in the wire form the sampled epoch signs with; an epoch not in the store keeps the legacy default
			if signing, serr := trustBaseStore.SigningConfig(samplerConfig.TrustBase.Epoch); serr == nil {
				samplerConfig.Signing = signing
			}
		}
		frontier, err = newFrontierSampler(samplerConfig, reader)
		if err != nil {
			return nil, err
		}
		store = &frontierPersistentStore{PersistentStore: rcDB, sampler: frontier, reader: reader}
	}
	if optional.FrontierSigning {
		if frontier == nil {
			return nil, errors.New("frontier signing requires frontier sampler")
		}
		if err := frontier.enableSigning(nodeID.String(), signer); err != nil {
			return nil, err
		}
	}

	if cParams.NetworkProfileVersion == storage.ProfileHandoff {
		if profileOrchestration, ok := orchestration.(interface{ EnableHandoffProfile() }); ok {
			profileOrchestration.EnableHandoffProfile()
		}
	}
	// init storage
	bStore, err := storage.New(cParams.HashAlgorithm, store, orchestration, log, cParams.NetworkProfileVersion)
	if err != nil {
		return nil, fmt.Errorf("consensus block storage init failed: %w", err)
	}
	// Pin the genesis QC, so that the only round-1 QC a verifier accepts without signatures is this node's own: the QC of the genesis block the
	// store still holds (its Qc: the CommitQc is replaced when the block is committed, so after QC2 it is a round-2 certificate), else the one the software builds for an empty store (a store that has moved past round 1 no longer holds the block).
	genesisQC := (*drctypes.QuorumCert)(nil)
	if b, err := bStore.Block(drctypes.GenesisRootRound); err == nil && b.Qc != nil {
		genesisQC = b.Qc
	} else {
		genesis, err := storage.NewGenesisBlock(orchestration.NetworkID(), crypto.SHA256, cParams.NetworkProfileVersion)
		if err != nil {
			return nil, fmt.Errorf("deriving the genesis QC: %w", err)
		}
		genesisQC = genesis.CommitQc
	}
	pin, err := drctypes.GenesisPinOf(genesisQC)
	if err != nil {
		return nil, fmt.Errorf("pinning the genesis QC: %w", err)
	}
	trustBaseStore.SetGenesisPin(pin)
	reqVerifier, err := NewIRChangeReqVerifier(cParams, bStore)
	if err != nil {
		return nil, fmt.Errorf("block verifier construct error: %w", err)
	}
	t2TimeoutGen, err := NewLucBasedT2TimeoutGenerator(cParams, bStore)
	if err != nil {
		return nil, fmt.Errorf("failed to create T2 timeout generator: %w", err)
	}
	trustBase, err := trustBaseStore.LoadFirst()
	if err != nil {
		return nil, err
	}
	var installedAnchor *drctypes.EpochAnchor
	if cParams.NetworkProfileVersion == storage.ProfileHandoff {
		if durable, ok := store.(epochAnchorSafetyStore); ok {
			installedAnchor, err = durable.ReadEpochAnchorSafety()
			if err != nil {
				return nil, fmt.Errorf("read durable epoch anchor: %w", err)
			}
		}
		if rootAnchor := bStore.RootAnchor(); rootAnchor != nil &&
			(installedAnchor == nil || !bytes.Equal(rootAnchor.GenesisID, installedAnchor.GenesisID)) {
			return nil, errors.New("root anchor has no matching durable safety state")
		}
		if installedAnchor != nil {
			if !optional.RecoveryProfile2 || optional.RecoveryHistory == nil {
				return nil, fmt.Errorf("installed epoch anchor requires profile 2 recovery: %w", abdrc.ErrRecoveryEpoch)
			}
			if bStore.RootEpoch() != installedAnchor.Epoch {
				return nil, errors.New("root epoch differs from installed anchor")
			}
			trustBase, err = trustBaseStore.GetByEpoch(installedAnchor.Epoch)
			if err != nil {
				return nil, fmt.Errorf("successor trust base unavailable: %w", err)
			}
		}
	}
	if cParams.NetworkProfileVersion == storage.ProfileHandoff && installedAnchor == nil {
		if err := bStore.ConfigureHandoffAuthority(trustBase); err != nil {
			return nil, fmt.Errorf("handoff authority: %w", err)
		}
		if optional.Q3 != nil { // the genesis committee may order the first V3 activation
			if err := bStore.EnableV3Freeze(optional.Q3.FreezeRules()); err != nil {
				return nil, fmt.Errorf("handoff authority: %w", err)
			}
		}
	} else if cParams.NetworkProfileVersion == storage.ProfileHandoff && installedAnchor != nil && q3Activated(optional.Q3, installedAnchor) {
		// The anchor is the first epoch of a Q3 activation: its lineage is the verified history, and the V2 handoff authority has no
		// body to be built from. Its authority is the verified entry's: the activated epoch orders V3 successors only.
		if err := configureV3Authority(bStore, optional.Q3, trustBase, installedAnchor.Epoch); err != nil {
			return nil, fmt.Errorf("handoff authority: %w", err)
		}
	} else if cParams.NetworkProfileVersion == storage.ProfileHandoff && installedAnchor != nil {
		prior, historyErr := optional.RecoveryHistory.ByEpoch(installedAnchor.Epoch)
		if historyErr != nil {
			return nil, fmt.Errorf("handoff authority lineage: %w", historyErr)
		}
		if err := bStore.ConfigureHandoffV2Authority(trustBase, prior); err != nil {
			return nil, fmt.Errorf("handoff authority: %w", err)
		}
	}
	// The lookup reads the manager's CURRENT block store: recovery replaces x.blockStore, and a store captured here would go stale.
	// The manager is assigned below, before anything can sign.
	var manager *ConsensusManager
	safetyOptions := []SafetyOption{
		WithParentTimestamp(func(round uint64) (uint64, error) {
			b, err := manager.blockStore.Block(round)
			if err != nil {
				return 0, err
			}
			return b.BlockData.Timestamp, nil
		}),
		WithDomainBoundSigning(trustBaseStore, func(round uint64) (CommittedBlockInfo, error) {
			b, err := manager.blockStore.Block(round)
			if err != nil {
				return CommittedBlockInfo{}, err
			}
			return CommittedBlockInfo{Epoch: b.BlockData.Epoch, RootHash: b.RootHash, Timestamp: b.BlockData.Timestamp}, nil
		})}
	if optional.Q3 != nil {
		safetyOptions = append(safetyOptions, WithActivationGate(optional.Q3))
	}
	safetyModule, err := NewSafetyModule(trustBase.GetNetworkID(), nodeID.String(), signer, store, safetyOptions...)
	if err != nil {
		return nil, err
	}

	// we're limited to window size and exclude size 1 as our block loader (block store) doesn't
	// keep history, ie we can't load blocks older than previous block.
	ls, err := leader.NewReputationBased(1, 1, trustBaseStore)
	if err != nil {
		return nil, fmt.Errorf("failed to create consensus leader selector: %w", err)
	}
	var chosenLeader Leader = ls
	if installedAnchor != nil {
		chosenLeader, err = newEpochLeader(trustBaseStore, installedAnchor.Epoch, installedAnchor.Slot+1, trustBase.RootNodes,
			func() (Leader, error) { return newBootstrapLeader(ls, installedAnchor.Slot+1, trustBase.RootNodes) })
	} else if cParams.NetworkProfileVersion == storage.ProfileHandoff {
		// the genesis epoch: its schedule starts at the genesis round, whatever start the trust base records
		chosenLeader, err = newEpochLeader(trustBaseStore, trustBase.GetEpoch(), max(trustBase.GetEpochStart(), 1), trustBase.RootNodes,
			func() (Leader, error) { return ls, nil })
	}
	if err != nil {
		return nil, err
	}

	consensusManager := &ConsensusManager{
		certReqCh:        make(chan certRequest),
		certResultCh:     make(chan *certification.CertificationResponse),
		ucSink:           make(chan []*certification.CertificationResponse, 1),
		params:           cParams,
		id:               nodeID,
		net:              net,
		pacemaker:        pm,
		leaderSelector:   chosenLeader,
		trustBaseStore:   trustBaseStore,
		irReqBuffer:      NewIrReqBuffer(log, cParams.NetworkProfileVersion),
		safety:           safetyModule,
		blockStore:       bStore,
		orchestration:    orchestration,
		irReqVerifier:    reqVerifier,
		t2Timeouts:       t2TimeoutGen,
		voteBuffer:       make(map[string]*abdrc.VoteMsg),
		recovery:         &recoveryState{},
		frontier:         frontier,
		recoveryProfile2: optional.RecoveryProfile2,
		recoveryHistory:  optional.RecoveryHistory,
		witnesses:        optional.Witnesses,
		q3:               optional.Q3,
		epochAnchor:      installedAnchor,
		log:              log,
		tracer:           observe.Tracer("cm.distributed"),
	}

	// Probably not the correct trust base, but we start with it and update as we discover current round
	consensusManager.trustBase.Store(trustBase)

	if err := consensusManager.initMetrics(observe); err != nil {
		return nil, fmt.Errorf("initializing metrics: %w", err)
	}
	manager = consensusManager
	return consensusManager, nil
}

func (x *ConsensusManager) initMetrics(observe Observability) (err error) {
	m := observe.Meter("cm.distributed")

	_, err = m.Int64ObservableCounter("round", metric.WithDescription("current round"),
		metric.WithInt64Callback(func(ctx context.Context, io metric.Int64Observer) error {
			io.Observe(int64(x.pacemaker.GetCurrentRound())) /* #nosec G115 its unlikely that value of current round exceeds int64 max value */
			return nil
		}))
	if err != nil {
		return fmt.Errorf("creating counter for round number: %w", err)
	}

	x.leaderCnt, err = m.Int64Counter("round.leader", metric.WithDescription("Number of times node has been round leader"))
	if err != nil {
		return fmt.Errorf("creating counter for leader count: %w", err)
	}
	x.voteCnt, err = m.Int64Counter("count.vote", metric.WithDescription("Number of times node has voted (might be more than once per round for a different reason, ie proposal and timeout)"))
	if err != nil {
		return fmt.Errorf("creating vote counter: %w", err)
	}
	x.susVotes, err = m.Int64Counter("sus.vote", metric.WithDescription(`Number of "suspicious" votes node has seen (ie stale votes, votes before proposal, etc)`))
	if err != nil {
		return fmt.Errorf("creating suspicious vote counter: %w", err)
	}

	x.proposedCR, err = m.Int64Counter("count.proposed.cr", metric.WithDescription("Number of Change Requests included into proposal by the round leader"))
	if err != nil {
		return fmt.Errorf("creating counter for proposal change requests count: %w", err)
	}
	x.fwdIRCRCnt, err = m.Int64Counter("count.fwd.ircr", metric.WithDescription(`Number of IR Change Requests messages forwarded ("lost" messages)`))
	if err != nil {
		return fmt.Errorf("creating counter for proposal change requests count: %w", err)
	}

	x.execMsgCnt, err = m.Int64Counter("exec.msg.count", metric.WithDescription("Number of messages processed by the consensus manager"))
	if err != nil {
		return fmt.Errorf("creating counter for processed messages: %w", err)
	}
	x.execMsgDur, err = m.Float64Histogram("exec.msg.time",
		metric.WithDescription("How long it took to process message"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(100e-6, 200e-6, 400e-6, 800e-6, 0.0016, 0.01, 0.05, 0.1))
	if err != nil {
		return fmt.Errorf("creating histogram for processed messages: %w", err)
	}

	x.addBlockDur, err = m.Float64Histogram("add.block.time",
		metric.WithDescription("How long it took to add block from proposal"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.001, 0.002, 0.004, 0.008, 0.016, 0.032, 0.064, 0.128))
	if err != nil {
		return fmt.Errorf("creating histogram for adding block: %w", err)
	}

	x.qcSize, err = m.Int64Counter("qc.vote.count", metric.WithDescription("Number of votes in the quorum certificate"))
	if err != nil {
		return fmt.Errorf("creating counter for votes in QC: %w", err)
	}
	x.qcVoters, err = m.Int64Counter("qc.participated", metric.WithDescription("Number of times node participated in the QC (vote was included)"))
	if err != nil {
		return fmt.Errorf("creating counter for votes by node included into QC: %w", err)
	}

	x.recoveryReq, err = m.Int64Counter("recovery", metric.WithDescription("Number of times node has entered into recovery state and sent out state request"))
	if err != nil {
		return fmt.Errorf("creating counter for recovery attempts: %w", err)
	}

	return nil
}

func (x *ConsensusManager) RequestCertification(ctx context.Context, cr IRChangeRequest) error {
	ctx, span := x.tracer.Start(ctx, "ConsensusManager.RequestCertification")
	defer span.End()

	if x.recovery.InRecovery() {
		return fmt.Errorf("node is in recovery: %s", x.recovery)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case x.certReqCh <- certRequest{ircr: cr, rsc: trace.SpanContextFromContext(ctx)}:
	}
	return nil
}

func (x *ConsensusManager) CertificationResult() <-chan *certification.CertificationResponse {
	return x.certResultCh
}

func (x *ConsensusManager) Run(ctx context.Context) error {
	if x.frontier != nil {
		if !x.frontier.runState.CompareAndSwap(0, 1) {
			return errors.New("frontier sampler permits only one Run owner")
		}
		defer func() {
			x.frontier.eligible.Store(false)
			x.frontier.runState.Store(2)
			x.frontier.stopOnce.Do(func() { close(x.frontier.stopped) })
		}()
	}
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		defer x.pacemaker.Stop()
		vote, err := x.blockStore.ReadLastVote()
		if err != nil {
			return fmt.Errorf("last vote read failed: %w", err)
		}
		hQc := x.blockStore.GetHighQc()
		lastTC, err := x.blockStore.GetLastTC()
		if err != nil {
			return fmt.Errorf("failed to read last TC from block store: %w", err)
		}
		highRound := hQc.GetRound()
		if x.epochAnchor != nil {
			if hQc != nil && hQc.VoteInfo.Epoch != x.epochAnchor.Epoch {
				return errors.New("old QC cannot start successor pacemaker")
			}
			if lastTC != nil && (lastTC.Timeout == nil || lastTC.Timeout.Epoch != x.epochAnchor.Epoch) {
				return errors.New("old TC cannot start successor pacemaker")
			}
			highRound = max(highRound, x.epochAnchor.Slot)
		}
		logRecoveredVote(ctx, x.log, vote)
		x.pacemaker.Reset(ctx, highRound, lastTC, vote)

		// Now that we have a better idea of current round, let's see if we need to update our trust base.
		x.updateTrustBase()

		err = x.leaderSelector.UpdateWithTrustBase(x.trustBase.Load(), x.pacemaker.GetCurrentRound())
		if err != nil {
			return fmt.Errorf("failed to update leader from trust base: %w", err)
		}

		leader, err := x.leaderSelector.GetLeaderForRound(x.pacemaker.GetCurrentRound())
		if err != nil {
			// start CM even if leader selection failed
			x.log.WarnContext(ctx, "Failed to select leader when starting consensus manager", logger.Error(err))
		}
		x.log.InfoContext(ctx, fmt.Sprintf("CM starting, leader is %s", leader))
		if x.frontier != nil && !x.frontier.faulted.Load() {
			x.frontier.eligible.Store(true)
		}
		return x.loop(ctx)
	})

	g.Go(func() error { return x.sendCertificates(ctx) })

	err := g.Wait()
	x.log.InfoContext(ctx, "exited distributed consensus manager main loop", logger.Error(err))
	return err
}

func (x *ConsensusManager) loop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-x.net.ReceivedChannel():
			if !ok {
				return fmt.Errorf("root network received channel has been closed")
			}
			x.log.LogAttrs(ctx, logger.LevelTrace, fmt.Sprintf("received %T", msg), logger.Data(msg))
			if err := x.handleRootNetMsg(ctx, msg); err != nil {
				x.log.WarnContext(ctx, fmt.Sprintf("processing %T", msg), logger.Error(err))
			}
		case req := <-x.certReqCh:
			ctx := trace.ContextWithRemoteSpanContext(ctx, req.rsc)
			if err := x.onPartitionIRChangeReq(ctx, &req.ircr); err != nil {
				x.log.WarnContext(ctx, "failed to process IR change request from partition", logger.Error(err), logger.Shard(req.ircr.Partition, req.ircr.Shard))
			}
		case event := <-x.pacemaker.StatusEvents():
			x.handlePacemakerEvent(ctx, event)
		case req := <-x.frontierRequests():
			x.handleFrontierRequest(ctx, req)
		}
	}
}

func (x *ConsensusManager) frontierRequests() <-chan frontierRequest {
	if x.frontier == nil {
		return nil
	}
	return x.frontier.requests
}

/*
handleRootNetMsg routes messages from "root net" iow messages sent by other rootchain
validators to appropriate message handler.
*/
func (x *ConsensusManager) handleRootNetMsg(ctx context.Context, msg any) (rErr error) {
	ctx, span := x.tracer.Start(ctx, "ConsensusManager.handleRootNetMsg", trace.WithNewRoot(), trace.WithAttributes(observability.Round(x.pacemaker.GetCurrentRound())), trace.WithSpanKind(trace.SpanKindServer))
	defer func(start time.Time) {
		if rErr != nil {
			span.RecordError(rErr)
			span.SetStatus(codes.Error, rErr.Error())
		}
		msgAttr := attribute.String("msg", fmt.Sprintf("%T", msg))
		x.execMsgCnt.Add(ctx, 1, metric.WithAttributeSet(attribute.NewSet(msgAttr, observability.ErrStatus(rErr))))
		x.execMsgDur.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(msgAttr))
		span.SetAttributes(msgAttr)
		span.End()
	}(time.Now())

	switch mt := msg.(type) {
	case *abdrc.IrChangeReqMsg:
		return x.onIRChangeMsg(ctx, mt)
	case *abdrc.ProposalMsg:
		return x.onProposalMsg(ctx, mt)
	case *abdrc.VoteMsg:
		return x.onVoteMsg(ctx, mt)
	case *abdrc.TimeoutMsg:
		return x.onTimeoutMsg(ctx, mt)
	case *abdrc.StateRequestMsg:
		return x.onStateReq(ctx, mt)
	case *abdrc.StateMsg:
		return x.onStateResponse(ctx, mt)
	case *abdrc.HandoffApprovalMsg:
		return x.onHandoffApprovalMsg(ctx, mt)
	case *abdrc.HandoffAbortApprovalMsg:
		return x.onHandoffAbortApprovalMsg(mt)
	case *abdrc.PosControlSubmissionMsg:
		return x.onPosControlSubmission(ctx, mt)
	}
	return fmt.Errorf("unknown message type %T", msg)
}

func (x *ConsensusManager) handlePacemakerEvent(ctx context.Context, event paceMakerStatus) {
	currentRound := x.pacemaker.GetCurrentRound()
	ctx, span := x.tracer.Start(ctx, "ConsensusManager.handlePacemakerEvent", trace.WithNewRoot(), trace.WithAttributes(observability.Round(currentRound), attribute.Stringer("event", event)))
	defer span.End()

	switch event {
	case pmsRoundMatured:
		nextLeader, err := x.leaderAfter(currentRound)
		if err != nil {
			x.log.WarnContext(ctx, "could not determine next leader", logger.Error(err))
		}
		x.log.DebugContext(ctx, fmt.Sprintf("round has lasted minimum required duration; next leader %s", nextLeader.ShortString()))
		// round 2 is system bootstrap and is a special case - as there is no proposal no one is sending votes
		// and thus leader won't achieve quorum and doesn't make next proposal (and the round would time out).
		// So we just have the round 2 leader to trigger next round when it's mature (root genesis QC will be
		// used as HighQc in the proposal).
		isLeader := nextLeader == x.id
		if !isLeader && currentRound == 2 {
			round2Leader, err := x.leaderSelector.GetLeaderForRound(2)
			if err != nil {
				x.log.WarnContext(ctx, "could not determine leader for round 2", logger.Error(err))
			} else if x.id == round2Leader {
				isLeader = true
			}
		}

		if isLeader {
			if qc := x.pacemaker.RoundQC(); qc != nil || currentRound == 2 {
				x.processQC(ctx, qc)
				x.processNewRoundEvent(ctx)
				x.updateQCMetrics(ctx, qc)
			}
		}
	case pmsRoundTimeout:
		x.onLocalTimeout(ctx)
	}
}

// onLocalTimeout handle local timeout, either no proposal is received or voting does not
// reach consensus. Triggers timeout voting.
func (x *ConsensusManager) onLocalTimeout(ctx context.Context) {
	ctx, span := x.tracer.Start(ctx, "ConsensusManager.onLocalTimeout")
	defer span.End()
	x.log.InfoContext(ctx, "local timeout")

	// has the validator voted in this round, if true send the same (timeout)vote
	// maybe less than quorum of nodes where operational the last time
	timeoutVoteMsg := x.pacemaker.GetTimeoutVote()
	if timeoutVoteMsg == nil {
		// create timeout vote
		qc := x.blockStore.GetHighQc()
		var timeout *drctypes.Timeout
		if x.epochAnchor != nil && qc == nil {
			timeout = drctypes.NewAnchorTimeout(x.pacemaker.GetCurrentRound(), x.epochAnchor)
		} else {
			timeout = drctypes.NewTimeout(x.pacemaker.GetCurrentRound(), x.trustBase.Load().Epoch, qc)
		}
		// A timeout this node already signed for the round (and recorded with its decision before it left the node) is sent
		// again as it was, with the HighQC it carried: a node restarted after the signing may hold a newer HighQC, and a
		// timeout built from it would be a different statement that the decision refuses.
		recorded, err := x.safety.RecordedTimeout(timeout.Epoch, timeout.Round)
		if err != nil {
			x.log.WarnContext(ctx, "failed to read the recorded timeout", logger.Error(err))
			return
		}
		if recorded != nil {
			timeoutVoteMsg = recorded
			x.log.InfoContext(ctx, "recovered recorded timeout vote", "epoch", timeout.Epoch, "round", timeout.Round, "messageID", timeoutMessageID(recorded))
		} else {
			timeoutVoteMsg = abdrc.NewTimeoutMsg(
				timeout,
				x.id.String(),
				x.pacemaker.LastRoundTC())
			if err := x.safety.SignTimeout(timeoutVoteMsg, x.pacemaker.LastRoundTC()); err != nil {
				x.log.WarnContext(ctx, "failed to sign timeout", logger.Error(err))
				return
			}
			x.log.InfoContext(ctx, "signed timeout vote", "epoch", timeout.Epoch, "round", timeout.Round, "messageID", timeoutMessageID(timeoutVoteMsg))
		}
		if err := x.blockStore.StoreLastVote(timeoutVoteMsg); err != nil {
			x.log.WarnContext(ctx, "failed to store timeout vote", logger.Error(err))
		}
		x.pacemaker.SetTimeoutVote(timeoutVoteMsg)
	}
	// in the case root chain has not made any progress (less than quorum nodes online), broadcast the same vote again
	// broadcast timeout vote
	x.log.LogAttrs(ctx, logger.LevelTrace, "broadcasting timeout vote")
	x.log.InfoContext(ctx, "broadcast timeout vote", "round", x.pacemaker.GetCurrentRound(), "messageID", timeoutMessageID(timeoutVoteMsg))
	if err := x.net.Send(ctx, timeoutVoteMsg, x.Validators()...); err != nil {
		x.log.WarnContext(ctx, "error on broadcasting timeout vote", logger.Error(err))
	}
	x.voteCnt.Add(ctx, 1, attrSetVoteForTC)
}

// onPartitionIRChangeReq handle partition change requests. Received from go routine handling
// partition communication when either partition reaches consensus or cannot reach consensus.
func (x *ConsensusManager) onPartitionIRChangeReq(ctx context.Context, req *IRChangeRequest) (rErr error) {
	ctx, span := x.tracer.Start(ctx, "ConsensusManager.onPartitionIRChangeReq", trace.WithAttributes(observability.Round(x.pacemaker.GetCurrentRound())))
	defer func() {
		if rErr != nil {
			span.RecordError(rErr)
			span.SetStatus(codes.Error, rErr.Error())
		}
		span.End()
	}()

	irReq := &drctypes.IRChangeReq{
		Partition: req.Partition,
		Shard:     req.Shard,
		Requests:  req.Requests,
	}
	if err := x.refuseFrozenIR(irReq); err != nil {
		return err
	}
	switch req.Reason {
	case Quorum:
		irReq.CertReason = drctypes.Quorum
	case QuorumNotPossible:
		irReq.CertReason = drctypes.QuorumNotPossible
	default:
		return fmt.Errorf("invalid IR change request from partition %s: unknown reason %v", irReq.Partition, req.Reason)
	}

	nextLeader, err := x.leaderAfter(x.pacemaker.GetCurrentRound())
	if err != nil {
		return fmt.Errorf("failed to get next leader to forward IR change request: %w", err)
	}
	if nextLeader == x.id {
		if err := x.bufferIRChange(irReq); err != nil {
			return fmt.Errorf("failed to add IR change request from partition %s into buffer: %w", irReq.Partition, err)
		}
		x.log.DebugContext(ctx, "IR change request buffered", logger.Shard(req.Partition, req.Shard))
		return nil
	}
	// forward to leader
	irMsg := &abdrc.IrChangeReqMsg{
		Author:      x.id.String(),
		IrChangeReq: irReq,
	}
	if err := x.safety.Sign(x.trustBase.Load().Epoch, irMsg); err != nil {
		return fmt.Errorf("failed to sign IR change request from partition %s: %w", irReq.Partition, err)
	}
	if err := x.net.Send(ctx, irMsg, nextLeader); err != nil {
		return fmt.Errorf("failed to send IR change request from partition %s: %w", irReq.Partition, err)
	}
	x.log.DebugContext(ctx, fmt.Sprintf("IR change request forwarded to %s", nextLeader.ShortString()), logger.Shard(req.Partition, req.Shard))
	return nil
}

// SelectRequestHistory selects the view-aware branch of request collection and judgement from a committed request history: the request
// verifier judges every certification request under the view resolved from it, and the leader's buffer, timeouts and proposal payload
// resolve the same views. Without it a shard whose installed assignment is weighted has no request context at all (counting is refused,
// never a fallback to counting members), so a Q3 deployment selects it at startup, before any activation.
func (x *ConsensusManager) SelectRequestHistory(h storage.RequestHistory) error {
	if h == nil {
		return ErrNoRequestHistory
	}
	parent := func(p types.PartitionID, s types.ShardID) (*storage.ShardInfo, []byte, *types.InputRecord, error) {
		state, err := x.blockStore.GetState()
		if err != nil {
			return nil, nil, nil, err
		}
		id, err := state.CommittedHead.Block.Hash(crypto.SHA256)
		return x.blockStore.ShardInfo(p, s), id, nil, err
	}
	resolver, err := NewRequestViewResolver(h, crypto.SHA256, parent, nil)
	if err != nil {
		return err
	}
	x.irReqVerifier.SetRequestHistory(h)
	x.SetViewResolver(resolver)
	return nil
}

// ErrNoRequestHistory is returned when the view-aware branch is selected without a request history.
var ErrNoRequestHistory = errors.New("consensus: no request history to select")

// HandoffCandidate is the retained candidate preimage of a committed successor body: the source a request history serves from.
func (x *ConsensusManager) HandoffCandidate(bodyID []byte) ([]byte, error) {
	return x.blockStore.HandoffCandidate(bodyID)
}

// SetViewResolver selects the view-aware branch of the leader's buffer, timeouts and proposal payload. Production selects it only through
// SelectRequestHistory (a Q3 deployment); otherwise the legacy dispatch stays.
func (x *ConsensusManager) SetViewResolver(r ViewResolver) { x.viewResolver = r }

// RequestView resolves the authenticated view the node's collector admits the shard's certification requests under, for the next
// proposal round and the collection purpose (which may name a committed successor before its activation round: the view is then
// collection-only). enabled is false while the view-aware branch is not selected, so the collector keeps the committed ShardInfo.
// A node in recovery refuses, like ShardInfo.
func (x *ConsensusManager) RequestView(partition types.PartitionID, shard types.ShardID) (*storage.RequestRoundView, bool, error) {
	if x.viewResolver == nil {
		return nil, false, nil
	}
	if x.recovery.InRecovery() {
		return nil, true, fmt.Errorf("%w: %w: node is in recovery: %s", ErrViewRecovery, storage.ErrAssignmentHistory, x.recovery)
	}
	view, err := x.viewResolver.ResolveView(partition, shard, x.pacemaker.GetCurrentRound()+1, storage.PurposeCollect)
	return view, true, err
}

// bufferIRChange buffers an IR change request of the next proposal, under the view resolved for it when the view-aware branch is
// selected, else by the legacy round-only verification.
func (x *ConsensusManager) bufferIRChange(req *drctypes.IRChangeReq) error {
	if x.viewResolver == nil || req == nil {
		return x.irReqBuffer.Add(x.pacemaker.GetCurrentRound(), req, x.irReqVerifier)
	}
	view, err := x.viewResolver.ResolveView(req.Partition, req.Shard, x.pacemaker.GetCurrentRound()+1, storage.PurposeCertify)
	if err != nil {
		return fmt.Errorf("resolving the request view: %w", err)
	}
	return x.irReqBuffer.AddView(view, req, x.irReqVerifier)
}

// stateHistory is the lineage a StateMsg's certificates are verified against: the verified Q3 history's view over the recovery
// history when the binary knows Q3, so that the certificates of an activated epoch are checked under its own weights, and the
// recovery history alone otherwise.
func (x *ConsensusManager) stateHistory() abdrc.HistoricalTrustBases {
	if x.q3 != nil {
		return x.q3.Lineage(x.recoveryHistory)
	}
	return x.recoveryHistory
}

// carryRequestHistory keeps the history the view-aware branch resolves from across a recovery that replaces the verifier: it is
// committed state, not recovered state, and losing it would silently select the legacy dispatch.
func carryRequestHistory(from, to *IRChangeReqVerifier) {
	if from != nil && to != nil {
		to.SetRequestHistory(from.RequestHistory())
	}
}

// onIRChangeMsg handles IR change request messages from other root nodes
func (x *ConsensusManager) onIRChangeMsg(ctx context.Context, irChangeMsg *abdrc.IrChangeReqMsg) error {
	ctx, span := x.tracer.Start(ctx, "ConsensusManager.onIRChangeMsg")
	defer span.End()

	if err := irChangeMsg.Verify(x.trustBase.Load()); err != nil {
		return fmt.Errorf("invalid IR change request from node %s: %w", irChangeMsg.Author, err)
	}
	if err := x.refuseFrozenIR(irChangeMsg.IrChangeReq); err != nil {
		return err
	}
	nextLeader, err := x.leaderAfter(x.pacemaker.GetCurrentRound())
	if err != nil {
		return fmt.Errorf("failed to get next leader to forward IR change request: %w", err)
	}
	// if the node will be the next leader then buffer the request to be included in the block proposal
	// todo: if in recovery then forward to next?
	if nextLeader == x.id {
		if err := x.bufferIRChange(irChangeMsg.IrChangeReq); err != nil {
			// if duplicate - the same is already in progress, then it is ok; this is just most likely a delayed request
			if errors.Is(err, ErrDuplicateChangeReq) {
				return nil
			}
			return fmt.Errorf("failed to add IR change request from %s into buffer: %w", irChangeMsg.Author, err)
		}
		x.log.DebugContext(ctx, fmt.Sprintf("IR change request from node %s buffered", irChangeMsg.Author), logger.Shard(irChangeMsg.IrChangeReq.Partition, irChangeMsg.IrChangeReq.Shard))
		return nil
	}
	// todo: AB-549 add max hop count or some sort of TTL?
	// either this is a completely lost message or because of race we just proposed, forward the original
	// message again to next leader
	x.fwdIRCRCnt.Add(ctx, 1, observability.Shard(irChangeMsg.IrChangeReq.Partition, irChangeMsg.IrChangeReq.Shard, attribute.String("reason", irChangeMsg.IrChangeReq.CertReason.String())))
	if err := x.net.Send(ctx, irChangeMsg, nextLeader); err != nil {
		return fmt.Errorf("failed to forward IR change request from %s to the next leader: %w", irChangeMsg.Author, err)
	}
	return nil
}

func (x *ConsensusManager) refuseFrozenIR(req *drctypes.IRChangeReq) error {
	if req == nil || x.params.NetworkProfileVersion != storage.ProfileHandoff {
		return nil
	}
	qc := x.blockStore.GetHighQc()
	if qc == nil {
		return nil
	}
	frozen, active, err := x.blockStore.FrozenShardAt(qc.GetRound())
	if err != nil {
		return err
	}
	if active && frozen == (types.PartitionShardID{PartitionID: req.Partition, ShardID: req.Shard.Key()}) {
		return storage.ErrHandoffFrozen
	}
	return nil
}

// onVoteMsg handle votes messages from other root validators
func (x *ConsensusManager) onVoteMsg(ctx context.Context, vote *abdrc.VoteMsg) error {
	ctx, span := x.tracer.Start(ctx, "ConsensusManager.onVoteMsg", trace.WithAttributes(observability.Round(vote.VoteInfo.RoundNumber)))
	defer span.End()

	if vote.VoteInfo.RoundNumber < x.pacemaker.GetCurrentRound() {
		x.susVotes.Add(ctx, 1, attrSetQCVoteStale)
		return fmt.Errorf("stale vote for round %d from %s", vote.VoteInfo.RoundNumber, vote.Author)
	}
	// verify signature on vote
	if err := vote.Verify(x.trustBaseStore); err != nil {
		return fmt.Errorf("invalid vote: %w", err)
	}
	// The author was authenticated under the trust base of the vote's epoch; its weight is taken from the current one.
	if err := x.checkWeightEpoch(vote.VoteInfo.Epoch); err != nil {
		return err
	}
	if x.epochAnchor != nil {
		if vote.VoteInfo.Epoch != x.epochAnchor.Epoch ||
			(vote.Anchor != nil && !x.matchesInstalledAnchor(vote.Anchor)) ||
			(vote.HighQc != nil && (vote.HighQc.VoteInfo == nil || vote.HighQc.VoteInfo.Epoch != x.epochAnchor.Epoch)) {
			return drctypes.ErrEpochAnchor
		}
	} else if vote.Anchor != nil {
		return drctypes.ErrEpochAnchor
	}
	// if a vote is received for future round it is intended for the node which is going to be the
	// leader. Cache the vote and wait for more one vote is not enough to trigger recovery.
	// If the node has received at least f+1 votes, then at least 1 honest node also agrees that this node
	// should be the next leader - try and recover.
	if vote.VoteInfo.RoundNumber > x.pacemaker.GetCurrentRound() {
		// either vote arrived before proposal or node is just behind (others think we're the leader of
		// the round, but we haven't seen QC or TC for previous round?)
		// Votes are buffered for one round only so if we overwrite author's vote it is either stale
		// or we have received the vote more than once.
		x.susVotes.Add(ctx, 1, attrSetQCVoteEarly)
		x.log.DebugContext(ctx, "received vote for future round")
		x.voteBuffer[vote.Author] = vote
		// if we have received quorum votes, but no proposal yet or otherwise behind, then try and recover.
		// other nodes seem to think we are the next leader
		// NB! it seems that it's quite common that votes arrive before proposal and going into recovery
		// too early is counterproductive... maybe do not trigger recovery here at all - if we're lucky
		// proposal will arrive on time, otherwise round will likely TO anyway?
		bufferedWeight, err := x.bufferedWeight()
		if err != nil {
			return fmt.Errorf("buffered vote weight: %w", err)
		}
		if reached(bufferedWeight, x.voteQuorumInfo()) {
			err := fmt.Errorf("have received vote weight %d but no proposal, entering recovery", bufferedWeight)
			if e := x.sendRecoveryRequests(ctx, vote); e != nil {
				err = errors.Join(err, fmt.Errorf("sending recovery requests failed: %w", e))
			}
			return err
		}
		return nil
	}
	if vote.HighQc != nil {
		if err := x.checkRecoveryNeeded(vote.HighQc); err != nil {
			// we need to buffer the vote(s) so that when recovery succeeds we can "replay"
			// them - otherwise there might not be enough votes to achieve quorum and round
			// will time out
			x.voteBuffer[vote.Author] = vote
			err = fmt.Errorf("vote triggers recovery: %w", err)
			if e := x.sendRecoveryRequests(ctx, vote); e != nil {
				err = errors.Join(err, fmt.Errorf("sending recovery requests failed: %w", e))
			}
			return err
		}
	}

	// Normal votes are only sent to the next leader (timeout votes are broadcast) is it us?
	// NB! we assume vote.VoteInfo.RoundNumber == x.pacemaker.GetCurrentRound() but it also could be that VVR > CR+1
	nextLeader, err := x.leaderAfter(vote.VoteInfo.RoundNumber)
	if err != nil {
		return fmt.Errorf("could not determine leader for the round after %d: %w", vote.VoteInfo.RoundNumber, err)
	}
	if nextLeader != x.id {
		return fmt.Errorf("validator is not the leader for the round after %d", vote.VoteInfo.RoundNumber)
	}

	qc, mature, err := x.pacemaker.RegisterVote(vote, x.voteQuorumInfo())
	if err != nil {
		return fmt.Errorf("failed to register vote: %w", err)
	}
	x.log.LogAttrs(ctx, logger.LevelTrace, fmt.Sprintf("processed vote, quorum: %t, mature: %t", qc != nil, mature))
	if qc != nil && mature {
		x.processQC(ctx, qc)
		x.processNewRoundEvent(ctx)
		x.updateQCMetrics(ctx, qc)
	}
	return nil
}

// bufferedVoteWeight is the weight of the authors of the buffered future-round votes, under the same weighting as QC
// formation: it must be taken from the profile-aware quorum info, not from the raw trust base.
func bufferedVoteWeight(buffer map[string]*abdrc.VoteMsg, quorum QuorumInfo) (uint64, error) {
	var tally quorumweight.Tally
	for author := range buffer {
		w, err := authorWeight(quorum, author)
		if err == nil {
			err = tally.Add(author, w)
		}
		if err != nil {
			return 0, err
		}
	}
	return tally.Weight(), nil
}

// bufferedWeight weighs the buffered votes with the manager's profile-aware quorum info (see voteQuorumInfo).
func (x *ConsensusManager) bufferedWeight() (uint64, error) {
	return bufferedVoteWeight(x.voteBuffer, x.voteQuorumInfo())
}

// ErrVoteEpoch is returned for a vote or timeout vote whose epoch is not the epoch the voting weights are taken from.
// ErrViewRecovery refuses a request view while the node is in recovery. It is an unavailable-view refusal (also
// storage.ErrAssignmentHistory), never a fallback to the legacy dispatch.
var ErrViewRecovery = errors.New("request view unavailable: node is in recovery")

var ErrVoteEpoch = errors.New("vote epoch differs from the weighting epoch")

// checkWeightEpoch refuses a vote for another epoch than the current trust base: its author would be weighed by a
// committee that did not authenticate it (an author of the previous epoch is unknown, or has another weight, here).
func (x *ConsensusManager) checkWeightEpoch(epoch uint64) error {
	if tb := x.trustBase.Load(); tb != nil && tb.Epoch != epoch {
		return fmt.Errorf("%w: message epoch %d, trust base epoch %d", ErrVoteEpoch, epoch, tb.Epoch)
	}
	return nil
}

func (x *ConsensusManager) voteQuorumInfo() QuorumInfo {
	trust := x.trustBase.Load()
	if x.params.NetworkProfileVersion == storage.ProfileHandoff {
		return profile2QuorumInfo{QuorumInfo: trust}
	}
	return trust
}

// onTimeoutMsg handles timeout vote messages from other root validators
// Timeout votes are broadcast to all nodes on local timeout and all validators try to assemble
// timeout certificate independently.
func (x *ConsensusManager) onTimeoutMsg(ctx context.Context, vote *abdrc.TimeoutMsg) error {
	ctx, span := x.tracer.Start(ctx, "ConsensusManager.onTimeoutMsg")
	defer span.End()
	if vote.Timeout.Round < x.pacemaker.GetCurrentRound() {
		return fmt.Errorf("stale timeout vote for round %d from %s", vote.Timeout.Round, vote.Author)
	}
	// verify signature on vote
	if err := vote.Verify(x.trustBaseStore); err != nil {
		return fmt.Errorf("invalid timeout vote: %w", err)
	}
	if err := x.checkWeightEpoch(vote.Timeout.Epoch); err != nil {
		return err
	}
	if err := x.validateTimeoutParent(vote.Timeout); err != nil {
		return err
	}
	if err := x.validateTimeoutCert(vote.LastTC); err != nil {
		return err
	}
	// SyncState, compare last handled QC
	if vote.Timeout.HighQc != nil {
		if err := x.checkRecoveryNeeded(vote.Timeout.HighQc); err != nil {
			err = fmt.Errorf("timeout vote triggers recovery: %w", err)
			if e := x.sendRecoveryRequests(ctx, vote); e != nil {
				err = errors.Join(err, fmt.Errorf("sending recovery requests failed: %w", e))
			}
			return err
		}
	}
	// node is up-to-date, first handle high QC, maybe this has not been seen yet
	x.processQC(ctx, vote.Timeout.HighQc)
	// when there is multiple consecutive timeout rounds and instance is in one of the previous round
	// (ie haven't got enough timeout votes for the latest round quorum) recovery is not triggered as
	// the highQC is the same for both rounds. So checking the lastTC helps the instance into latest TO round.
	x.processTC(ctx, vote.LastTC)

	tc, err := x.pacemaker.RegisterTimeoutVote(ctx, vote, x.voteQuorumInfo())
	if err != nil {
		return fmt.Errorf("failed to register timeout vote: %w", err)
	}
	if tc == nil {
		x.log.LogAttrs(ctx, logger.LevelTrace, fmt.Sprintf("processed timeout vote for round %d, no quorum yet", vote.Timeout.Round))
		return nil
	}
	x.log.DebugContext(ctx, fmt.Sprintf("timeout quorum for round %d achieved", vote.Timeout.Round))
	// process timeout certificate to advance to next the view/round
	x.processTC(ctx, tc)
	// if this node is the leader in this round then issue a proposal
	l, err := x.leaderSelector.GetLeaderForRound(x.pacemaker.GetCurrentRound())
	if err != nil {
		x.log.WarnContext(ctx, "could not determine leader for new round, waiting for proposal", logger.Error(err))
		return nil
	}
	if l == x.id {
		x.processNewRoundEvent(ctx)
	} else {
		x.log.LogAttrs(ctx, logger.LevelTrace, fmt.Sprintf("new leader is %s, waiting for proposal", l.String()))
	}
	return nil
}

/*
checkRecoveryNeeded verify current state against received state and determine if the validator needs to
recover or not. Basically either the state is different or validator is behind (has skipped some views/rounds).
Returns nil when no recovery is needed and error describing the reason to trigger the recovery otherwise.
*/
func (x *ConsensusManager) checkRecoveryNeeded(qc *drctypes.QuorumCert) error {
	// when node has fallen behind we trigger recovery here as we fail to load block for
	// the round - it would be nicer to have explicit round check?
	block, err := x.blockStore.Block(qc.VoteInfo.RoundNumber)
	if err != nil {
		return fmt.Errorf("failed to read root hash for round %d from local block store: %w", qc.VoteInfo.RoundNumber, err)
	}
	if !bytes.Equal(qc.VoteInfo.CurrentRootHash, block.RootHash) {
		return fmt.Errorf("unexpected round %d state - expected %X, local %X", qc.VoteInfo.RoundNumber, qc.VoteInfo.CurrentRootHash, block.RootHash)
	}
	return drctypes.VerifyTimestampProof(block.BlockData, qc)
}

// onProposalMsg handles block proposal messages from other validators.
// Only a proposal made by the leader of this view/round shall be accepted and processed
func (x *ConsensusManager) onProposalMsg(ctx context.Context, proposal *abdrc.ProposalMsg) error {
	ctx, span := x.tracer.Start(ctx, "ConsensusManager.onProposalMsg")
	defer span.End()
	if proposal.Block.Round < x.pacemaker.GetCurrentRound() {
		return fmt.Errorf("stale proposal for round %d from %s", proposal.Block.Round, proposal.Block.Author)
	}
	// verify signature on proposal (does not verify partition request signatures)
	if err := proposal.Verify(x.trustBaseStore); err != nil {
		return fmt.Errorf("invalid proposal: %w", err)
	}
	if err := x.validateProposalParent(proposal.Block); err != nil {
		return err
	}
	if err := x.validateTimeoutCert(proposal.LastRoundTc); err != nil {
		return err
	}
	// Check current state against new QC
	if proposal.Block.Qc != nil {
		if err := x.checkRecoveryNeeded(proposal.Block.Qc); err != nil {
			err = fmt.Errorf("proposal triggers recovery: %w", err)
			if e := x.sendRecoveryRequests(ctx, proposal); e != nil {
				err = errors.Join(err, fmt.Errorf("sending recovery requests failed: %w", e))
			}
			return err
		}
	}
	// Is from valid leader
	l, err := x.leaderSelector.GetLeaderForRound(proposal.Block.Round)
	if err != nil {
		return fmt.Errorf("could not determine leader for round %d to verify proposal: %w", proposal.Block.Round, err)
	}
	if l.String() != proposal.Block.Author {
		return fmt.Errorf("expected %s to be leader of the round %d but got proposal from %s", l, proposal.Block.Round, proposal.Block.Author)
	}
	// Refuse invalid live time before executing or mutating the pacemaker.
	if err := x.safety.validateVoteTimestamp(proposal.Block); err != nil {
		return fmt.Errorf("proposal timestamp: %w", err)
	}
	// Every proposal must carry a QC or TC for previous round
	// Process QC first, update round
	x.processQC(ctx, proposal.Block.Qc)
	x.processTC(ctx, proposal.LastRoundTc)
	// the witnesses of the block's controls are not in the proposal: fetch what is missing from the root nodes, the author first
	if err := x.fetchWitnesses(ctx, x.blockStore, proposal.Block); err != nil {
		return fmt.Errorf("proposal controls: %w", err)
	}
	// execute proposed payload
	start := time.Now()
	execStateId, err := x.blockStore.Add(proposal.Block, x.irReqVerifier)
	x.addBlockDur.Record(ctx, time.Since(start).Seconds())
	if err != nil {
		// wait for timeout, if others make progress this node will need to recover
		// cannot send vote, so just return and wait for local timeout or new proposal (and try to recover then)
		return fmt.Errorf("failed to execute proposal: %w", err)
	}
	// make vote
	voteMsg, err := x.safety.MakeVote(proposal.Block, execStateId, x.blockStore.GetHighQc(), x.pacemaker.LastRoundTC())
	if err != nil {
		// wait for timeout, if others make progress this node will need to recover
		return fmt.Errorf("failed to sign vote: %w", err)
	}
	x.log.InfoContext(ctx, "signed vote", "round", proposal.Block.Round, "messageID", voteMessageID(voteMsg))
	if err = x.blockStore.StoreLastVote(voteMsg); err != nil {
		x.log.WarnContext(ctx, "vote store failed", logger.Error(err))
	}
	x.pacemaker.SetVoted(voteMsg)
	nextLeader, err := x.leaderAfter(x.pacemaker.GetCurrentRound())
	if err != nil {
		return fmt.Errorf("could not determine next leader to send vote: %w", err)
	}
	x.log.LogAttrs(ctx, logger.LevelTrace, fmt.Sprintf("sending vote to next leader %s, round %d", nextLeader.String(), proposal.Block.Round))
	x.voteCnt.Add(ctx, 1, attrSetVoteForQC)
	if err = x.net.Send(ctx, voteMsg, nextLeader); err != nil {
		return fmt.Errorf("failed to send vote to next leader: %w", err)
	}
	x.replayVoteBuffer(ctx)
	// if everything goes fine, but the node is in recovery state, then clear it
	// most likely ended up here because proposal was late and votes arrived before
	if x.recovery.Clear() != nil {
		x.log.DebugContext(ctx, "clearing recovery state on proposal")
	}
	return nil
}

// processQC - handles quorum certificate
func (x *ConsensusManager) processQC(ctx context.Context, qc *drctypes.QuorumCert) {
	ctx, span := x.tracer.Start(ctx, "ConsensusManager.processQC")
	defer span.End()
	if qc == nil {
		return
	}
	if x.epochAnchor != nil && (qc.VoteInfo == nil || qc.VoteInfo.Epoch != x.epochAnchor.Epoch) {
		return
	}
	if parent, err := x.blockStore.Block(qc.GetRound()); err == nil && parent.BlockData.Anchor == nil {
		if err := drctypes.VerifyTimestampProof(parent.BlockData, qc); err != nil {
			x.log.WarnContext(ctx, "QC timestamp differs from executed block", logger.Error(err))
			if e := x.sendRecoveryRequests(ctx, qc); e != nil {
				x.log.WarnContext(ctx, "timestamp recovery request failed", logger.Error(e))
			}
			return
		}
	}
	certs, err := x.blockStore.ProcessQc(qc)
	if err != nil {
		if x.frontier != nil && errors.Is(err, storage.ErrPersistenceUncertain) {
			x.frontier.latchFault()
		}
		x.log.WarnContext(ctx, "failure to process QC triggers recovery", logger.Error(err))
		if err := x.sendRecoveryRequests(ctx, qc); err != nil {
			x.log.WarnContext(ctx, "sending recovery requests failed", logger.Error(err))
		}
		return
	}
	if shouldSendCertificateBatch(x.params.NetworkProfileVersion, certs) {
		select {
		case <-ctx.Done():
			return // node is exiting certificates have been stored and we are done
		case x.ucSink <- certs: // trigger update to partition nodes
		}
	}

	if !x.pacemaker.AdvanceRoundQC(ctx, qc) {
		return
	}

	// Round was advanced, we could have a new trust base.
	x.updateTrustBase()

	// in the "DiemBFT v4" pseudocode the process_certificate_qc first calls
	// leaderSelector.Update and after that pacemaker.AdvanceRound - we do it the
	// other way around as otherwise current leader goes out of sync with peers...
	if err := x.leaderSelector.Update(qc, x.pacemaker.GetCurrentRound(), x.blockStore.Block); err != nil {
		x.log.ErrorContext(ctx, "failed to update leader selector", logger.Error(err))
	}
}

func shouldSendCertificateBatch(profile uint64, certs []*certification.CertificationResponse) bool {
	return len(certs) > 0 || profile != storage.ProfileHandoff
}

// processTC - handles timeout certificate
func (x *ConsensusManager) processTC(ctx context.Context, tc *drctypes.TimeoutCert) {
	_, span := x.tracer.Start(ctx, "ConsensusManager.processTC")
	defer span.End()
	if tc == nil {
		return
	}
	if x.validateTimeoutCert(tc) != nil {
		return
	}
	if err := x.blockStore.ProcessTc(tc); err != nil {
		// method deletes the block that got TC - it will never be part of the chain.
		// however, this node might not have even seen the block, in which case error is returned, but this is ok - just log
		x.log.DebugContext(ctx, "could not remove the timeout block, node has not received it", logger.Error(err))
	}
	if x.pacemaker.AdvanceRoundTC(ctx, tc) {
		// Round was advanced, we could have a new trust base.
		x.updateTrustBase()
	}
}

/*
sendCertificates reads UCs produced by processing QC and makes them available for
validator via certResultCh chan (returned by CertificationResult method).
The idea is not to block CM until validator consumes the certificates, ie to
send the UCs in an async fashion.
*/
func (x *ConsensusManager) sendCertificates(ctx context.Context) error {
	// pending certificates, to be consumed by the validator.
	// access to it is "serialized" ie we either update it with
	// new certs sent by CM or we feed it's content to validator
	certs := make(map[types.PartitionShardID]*certification.CertificationResponse)

	feedValidator := func(ctx context.Context) chan struct{} {
		stopped := make(chan struct{})
		go func() {
			defer close(stopped)
			for key, uc := range certs {
				select {
				case x.certResultCh <- uc:
					delete(certs, key)
				case <-ctx.Done():
					return
				}
			}
		}()
		return stopped
	}

	stopFeed := func() { /* init to NOP */ }
	for {
		select {
		case nm := <-x.ucSink:
			stopFeed()
			// NB! if previous UC for given system hasn't been consumed yet we'll overwrite it!
			// this means that the validator sees newer UC than expected and goes into recovery,
			// rolling back pending block proposal?
			for _, uc := range nm {
				certs[types.PartitionShardID{PartitionID: uc.Partition, ShardID: uc.Shard.Key()}] = uc
			}
			feedCtx, cancel := context.WithCancel(ctx) // #nosec G118 cancel is called via stopFeed closure
			stopped := feedValidator(feedCtx)
			stopFeed = func() {
				cancel()
				<-stopped
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

/*
replayVoteBuffer processes buffered votes. When method returns the buffer should be empty.
*/
func (x *ConsensusManager) replayVoteBuffer(ctx context.Context) {
	ctx, span := x.tracer.Start(ctx, "ConsensusManager.replayVoteBuffer")
	defer span.End()

	voteCnt := len(x.voteBuffer)
	if voteCnt == 0 {
		return
	}

	x.log.DebugContext(ctx, fmt.Sprintf("replaying %d buffered votes", voteCnt))
	var errs []error
	for _, v := range x.voteBuffer {
		if err := x.onVoteMsg(ctx, v); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		// log the error(s) rather than return them as failing to process buffered
		// votes is not critical from the callers POV, but we want to have this info
		// for debugging
		err := errors.Join(errs...)
		x.log.WarnContext(ctx, fmt.Sprintf("out of %d buffered votes %d caused error on replay", voteCnt, len(errs)), logger.Error(err))
		span.RecordError(err)
	}

	clear(x.voteBuffer)
}

// processNewRoundEvent handled new view event, is called when either QC or TC is reached locally and
// triggers a new round. If this node is the leader in the new view/round, then make a proposal otherwise
// wait for a proposal from a leader in this round/view
// errRoundOverflow is returned when the successor of a round does not exist in uint64.
var errRoundOverflow = errors.New("round has no successor")

// leaderAfter is the leader of the round after the given one. The successor is overflow-checked before the lookup, so a round at the top
// of the space is refused instead of wrapping to round 0. The lookup itself is O(1), read-only and allocation-free (the weighted selector
// is a period table), so it needs no further guard; the selector asked is always the current epoch's, which is built only from verified
// context.
func (x *ConsensusManager) leaderAfter(round uint64) (peer.ID, error) {
	if round == math.MaxUint64 {
		return "", errRoundOverflow
	}
	return x.leaderSelector.GetLeaderForRound(round + 1)
}

func (x *ConsensusManager) processNewRoundEvent(ctx context.Context) {
	ctx, span := x.tracer.Start(ctx, "ConsensusManager.processNewRoundEvent")
	defer span.End()
	round := x.pacemaker.GetCurrentRound()

	l, err := x.leaderSelector.GetLeaderForRound(round)
	if err != nil {
		x.log.WarnContext(ctx, "could not determine leader for new round, awaiting proposal", "round", round, logger.Error(err))
		return
	}
	if l != x.id {
		x.log.InfoContext(ctx, fmt.Sprintf("new round start, not leader, awaiting proposal from %s", l.ShortString()))
		return
	}

	x.leaderCnt.Add(ctx, 1)
	// x.log.InfoContext(ctx, "new round start, node is leader")

	// find shards with T2 timeouts
	profile := x.params.NetworkProfileVersion
	if profile == 0 {
		profile = storage.ProfileLegacy
	}
	oldSuffix := false
	if highQC := x.blockStore.GetHighQc(); profile == storage.ProfileHandoff && highQC != nil {
		oldSuffix, err = x.blockStore.SuffixParent(highQC.GetRound(), x.trustBase.Load().Epoch)
		if err != nil {
			x.log.WarnContext(ctx, "cannot establish parent control state", logger.Error(err))
			return
		}
	}
	var timedOutShards []*types.UnicityCertificate
	if !oldSuffix {
		if x.viewResolver != nil {
			timedOutShards, err = x.t2Timeouts.GetT2TimeoutsView(round, x.viewResolver)
		} else {
			timedOutShards, err = x.t2Timeouts.GetT2Timeouts(round)
		}
	}
	if err != nil {
		// error here is not fatal, still make a proposal, hopefully the next node will generate timeout
		// requests for partitions this node failed to query
		x.log.WarnContext(ctx, "failed to check timeouts for some partitions", logger.Error(err))
	}
	payload := &drctypes.Payload{}
	if profile == storage.ProfileHandoff {
		payload.Version = profile
	}
	parentQC := x.blockStore.GetHighQc()
	var handoffRecords [][]byte
	if profile == storage.ProfileHandoff && !oldSuffix {
		handoffRecords, err = x.handoffRecordsForRound(round, parentQC)
		if err != nil {
			x.log.WarnContext(ctx, "cannot propose root handoff record", logger.Error(err))
			return
		}
	}
	if len(handoffRecords) != 0 {
		payload.HandoffRecords = handoffRecords
	} else if !oldSuffix {
		if x.viewResolver != nil {
			var perr error
			if payload, perr = x.irReqBuffer.GeneratePayloadView(round, timedOutShards, x.blockStore.IsChangeInProgress, x.viewResolver, x.irReqVerifier); perr != nil {
				x.log.WarnContext(ctx, "cannot resolve the request views of the proposal", logger.Error(perr))
				return
			}
		} else {
			payload = x.irReqBuffer.GeneratePayload(round, timedOutShards, x.blockStore.IsChangeInProgress)
		}
		if profile == storage.ProfileHandoff {
			payload.Version = profile
			if parentQC != nil {
				frozen, active, err := x.blockStore.FrozenShardForBlock(parentQC.GetRound(), round)
				if err != nil {
					x.log.WarnContext(ctx, "cannot establish frozen EVM shard", logger.Error(err))
					return
				}
				if active {
					kept := payload.Requests[:0]
					for _, req := range payload.Requests {
						if req != nil && frozen == (types.PartitionShardID{PartitionID: req.Partition, ShardID: req.Shard.Key()}) {
							continue
						}
						kept = append(kept, req)
					}
					payload.Requests = kept
				}
			}
		}
	}
	if profile == storage.ProfileHandoff && !oldSuffix && parentQC != nil {
		// a closed epoch's CloseLiability is mandatory in the first ordinary block after its freeze, and in every block until it is in
		closures, err := x.blockStore.ClosureControls(parentQC.GetRound(), x.trustBase.Load().Epoch, round)
		if err != nil {
			x.log.WarnContext(ctx, "cannot build the mandatory closure of the proposal", logger.Error(err))
			return
		}
		payload.PosControls = append(closures, payload.PosControls...)
	}
	var parentAnchor *drctypes.EpochAnchor
	if x.epochAnchor != nil && parentQC == nil {
		parentAnchor = x.epochAnchor
	}
	parentRound := parentQC.GetRound()
	if parentAnchor != nil {
		parentRound = parentAnchor.Slot
	}
	parent, err := x.blockStore.Block(parentRound)
	if err != nil {
		x.log.WarnContext(ctx, "cannot read proposal parent timestamp", logger.Error(err))
		return
	}
	timestamp := proposalTimestamp(types.NewTimestamp(), parent.BlockData.Timestamp)
	block := &drctypes.BlockData{
		Version:   types.Version(profile),
		Author:    x.id.String(),
		Round:     round,
		Epoch:     x.trustBase.Load().Epoch,
		Timestamp: timestamp,
		Payload:   payload,
		Qc:        parentQC,
		Anchor:    parentAnchor,
	}
	if profile == storage.ProfileHandoff && !oldSuffix && parentQC != nil && len(payload.PosControls) < drctypes.MaxPosControls {
		x.orderSubmittedControl(ctx, block)
	}
	proposalMsg := &abdrc.ProposalMsg{
		Block:       block,
		LastRoundTc: x.pacemaker.LastRoundTC(),
	}
	// safety makes simple sanity checks and signs if everything is ok
	if err = x.safety.Sign(proposalMsg.Block.Epoch, proposalMsg); err != nil {
		x.log.WarnContext(ctx, "failed to send proposal message, signing failed", logger.Error(err))
		return
	}
	// broadcast proposal message (also to self)
	span.AddEvent(proposalMsg.Block.String())
	x.log.LogAttrs(ctx, slog.LevelDebug, "broadcast proposal", logger.Data(proposalMsg.Block.String()))

	sendTo := make(map[peer.ID]struct{})
	addAll(sendTo, x.Validators())
	if profile != storage.ProfileHandoff && round == x.trustBase.Load().EpochStart {
		// New epoch was activated in this round. Also send the proposal to previous epoch
		// validators so that they can generae UCs for the round they voted to commit.
		prevTrustBase, err := x.trustBaseStore.GetByEpoch(x.trustBase.Load().Epoch - 1)
		if err != nil {
			x.log.WarnContext(ctx, "failed to get trust base for previous epoch", logger.Error(err))
		}
		addAll(sendTo, toIDSlice(prevTrustBase.RootNodes, x.log))
	}
	if err = x.net.Send(ctx, proposalMsg, slices.Collect(maps.Keys(sendTo))...); err != nil {
		x.log.WarnContext(ctx, "error on broadcasting proposal message", logger.Error(err))
	}
	for _, cr := range proposalMsg.Block.Payload.Requests {
		x.proposedCR.Add(ctx, 1, observability.Shard(cr.Partition, cr.Shard, attribute.String("reason", cr.CertReason.String())))
	}
}

func (x *ConsensusManager) onStateReq(ctx context.Context, req *abdrc.StateRequestMsg) error {
	if x.recovery.InRecovery() {
		return fmt.Errorf("node is in recovery: %s", x.recovery)
	}
	peerID, err := peer.Decode(req.NodeId)
	if err != nil {
		return fmt.Errorf("invalid receiver identifier %q: %w", req.NodeId, err)
	}
	stateMsg, err := x.blockStore.GetState()
	if err != nil {
		return fmt.Errorf("creating state message: %w", err)
	}
	if err = x.net.Send(ctx, stateMsg, peerID); err != nil {
		return fmt.Errorf("failed to send state response message: %w", err)
	}
	return nil
}

func (x *ConsensusManager) onStateResponse(ctx context.Context, rsp *abdrc.StateMsg) (rErr error) {
	ctx, span := x.tracer.Start(ctx, "ConsensusManager.onStateResponse")
	defer span.End()
	x.log.LogAttrs(ctx, logger.LevelTrace, "received state response; recoveryState: "+x.recovery.String())
	if !x.recovery.InRecovery() {
		// we do send out multiple state recovery request so do not return error when we ignore the ones after successful recovery...
		return nil
	}
	if x.epochAnchor != nil && !x.recoveryProfile2 {
		return fmt.Errorf("recovery response verification failed: %w", abdrc.ErrRecoveryEpoch)
	}
	var verifyErr error
	if x.recoveryProfile2 {
		if x.recoveryHistory == nil {
			return fmt.Errorf("recovery response verification failed: %w", abdrc.ErrHistoricalTrustBase)
		}
		verifyErr = rsp.VerifyWithAnchorSigning(x.params.HashAlgorithm, x.trustBase.Load(), x.stateHistory(), x.blockStore, x.trustBaseStore, x.trustBaseStore.GenesisPin())
	} else {
		verifyErr = rsp.VerifySigning(x.params.HashAlgorithm, x.trustBase.Load(), x.trustBaseStore, x.trustBaseStore.GenesisPin())
	}
	if err := verifyErr; err != nil {
		return fmt.Errorf("recovery response verification failed: %w", err)
	}
	if err := rsp.CanRecoverToRound(x.recovery.ToRound()); err != nil {
		return fmt.Errorf("state message not suitable for recovery: %w", err)
	}
	// sort blocks by round
	slices.SortFunc(rsp.Pending, func(a, b *drctypes.BlockData) int {
		return cmp.Compare(a.GetRound(), b.GetRound())
	})
	recoveryWriteStarted := true
	defer func() {
		if recoveryWriteStarted && rErr != nil && x.frontier != nil {
			x.frontier.latchFault()
		}
	}()
	var blockStore *storage.BlockStore
	var err error
	if x.recoveryProfile2 && rsp.CommittedHead.Anchor != nil {
		blockStore, err = x.blockStore.NewFromAnchorState(rsp.CommittedHead)
	} else {
		blockStore, err = storage.NewFromState(x.params.HashAlgorithm, rsp.CommittedHead, x.blockStore.GetDB(), x.orchestration, x.log, x.params.NetworkProfileVersion)
	}
	if err != nil {
		if errors.Is(err, storage.ErrRefusedBeforeWrite) {
			// The state was refused before the first write: the store is untouched, so there is no uncertainty to latch.
			recoveryWriteStarted = false
		}
		return fmt.Errorf("recovery, new block store init failed: %w", err)
	}
	if x.params.NetworkProfileVersion == storage.ProfileHandoff {
		if x.epochAnchor == nil {
			if err := blockStore.ConfigureHandoffAuthority(x.trustBase.Load()); err != nil {
				return fmt.Errorf("recovery handoff authority: %w", err)
			}
		} else if q3Activated(x.q3, x.epochAnchor) {
			if err := configureV3Authority(blockStore, x.q3, x.trustBase.Load(), x.epochAnchor.Epoch); err != nil {
				return fmt.Errorf("recovery handoff authority: %w", err)
			}
		} else {
			prior, historyErr := x.recoveryHistory.ByEpoch(x.epochAnchor.Epoch)
			if historyErr != nil {
				return fmt.Errorf("recovery handoff authority lineage: %w", historyErr)
			}
			if err := blockStore.ConfigureHandoffV2Authority(x.trustBase.Load(), prior); err != nil {
				return fmt.Errorf("recovery handoff authority: %w", err)
			}
		}
	}
	// create new verifier
	reqVerifier, err := NewIRChangeReqVerifier(x.params, blockStore)
	if err != nil {
		return fmt.Errorf("verifier construction failed: %w", err)
	}
	// the replacement store executes the recovery blocks and then the live ones: it needs the control collaborators of the one it replaces
	blockStore.SetPosServices(x.blockStore.PosServices())
	recoveryRound := blockStore.GetHighQc().GetRound()
	if a := blockStore.RootAnchor(); a != nil && recoveryRound < a.Slot {
		recoveryRound = a.Slot
	}
	x.pacemaker.Reset(ctx, recoveryRound, nil, nil)

	for i, block := range rsp.Pending {
		// if received block has QC then process it first as with a block received normally
		if block.Qc != nil {
			if _, err = blockStore.ProcessQc(block.Qc); err != nil {
				if i != 0 || !errors.Is(err, storage.ErrCommitFailed) {
					// since history is only kept until the last committed round it is not possible to commit a previous round
					return fmt.Errorf("block %d for round %v add qc failed: %w", i, block.GetRound(), err)
				}
				x.log.DebugContext(ctx, "processing QC from recovery block", logger.Error(err))
			}
			x.pacemaker.AdvanceRoundQC(ctx, block.Qc)
			x.updateTrustBase()
		}
		if err = x.fetchWitnesses(ctx, blockStore, block); err != nil {
			return fmt.Errorf("recovery block %d controls: %w", i, err)
		}
		if _, err = blockStore.Add(block, reqVerifier); err != nil {
			return fmt.Errorf("failed to add recovery block %d: %w", i, err)
		}
	}
	t2TimeoutGen, err := NewLucBasedT2TimeoutGenerator(x.params, blockStore)
	if err != nil {
		return fmt.Errorf("recovery T2 timeout generator init failed: %w", err)
	}
	// all ok
	x.blockStore = blockStore
	carryRequestHistory(x.irReqVerifier, reqVerifier)
	x.irReqVerifier = reqVerifier
	x.t2Timeouts = t2TimeoutGen
	// exit recovery status and replay buffered messages
	x.log.DebugContext(ctx, "completed recovery")
	triggerMsg := x.recovery.Clear()
	// in the "DiemBFT v4" pseudocode the process_certificate_qc first calls
	// leaderSelector.Update and after that pacemaker.AdvanceRound - we do it the
	// other way around as otherwise current leader goes out of sync with peers...
	if err = x.leaderSelector.Update(x.blockStore.GetHighQc(), x.pacemaker.GetCurrentRound(), x.blockStore.Block); err != nil {
		x.log.ErrorContext(ctx, "failed to update leader selector", logger.Error(err))
		if x.frontier != nil {
			x.frontier.latchFault()
		}
	}
	// Replay is complete. Ordinary live admission errors below are not uncertain writes.
	recoveryWriteStarted = false
	if prop, ok := triggerMsg.(*abdrc.ProposalMsg); ok {
		// Authenticate the trigger QC against its executed parent before live time admission.
		if prop.Block.Qc != nil {
			if err := x.checkRecoveryNeeded(prop.Block.Qc); err != nil {
				return fmt.Errorf("recovery trigger parent: %w", err)
			}
		}
		// Recheck after recovery with the current store and current clock.
		if err := x.safety.validateVoteTimestamp(prop.Block); err != nil {
			return fmt.Errorf("recovery proposal timestamp: %w", err)
		}
		// Live execution and signing can write again. Preserve conservative fault
		// handling for failures after admission, including the recovered vote path.
		recoveryWriteStarted = true
		// the proposal was verified when it was received, so try and execute it now
		// Every proposal must carry a QC or TC for previous round
		// Process QC first, update round
		x.processQC(ctx, prop.Block.Qc)
		x.processTC(ctx, prop.LastRoundTc)
		var stateHash []byte
		if block, err := x.blockStore.Block(prop.Block.Round); err != nil {
			// Block not found, was not sent with recovery info
			// execute proposed payload
			if err = x.fetchWitnesses(ctx, x.blockStore, prop.Block); err == nil {
				stateHash, err = x.blockStore.Add(prop.Block, x.irReqVerifier)
			}
			if err != nil {
				// wait for timeout, if others make progress this node will need to recover
				// cannot send vote, so just return and wait for local timeout or new proposal (and try to recover then)
				return fmt.Errorf("recovery failed to execute proposal: %w", err)
			}
		} else {
			// use the state hash from storage
			stateHash = block.RootHash
		}
		// send a vote message to next leader
		voteMsg, err := x.safety.MakeVote(prop.Block, stateHash, x.blockStore.GetHighQc(), x.pacemaker.LastRoundTC())
		if err != nil {
			// wait for timeout, if others make progress this node will need to recover
			return fmt.Errorf("failed to sign vote: %w", err)
		}
		x.log.InfoContext(ctx, "signed vote", "round", prop.Block.Round, "messageID", voteMessageID(voteMsg))
		x.pacemaker.SetVoted(voteMsg)
		// send vote to the next leader
		nextLeader, err := x.leaderAfter(x.pacemaker.GetCurrentRound())
		if err != nil {
			return fmt.Errorf("could not determine next leader to send vote after recovery: %w", err)
		}
		x.log.LogAttrs(ctx, logger.LevelTrace, fmt.Sprintf("sending block %d vote after recovery to next leader %s", prop.Block.Round, nextLeader.String()))
		if err = x.net.Send(ctx, voteMsg, nextLeader); err != nil {
			return fmt.Errorf("failed to send vote to next leader: %w", err)
		}
	}
	if tmo, ok := triggerMsg.(*abdrc.TimeoutMsg); ok {
		// timeout vote carries last round TC, if not nil, use it to advance pacemaker to correct round
		// todo: timeout votes are not buffered
		x.processTC(ctx, tmo.LastTC)
	}
	x.replayVoteBuffer(ctx)
	recoveryWriteStarted = false
	return nil
}

func (x *ConsensusManager) sendRecoveryRequests(ctx context.Context, triggerMsg any) error {
	ctx, span := x.tracer.Start(ctx, "ConsensusManager.sendRecoveryRequests")
	defer span.End()

	signatures, err := x.recovery.Set(triggerMsg)
	if err != nil {
		return err
	}

	x.recoveryReq.Add(ctx, 1)

	if err = x.net.Send(ctx, &abdrc.StateRequestMsg{NodeId: x.id.String()},
		selectRandomNodeIdsFromSignatureMap(signatures, 2)...); err != nil {
		return fmt.Errorf("failed to send recovery request: %w", err)
	}
	return nil
}

/*
selectRandomNodeIdsFromSignatureMap returns slice with up to "count" random keys
from "m" without duplicates. The "count" assumed to be greater than zero, iow the
function always returns at least one item (given that map is not empty).
The key of the "m" must be of type peer.ID encoded as string (if it's not it is ignored).
When "m" has fewer items than "count" then len(m) items is returned (iow all map keys),
when "m" is empty then empty/nil slice is returned.
*/
func selectRandomNodeIdsFromSignatureMap(m map[string]hex.Bytes, count int) (nodes []peer.ID) {
	for k := range m {
		id, err := peer.Decode(k)
		if err != nil {
			continue
		}
		if slices.Contains(nodes, id) {
			continue
		}
		nodes = append(nodes, id)
		if count--; count == 0 {
			return nodes
		}
	}
	return nodes
}

func (x *ConsensusManager) ShardInfo(partition types.PartitionID, shard types.ShardID) (*storage.ShardInfo, error) {
	if x.recovery.InRecovery() {
		return nil, fmt.Errorf("node is in recovery: %s", x.recovery)
	}
	si := x.blockStore.ShardInfo(partition, shard)
	if si == nil {
		return nil, fmt.Errorf("unknown partition %s shard %s", partition, shard.String())
	}
	return si, nil
}

/*
updateQCMetrics updates metrics about QC. Only leader should call it, so we get "per round" counts.
*/
func (x *ConsensusManager) updateQCMetrics(ctx context.Context, qc *drctypes.QuorumCert) {
	if qc == nil {
		return
	}

	x.qcSize.Add(ctx, int64(len(qc.Signatures)))

	// when node count gets big this is potentially bad metric (cardinality of the node id)
	// but have it for debugging for now?
	for nodeID := range qc.Signatures {
		x.qcVoters.Add(ctx, 1, metric.WithAttributeSet(attribute.NewSet(attribute.String("node.id", nodeID))))
	}
}

func (x *ConsensusManager) GetState() (*abdrc.StateMsg, error) {
	return x.blockStore.GetState()
}

func addAll(set map[peer.ID]struct{}, items peer.IDSlice) {
	for _, item := range items {
		set[item] = struct{}{}
	}
}

func toIDSlice(nodes []*types.NodeInfo, log *slog.Logger) peer.IDSlice {
	nodeIDs := make(peer.IDSlice, len(nodes))
	for idx, node := range nodes {
		nodeID, err := peer.Decode(node.NodeID)
		if err != nil {
			log.Error(fmt.Sprintf("failed to decode node ID %s", node.NodeID), logger.Error(err))
			continue
		}
		nodeIDs[idx] = nodeID
	}
	return nodeIDs
}

func (x *ConsensusManager) Validators() peer.IDSlice {
	return toIDSlice(x.trustBase.Load().RootNodes, x.log)
}

func (x *ConsensusManager) HandoffProfileEnabled() bool {
	return x.params.NetworkProfileVersion == storage.ProfileHandoff
}

func (x *ConsensusManager) updateTrustBase() {
	// Profile 2 keeps the old committee voting on an empty suffix until the
	// typed epoch anchor path installs the successor committee.
	if x.params.NetworkProfileVersion == storage.ProfileHandoff {
		return
	}
	trustBase, err := x.trustBaseStore.GetByRound(x.pacemaker.GetCurrentRound())
	if err != nil {
		if x.frontier != nil {
			x.frontier.latchFault()
		}
		x.log.Error("failed to update trust base", logger.Error(err))
		return
	}
	if x.trustBase.Load().Epoch != trustBase.Epoch {
		x.log.Info(fmt.Sprintf("Activated trust base epoch %d", trustBase.Epoch))
		x.trustBase.Store(trustBase)
	}
}

// "constant" (ie without variable part) attribute sets for observability
var (
	attrSetQCVoteStale = metric.WithAttributeSet(attribute.NewSet(attribute.String("reason", "stale")))
	attrSetQCVoteEarly = metric.WithAttributeSet(attribute.NewSet(attribute.String("reason", "early")))

	attrSetVoteForQC = metric.WithAttributeSet(attribute.NewSet(attribute.String("reason", "proposal")))
	attrSetVoteForTC = metric.WithAttributeSet(attribute.NewSet(attribute.String("reason", "timeout")))
)

// timeoutMessageID identifies the exact statement a timeout vote is: the SHA-256 of its canonical encoding, signature included. The same
// recorded message recovered after a restart and broadcast again has the same identity; a different statement for the round has another.
func timeoutMessageID(msg *abdrc.TimeoutMsg) string { return messageID(msg) }

// voteMessageID is the identity of a signed vote: the SHA-256 of the exact message, like timeoutMessageID.
func voteMessageID(msg *abdrc.VoteMsg) string { return messageID(msg) }

// logRecoveredVote records, with its identity, the last vote the node signed before it stopped and now holds again (a vote or a timeout
// vote), so the lane can compare it with the identity logged when it was signed.
func logRecoveredVote(ctx context.Context, log *slog.Logger, last any) {
	switch v := last.(type) {
	case *abdrc.VoteMsg:
		if v != nil {
			log.InfoContext(ctx, "recovered last vote", "kind", "vote", "round", v.VoteInfo.RoundNumber, "messageID", voteMessageID(v))
		}
	case *abdrc.TimeoutMsg:
		if v != nil {
			log.InfoContext(ctx, "recovered last vote", "kind", "timeout", "round", v.Timeout.Round, "messageID", timeoutMessageID(v))
		}
	}
}

func messageID(msg any) string {
	raw, err := types.Cbor.Marshal(msg)
	if err != nil {
		return "unencodable"
	}
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("%x", sum)
}

// witnessHolder is the part of the block store that retains control witnesses.
type witnessHolder interface {
	HasWitness(hash [32]byte) bool
	StoreWitness(data []byte) error
}

// fetchWitnesses makes the witnesses of the block's controls available to the store before the block is executed. The block's author
// is asked first (it built the controls and retains their witnesses), then the other root nodes of the block's epoch. A witness that
// cannot be had refuses the block as unavailable, never as invalid: the node does not vote, and asks again when it recovers.
//
// It runs on the consensus loop, so the whole step has one deadline, half the local timeout: a peer that trickles bytes cannot keep the
// node from voting on, or timing out, the round. A control whose envelope cannot be valid in this block (another deployment, another
// position, a malformed item) is refused before anything is fetched or stored, so a Byzantine author cannot make voters retain bytes
// for a block the executor would refuse anyway.
func (x *ConsensusManager) fetchWitnesses(ctx context.Context, store witnessHolder, block *drctypes.BlockData) error {
	if x.witnesses == nil || block == nil || block.Payload == nil || len(block.Payload.PosControls) == 0 {
		return nil
	}
	budget := 5 * time.Second
	if x.params != nil && x.params.LocalTimeout > 0 {
		budget = x.params.LocalTimeout / 2
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var peers []peer.ID
	for _, c := range block.Payload.PosControls {
		if err := x.checkControlEnvelope(c, block); err != nil {
			return err
		}
		if store.HasWitness(c.WitnessHash) {
			continue
		}
		if peers == nil {
			peers = x.witnessPeers(block)
		}
		data, err := x.witnesses(ctx, c.WitnessHash, peers, storage.WitnessBound(c.Op))
		if err != nil {
			return errors.Join(storage.ErrWitnessUnavailable, err)
		}
		// the fetcher checks the hash too; the executor reads by this hash, so bytes under another key would only read as missing later
		if sha256.Sum256(data) != c.WitnessHash {
			return errors.Join(storage.ErrWitnessUnavailable, errors.New("the fetched bytes are not the committed witness"))
		}
		if err := store.StoreWitness(data); err != nil {
			return err
		}
	}
	return nil
}

// checkControlEnvelope is the part of a control's validity that needs neither its witness nor the root state.
func (x *ConsensusManager) checkControlEnvelope(c drctypes.PosControl, block *drctypes.BlockData) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.OrderingEpoch != block.Epoch || c.OrderingRound != block.Round {
		return fmt.Errorf("%w: a control names another ordering position than its block", storage.ErrPosControlRefused)
	}
	var svc *storage.PosServices
	if x.blockStore != nil {
		svc = x.blockStore.PosServices()
	}
	if svc != nil &&
		(c.Network != svc.Deployment.RootNetwork || c.ChainID != svc.Deployment.ChainID || c.Custody != svc.Deployment.Custody) {
		return fmt.Errorf("%w: a control names another deployment", storage.ErrPosControlRefused)
	}
	return nil
}

// witnessPeers are the root nodes of the block's epoch other than this node, the block's author first.
func (x *ConsensusManager) witnessPeers(block *drctypes.BlockData) []peer.ID {
	tb := x.trustBase.Load()
	if x.trustBaseStore != nil {
		if stored, err := x.trustBaseStore.GetByEpoch(block.Epoch); err == nil {
			tb = stored
		}
	}
	var author, rest []peer.ID
	for _, id := range toIDSlice(tb.RootNodes, x.log) {
		switch {
		case id == "" || id == x.id:
		case id.String() == block.Author:
			author = append(author, id)
		default:
			rest = append(rest, id)
		}
	}
	return append(author, rest...)
}
