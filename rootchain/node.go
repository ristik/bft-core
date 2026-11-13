package rootchain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"

	"github.com/unicitynetwork/bft-core/internal/debug"
	"github.com/unicitynetwork/bft-core/logger"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/network/protocol/handshake"
	"github.com/unicitynetwork/bft-core/observability"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

type (
	PartitionNet interface {
		Send(ctx context.Context, msg any, receivers ...peer.ID) error
		// SendCertificationResponse sends the response using the best protocol version
		// supported by each receiver.
		SendCertificationResponse(ctx context.Context, cr *certification.CertificationResponse, receivers ...peer.ID) error
		ReceivedChannel() <-chan any
	}

	// RequestViewSource is the optional capability of a ConsensusManager that selects the view-aware branch of collector
	// admission (Q2-C3). RequestView resolves, from the committed activation history and the verified parent state, the
	// authenticated request view of the shard for collection. enabled is false for a manager that keeps the legacy dispatch,
	// which then admits, dispatches proofs and counts under the committed ShardInfo exactly as before. A resolution error with
	// enabled true is a refusal: nothing is answered from the committed ShardInfo instead.
	RequestViewSource interface {
		RequestView(partition types.PartitionID, shard types.ShardID) (view *storage.RequestRoundView, enabled bool, err error)
	}

	Observability interface {
		Meter(name string, opts ...metric.MeterOption) metric.Meter
		Tracer(name string, options ...trace.TracerOption) trace.Tracer
		Logger() *slog.Logger
	}

	ConsensusManager interface {
		// RequestCertification accepts certification requests with proof of quorum or no-quorum.
		RequestCertification(ctx context.Context, cr consensus.IRChangeRequest) error
		// CertificationResult read the channel to receive certification results
		CertificationResult() <-chan *certification.CertificationResponse
		ShardInfo(partition types.PartitionID, shard types.ShardID) (*storage.ShardInfo, error)
		// Run consensus algorithm
		Run(ctx context.Context) error
	}

	Node struct {
		peer             *network.Peer // p2p network host for partition
		incomingRequests *CertRequestBuffer
		subscription     *Subscriptions
		net              PartitionNet
		consensusManager ConsensusManager
		zkRegistry       *zkverifier.Registry
		offers           EntryOffers    // nil: the legacy certificate protocol only
		early            *earlyRequests // near-future requests held until the committed context advances (#1032)
		replay           chan shardRef  // shards whose committed context advanced: their held requests are admitted again

		log    *slog.Logger
		tracer trace.Tracer

		execMsgCnt metric.Int64Counter
	}
)

// New creates a new instance of the root chain node
func New(
	peer *network.Peer,
	pNet PartitionNet,
	cm ConsensusManager,
	observe Observability,
) (*Node, error) {
	if peer == nil {
		return nil, fmt.Errorf("partition listener is nil")
	}
	if pNet == nil {
		return nil, fmt.Errorf("network is nil")
	}

	meter := observe.Meter("rootchain.node")
	reqBuf, err := NewCertificationRequestBuffer(meter)
	if err != nil {
		return nil, fmt.Errorf("creating request buffer: %w", err)
	}
	subs, err := NewSubscriptions(pNet.SendCertificationResponse, observe)
	if err != nil {
		return nil, fmt.Errorf("creating subscribers list: %w", err)
	}
	node := &Node{
		peer:             peer,
		incomingRequests: reqBuf,
		subscription:     subs,
		net:              pNet,
		consensusManager: cm,
		zkRegistry:       zkverifier.NewRegistry(),
		early:            newEarlyRequests(),
		replay:           make(chan shardRef, earlyRequestShards),
		log:              observe.Logger(),
		tracer:           observe.Tracer("rootchain.node"),
	}
	if err := node.initMetrics(meter); err != nil {
		return nil, fmt.Errorf("initializing metrics: %w", err)
	}

	observe.Logger().Info("Root node initialized with per-partition ZK proof verification")

	return node, nil
}

// SetEntryOffers makes the node answer on the version 3 certificate protocol with the finalized signed trust-base entries the offers choose. Call it
// before Run.
func (v *Node) SetEntryOffers(o EntryOffers) {
	v.offers = o
	v.subscription.offers = o
	v.subscription.offerSender = v.net.Send
}

func (v *Node) initMetrics(m metric.Meter) (err error) {
	v.execMsgCnt, err = m.Int64Counter("exec.msg.count", metric.WithDescription("Number of messages processed by the node"))
	if err != nil {
		return fmt.Errorf("creating counter for processed messages: %w", err)
	}

	return nil
}

func (v *Node) Run(ctx context.Context) error {
	v.log.InfoContext(ctx, fmt.Sprintf("Starting root node. Addresses=%v; BuildInfo=%s", v.peer.MultiAddresses(), debug.ReadBuildInfo()))
	g, gctx := errgroup.WithContext(ctx)
	// Run root consensus algorithm
	g.Go(func() error { return v.consensusManager.Run(gctx) })
	// Start receiving messages from partition nodes
	g.Go(func() error { return v.partitionMsgLoop(gctx) })
	// Start handling certification responses
	g.Go(func() error { return v.handleConsensus(gctx) })
	err := g.Wait()
	// handleConsensus has returned, so nothing can call subscription.Send any more;
	// drain the sends already in flight rather than leaving them writing to the
	// logger and the meter after Run has reported the node stopped.
	v.subscription.Wait()
	return err
}

func (v *Node) GetPeer() *network.Peer {
	return v.peer
}

// handle messages from partition nodes
func (v *Node) partitionMsgLoop(ctx context.Context) error {
	sweep := time.NewTicker(earlyRequestSweep)
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ref := <-v.replay:
			v.replayEarly(ctx, ref)
		case <-sweep.C:
			// a certificate that did not reach this loop (or a context that advanced without one) must not strand a held request
			for _, ref := range v.early.shardsHeld() {
				v.replayEarly(ctx, ref)
			}
		case msg, ok := <-v.net.ReceivedChannel():
			if !ok {
				return fmt.Errorf("partition channel closed")
			}
			v.log.LogAttrs(ctx, logger.LevelTrace, fmt.Sprintf("received %T", msg), logger.Data(msg))
			if err := v.handlePartitionMsg(ctx, msg); err != nil {
				v.log.WarnContext(ctx, fmt.Sprintf("processing %T", msg), logger.Error(err))
			}
		}
	}
}

func (v *Node) handlePartitionMsg(ctx context.Context, msg any) (rErr error) {
	partitionID, shardID, nodeID := types.PartitionID(0), types.ShardID{}, ""
	ctx, span := v.tracer.Start(ctx, "node.handlePartitionMsg")
	defer func() {
		if rErr != nil {
			span.RecordError(rErr)
			span.SetStatus(codes.Error, rErr.Error())
		}
		msgAttr := attribute.String("msg", fmt.Sprintf("%T", msg))
		attrNode := attribute.String("node.id", nodeID)
		v.execMsgCnt.Add(ctx, 1, observability.Shard(partitionID, shardID, msgAttr, attrNode, observability.ErrStatus(rErr)))
		span.SetAttributes(msgAttr, observability.Partition(partitionID), attrNode)
		span.End()
	}()

	switch mt := msg.(type) {
	case *certification.BlockCertificationRequest:
		partitionID, shardID, nodeID = mt.PartitionID, mt.ShardID, mt.NodeID
		return v.onBlockCertificationRequest(ctx, mt)
	case *handshake.Handshake:
		partitionID, shardID, nodeID = mt.PartitionID, mt.ShardID, mt.NodeID
		return v.onHandshake(ctx, mt)
	default:
		return fmt.Errorf("unknown message type %T", msg)
	}
}

func (v *Node) sendResponse(ctx context.Context, nodeID string, cr *certification.CertificationResponse) error {
	ctx, span := v.tracer.Start(ctx, "node.sendResponse")
	defer span.End()

	peerID, err := peer.Decode(nodeID)
	if err != nil {
		return fmt.Errorf("invalid receiver id: %w", err)
	}

	if err := cr.IsValid(); err != nil {
		return fmt.Errorf("invalid certification response: %w", err)
	}
	if v.offers == nil {
		// no trust-base entries to attach: the network chooses between the sidecar and the legacy protocol from what the receiver announced
		return v.net.SendCertificationResponse(ctx, cr, peerID)
	}
	msg, sent := withOffers(v.offers, peerID, cr)
	if err := v.net.Send(ctx, msg, peerID); err != nil {
		return err
	}
	if sent != nil {
		sent()
	}
	return nil
}

// sendRejection attaches a status code and diagnostic message to a copy of the
// last-good CertificationResponse (so the submitter can still resync from the
// wrapped UC) and sends it. The shared `last` pointer is NOT mutated — we only
// ever write to a shallow copy.
func (v *Node) sendRejection(ctx context.Context, nodeID string, last *certification.CertificationResponse, status uint32, cause error) error {
	if last == nil {
		return fmt.Errorf("no last CR available to attach to rejection")
	}
	msg := ""
	if cause != nil {
		msg = cause.Error()
		if len(msg) > certification.MaxStatusMessageLen {
			msg = msg[:certification.MaxStatusMessageLen]
		}
	}
	resp := *last
	resp.Status = status
	resp.Message = msg
	return v.sendResponse(ctx, nodeID, &resp)
}

func (v *Node) onHandshake(ctx context.Context, req *handshake.Handshake) error {
	ctx, span := v.tracer.Start(ctx, "node.onHandshake")
	defer span.End()
	if profile, ok := v.consensusManager.(interface{ HandoffProfileEnabled() bool }); ok && profile.HandoffProfileEnabled() && req != nil && req.PartitionID == rctypes.ControlPartition {
		return rctypes.ErrControlPartition
	}

	if err := req.IsValid(); err != nil {
		return fmt.Errorf("invalid handshake request: %w", err)
	}
	si, err := v.consensusManager.ShardInfo(req.PartitionID, req.ShardID)
	if err != nil {
		return fmt.Errorf("reading partition %s certificate: %w", req.PartitionID, err)
	}
	// verifies nodeID is part of active validator set
	err = si.Verify(req.NodeID, func(v abcrypto.Verifier) error {
		return nil
	})
	if err != nil {
		return fmt.Errorf("node ID is not in active validator set %s - %s - %s: %w", req.PartitionID, req.ShardID, req.NodeID, err)
	}

	// (Re)subscribe on every handshake. Subscriptions have a bounded response
	// quota (see responsesPerSubscription in subscription.go) which is only
	// refilled by Subscribe; repeat UCs sent to an idle partition consume quota
	// without refilling it, so after ~responsesPerSubscription T2 timeouts the
	// partition would otherwise fall off the subscriber map entirely. The
	// handshake is the partition's only refresh mechanism when it has no
	// BlockCertificationRequests to send, so it must always re-subscribe —
	// not just before the first certified block.
	if v.offers != nil { // a handshake is a (re)connect: the answer carries the relevant entries again
		if id, derr := peer.Decode(req.NodeID); derr == nil {
			v.offers.Reset(id)
		}
	}
	if err := v.subscription.Subscribe(req.PartitionID, req.ShardID, req.NodeID); err != nil {
		return fmt.Errorf("subscribing the sender: %w", err)
	}
	if err = v.sendResponse(ctx, req.NodeID, si.LastCR); err != nil {
		return fmt.Errorf("failed to send response: %w", err)
	}
	return nil
}

/*
onBlockCertificationRequest handles Certification Request from shard nodes.
Shard nodes can only extend the stored/certified state.
*/
func (v *Node) onBlockCertificationRequest(ctx context.Context, req *certification.BlockCertificationRequest) error {
	return v.admitRequest(ctx, req, time.Time{})
}

// admitRequest is onBlockCertificationRequest; held is the first deadline of a near-future request admitted again after it was
// held, zero for a request just received.
func (v *Node) admitRequest(ctx context.Context, req *certification.BlockCertificationRequest, held time.Time) (rErr error) {
	ctx, span := v.tracer.Start(ctx, "node.onBlockCertificationRequest")
	defer span.End()
	if profile, ok := v.consensusManager.(interface{ HandoffProfileEnabled() bool }); ok && profile.HandoffProfileEnabled() && req != nil && req.PartitionID == rctypes.ControlPartition {
		return rctypes.ErrControlPartition
	}

	if req == nil {
		return fmt.Errorf("%w: %w", rctypes.ErrInvalidRequest, certification.ErrBlockCertificationRequestIsNil)
	}

	if src, ok := v.consensusManager.(RequestViewSource); ok {
		view, enabled, err := src.RequestView(req.PartitionID, req.ShardID)
		if err != nil {
			return fmt.Errorf("resolving the request view of shard %s - %s: %w", req.PartitionID, req.ShardID, err)
		}
		if enabled {
			resolve := func() (requestAdmission, error) {
				view, _, err := src.RequestView(req.PartitionID, req.ShardID)
				if err != nil || view == nil {
					return nil, err
				}
				return view, nil
			}
			return v.collectUnderView(ctx, req, view, resolve, held)
		}
	}

	si, err := v.consensusManager.ShardInfo(req.PartitionID, req.ShardID)
	if err != nil {
		return fmt.Errorf("acquiring shard %s - %s info: %w", req.PartitionID, req.ShardID, err)
	}
	// we got the shard info thus it's a valid partition/shard
	if err := si.ValidRequest(req); err != nil {
		if legacyNearFuture(si, req) {
			herr := v.early.hold(req, held)
			if herr == nil {
				v.log.DebugContext(ctx, fmt.Sprintf("holding the request of round %d until the commit of round %d applies", req.IRRound(), si.LastCR.Technical.Round),
					logger.Shard(req.PartitionID, req.ShardID))
				return nil
			}
			err = errors.Join(err, herr)
		}
		err = fmt.Errorf("invalid block certification request: %w", err)
		if se := v.sendRejection(ctx, req.NodeID, si.LastCR, certification.CertStatusRequestInvalid, err); se != nil {
			err = errors.Join(err, fmt.Errorf("sending latest cert: %w", se))
		}
		return err
	}

	// Verify ZK proof (if verifier is enabled)
	if err := v.verifyZKProof(ctx, req, zkTarget{partition: si.PartitionID, shard: si.ShardID, epoch: si.IR.Epoch, params: si.PartitionParams}); err != nil {
		v.log.WarnContext(ctx, "ZK proof verification failed - sending last valid UC",
			logger.Error(err),
			logger.Shard(req.PartitionID, req.ShardID))

		// Send last valid UC immediately when proof verification fails so the
		// partition can sync back to the last certified state. The outer
		// response carries CertStatusProofInvalid + the verifier's error so
		// the submitter can distinguish this from a timeout repeat UC.
		if se := v.sendRejection(ctx, req.NodeID, si.LastCR, certification.CertStatusProofInvalid, err); se != nil {
			err = errors.Join(err, fmt.Errorf("failed to send last valid UC: %w", se))
		}
		return fmt.Errorf("ZK proof verification failed: %w", err)
	}

	if err := v.subscription.Subscribe(req.PartitionID, req.ShardID, req.NodeID); err != nil {
		return fmt.Errorf("subscribing the sender: %w", err)
	}

	return v.countRequest(ctx, req, si, false)
}

// legacyNearFuture reports whether a request refused under the committed ShardInfo is the authentic request of the round right after
// the expected one: of this shard, signed by a member, one round ahead (#1032).
func legacyNearFuture(si *storage.ShardInfo, req *certification.BlockCertificationRequest) bool {
	if si == nil || si.LastCR == nil || req.PartitionID != si.PartitionID || !req.ShardID.Equal(si.ShardID) || req.IRRound() != si.LastCR.Technical.Round+1 {
		return false
	}
	return si.Verify(req.NodeID, func(ver abcrypto.Verifier) error { return req.IsValid(ver) }) == nil
}

// viewChanged reports whether a view resolved again is another view than the first: another key, or another expected record.
func viewChanged(a, b requestAdmission) bool {
	type keyed interface{ ViewKey() []byte }
	if ka, ok := a.(keyed); ok {
		if kb, ok := b.(keyed); ok {
			return !bytes.Equal(ka.ViewKey(), kb.ViewKey())
		}
	}
	ta, tb := a.ExpectedTR(), b.ExpectedTR()
	return ta.Round != tb.Round || ta.Epoch != tb.Epoch
}

// replayEarly admits again, from scratch, the requests held for a shard; one still ahead is held again under its first deadline.
func (v *Node) replayEarly(ctx context.Context, ref shardRef) {
	for _, e := range v.early.take(ref.partition, ref.shard) {
		if err := v.admitRequest(ctx, e.req, e.deadline); err != nil {
			v.log.DebugContext(ctx, "held near-future request refused", logger.Shard(ref.partition, ref.shard), logger.Error(err))
		}
	}
}

// signalReplay asks the partition loop to admit the shard's held requests again; a full queue is left to the periodic sweep.
func (v *Node) signalReplay(partition types.PartitionID, shard types.ShardID) {
	select {
	case v.replay <- shardRef{partition: partition, shard: shard}:
	default:
	}
}

// requestAdmission is what collector admission uses of a resolved request view; *storage.RequestRoundView is the one
// implementation (it is an interface so that the collection-only branch can be driven without a committed successor).
type requestAdmission interface {
	QuorumInfo
	RoundTagged
	ValidRequest(req *certification.BlockCertificationRequest) error
	PDR() (*types.PartitionDescriptionRecord, error)
	ExpectedTR() certification.TechnicalRecord
	CollectionOnly() bool
}

var _ requestAdmission = (*storage.RequestRoundView)(nil)

// collectUnderView is the admission of one request under the authenticated view resolved for it: membership, signature and
// shard continuity (ValidRequest), the proof dispatched from the view's PDR, partition parameters and expected shard epoch,
// and the buffer counted with the view's weights, assignment and shard-round tag. The committed ShardInfo is consulted for
// nothing but the last response a rejection carries. A view resolved before its activation round collects only.
//
// A request refused as stale is judged again under a view resolved anew when the committed parent changed meanwhile (resolve may be
// nil). A request for the round right after the view's expected one, whose sender passed membership and signature, is held (#1032)
// rather than refused: it is admitted from scratch when the committed context advances. held is its first deadline when it is being
// admitted again, else zero.
func (v *Node) collectUnderView(ctx context.Context, req *certification.BlockCertificationRequest, view requestAdmission,
	resolve func() (requestAdmission, error), held time.Time) error {
	lastCR := func() *certification.CertificationResponse {
		if si, err := v.consensusManager.ShardInfo(req.PartitionID, req.ShardID); err == nil && si != nil {
			return si.LastCR
		}
		return nil
	}
	err := view.ValidRequest(req)
	if err != nil && errors.Is(err, storage.ErrStaleRequestContext) && resolve != nil {
		// the parent may have been committed during the resolution: never refuse as stale under a parent that is no longer the committed one
		if again, rerr := resolve(); rerr == nil && again != nil && viewChanged(view, again) {
			view = again
			err = view.ValidRequest(req)
		}
	}
	if err != nil && errors.Is(err, storage.ErrStaleRequestContext) && req.IRRound() == view.ExpectedTR().Round+1 {
		// ValidRequest compares the round only after membership, signature and shard passed under this view: the request is
		// authentic and exactly one round ahead. It is counted for nothing until it is admitted under the committed context.
		herr := v.early.hold(req, held)
		if herr == nil {
			v.log.DebugContext(ctx, fmt.Sprintf("holding the request of round %d until the commit of round %d applies", req.IRRound(), view.ExpectedTR().Round),
				logger.Shard(req.PartitionID, req.ShardID))
			return nil
		}
		err = errors.Join(err, herr)
	}
	if err != nil {
		err = fmt.Errorf("invalid block certification request: %w", err)
		if se := v.sendRejection(ctx, req.NodeID, lastCR(), certification.CertStatusRequestInvalid, err); se != nil {
			err = errors.Join(err, fmt.Errorf("sending latest cert: %w", se))
		}
		return err
	}
	pdr, err := view.PDR()
	if err != nil {
		return fmt.Errorf("the PDR of the request view: %w", err)
	}
	target := zkTarget{partition: req.PartitionID, shard: req.ShardID, epoch: view.ExpectedTR().Epoch, params: pdr.GetPartitionParams(), viewed: true}
	if err := v.verifyZKProof(ctx, req, target); err != nil {
		v.log.WarnContext(ctx, "ZK proof verification failed - sending last valid UC", logger.Error(err), logger.Shard(req.PartitionID, req.ShardID))
		if se := v.sendRejection(ctx, req.NodeID, lastCR(), certification.CertStatusProofInvalid, err); se != nil {
			err = errors.Join(err, fmt.Errorf("failed to send last valid UC: %w", se))
		}
		return fmt.Errorf("ZK proof verification failed: %w", err)
	}
	if err := v.subscription.Subscribe(req.PartitionID, req.ShardID, req.NodeID); err != nil {
		return fmt.Errorf("subscribing the sender: %w", err)
	}
	return v.countRequest(ctx, req, view, view.CollectionOnly())
}

// countRequest counts an admitted request under tb and asks for certification when a quorum, or the impossibility of one, is
// reached. A collection-only view never certifies: a decisive outcome clears the shard's buffer, so that the requests sent again
// from the activation round on are counted under the view then in force, never dropped as already decided.
// redeliverMinInterval bounds, per shard, how often a repeated request hands its decided outcome to the consensus manager again.
var redeliverMinInterval = 2 * time.Second

func (v *Node) countRequest(ctx context.Context, req *certification.BlockCertificationRequest, tb QuorumInfo, collectionOnly bool) (rErr error) {
	// requests counted for an earlier shard round, anchor or assignment are retired, never counted again
	v.incomingRequests.Retire(req.PartitionID, req.ShardID, tb)
	// check if consensus is already achieved
	if res := v.incomingRequests.IsConsensusReceived(req.PartitionID, req.ShardID, tb); res != QuorumInProgress {
		if !collectionOnly {
			if status, requests, again := v.incomingRequests.Redeliver(req, tb, redeliverMinInterval); again {
				// the node repeats, byte for byte, the request whose outcome was decided but is not certified yet: the first hand-over to
				// the leader may have been lost (#665). Hand it over again; the leader's buffer ignores a duplicate.
				reason := consensus.Quorum
				if status == QuorumNotPossible {
					reason = consensus.QuorumNotPossible
				}
				v.log.DebugContext(ctx, fmt.Sprintf("partition %s repeated request of a decided, uncertified outcome (%s), handing it over again", req.PartitionID, status),
					logger.Shard(req.PartitionID, req.ShardID))
				return v.consensusManager.RequestCertification(ctx, consensus.IRChangeRequest{
					Partition: req.PartitionID, Shard: req.ShardID, Reason: reason, Requests: requests})
			}
		}
		v.log.DebugContext(ctx, fmt.Sprintf("dropping stale block certification request (%s) for partition %s", res, req.PartitionID), logger.Shard(req.PartitionID, req.ShardID))
		return
	}
	// store the new request and see if quorum is now achieved
	res, requests, err := v.incomingRequests.Add(ctx, req, tb)
	if err != nil {
		return fmt.Errorf("storing request: %w", err)
	}
	if collectionOnly && res != QuorumInProgress {
		v.log.DebugContext(ctx, "collection-only view: the outcome is not certified before the activation round", logger.Shard(req.PartitionID, req.ShardID))
		v.incomingRequests.Clear(ctx, req.PartitionID, req.ShardID)
		return nil
	}
	var reason consensus.CertReqReason
	switch res {
	case QuorumAchieved:
		if v.log.Enabled(ctx, slog.LevelDebug) {
			requestNodeIDs := make([]string, len(requests))
			for i, request := range requests {
				requestNodeIDs[i] = request.NodeID
			}
			weights, matching := requestWeightEvidence(tb, requests)
			v.log.DebugContext(ctx, fmt.Sprintf("partition %s reached consensus, new InputHash: %X", req.PartitionID, requests[0].InputRecord.Hash),
				logger.Shard(req.PartitionID, req.ShardID), slog.Uint64("requestRound", requests[0].InputRecord.RoundNumber),
				slog.Any("requestNodeIDs", requestNodeIDs), slog.Any("requestWeights", weights), slog.Uint64("matchingWeight", matching),
				slog.Uint64("threshold", tb.Threshold()), slog.Uint64("totalWeight", tb.TotalWeight()))
		}
		reason = consensus.Quorum
	case QuorumNotPossible:
		v.log.DebugContext(ctx, fmt.Sprintf("partition %s consensus not possible, repeat UC", req.PartitionID), logger.Shard(req.PartitionID, req.ShardID))
		reason = consensus.QuorumNotPossible
	case QuorumInProgress:
		v.log.DebugContext(ctx, fmt.Sprintf("partition %s quorum not yet reached, but possible in the future", req.PartitionID), logger.Shard(req.PartitionID, req.ShardID))
		return nil
	}

	if err = v.consensusManager.RequestCertification(ctx,
		consensus.IRChangeRequest{
			Partition: req.PartitionID,
			Shard:     req.ShardID,
			Reason:    reason,
			Requests:  requests,
		}); err != nil {
		v.incomingRequests.Clear(ctx, req.PartitionID, req.ShardID)
		return fmt.Errorf("requesting certification: %w", err)
	}
	return nil
}

// requestWeightEvidence is the weight each counted request carries under the view that counted it, in request order, and their sum: the
// evidence that a shard quorum was reached by weight (a heavy signer alone, or many light ones), logged beside the node ids.
func requestWeightEvidence(tb rctypes.RequestWeights, requests []*certification.BlockCertificationRequest) (weights []uint64, matching uint64) {
	weights = make([]uint64, len(requests))
	for i, r := range requests {
		w, err := tb.SignerWeight(r.NodeID)
		if err != nil {
			continue // not a member under this view: it carries no weight
		}
		weights[i] = w
		matching += w
	}
	return weights, matching
}

// handleConsensus - receives consensus results and delivers certificates to subscribers
func (v *Node) handleConsensus(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case cr, ok := <-v.consensusManager.CertificationResult():
			if !ok {
				return fmt.Errorf("consensus channel closed")
			}
			v.subscription.Send(ctx, cr)
			v.incomingRequests.Clear(ctx, cr.Partition, cr.Shard)
			// the committed context of the shard advanced: requests held for the round after it are admitted again
			v.signalReplay(cr.Partition, cr.Shard)
		}
	}
}

// zkTarget is where the proof registry takes its verifier from: the legacy path names the committed ShardInfo's identity,
// epoch and parameters, the view-aware path the resolved view's PDR and expected shard epoch.
type zkTarget struct {
	partition types.PartitionID
	shard     types.ShardID
	epoch     uint64
	params    map[string]string
	viewed    bool
}

// verifyZKProof verifies the ZK proof in the block certification request
func (v *Node) verifyZKProof(ctx context.Context, req *certification.BlockCertificationRequest, target zkTarget) error {
	ir := req.InputRecord
	if ir == nil {
		return fmt.Errorf("input record is nil")
	}

	// Get verifier for this partition's configuration
	// under a view the proof is checked for the view's shard epoch and no other: the request's own epoch is only ever compared
	// with it, never used to select the verifier
	if target.viewed && ir.Epoch != target.epoch {
		return fmt.Errorf("proof for shard epoch %d, the view's is %d: %w", ir.Epoch, target.epoch, storage.ErrStaleRequestContext)
	}
	proofTarget := zkverifier.Target{Partition: target.partition, Shard: target.shard, Epoch: target.epoch, Params: target.params}
	start := time.Now()
	res, verifyErr := v.zkRegistry.VerifyRequest(req, proofTarget)
	elapsed := time.Since(start)
	proofSize := len(req.ZkProof)
	proofType := string(res.ProofType)

	switch {
	case res.Outcome == zkverifier.SkippedSync:
		v.log.DebugContext(ctx, "Skipping ZK proof verification for sync UC", logger.Shard(req.PartitionID, req.ShardID))
	case res.Outcome == zkverifier.SkippedGenesis:
		v.log.InfoContext(ctx, "Skipping ZK proof verification for genesis block", logger.Shard(req.PartitionID, req.ShardID))
	case res.Outcome == zkverifier.Verified || (res.ProofType != "" && verifyErr != nil):
		// the proof was checked: the line the lanes count (scripts/f8-mixed-lane.sh), with the verifier's type and the proof's size
		v.log.DebugContext(ctx, "Verifying ZK proof",
			logger.Shard(req.PartitionID, req.ShardID),
			slog.String("verifier_type", proofType),
			slog.Int("proof_size", proofSize),
			slog.Uint64("round", ir.RoundNumber))
	}
	if verifyErr != nil {
		v.log.WarnContext(ctx, "ZK proof verification failed",
			logger.Shard(req.PartitionID, req.ShardID),
			slog.String("verifier_type", proofType),
			slog.Int("proof_size", proofSize),
			slog.Duration("verification_time", elapsed),
			slog.Uint64("round", ir.RoundNumber),
			logger.Error(verifyErr))
		return verifyErr
	}
	if res.Outcome == zkverifier.Verified {
		v.log.InfoContext(ctx, "ZK proof verified successfully",
			logger.Shard(req.PartitionID, req.ShardID),
			slog.String("verifier_type", proofType),
			slog.Int("proof_size", proofSize),
			slog.Uint64("num_leaves", req.BlockSize),
			slog.Duration("verification_time", elapsed),
			slog.Uint64("round", ir.RoundNumber))
	}
	return nil
}
