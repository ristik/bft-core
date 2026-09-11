package shardnode

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/network/protocol/handshake"
)

/*
RootNetwork is the part of the shard network BFTClient uses: send to root nodes, and read what they
send back. Narrow on purpose — the concrete network.ShardNetwork satisfies it, and depending on the
interface is what lets the subscription-renewal path below be tested against a real BFTClient rather
than only read.
*/
type RootNetwork interface {
	Send(ctx context.Context, msg any, receivers ...peer.ID) error
	ReceivedChannel() <-chan any
}

// RoundDriver is what BFTClient hands every accepted certificate to. Round
// implements it; BFTClient depends only on this interface so the root-chain
// protocol (handshake, UC feed, classification, non-equivocation) stays
// separated from the round logic that consumes it — see
// docs/adr/0001-executor-boundary.md.
type RoundDriver interface {
	HandleCertificate(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error
}

// BFTClientOptions are ported from aggregator-go/internal/bft's
// NetworkOptions and heartbeat/inactivity constants.
type BFTClientOptions struct {
	HandshakeNodes    int           // how many root nodes to handshake with
	CertNodes         int           // how many root nodes to submit certification requests to
	HeartbeatInterval time.Duration // how often to check for inactivity
	InactivityTimeout time.Duration // re-handshake if no UC received for this long
}

var DefaultBFTClientOptions = BFTClientOptions{
	HandshakeNodes:    defaultHandshakeNodes,
	CertNodes:         defaultNofRootNodes,
	HeartbeatInterval: 5 * time.Second,
	InactivityTimeout: 30 * time.Second,
}

// BFTClient is the shard-node framework's root-chain protocol client: it
// owns the libp2p connection to the root chain, subscribes to the UC feed,
// verifies and classifies every certificate received, and hands accepted
// ones to a RoundDriver. Ported from aggregator-go/internal/bft/client.go
// with its durable-proposal machinery dropped — see
// docs/adr/0001-executor-boundary.md §"What changed in the port": an
// Executor that only ever commits a UC-certified block has nothing to
// abandon on restart, so the recovery path that machinery existed for does
// not apply here.
type BFTClient struct {
	partitionID types.PartitionID
	shardID     types.ShardID
	// shardConfHash is the hash of the shard configuration THIS NODE was started with, and every
	// certificate must commit to it (#134). It is owned by this client — cloned on the way in — so a
	// caller that later mutates its own slice cannot change what this node enforces, and it is never
	// derived from a certificate, a checkpoint, a peer or the execution client: those are the claims
	// under test. UnicityCertificate.IsValid compares it only when it is non-nil, so an empty value
	// would not weaken the check, it would remove it; the constructor refuses one.
	shardConfHash []byte
	nodeID        string

	peer           *network.Peer
	net            RootNetwork
	signer         abcrypto.Signer
	trustBaseStore TrustBaseStore
	driver         RoundDriver
	log            *slog.Logger
	opts           BFTClientOptions
	metrics        *Metrics // optional; nil-safe, see metrics.go
	health         *Health  // optional; nil-safe, see health.go

	mu  sync.Mutex
	luc *types.UnicityCertificate
	// submittedSinceHandshake tracks whether this node has given the root chain a reason to renew
	// its subscription since the last time it asked for one. See renewSubscriptionIfIdle.
	submittedSinceHandshake bool
	// lastRenewedFor coalesces renewal per CERTIFICATE: several deliveries about the same one — a
	// retransmission, a retry of a failed application — ask for a subscription at most once.
	lastRenewedFor deliveryAttempt
	// nextRenewalAllowed and renewalBackoff bound retrying a handshake that is failing.
	nextRenewalAllowed time.Time
	renewalBackoff     time.Duration
	// unapplied names the certificate whose delivery to the driver FAILED, and is cleared as soon
	// as one succeeds. It is the applied cursor kept separate from the observation cursor `luc`
	// (design §5): a driver error leaves `luc` ahead of what was actually applied, and without
	// this the retransmission that would retry it is classified UCDuplicate and dropped, so the
	// failure is never retried by any route. It is not a queue — only the latest failure is worth
	// retrying, since a later certificate supersedes an earlier one.
	unapplied *deliveryAttempt

	lastCertResponseTime atomic.Int64
}

// deliveryAttempt identifies one certificate for retry purposes. Rounds are enough: a UCDuplicate
// has, by classification, the same partition round, the same root round and a byte-identical input
// record as the certificate held, so a duplicate matching these is the same certified statement.
type deliveryAttempt struct {
	partitionRound uint64
	rootRound      uint64
}

func NewBFTClient(
	peer *network.Peer,
	net RootNetwork,
	signer abcrypto.Signer,
	partitionID types.PartitionID,
	shardID types.ShardID,
	shardConfHash []byte,
	trustBaseStore TrustBaseStore,
	driver RoundDriver,
	log *slog.Logger,
	opts BFTClientOptions,
) (*BFTClient, error) {
	if len(shardConfHash) == 0 {
		return nil, errors.New("no shard configuration hash: a certificate would then be accepted whatever configuration it was issued under")
	}
	if peer == nil {
		return nil, errors.New("peer is nil")
	}
	if net == nil {
		return nil, errors.New("network is nil")
	}
	if trustBaseStore == nil {
		return nil, errors.New("trust base store is nil")
	}
	// driver may be nil here and supplied later via SetDriver — see that
	// method's comment for why (Round needs a Submitter, which BFTClient
	// implements, so one of the two must be constructible before the other
	// is complete). Run refuses to start without one.
	c := &BFTClient{
		partitionID:    partitionID,
		shardID:        shardID,
		shardConfHash:  bytes.Clone(shardConfHash),
		nodeID:         peer.ID().String(),
		peer:           peer,
		net:            net,
		signer:         signer,
		trustBaseStore: trustBaseStore,
		driver:         driver,
		log:            log,
		opts:           opts,
	}
	c.lastCertResponseTime.Store(time.Now().UnixMilli())
	return c, nil
}

// SeedLUC installs a previously-persisted last UC (see store.go) so a
// restarted node's non-equivocation check and root-node selection have
// somewhere to start from other than scratch. Call before Run.
func (c *BFTClient) SeedLUC(uc *types.UnicityCertificate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.luc = uc
}

// SetDriver supplies the RoundDriver that processes accepted certificates.
// Exists as a separate step from the constructor because a Round (the
// framework's usual RoundDriver) needs a Submitter — which BFTClient itself
// implements — so building "Round, then BFTClient" and "BFTClient, then
// Round" are both partially circular; this breaks the cycle by letting
// BFTClient exist (and be usable as a Submitter) before its driver is
// finalized. See node.go for the wiring order this enables.
func (c *BFTClient) SetDriver(driver RoundDriver) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.driver = driver
}

// SetMetrics attaches an optional Metrics recorder.
func (c *BFTClient) SetMetrics(m *Metrics) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.metrics = m
}

// SetHealth attaches an optional Health snapshot.
func (c *BFTClient) SetHealth(h *Health) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.health = h
}

// Run subscribes to the root chain's UC feed and processes certificates
// until ctx is done. It is the client's entire lifecycle — there is no
// separate Stop; cancel ctx.
func (c *BFTClient) Run(ctx context.Context) error {
	c.mu.Lock()
	hasDriver := c.driver != nil
	c.mu.Unlock()
	if !hasDriver {
		return errors.New("shardnode: no round driver configured — call SetDriver before Run")
	}

	if err := c.sendHandshake(ctx); err != nil {
		return fmt.Errorf("initial handshake: %w", err)
	}

	heartbeat := time.NewTicker(c.opts.HeartbeatInterval)
	defer heartbeat.Stop()

	received := c.net.ReceivedChannel()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-received:
			if !ok {
				return errors.New("shardnode: network received channel closed")
			}
			c.handleMessage(ctx, msg)
		case <-heartbeat.C:
			last := time.UnixMilli(c.lastCertResponseTime.Load())
			if time.Since(last) > c.opts.InactivityTimeout {
				if c.log != nil {
					c.log.WarnContext(ctx, "inactivity timeout exceeded, re-sending handshake")
				}
				if c.log != nil {
					c.log.DebugContext(ctx, "renewing the certificate subscription: this node submitted nothing for the last certificate")
				}
				if err := c.sendHandshake(ctx); err != nil && c.log != nil {
					c.log.ErrorContext(ctx, "re-handshake failed", slog.String("err", err.Error()))
				}
			}
		}
	}
}

/*
renewSubscriptionIfIdle keeps a node that is not submitting from silently falling off the root
chain's certificate feed.

A subscription carries a bounded quota (rootchain: responsesPerSubscription), refilled only by
Subscribe — which the root chain calls from exactly two places: the handshake handler, and the block
certification request handler. A validator that submits every round therefore renews itself as a side
effect of voting. One that does not submit renews only when it handshakes, which until now happened
at startup and then only after InactivityTimeout, 30 seconds by default.

That case is now reachable in production: a node resumed from a persisted certificate is non-voting
until #105 supplies the monotonic signing record. Traced on a real devnet (#109): such a node
received three certificates after restarting, then nothing for 34 seconds, then a certificate six
partition rounds later — and the assignments lost in that window invalidated its continuity state,
leaving it unable to recover at all.

So renewal is decoupled from voting: after a certificate this node did not submit for, it asks for a
subscription again. It reuses the existing handshake, so the root chain's membership check and the
existing expiry both still apply; nothing is refilled on delivery, and no vote is fabricated to
provoke a refill. The cost is one handshake per certified round for a node that is not voting, which
is the same order as the certification request a voting node sends anyway — and a node that stops
entirely still stops renewing, so it still expires.
*/
// renewalBackoffStart and renewalBackoffMax bound retrying a handshake that is FAILING. A failed
// renewal is a network or trust-base problem and retrying it per certificate helps nothing; the
// inactivity timer remains the long stop.
const (
	renewalBackoffStart = 1 * time.Second
	renewalBackoffMax   = 30 * time.Second
)

// renewSubscriptionIfIdle asks the root chain for a subscription again when this node has given it
// no other reason to renew one.
//
// newEvidence says whether this delivery carried something this node had not already observed. It
// is the difference between renewal and a feedback loop, and the loop is not hypothetical: a
// duplicate of a certificate whose APPLICATION failed is deliberately re-delivered to the driver
// (that is how a transient executor failure recovers), the root chain answers a handshake
// immediately with its current certificate and outside the subscription quota, and that answer is
// the very certificate being retried. Renewing on it closed the circle — failed application,
// handshake, the same certificate back, failed application — with no new certificate and no timer
// needed to keep it spinning.
//
// So an already-observed certificate may retry application as often as it likes and never renews.
// Renewal tracks certified PROGRESS, which is what consumes the subscription's quota in the first
// place; a node whose executor is failing still renews on every new certificate, so it does not
// need to succeed at anything to keep its feed.
func (c *BFTClient) renewSubscriptionIfIdle(ctx context.Context, uc *types.UnicityCertificate, newEvidence bool) {
	if !newEvidence {
		return
	}
	this := deliveryAttempt{partitionRound: uc.GetRoundNumber(), rootRound: uc.GetRootRoundNumber()}
	// The credit is CONSUMED, not merely read. One submitted request refills the quota once and
	// one delivered certificate spends one response, so a single submission covers exactly one
	// round — the same accounting the root chain does.
	// Credit, coalescing and backoff are decided under one lock, so two deliveries about the same
	// certificate cannot both conclude they should renew.
	c.mu.Lock()
	submitted := c.submittedSinceHandshake
	c.submittedSinceHandshake = false
	alreadyRenewed := c.lastRenewedFor == this
	backedOff := time.Now().Before(c.nextRenewalAllowed)
	if !submitted && !alreadyRenewed && !backedOff {
		c.lastRenewedFor = this
	}
	c.mu.Unlock()
	if submitted || alreadyRenewed || backedOff {
		return
	}
	if err := c.sendHandshake(ctx); err != nil {
		c.mu.Lock()
		if c.renewalBackoff == 0 {
			c.renewalBackoff = renewalBackoffStart
		} else if c.renewalBackoff < renewalBackoffMax {
			c.renewalBackoff *= 2
		}
		backoff := c.renewalBackoff
		c.nextRenewalAllowed = time.Now().Add(backoff)
		c.mu.Unlock()
		if c.log != nil {
			c.log.WarnContext(ctx, "could not renew the certificate subscription; this node may stop receiving certificates until the inactivity timer fires",
				slog.String("err", err.Error()), slog.Duration("backoff", backoff))
		}
		return
	}
	c.mu.Lock()
	c.renewalBackoff = 0
	c.mu.Unlock()
}

func (c *BFTClient) sendHandshake(ctx context.Context) error {
	c.mu.Lock()
	luc := c.luc
	c.mu.Unlock()

	epoch := uint64(1)
	if luc != nil {
		epoch = luc.GetRootEpoch()
	}
	tb, err := c.trustBaseStore.GetByEpoch(ctx, epoch)
	if err != nil {
		return fmt.Errorf("loading trust base for epoch %d: %w", epoch, err)
	}
	rootIDs, err := randomNodeSelector(tb, c.opts.HandshakeNodes)
	if err != nil {
		return fmt.Errorf("selecting root nodes for handshake: %w", err)
	}
	msg := handshake.Handshake{PartitionID: c.partitionID, ShardID: c.shardID, NodeID: c.nodeID}
	if err := c.net.Send(ctx, msg, rootIDs...); err != nil {
		return fmt.Errorf("sending handshake: %w", err)
	}
	return nil
}

func (c *BFTClient) handleMessage(ctx context.Context, msg any) {
	cr, ok := msg.(*certification.CertificationResponse)
	if !ok {
		if c.log != nil {
			c.log.WarnContext(ctx, "received unexpected message type", slog.String("type", fmt.Sprintf("%T", msg)))
		}
		return
	}
	if err := c.handleCertificationResponse(ctx, cr); err != nil && c.log != nil {
		c.log.ErrorContext(ctx, "processing certification response", slog.String("err", err.Error()))
	}
}

func (c *BFTClient) handleCertificationResponse(ctx context.Context, cr *certification.CertificationResponse) error {
	c.lastCertResponseTime.Store(time.Now().UnixMilli())

	if err := cr.IsValid(); err != nil {
		return fmt.Errorf("invalid certification response: %w", err)
	}
	if cr.Partition != c.partitionID || !cr.Shard.Equal(c.shardID) {
		return fmt.Errorf("certification response for wrong shard %s-%s", cr.Partition, cr.Shard)
	}

	tb, err := c.trustBaseStore.GetByEpoch(ctx, cr.UC.GetRootEpoch())
	if err != nil {
		return fmt.Errorf("loading trust base for epoch %d: %w", cr.UC.GetRootEpoch(), err)
	}
	// The configured shard configuration is part of what is verified: a certificate correctly signed
	// by the trusted root quorum, for this partition and shard, but issued under another shard
	// configuration is a certificate about a different chain (#134). Refused here, before
	// classification, so it never becomes the cursor `luc`, never reaches the driver and never
	// advances the applied cursor. The expected value is this node's own; the certificate's claim
	// about its configuration is exactly what is being checked.
	if len(c.shardConfHash) == 0 {
		return errors.New("this client has no configured shard configuration hash, so a certificate's configuration cannot be checked")
	}
	if err := cr.UC.Verify(tb, crypto.SHA256, c.partitionID, c.shardID, c.shardConfHash); err != nil {
		return fmt.Errorf("verifying unicity certificate: %w", err)
	}

	c.mu.Lock()
	prevLUC := c.luc
	class, err := ClassifyUC(prevLUC, &cr.UC)
	if err != nil {
		c.mu.Unlock()
		// Log the two certificates that were compared before returning. The error string alone
		// says a conflict happened but not which field differs or which root rounds the seals
		// came from, and this node will now reject every subsequent certificate the same way
		// (c.luc is deliberately left unchanged), so without this the first rejection — the only
		// one that carries information — is unrecoverable after the fact. See F1 #9 review
		// 5132493933. Diagnostic only; the classification decision is unchanged.
		if c.log != nil {
			c.log.ErrorContext(ctx, "certificate rejected by classification",
				slog.String("err", err.Error()),
				slog.Uint64("nextRound", cr.Technical.Round),
				slog.String("nextLeader", cr.Technical.Leader),
				slog.String("comparison", DescribeUCConflict(prevLUC, &cr.UC)))
		}
		return fmt.Errorf("classifying certificate: %w", err)
	}
	// A duplicate of a certificate this node OBSERVED but failed to APPLY is a retry opportunity,
	// not a no-op (design §5 point 5). The round driver's steps are all idempotent — Commit on an
	// already-canonical hash returns VALID, observation of an already-observed certificate is a
	// no-op — so re-running the delivery is safe, and it is the only route by which a transient
	// executor failure recovers on its own. A duplicate arriving after a SUCCESSFUL delivery is
	// still dropped: `unapplied` is cleared the moment one succeeds, so a completed round is never
	// driven, or signed, twice.
	retryOfFailedApply := class == UCDuplicate && c.unapplied != nil &&
		c.unapplied.partitionRound == cr.UC.GetRoundNumber() && c.unapplied.rootRound == cr.UC.GetRootRoundNumber()

	if (class == UCDuplicate || class == UCStale) && !retryOfFailedApply {
		// Neither advances nor reverts anything: c.luc stays where it is, the driver is not
		// called, and no error is returned. A stale certificate is an authentic statement about
		// a round this node has already moved past — see ClassifyUC on why that is routine
		// rather than a fault (#93). Kept observable: a counter, and DEBUG rather than ERROR.
		metrics := c.metrics
		c.mu.Unlock()
		if class == UCStale {
			metrics.recordStaleUC(ctx)
		}
		if c.log != nil {
			c.log.DebugContext(ctx, class.String()+" UC, ignoring",
				slog.Uint64("rootRound", cr.UC.GetRootRoundNumber()),
				slog.Uint64("partitionRound", cr.UC.GetRoundNumber()),
				slog.Uint64("heldRootRound", prevLUC.GetRootRoundNumber()),
				slog.Uint64("heldPartitionRound", prevLUC.GetRoundNumber()))
		}
		return nil
	}
	c.luc = &cr.UC
	metrics := c.metrics
	health := c.health
	c.mu.Unlock()

	if class == UCRepeat {
		metrics.recordRepeatUC(ctx)
	}
	health.updateCertificate(cr.UC.GetRoundNumber(), cr.UC.GetRootRoundNumber(), cr.Technical.Leader, c.nodeID)

	if c.log != nil {
		c.log.InfoContext(ctx, "accepted certificate",
			slog.String("class", class.String()),
			slog.Bool("retryOfFailedApply", retryOfFailedApply),
			slog.Uint64("partitionRound", cr.UC.GetRoundNumber()),
			slog.Uint64("rootRound", cr.UC.GetRootRoundNumber()),
			slog.Uint64("nextRound", cr.Technical.Round),
			slog.String("nextLeader", cr.Technical.Leader))
	}

	c.mu.Lock()
	driver := c.driver
	c.mu.Unlock()

	err = driver.HandleCertificate(ctx, &cr.UC, &cr.Technical)

	// Renew before returning. Only a certificate carrying something this node had not already
	// observed counts: a retry of one it has is not progress, and treating it as progress is what
	// let a failing application drive a handshake loop.
	c.renewSubscriptionIfIdle(ctx, &cr.UC, !retryOfFailedApply)

	// Record whether this certificate was actually applied, separately from having been observed.
	// This is the whole of the applied-versus-observed split at this layer: on failure the
	// certificate stays marked unapplied so a retransmission retries it, and on success the mark
	// is cleared so later duplicates go back to being no-ops.
	// APPLIED is not the same as SENT, and only the first one decides whether to retry.
	//
	// A driver error that is ErrSubmissionFailed means the certificate WAS applied — observed,
	// committed, reconciled — and that the next round's certification request did not reach the
	// root chain. Retrying the delivery would not resend that request (it belongs to a round the
	// driver has already moved past); it would re-enter the round with a proposal the root chain
	// has certified nothing about. That is exactly the path that finalised an uncertified block,
	// so a send failure is reported and the certificate stays applied.
	c.mu.Lock()
	switch {
	case err == nil:
		c.unapplied = nil
	case errors.Is(err, ErrSubmissionFailed):
		c.unapplied = nil
		metrics.recordIRDivergence(ctx, "delivery_send_failed")
	default:
		c.unapplied = &deliveryAttempt{partitionRound: cr.UC.GetRoundNumber(), rootRound: cr.UC.GetRootRoundNumber()}
	}
	c.mu.Unlock()
	return err
}

// Submit implements shardnode.Submitter. It selects root nodes
// deterministically from the last accepted UC's hash — see rootnodes.go —
// so every honest validator submitting the same round spreads load across
// root nodes identically without coordinating.
func (c *BFTClient) Submit(ctx context.Context, req *certification.BlockCertificationRequest) error {
	c.mu.Lock()
	luc := c.luc
	c.mu.Unlock()

	if luc == nil {
		return errors.New("shardnode: no certificate received yet, cannot select root nodes to submit to")
	}
	tb, err := c.trustBaseStore.GetByEpoch(ctx, luc.GetRootEpoch())
	if err != nil {
		return fmt.Errorf("loading trust base for epoch %d: %w", luc.GetRootEpoch(), err)
	}
	rootIDs, err := rootNodesSelector(luc, tb, c.opts.CertNodes)
	if err != nil {
		return fmt.Errorf("selecting root nodes for certification: %w", err)
	}
	if err := c.net.Send(ctx, req, rootIDs...); err != nil {
		return err
	}
	// A submitted request refills this node's subscription at the root chain, so nothing else needs
	// to ask for one this round.
	c.mu.Lock()
	c.submittedSinceHandshake = true
	c.mu.Unlock()
	return nil
}
