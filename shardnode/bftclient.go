package shardnode

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
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

	admissionFactory     CertificateAdmissionFactory
	admissionGate        FinalityBoundary
	admissionSink        RoundDriver
	admission            CertificateAdmission
	admissionWake        chan struct{}
	feedPending          *types.UnicityCertificate
	feedPendingCount     uint8
	feedHeld             *types.UnicityCertificate
	feedHeldIdentity     [32]byte
	configuredApplied    [32]byte
	configuredFailed     [32]byte
	hasConfiguredApplied bool
	hasConfiguredFailed  bool
	running              bool
	seeded               bool
	configuredStarted    bool
	admissionEpoch       uint64
	admissionEpochSet    bool

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
	profile2             *Profile2Consumer
}

// SetProfile2Consumer enables the proof-gated epoch boundary before Run.
// The configured journal admission path needs its own proof-aware durability
// boundary; until i-b/H4 supplies it, combining the two modes fails closed.
func (c *BFTClient) SetProfile2Consumer(consumer *Profile2Consumer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return ErrClientRunning
	}
	if consumer == nil {
		return ErrProfile2Unready
	}
	if c.admissionFactory != nil {
		return fmt.Errorf("%w: profile 2 requires proof-aware journal admission", ErrAdmissionMode)
	}
	c.profile2 = consumer
	return nil
}

func (c *BFTClient) classifyUC(prev, next *types.UnicityCertificate) (UCClass, error) {
	if c.profile2 != nil {
		return c.profile2.Classify(prev, next)
	}
	if next != nil && c.admission != nil {
		if gate, ok := c.admission.(interface{ Profile2Ready(uint64) bool }); ok && gate.Profile2Ready(next.GetRootEpoch()) {
			return ClassifyUCEpoch(prev, next)
		}
	}
	return ClassifyUC(prev, next)
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
	if err := validateShardConfHashWidth(shardConfHash); err != nil {
		return nil, err
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
func (c *BFTClient) SeedLUC(uc *types.UnicityCertificate) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return ErrClientRunning
	}
	if c.admissionFactory != nil {
		return fmt.Errorf("%w: legacy LUC seed after configured admission attachment", ErrAdmissionMode)
	}
	c.luc = uc
	c.seeded = uc != nil
	return nil
}

// SetDriver supplies the RoundDriver that processes accepted certificates.
// Exists as a separate step from the constructor because a Round (the
// framework's usual RoundDriver) needs a Submitter — which BFTClient itself
// implements — so building "Round, then BFTClient" and "BFTClient, then
// Round" are both partially circular; this breaks the cycle by letting
// BFTClient exist (and be usable as a Submitter) before its driver is
// finalized. See node.go for the wiring order this enables.
func (c *BFTClient) SetDriver(driver RoundDriver) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return ErrClientRunning
	}
	if c.admissionFactory != nil {
		return fmt.Errorf("%w: driver is frozen after configured admission attachment", ErrAdmissionMode)
	}
	c.driver = driver
	return nil
}

// SetCertificateAdmission installs an optional pre-LUC admission boundary. It is intentionally
// BFTClient-only: no production Node or CLI path selects it yet. The explicit sink is not the
// legacy persisting driver and is invoked only for a durably admitted owned pair.
func (c *BFTClient) SetCertificateAdmission(factory CertificateAdmissionFactory, gate FinalityBoundary, sink RoundDriver) error {
	if factory == nil || gate == nil || sink == nil {
		return fmt.Errorf("%w: factory, gate and sink are required", ErrAdmissionMode)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return ErrClientRunning
	}
	if c.seeded || c.luc != nil {
		return fmt.Errorf("%w: legacy LUC was already seeded", ErrAdmissionMode)
	}
	if c.admissionFactory != nil {
		return fmt.Errorf("%w: admission already attached", ErrAdmissionMode)
	}
	if c.profile2 != nil {
		return fmt.Errorf("%w: configured admission cannot bypass profile 2 proof gate", ErrAdmissionMode)
	}
	c.admissionFactory, c.admissionGate, c.admissionSink = factory, gate, sink
	c.admissionWake = make(chan struct{}, 1)
	return nil
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
	if c.running {
		c.mu.Unlock()
		return ErrClientRunning
	}
	hasDriver := c.driver != nil
	factory, gate := c.admissionFactory, c.admissionGate
	if factory != nil && c.configuredStarted {
		c.mu.Unlock()
		return fmt.Errorf("%w: configured client Run is single-use", ErrAdmissionMode)
	}
	if factory != nil {
		c.configuredStarted = true
	}
	c.running = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()
	if factory == nil && !hasDriver {
		return errors.New("shardnode: no round driver configured — call SetDriver before Run")
	}
	if factory != nil {
		identity, err := ownAdmissionIdentity(c.partitionID, c.shardID, c.shardConfHash, c.trustBaseStore)
		if err != nil {
			return err
		}
		admission, err := factory.Start(ctx, identity, gate, AdmissionCallbacks{AuthenticatedFeed: c.observeConfiguredFeed, DeliverDurable: c.deliverConfigured})
		if err != nil {
			return fmt.Errorf("starting configured certificate admission: %w", err)
		}
		if admission == nil {
			return fmt.Errorf("starting configured certificate admission: nil admission")
		}
		c.mu.Lock()
		c.admission = admission
		c.admissionEpoch = admission.RootEpoch()
		c.admissionEpochSet = true
		c.mu.Unlock()
		defer func() {
			_ = admission.Close()
			c.mu.Lock()
			c.admission = nil
			c.mu.Unlock()
		}()
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
		case <-c.admissionWake:
			c.mu.Lock()
			uc := c.feedPending
			count := c.feedPendingCount
			c.feedPending = nil
			c.feedPendingCount = 0
			c.mu.Unlock()
			if uc != nil {
				c.renewSubscriptionIfIdle(ctx, uc, true, count)
			}
		case msg, ok := <-received:
			if !ok {
				return errors.New("shardnode: network received channel closed")
			}
			batch, closed := c.coalesceBufferedCertificationResponses(ctx, msg, received)
			for _, queued := range batch {
				c.handleMessage(ctx, queued)
			}
			if closed {
				return errors.New("shardnode: network received channel closed")
			}
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
func (c *BFTClient) renewSubscriptionIfIdle(ctx context.Context, uc *types.UnicityCertificate, newEvidence bool, delivered uint8) {
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
	// One submission credit covers one response. A coalesced wake represents several distinct
	// authenticated responses, so it must renew even if one credit was pending.
	if delivered > 1 {
		submitted = false
	}
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
	c.mu.Lock()
	configuredEpoch := c.admissionEpoch
	configuredEpochSet := c.admissionEpochSet
	admission := c.admission
	c.mu.Unlock()
	if admission != nil {
		configuredEpoch = admission.RootEpoch()
	}
	if configuredEpochSet {
		epoch = configuredEpoch
		if admission != nil {
			epoch = admission.RootEpoch()
		}
	}
	if luc != nil && !configuredEpochSet {
		epoch = luc.GetRootEpoch()
	}
	if c.profile2 != nil {
		if floor, installed := c.profile2.EpochFloor(); installed {
			if floor > epoch {
				epoch = floor
			}
		}
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

// certificationAuthorization is populated only after the wrapped UC has been verified against
// this client's configured shard and a locally trusted root epoch. Its round fields are therefore
// safe to use when deciding which queued response carries the newest authorization.
type certificationAuthorization struct {
	rootEpoch    uint64
	rootRound    uint64
	inputRecord  string
	pairIdentity [32]byte
}

type queuedCertificationMessage struct {
	message       any
	authorization *certificationAuthorization
}

// verifyCertificationAuthorization authenticates the response before any round number from it is
// trusted by the queue coalescer. handleCertificationResponse repeats these checks on delivery: the
// queue check is an ordering guard, not an alternate certificate acceptance path.
func (c *BFTClient) verifyCertificationAuthorization(ctx context.Context, cr *certification.CertificationResponse) (*certificationAuthorization, error) {
	if err := cr.IsValid(); err != nil {
		return nil, fmt.Errorf("invalid certification response: %w", err)
	}
	if cr.Partition != c.partitionID || !cr.Shard.Equal(c.shardID) {
		return nil, fmt.Errorf("certification response for wrong shard %s-%s", cr.Partition, cr.Shard)
	}
	if len(c.shardConfHash) == 0 {
		return nil, errors.New("this client has no configured shard configuration hash, so a certificate's configuration cannot be checked")
	}
	if cr.UC.InputRecord == nil || cr.UC.UnicitySeal == nil {
		return nil, errors.New("invalid certification response: unicity certificate is incomplete")
	}
	epoch := cr.UC.GetRootEpoch()
	tb, err := c.trustBaseStore.GetByEpoch(ctx, epoch)
	if err != nil {
		return nil, fmt.Errorf("loading trust base for epoch %d: %w", epoch, err)
	}
	if tb == nil {
		return nil, fmt.Errorf("loading trust base for epoch %d: trust base is nil", epoch)
	}
	if err = cr.UC.Verify(tb, crypto.SHA256, c.partitionID, c.shardID, c.shardConfHash); err != nil {
		return nil, fmt.Errorf("verifying unicity certificate: %w", err)
	}
	input, err := cr.UC.InputRecord.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encoding certified input record: %w", err)
	}
	pairIdentity, err := configuredPairIdentity(&cr.UC, &cr.Technical)
	if err != nil {
		return nil, fmt.Errorf("identifying certified response: %w", err)
	}
	return &certificationAuthorization{
		rootEpoch: epoch, rootRound: cr.UC.GetRootRoundNumber(), inputRecord: string(input), pairIdentity: pairIdentity,
	}, nil
}

func compareCertificationAuthorization(a, b *certificationAuthorization) int {
	if a.rootEpoch < b.rootEpoch {
		return -1
	}
	if a.rootEpoch > b.rootEpoch {
		return 1
	}
	if a.rootRound < b.rootRound {
		return -1
	}
	if a.rootRound > b.rootRound {
		return 1
	}
	return 0
}

// coalesceBufferedCertificationResponses drains the currently queued feed before handing anything
// to the synchronous round driver. Repeats for one exact InputRecord are one authorization stream:
// once a newer, authenticated root round is present, earlier responses in that stream cannot
// authorize useful work and are collapsed. Distinct InputRecords stay in arrival order because
// each certified block may need to be applied. Equal-round conflicting statements are preserved
// so the normal non-equivocation check still sees them.
func (c *BFTClient) coalesceBufferedCertificationResponses(ctx context.Context, first any, received <-chan any) ([]any, bool) {
	queued := make([]queuedCertificationMessage, 0, 1)
	activeInput := ""
	activeAuth := (*certificationAuthorization)(nil)
	activeIndices := make([]int, 0, 1)
	activeAmbiguous := false
	appendMessage := func(message any) {
		entry := queuedCertificationMessage{message: message}
		cr, ok := message.(*certification.CertificationResponse)
		if ok && cr != nil {
			if authorization, err := c.verifyCertificationAuthorization(ctx, cr); err == nil {
				entry.authorization = authorization
			}
		}

		// Invalid or unrelated messages are retained for ordinary handling and do not break the
		// active group; a distinct authenticated input record does.
		if entry.authorization == nil {
			queued = append(queued, entry)
			return
		}
		if activeAuth == nil || activeInput != entry.authorization.inputRecord {
			activeInput = entry.authorization.inputRecord
			activeAuth = entry.authorization
			activeIndices = []int{len(queued)}
			activeAmbiguous = false
			queued = append(queued, entry)
			return
		}
		if activeAmbiguous {
			activeIndices = append(activeIndices, len(queued))
			queued = append(queued, entry)
			return
		}

		order := compareCertificationAuthorization(activeAuth, entry.authorization)
		if order > 0 {
			if c.log != nil {
				c.log.DebugContext(ctx, "dropping verified older certification response",
					slog.Uint64("rootEpoch", entry.authorization.rootEpoch),
					slog.Uint64("rootRound", entry.authorization.rootRound),
					slog.Uint64("newerRootEpoch", activeAuth.rootEpoch),
					slog.Uint64("newerRootRound", activeAuth.rootRound))
			}
			return
		}
		if order == 0 {
			// A repeated byte-identical authorization may be the retry that recovers a failed
			// driver delivery, so preserve it. If the UC or TechnicalRecord differs, keep both
			// for classification rather than hiding a same-round conflict.
			if activeAuth.pairIdentity != entry.authorization.pairIdentity {
				activeAmbiguous = true
			}
			activeIndices = append(activeIndices, len(queued))
			queued = append(queued, entry)
			return
		}

		// A higher root authorization for the same exact input record supersedes every queued
		// occurrence of its earlier authorizations. Keep the newest response in the first slot so
		// it remains before any later distinct InputRecord that must be applied after it.
		firstIndex := activeIndices[0]
		queued[firstIndex] = entry
		for _, index := range activeIndices[1:] {
			queued[index] = queuedCertificationMessage{}
		}
		activeAuth = entry.authorization
		activeIndices = []int{firstIndex}
	}

	appendMessage(first)
	closed := false
	for {
		select {
		case message, ok := <-received:
			if !ok {
				closed = true
				goto drained
			}
			appendMessage(message)
		default:
			goto drained
		}
	}

drained:
	batch := make([]any, 0, len(queued))
	for _, entry := range queued {
		if entry.message != nil {
			batch = append(batch, entry.message)
		}
	}
	return batch, closed
}

func configuredPairIdentity(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) ([32]byte, error) {
	var zero [32]byte
	if uc == nil || uc.InputRecord == nil || uc.UnicitySeal == nil || tr == nil {
		return zero, errors.New("configured delivery pair is incomplete")
	}
	ir, err := uc.InputRecord.Bytes()
	if err != nil {
		return zero, err
	}
	seal, err := uc.UnicitySeal.SigBytes()
	if err != nil {
		return zero, err
	}
	tb, err := types.Cbor.Marshal(tr)
	if err != nil {
		return zero, err
	}
	h := sha256.New()
	var n [8]byte
	for _, part := range [][]byte{ir, seal, tb} {
		binary.BigEndian.PutUint64(n[:], uint64(len(part)))
		_, _ = h.Write(n[:])
		_, _ = h.Write(part)
	}
	copy(zero[:], h.Sum(nil))
	return zero, nil
}

func ownConfiguredPair(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) (*types.UnicityCertificate, *certification.TechnicalRecord, error) {
	ub, err := types.Cbor.Marshal(uc)
	if err != nil {
		return nil, nil, err
	}
	tb, err := types.Cbor.Marshal(tr)
	if err != nil {
		return nil, nil, err
	}
	var u types.UnicityCertificate
	var t certification.TechnicalRecord
	if err = types.Cbor.Unmarshal(ub, &u); err != nil {
		return nil, nil, err
	}
	if err = types.Cbor.Unmarshal(tb, &t); err != nil {
		return nil, nil, err
	}
	return &u, &t, nil
}

// observeConfiguredFeed is called only by the admission factory after bounded authentication.
// It owns and coalesces progress, then wakes Run; it performs no network I/O in the callback.
func (c *BFTClient) observeConfiguredFeed(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) {
	u, _, err := ownConfiguredPair(uc, tr)
	if err != nil {
		return
	}
	id, err := configuredPairIdentity(uc, tr)
	if err != nil {
		return
	}
	c.mu.Lock()
	progress := c.feedHeld == nil
	if c.feedHeld != nil {
		class, classErr := c.classifyUC(c.feedHeld, u)
		progress = classErr == nil && (class == UCValid || class == UCRepeat)
		if class == UCDuplicate && id != c.feedHeldIdentity {
			progress = false
		}
	}
	if progress {
		c.feedHeld, c.feedHeldIdentity = u, id
		c.feedPending = u
		if c.feedPendingCount < ^uint8(0) {
			c.feedPendingCount++
		}
		select {
		case c.admissionWake <- struct{}{}:
		default:
		}
	}
	c.mu.Unlock()
}

// deliverConfigured is the sole configured-mode LUC adoption path. The coordinator calls it
// only after durable commit and after releasing the finality gate.
func (c *BFTClient) deliverConfigured(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	id, err := configuredPairIdentity(uc, tr)
	if err != nil {
		return err
	}
	cursor, _, err := ownConfiguredPair(uc, tr)
	if err != nil {
		return err
	}
	driverUC, driverTR, err := ownConfiguredPair(uc, tr)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return err
	}
	if c.hasConfiguredApplied && c.configuredApplied == id {
		c.mu.Unlock()
		return nil
	}
	retry := c.hasConfiguredFailed && c.configuredFailed == id
	class, err := c.classifyUC(c.luc, cursor)
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("classifying durably admitted certificate: %w", err)
	}
	if class == UCDuplicate && !retry {
		c.mu.Unlock()
		return fmt.Errorf("%w: duplicate LUC has another full statement or technical record", ErrAdmissionMode)
	}
	if class == UCStale {
		c.mu.Unlock()
		return fmt.Errorf("%w: durable delivery regressed configured LUC", ErrAdmissionMode)
	}
	if class != UCDuplicate {
		c.luc = cursor
	}
	sink := c.admissionSink
	metrics, health := c.metrics, c.health
	c.mu.Unlock()

	health.updateCertificate(cursor.GetRoundNumber(), cursor.GetRootRoundNumber(), driverTR.Leader, c.nodeID)
	err = sink.HandleCertificate(ctx, driverUC, driverTR)
	c.mu.Lock()
	switch {
	case err == nil:
		c.configuredApplied, c.hasConfiguredApplied = id, true
		c.hasConfiguredFailed = false
	case errors.Is(err, ErrSubmissionFailed):
		c.configuredApplied, c.hasConfiguredApplied = id, true
		c.hasConfiguredFailed = false
		metrics.recordIRDivergence(ctx, "delivery_send_failed")
	default:
		c.configuredFailed, c.hasConfiguredFailed = id, true
	}
	c.mu.Unlock()
	if errors.Is(err, ErrSubmissionFailed) {
		if c.log != nil {
			c.log.ErrorContext(ctx, "configured certificate applied but next request submission failed", slog.String("err", err.Error()))
		}
		return nil
	}
	return err
}

func (c *BFTClient) admissionPending() (PendingAdmission, bool) {
	c.mu.Lock()
	a := c.admission
	c.mu.Unlock()
	if p, ok := a.(interface {
		PendingAdmission() (PendingAdmission, bool)
	}); ok {
		return p.PendingAdmission()
	}
	return PendingAdmission{}, false
}

func (c *BFTClient) handleCertificationResponse(ctx context.Context, cr *certification.CertificationResponse) error {
	if cr == nil {
		return errors.New("nil certification response")
	}
	c.lastCertResponseTime.Store(time.Now().UnixMilli())
	c.mu.Lock()
	admission := c.admission
	profile2 := c.profile2
	c.mu.Unlock()
	// A configured profile-2 admission session is keyed to the installed epoch.
	// Authenticate late certificates from retired v2 epochs before discarding
	// them, so they cannot be mistaken for an unready certificate in the active
	// epoch by the readiness gate below.
	if profile2 == nil && cr.UC.UnicitySeal != nil {
		if history, ok := c.trustBaseStore.(interface {
			IsV2Epoch(uint64) bool
			CurrentRootEpoch() (uint64, bool)
		}); ok {
			certificateEpoch := cr.UC.GetRootEpoch()
			if currentEpoch, active := history.CurrentRootEpoch(); active && history.IsV2Epoch(certificateEpoch) && certificateEpoch < currentEpoch {
				if err := cr.IsValid(); err != nil {
					return fmt.Errorf("%w: %w", ErrStaleEpochCertificateInvalid, err)
				}
				if cr.Partition != c.partitionID || !cr.Shard.Equal(c.shardID) {
					return fmt.Errorf("%w: certification response for %s-%s", ErrStaleEpochResponseWrongShard, cr.Partition, cr.Shard)
				}
				tb, err := c.trustBaseStore.GetByEpoch(ctx, certificateEpoch)
				if err != nil {
					return fmt.Errorf("loading trust base for epoch %d: %w", certificateEpoch, err)
				}
				if err := cr.UC.Verify(tb, crypto.SHA256, c.partitionID, c.shardID, c.shardConfHash); err != nil {
					return fmt.Errorf("%w: %w", ErrStaleEpochCertificateInvalid, err)
				}
				if c.log != nil {
					c.log.DebugContext(ctx, "dropping verified certificate from retired root epoch",
						slog.Uint64("certificateEpoch", certificateEpoch), slog.Uint64("currentRootEpoch", currentEpoch))
				}
				return nil
			}
		}
	}
	// A committed handoff retires the old epoch before shard execution resumes.
	// Delayed old-committee responses are neither current admission nor driver
	// input; historical recovery authenticates them through its separate path.
	if profile2 != nil {
		if floor, installed := profile2.EpochFloor(); installed && cr.UC.GetRootEpoch() < floor {
			return nil
		}
	}
	// Configured admission verifies the installed lineage and persists the
	// certificate before delivery. Require its active epoch gate before the
	// legacy consumer can accept a profile-2 response.
	if history, ok := c.trustBaseStore.(interface{ IsV2Epoch(uint64) bool }); ok && history.IsV2Epoch(cr.UC.GetRootEpoch()) && profile2 == nil {
		ready := false
		if gate, ok := admission.(interface{ Profile2Ready(uint64) bool }); ok {
			ready = gate.Profile2Ready(cr.UC.GetRootEpoch())
		}
		if !ready {
			if c.log != nil {
				c.log.DebugContext(ctx, "certificate blocked by profile-2 readiness gate",
					slog.Uint64("certificateEpoch", cr.UC.GetRootEpoch()))
			}
			return ErrProfile2Unready
		}
	}
	if admission != nil {
		if cr.Partition != c.partitionID || !cr.Shard.Equal(c.shardID) {
			return fmt.Errorf("certification response for wrong shard %s-%s", cr.Partition, cr.Shard)
		}
		return admission.Submit(ctx, &cr.UC, &cr.Technical)
	}

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
	class, err := c.classifyUC(prevLUC, &cr.UC)
	if err != nil {
		c.mu.Unlock()
		if errors.Is(err, ErrProfile2TerminalRepeat) || errors.Is(err, ErrProfile2Unready) || errors.Is(err, ErrProfile2Epoch) {
			return nil
		}
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
			slog.String("blockHash", fmt.Sprintf("%x", cr.UC.InputRecord.BlockHash)),
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
	c.renewSubscriptionIfIdle(ctx, &cr.UC, !retryOfFailedApply, 1)

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
