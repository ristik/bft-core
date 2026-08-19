package shardnode

import (
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

	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/network/protocol/handshake"
)

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
	nodeID      string

	peer           *network.Peer
	net            *network.ShardNetwork
	signer         abcrypto.Signer
	trustBaseStore TrustBaseStore
	driver         RoundDriver
	log            *slog.Logger
	opts           BFTClientOptions

	mu  sync.Mutex
	luc *types.UnicityCertificate

	lastCertResponseTime atomic.Int64
}

func NewBFTClient(
	peer *network.Peer,
	net *network.ShardNetwork,
	signer abcrypto.Signer,
	partitionID types.PartitionID,
	shardID types.ShardID,
	trustBaseStore TrustBaseStore,
	driver RoundDriver,
	log *slog.Logger,
	opts BFTClientOptions,
) (*BFTClient, error) {
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
				if err := c.sendHandshake(ctx); err != nil && c.log != nil {
					c.log.ErrorContext(ctx, "re-handshake failed", slog.String("err", err.Error()))
				}
			}
		}
	}
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
	if err := cr.UC.Verify(tb, crypto.SHA256, c.partitionID, c.shardID, nil); err != nil {
		return fmt.Errorf("verifying unicity certificate: %w", err)
	}

	c.mu.Lock()
	prevLUC := c.luc
	class, err := ClassifyUC(prevLUC, &cr.UC)
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("classifying certificate: %w", err)
	}
	if class == UCDuplicate {
		c.mu.Unlock()
		if c.log != nil {
			c.log.DebugContext(ctx, "duplicate UC, ignoring", slog.Uint64("rootRound", cr.UC.GetRootRoundNumber()))
		}
		return nil
	}
	c.luc = &cr.UC
	c.mu.Unlock()

	if c.log != nil {
		c.log.InfoContext(ctx, "accepted certificate",
			slog.String("class", class.String()),
			slog.Uint64("partitionRound", cr.UC.GetRoundNumber()),
			slog.Uint64("rootRound", cr.UC.GetRootRoundNumber()),
			slog.Uint64("nextRound", cr.Technical.Round),
			slog.String("nextLeader", cr.Technical.Leader))
	}

	c.mu.Lock()
	driver := c.driver
	c.mu.Unlock()
	return driver.HandleCertificate(ctx, &cr.UC, &cr.Technical)
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
	return c.net.Send(ctx, req, rootIDs...)
}
