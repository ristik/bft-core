package rootchain

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/observability"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/hash"
	"github.com/unicitynetwork/bft-go-base/types"
)

type (
	QuorumStatus uint8

	// QuorumInfo is what the buffer counts requests with: the weights of the shard round and the identity of the
	// assignment they come from. Tallies are tagged with the identity, so requests counted under one assignment are never
	// retallied with the weights of another.
	QuorumInfo interface {
		rctypes.RequestWeights
		Identity() string
	}

	// RoundTagged is implemented by a QuorumInfo that also knows the shard round and anchor its requests build on (expected
	// round, epoch, previous state hash and timestamp). Tallies are tagged with it too; one that does not tag is untagged.
	RoundTagged interface {
		RoundTag() string
	}

	CertRequestBuffer struct {
		mu    sync.RWMutex
		store map[partitionShard]*requestBuffer

		consensusDur metric.Float64Histogram
		responseDur  metric.Float64Histogram
	}

	partitionShard struct {
		partition types.PartitionID
		shard     string // can't use ShardID type as it's not comparable
	}

	sha256Hash [sha256.Size]byte

	// requestBuffer keeps track of received Certification Request
	requestBuffer struct {
		// index of nodes which have voted (key is node identifier)
		nodeRequest map[string]struct{}
		// index to count votes, key is the hash of IR record and sizes
		requests map[sha256Hash][]*certification.BlockCertificationRequest
		// weights of the received requests, nil while the buffer is empty
		tally *rctypes.RequestTally
		// identity of the assignment the tally was counted under
		identity string
		// shard round and anchor the tally was counted for
		roundTag string
		qState   QuorumStatus

		start     time.Time
		attrShard metric.MeasurementOption
	}
)

const (
	QuorumUnknown QuorumStatus = iota
	QuorumInProgress
	QuorumAchieved
	QuorumNotPossible
)

func (qs QuorumStatus) String() string {
	switch qs {
	case QuorumInProgress:
		return "QuorumInProgress"
	case QuorumAchieved:
		return "QuorumAchieved"
	case QuorumNotPossible:
		return "QuorumNotPossible"
	case QuorumUnknown:
		return "QuorumUnknown"
	default:
		return fmt.Sprintf("QuorumStatus(%d)", int(qs))
	}
}

// NewCertificationRequestBuffer create new certification nodeRequest buffer
func NewCertificationRequestBuffer(m metric.Meter) (*CertRequestBuffer, error) {
	consensusDur, err := m.Float64Histogram("cert.req.consensus.time",
		metric.WithDescription("How long it took to achieve consensus about shard's certification request, ie enough shard nodes have sent in their take for the round"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(200e-6, 400e-6, 800e-6, 0.0016, 0.003, 0.006, 0.01, 0.05, 0.1, 0.2, 0.4, 0.8))
	if err != nil {
		return nil, fmt.Errorf("creating histogram for req consensus time: %w", err)
	}
	responseDur, err := m.Float64Histogram("cert.rsp.ready.time",
		metric.WithDescription("How long it took from handing certification request over to consensus manager to sending out certification result"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.1, 1.5))
	if err != nil {
		return nil, fmt.Errorf("creating histogram for cert ready time: %w", err)
	}

	return &CertRequestBuffer{
		store:        make(map[partitionShard]*requestBuffer),
		consensusDur: consensusDur,
		responseDur:  responseDur,
	}, nil
}

/*
Add request to certification store. Per node id first valid request is stored. Rest are either duplicate or
equivocating and in both cases error is returned. Clear in order to receive new nodeRequest (ie to start
collecting requests for the next round).
*/
func (c *CertRequestBuffer) Add(ctx context.Context, request *certification.BlockCertificationRequest, tb QuorumInfo) (QuorumStatus, []*certification.BlockCertificationRequest, error) {
	if request == nil || request.InputRecord == nil {
		return QuorumUnknown, nil, fmt.Errorf("%w: missing request or input record", rctypes.ErrInvalidRequest)
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// A store for a shard not seen before is published only once the request has been admitted: a refusal leaves no shard state.
	key := partitionShard{partition: request.PartitionID, shard: request.ShardID.Key()}
	rs, known := c.store[key]
	if !known {
		rs = newRequestStore()
		rs.attrShard = observability.Shard(request.PartitionID, request.ShardID)
	}
	qs, bcr, err := rs.add(request, tb)
	if err != nil {
		return qs, bcr, err
	}
	if !known {
		c.store[key] = rs
	}
	c.updQuorumStatus(ctx, rs, qs)
	return qs, bcr, err
}

func (c *CertRequestBuffer) IsConsensusReceived(partition types.PartitionID, shard types.ShardID, tb QuorumInfo) QuorumStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rs := c.get(partition, shard)
	if rs.tally != nil && tb != nil && (rs.identity != tb.Identity() || rs.roundTag != tagOf(tb)) {
		// counted under another assignment, shard round or anchor: the status says nothing about this one
		return QuorumUnknown
	}
	return rs.qState
}

// Retire forgets what was counted for the shard when it was counted under another assignment, shard round or anchor than tb
// names, and reports whether it did. Old signatures are dropped, never retallied with the weights of the new context. A buffer
// counted under tb, or an empty one, is untouched.
func (c *CertRequestBuffer) Retire(partition types.PartitionID, shard types.ShardID, tb QuorumInfo) bool {
	if tb == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := partitionShard{partition: partition, shard: shard.Key()}
	rs, ok := c.store[key]
	if !ok || rs.tally == nil || (rs.identity == tb.Identity() && rs.roundTag == tagOf(tb)) {
		return false
	}
	rs.reset()
	return true
}

// tagOf is the shard round and anchor tag of tb, empty for a QuorumInfo that does not carry one.
func tagOf(tb QuorumInfo) string {
	if t, ok := tb.(RoundTagged); ok {
		return t.RoundTag()
	}
	return ""
}

/*
Clear clears node request in one shard - this must be called when the shard's Certification Request for a
round has been processed in order for the buffer to accept requests for the next round.
*/
func (c *CertRequestBuffer) Clear(ctx context.Context, partition types.PartitionID, shard types.ShardID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	rs := c.get(partition, shard)
	switch rs.qState {
	case QuorumAchieved, QuorumNotPossible:
		c.responseDur.Record(ctx, time.Since(rs.start).Seconds())
	}
	rs.reset()
}

// get returns an existing store for shard or registers and returns a new one if none existed
func (c *CertRequestBuffer) get(partition types.PartitionID, shard types.ShardID) *requestBuffer {
	key := partitionShard{partition: partition, shard: shard.Key()}
	rs, f := c.store[key]
	if !f {
		rs = newRequestStore()
		rs.attrShard = observability.Shard(partition, shard)
		c.store[key] = rs
	}
	return rs
}

func (c *CertRequestBuffer) updQuorumStatus(ctx context.Context, rb *requestBuffer, qs QuorumStatus) {
	if rb.qState == qs {
		return
	}

	switch qs {
	case QuorumAchieved:
		c.consensusDur.Record(ctx, time.Since(rb.start).Seconds(), attrQuorumAchieved, rb.attrShard)
	case QuorumNotPossible:
		c.consensusDur.Record(ctx, time.Since(rb.start).Seconds(), attrQuorumNotPossible)
	}
	rb.qState = qs
	// start clock to track time until Clear is called (consensus has been certified)
	rb.start = time.Now()
}

// newRequestStore creates a new empty requestBuffer.
func newRequestStore() *requestBuffer {
	s := &requestBuffer{
		nodeRequest: make(map[string]struct{}),
		requests:    make(map[sha256Hash][]*certification.BlockCertificationRequest),
		qState:      QuorumInProgress,
	}
	return s
}

// add stores a new input record received from the node. Whatever is refused leaves the buffer, the tally and the status
// unchanged: the new state is computed on copies and published only at the end.
func (rs *requestBuffer) add(req *certification.BlockCertificationRequest, tb QuorumInfo) (QuorumStatus, []*certification.BlockCertificationRequest, error) {
	if req == nil || req.InputRecord == nil {
		return QuorumUnknown, nil, fmt.Errorf("%w: missing request or input record", rctypes.ErrInvalidRequest)
	}
	if tb == nil {
		return QuorumUnknown, nil, fmt.Errorf("%w: no quorum information", quorumweight.ErrRequestContext)
	}
	empty := len(rs.nodeRequest) == 0
	if !empty && rs.identity != tb.Identity() {
		return QuorumUnknown, nil, fmt.Errorf("%w: requests are counted under assignment %q, not %q", quorumweight.ErrRequestContext, rs.identity, tb.Identity())
	}
	if !empty && rs.roundTag != tagOf(tb) {
		return QuorumUnknown, nil, fmt.Errorf("%w: requests are counted for shard round/anchor %q, not %q", quorumweight.ErrRequestContext, rs.roundTag, tagOf(tb))
	}
	if _, f := rs.nodeRequest[req.NodeID]; f {
		return QuorumUnknown, nil, dupRequest{}
	}

	h, err := hash.HashValues(crypto.SHA256, req.InputRecord, req.BlockSize, req.StateSize)
	if err != nil {
		return QuorumUnknown, nil, fmt.Errorf("creating id for the request: %w", err)
	}
	reqID := sha256Hash(h)

	var tally *rctypes.RequestTally
	if empty || rs.tally == nil {
		tally = rctypes.NewRequestTally(tb)
	} else {
		tally = rs.tally.CloneWith(tb)
	}
	if err := tally.Add(req.NodeID, reqID); err != nil {
		return QuorumUnknown, nil, fmt.Errorf("counting the request: %w", err)
	}
	res, err := decide(tally, tb)
	if err != nil {
		return QuorumUnknown, nil, err
	}

	if empty {
		// start clock to track time until consensus is achieved
		rs.start = time.Now()
	}
	rs.tally, rs.identity, rs.roundTag = tally, tb.Identity(), tagOf(tb)
	rs.nodeRequest[req.NodeID] = struct{}{}
	rs.requests[reqID] = append(rs.requests[reqID], cloneRequest(req))
	return res, rs.proof(res, tally, tb), nil
}

// cloneRequest is a private copy of req: the buffer neither keeps the caller's request nor hands out its own, so a request
// mutated after Add or a proof mutated after it was returned cannot change what is counted.
func cloneRequest(req *certification.BlockCertificationRequest) *certification.BlockCertificationRequest {
	c := *req
	c.ZkProof = bytes.Clone(req.ZkProof)
	c.Signature = bytes.Clone(req.Signature)
	ir := *req.InputRecord
	ir.PreviousHash = bytes.Clone(ir.PreviousHash)
	ir.Hash = bytes.Clone(ir.Hash)
	ir.SummaryValue = bytes.Clone(ir.SummaryValue)
	ir.BlockHash = bytes.Clone(ir.BlockHash)
	ir.ETHash = bytes.Clone(ir.ETHash)
	c.InputRecord = &ir
	return &c
}

func cloneRequests(reqs []*certification.BlockCertificationRequest) []*certification.BlockCertificationRequest {
	out := make([]*certification.BlockCertificationRequest, len(reqs))
	for i, r := range reqs {
		out[i] = cloneRequest(r)
	}
	return out
}

// dupRequest is the refusal of a second request of the same node in the round, with its long-standing text.
type dupRequest struct{}

func (dupRequest) Error() string        { return "request of the node in this round already stored" }
func (dupRequest) Is(target error) bool { return target == quorumweight.ErrDuplicateSigner }

func (rs *requestBuffer) reset() {
	clear(rs.nodeRequest)
	clear(rs.requests)
	rs.tally, rs.identity, rs.roundTag = nil, "", ""
	rs.qState = QuorumInProgress
}

// decide is the quorum status of a tally. Quorum needs the heaviest group to reach Q; no quorum is possible exactly when
// M+U < Q strictly. Neither verdict is ever given on an inconsistent tally: that is an error.
func decide(tally *rctypes.RequestTally, tb QuorumInfo) (QuorumStatus, error) {
	if err := tally.Validate(); err != nil {
		return QuorumUnknown, fmt.Errorf("deciding the quorum status: %w", err)
	}
	if tally.QuorumReached() {
		return QuorumAchieved, nil
	}
	impossible, err := tally.QuorumImpossible()
	if err != nil {
		return QuorumUnknown, fmt.Errorf("deciding the quorum status: %w", err)
	}
	if impossible {
		// enough weight has voted and even if the rest of it joined the most popular option, quorum is still not possible
		return QuorumNotPossible, nil
	}
	// consensus possible in the future
	return QuorumInProgress, nil
}

// proof is the evidence for a status: the one matching group for a quorum (only one group can hold more than half of the
// total weight), every request for no quorum.
func (rs *requestBuffer) proof(res QuorumStatus, tally *rctypes.RequestTally, tb QuorumInfo) []*certification.BlockCertificationRequest {
	switch res {
	case QuorumAchieved:
		for g, reqs := range rs.requests {
			if quorumweight.Reached(tally.GroupWeight(g), tb.Threshold()) {
				return cloneRequests(reqs)
			}
		}
	case QuorumNotPossible:
		all := make([]*certification.BlockCertificationRequest, 0, len(rs.nodeRequest))
		for _, reqs := range rs.requests {
			all = append(all, reqs...)
		}
		return cloneRequests(all)
	}
	return nil
}

var (
	attrQuorumAchieved    = metric.WithAttributeSet(attribute.NewSet(attribute.Int("status", int(QuorumAchieved))))
	attrQuorumNotPossible = metric.WithAttributeSet(attribute.NewSet(attribute.Int("status", int(QuorumNotPossible))))
)
