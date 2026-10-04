package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"

	"github.com/unicitynetwork/bft-core/logger"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

type (
	IRChangeVerifier interface {
		VerifyIRChangeReq(round uint64, irChReq *drctypes.IRChangeReq) (*types.InputRecord, error)
	}
	PartitionTimeout interface {
		GetT2Timeouts(currenRound uint64) ([]types.PartitionID, error)
	}
	irChange struct {
		InputRecord *types.InputRecord
		Reason      drctypes.IRChangeReason
		Req         *drctypes.IRChangeReq
		// tags of the view-aware path (zero under legacy dispatch): the view that judged the proof, its assignment, its shard
		// round and anchor, and the digest of the proof bytes
		viewKey     []byte
		assignKey   []byte
		roundTag    string
		proofDigest []byte
	}
	IrReqBuffer struct {
		irChgReqBuffer map[types.PartitionShardID]*irChange
		log            *slog.Logger
		profile        uint64
	}

	// ViewResolver resolves, for the proposal target round and a purpose, the authenticated view of one shard from the committed
	// history and the verified parent state. A failure is an error: never a fallback to the last committed state.
	ViewResolver interface {
		ResolveView(partition types.PartitionID, shard types.ShardID, round uint64, purpose storage.RequestPurpose) (*storage.RequestRoundView, error)
	}

	// ViewVerifier judges a proof under a resolved view.
	ViewVerifier interface {
		VerifyIRChangeReqView(view *storage.RequestRoundView, irChReq *drctypes.IRChangeReq) (*storage.VerifiedRequest, error)
	}

	InProgressFn func(partition types.PartitionID, shard types.ShardID) *types.InputRecord
)

func NewIrReqBuffer(log *slog.Logger, profile ...uint64) *IrReqBuffer {
	var version uint64
	if len(profile) != 0 {
		version = profile[0]
	}
	return &IrReqBuffer{
		irChgReqBuffer: make(map[types.PartitionShardID]*irChange),
		log:            log,
		profile:        version,
	}
}

// Add validates incoming IR change request and buffers valid requests. If for any reason the IR request is found not
// valid, reason is logged, error is returned and request is ignored.
func (x *IrReqBuffer) Add(round uint64, irChReq *drctypes.IRChangeReq, ver IRChangeVerifier) error {
	if irChReq == nil {
		return errors.New("ir change request is nil")
	}
	if x.profile == 2 && irChReq.Partition == drctypes.ControlPartition {
		return drctypes.ErrControlPartition
	}
	// special case, timeout cannot be requested, it can only be added to a block by the leader
	if irChReq.CertReason == drctypes.T2Timeout {
		return errors.New("invalid ir change request, timeout can only be proposed by leader issuing a new block")
	}
	ir, err := ver.VerifyIRChangeReq(round, irChReq)
	if err != nil {
		return fmt.Errorf("ir change request verification: %w", err)
	}

	psID := types.PartitionShardID{PartitionID: irChReq.Partition, ShardID: irChReq.Shard.Key()}

	// verify and extract proposed IR, NB! in this case we set the age to 0 as
	// currently no request can be received to request timeout
	newIrChReq := &irChange{InputRecord: ir, Reason: irChReq.CertReason, Req: irChReq}
	if irChangeReq, found := x.irChgReqBuffer[psID]; found {
		if irChangeReq.Reason != newIrChReq.Reason {
			return fmt.Errorf("equivocating request for partition %s, reason has changed", psID.PartitionID)
		}
		if b, err := types.EqualIR(irChangeReq.InputRecord, newIrChReq.InputRecord); b || err != nil {
			if err != nil {
				return fmt.Errorf("failed to compare IRs: %w", err)
			}
			// duplicate already stored
			x.log.Debug("duplicate IR change request, ignored", logger.Shard(irChReq.Partition, irChReq.Shard))
			return nil
		}
		// At this point it is not possible to cast blame, so just return error and ignore
		return fmt.Errorf("equivocating request for partition %s-%s", irChReq.Partition, irChReq.Shard)
	}
	// Insert first valid request received and compare the others received against it
	x.irChgReqBuffer[psID] = newIrChReq
	return nil
}

// IsChangeInBuffer returns true if there is a request for IR change from the partition
// in the buffer
func (x *IrReqBuffer) IsChangeInBuffer(partitionID types.PartitionID, shardID types.ShardID) bool {
	psID := types.PartitionShardID{PartitionID: partitionID, ShardID: shardID.Key()}
	_, found := x.irChgReqBuffer[psID]
	return found
}

// GeneratePayload generates new proposal payload from buffered IR change requests.
func (x *IrReqBuffer) GeneratePayload(round uint64, timeouts []*types.UnicityCertificate, inProgress InProgressFn) *drctypes.Payload {
	payload := &drctypes.Payload{
		Requests: make([]*drctypes.IRChangeReq, 0, len(x.irChgReqBuffer)+len(timeouts)),
	}
	// first add timeout requests
	for _, uc := range timeouts {
		if x.profile == 2 && (uc == nil || uc.GetPartitionID() == drctypes.ControlPartition) {
			continue
		}
		pID := uc.GetPartitionID()
		sID := uc.GetShardID()
		// if there is a request for the same partition (same id) in buffer (prefer progress to timeout) or
		// if there is a change already in the pipeline for this partition id
		if x.IsChangeInBuffer(pID, sID) || inProgress(pID, sID) != nil {
			x.log.Debug(fmt.Sprintf("T2 timeout request ignored, partition %s has pending change in progress", pID),
				logger.Shard(pID, sID))
			continue
		}
		x.log.Debug(fmt.Sprintf("partition %s request T2 timeout", pID), logger.Shard(pID, sID))
		payload.Requests = append(payload.Requests, &drctypes.IRChangeReq{
			Partition:  pID,
			Shard:      sID,
			CertReason: drctypes.T2Timeout,
		})
	}
	for _, req := range x.irChgReqBuffer {
		if inProgress(req.Req.Partition, req.Req.Shard) != nil {
			// if there is a pending block with the partition id in progress then do not propose a change
			// before last has been certified
			x.log.Debug(fmt.Sprintf("partition %s request ignored, pending change in pipeline", req.Req.Partition), logger.Shard(req.Req.Partition, req.Req.Shard))
			continue
		}
		payload.Requests = append(payload.Requests, req.Req)
	}
	// clear the buffer once payload is done
	clear(x.irChgReqBuffer)
	return payload
}

// AddView is Add under a resolved view: the proof is verified by the view-aware verifier and the entry is tagged with the view
// key, the assignment, the shard round and anchor and the digest of an owned copy of the proof. An entry buffered under another
// assignment, round or anchor is stale: it is retired before the duplicate and equivocation comparison, so an old proof can never
// make fresh work look equivocating. Nothing changes unless the new proof verified.
var (
	// ErrTimeoutRequest is returned for a node-submitted T2 timeout request: only a leader issuing a new block proposes one.
	ErrTimeoutRequest = errors.New("invalid ir change request, timeout can only be proposed by leader issuing a new block")
	// ErrEquivocation is returned when a buffered request is contradicted, under the same view, by another reason or result.
	ErrEquivocation = errors.New("equivocating request")
)

func (x *IrReqBuffer) AddView(view *storage.RequestRoundView, irChReq *drctypes.IRChangeReq, ver ViewVerifier) error {
	if view == nil {
		return fmt.Errorf("%w: no request view", drctypes.ErrInvalidRequest)
	}
	if irChReq == nil {
		return fmt.Errorf("ir change request is nil: %w", drctypes.ErrInvalidRequest)
	}
	if x.profile == 2 && irChReq.Partition == drctypes.ControlPartition {
		return drctypes.ErrControlPartition
	}
	if irChReq.CertReason == drctypes.T2Timeout {
		return ErrTimeoutRequest
	}
	owned, err := cloneProof(irChReq)
	if err != nil {
		return fmt.Errorf("%w: copying the proof: %w", drctypes.ErrInvalidRequest, err)
	}
	vr, err := ver.VerifyIRChangeReqView(view, owned)
	if err != nil {
		return fmt.Errorf("ir change request verification: %w", err)
	}
	psID := types.PartitionShardID{PartitionID: owned.Partition, ShardID: owned.Shard.Key()}
	next := &irChange{InputRecord: vr.IR, Reason: owned.CertReason, Req: owned, viewKey: vr.ViewKey, assignKey: view.AssignmentKey(),
		roundTag: view.RoundTag(), proofDigest: vr.ProofDigest}
	if old, found := x.irChgReqBuffer[psID]; found {
		if old.stale(next) {
			x.log.Debug("stale IR change request retired", logger.Shard(owned.Partition, owned.Shard))
			delete(x.irChgReqBuffer, psID)
		} else {
			if old.Reason != next.Reason {
				return fmt.Errorf("%w for partition %s, reason has changed", ErrEquivocation, psID.PartitionID)
			}
			if b, err := types.EqualIR(old.InputRecord, next.InputRecord); b || err != nil {
				if err != nil {
					return fmt.Errorf("failed to compare IRs: %w", err)
				}
				x.log.Debug("duplicate IR change request, ignored", logger.Shard(owned.Partition, owned.Shard))
				return nil
			}
			return fmt.Errorf("%w for partition %s-%s", ErrEquivocation, owned.Partition, owned.Shard)
		}
	}
	x.irChgReqBuffer[psID] = next
	return nil
}

// stale reports whether the entry was judged under another assignment, shard round or anchor than other. An untagged entry
// (legacy dispatch) is never stale by this comparison.
func (c *irChange) stale(other *irChange) bool {
	return !bytes.Equal(c.assignKey, other.assignKey) || c.roundTag != other.roundTag
}

func cloneProof(req *drctypes.IRChangeReq) (*drctypes.IRChangeReq, error) {
	raw, err := types.Cbor.Marshal(req)
	if err != nil {
		return nil, err
	}
	out := new(drctypes.IRChangeReq)
	if err := types.Cbor.Unmarshal(raw, out); err != nil {
		return nil, err
	}
	return out, nil
}

// GeneratePayloadView is GeneratePayload for the proposal of the given round under views. The target is resolved for every
// buffered shard and the surviving entries are verified again under it: a proof of another assignment, shard round or anchor,
// one that is no longer eligible, or one whose pending state changed, is discarded and neither enters the payload nor
// suppresses a timeout. Only freshly verified entries do. If a view cannot be resolved the proposal is not generated: the error
// is returned, the buffer is left as it was, and no timeout is dropped or old state substituted.
func (x *IrReqBuffer) GeneratePayloadView(round uint64, timeouts []*types.UnicityCertificate, inProgress InProgressFn,
	res ViewResolver, ver ViewVerifier) (*drctypes.Payload, error) {
	eligible := make(map[types.PartitionShardID]*irChange, len(x.irChgReqBuffer))
	var stale []types.PartitionShardID
	for psID, entry := range x.irChgReqBuffer {
		view, err := res.ResolveView(entry.Req.Partition, entry.Req.Shard, round, storage.PurposeCertify)
		if err != nil {
			return nil, fmt.Errorf("resolving the view of %s-%s for round %d: %w", entry.Req.Partition, entry.Req.Shard, round, err)
		}
		if _, err := ver.VerifyIRChangeReqView(view, entry.Req); err != nil {
			x.log.Debug("buffered IR change request is no longer eligible, discarded", logger.Shard(entry.Req.Partition, entry.Req.Shard), logger.Error(err))
			stale = append(stale, psID)
			continue
		}
		eligible[psID] = entry
	}
	payload := &drctypes.Payload{Requests: make([]*drctypes.IRChangeReq, 0, len(eligible)+len(timeouts))}
	for _, uc := range timeouts {
		if uc == nil || (x.profile == 2 && uc.GetPartitionID() == drctypes.ControlPartition) {
			continue
		}
		pID, sID := uc.GetPartitionID(), uc.GetShardID()
		if _, ok := eligible[types.PartitionShardID{PartitionID: pID, ShardID: sID.Key()}]; ok || inProgress(pID, sID) != nil {
			x.log.Debug(fmt.Sprintf("T2 timeout request ignored, partition %s has pending change in progress", pID), logger.Shard(pID, sID))
			continue
		}
		payload.Requests = append(payload.Requests, &drctypes.IRChangeReq{Partition: pID, Shard: sID, CertReason: drctypes.T2Timeout})
	}
	for _, entry := range eligible {
		if inProgress(entry.Req.Partition, entry.Req.Shard) != nil {
			x.log.Debug(fmt.Sprintf("partition %s request ignored, pending change in pipeline", entry.Req.Partition), logger.Shard(entry.Req.Partition, entry.Req.Shard))
			continue
		}
		payload.Requests = append(payload.Requests, entry.Req)
	}
	clear(x.irChgReqBuffer)
	return payload, nil
}
