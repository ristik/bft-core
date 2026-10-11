package consensus

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ErrDuplicateChangeReq is shared with the storage view verifier, so both refuse with one identity.
var ErrDuplicateChangeReq = storage.ErrDuplicateChangeReq

// ErrProofInvalid refuses an IR change whose carried request has a configured consistency proof that does not hold.
var ErrProofInvalid = errors.New("configured proof of a carried request does not hold")

type (
	State interface {
		ShardInfo(partition types.PartitionID, shard types.ShardID) *storage.ShardInfo
		GetCertificates() []*types.UnicityCertificate
		IsChangeInProgress(id types.PartitionID, shard types.ShardID) *types.InputRecord
	}

	IRChangeReqVerifier struct {
		params *Parameters
		state  State
		// history, when set, selects the view-aware branch (Q2-C). Production leaves it nil: legacy dispatch stays selected.
		history storage.RequestHistory
		// proofs judges the configured consistency proof of every shard request an IR change carries: a voting root does not take the
		// receiving root's word that it held (a Byzantine receiving root could skip its own check)
		proofs     *zkverifier.Registry
		proofsOnce sync.Once
	}

	PartitionTimeoutGenerator struct {
		blockRate time.Duration
		state     State
		profile   uint64
	}
)

func NewIRChangeReqVerifier(c *Parameters, sMonitor State) (*IRChangeReqVerifier, error) {
	if sMonitor == nil {
		return nil, errors.New("state monitor is nil")
	}
	if c == nil {
		return nil, errors.New("consensus params is nil")
	}
	return &IRChangeReqVerifier{
		params: c,
		state:  sMonitor,
	}, nil
}

// SetRequestHistory selects the view-aware branch: requests are judged under views resolved from this committed history.
func (x *IRChangeReqVerifier) SetRequestHistory(h storage.RequestHistory) { x.history = h }

// RequestHistory is the history of the view-aware branch, nil under legacy dispatch.
func (x *IRChangeReqVerifier) RequestHistory() storage.RequestHistory { return x.history }

// PendingChange is the change of the shard in the uncommitted pipeline.
func (x *IRChangeReqVerifier) PendingChange(partition types.PartitionID, shard types.ShardID) *types.InputRecord {
	return x.state.IsChangeInProgress(partition, shard)
}

// VerifyIRChangeReqView judges a proof under the supplied view only: it never reads the last committed ShardInfo, so the
// committed anchor lagging behind an activation cannot select another assignment.
func (x *IRChangeReqVerifier) VerifyIRChangeReqView(view *storage.RequestRoundView, irChReq *drctypes.IRChangeReq) (*storage.VerifiedRequest, error) {
	if view == nil {
		return nil, fmt.Errorf("%w: no request view", drctypes.ErrInvalidRequest)
	}
	if irChReq == nil {
		return nil, fmt.Errorf("IR change request is nil: %w", drctypes.ErrInvalidRequest)
	}
	if x.params.NetworkProfileVersion == 2 && irChReq.Partition == drctypes.ControlPartition {
		return nil, drctypes.ErrControlPartition
	}
	vr, err := view.VerifyIRChangeReq(irChReq, t2TimeoutToRootRounds(view.T2Timeout(), x.params.BlockRate/2))
	if err != nil {
		return nil, err
	}
	pdr, err := view.PDR()
	if err != nil {
		return nil, fmt.Errorf("the PDR of the request view: %w", err)
	}
	target := zkverifier.Target{Partition: irChReq.Partition, Shard: irChReq.Shard, Epoch: view.ExpectedTR().Epoch, Params: pdr.GetPartitionParams()}
	for _, req := range irChReq.Requests {
		if err := x.verifyProof(req, target); err != nil {
			return nil, err
		}
	}
	return vr, nil
}

// verifyProof is the intake's configured-proof check on a request carried by an IR change. The work is bounded: an IR change carries
// at most one request per member (checked before this), and every verifier bounds its own input.
func (x *IRChangeReqVerifier) verifyProof(req *certification.BlockCertificationRequest, target zkverifier.Target) error {
	x.proofsOnce.Do(func() { x.proofs = zkverifier.NewRegistry() })
	if _, err := x.proofs.VerifyRequest(req, target); err != nil {
		return fmt.Errorf("%w: request of %s: %w", ErrProofInvalid, req.NodeID, err)
	}
	return nil
}

func (x *IRChangeReqVerifier) VerifyIRChangeReq(rootRound uint64, irChReq *drctypes.IRChangeReq) (*types.InputRecord, error) {
	if irChReq == nil {
		return nil, fmt.Errorf("IR change request is nil")
	}
	if x.params.NetworkProfileVersion == 2 && irChReq.Partition == drctypes.ControlPartition {
		return nil, drctypes.ErrControlPartition
	}
	// Certify input, everything needs to be verified again as if received from partition node, since we cannot trust the leader is honest.
	// This gets the shardInfo from committed round (for which there is UC), and irChReq should build on that.
	si := x.state.ShardInfo(irChReq.Partition, irChReq.Shard)
	if si == nil {
		// There shouldn't be an IR change request for a shard with no committed state
		return nil, fmt.Errorf("missing shard info for partition %d shard %s", irChReq.Partition, irChReq.Shard.String())
	}

	// verify request
	luc := si.LastCR.UC
	inputRecord, err := irChReq.Verify(si, &luc, rootRound, t2TimeoutToRootRounds(si.T2Timeout, x.params.BlockRate/2))
	if err != nil {
		return nil, fmt.Errorf("certification request verification failed: %w", err)
	}
	// the configured consistency proof of every carried request, as the receiving root checked it
	target := zkverifier.Target{Partition: irChReq.Partition, Shard: irChReq.Shard, Epoch: si.IR.Epoch, Params: si.PartitionParams}
	for _, req := range irChReq.Requests {
		if err := x.verifyProof(req, target); err != nil {
			return nil, err
		}
	}
	// verify that there are no pending changes in the pipeline for any of the updated partitions
	if ir := x.state.IsChangeInProgress(irChReq.Partition, irChReq.Shard); ir != nil {
		if b, err := types.EqualIR(inputRecord, ir); b || err != nil {
			if err != nil {
				return nil, fmt.Errorf("comparing input records: %w", err)
			}
			return nil, ErrDuplicateChangeReq
		}
		return nil, fmt.Errorf("shard %s-%s has pending changes in pipeline", irChReq.Partition, irChReq.Shard)
	}
	// check - should never happen, somehow the root node round must have been reset
	if rootRound < luc.UnicitySeal.RootChainRoundNumber {
		return nil, fmt.Errorf("current round %v is in the past, LUC round %v", rootRound, luc.UnicitySeal.RootChainRoundNumber)
	}
	return inputRecord, nil
}

func NewLucBasedT2TimeoutGenerator(c *Parameters, sMonitor State) (*PartitionTimeoutGenerator, error) {
	if sMonitor == nil {
		return nil, errors.New("state monitor is nil")
	}
	if c == nil {
		return nil, errors.New("consensus params is nil")
	}
	return &PartitionTimeoutGenerator{
		blockRate: c.BlockRate,
		state:     sMonitor,
		profile:   c.NetworkProfileVersion,
	}, nil
}

func (x *PartitionTimeoutGenerator) GetT2Timeouts(currentRound uint64) ([]*types.UnicityCertificate, error) {
	// Only activated shards with an UC can time out. New shards are activated by adding their ShardInfo and
	// an empty IR to the ExecutedBlock in the activation root round. Once the block gets committed, they
	// get their first UC and can start timing out.
	ucs := x.state.GetCertificates()

	timedOutShards := make([]*types.UnicityCertificate, 0, len(ucs))
	for _, uc := range ucs {
		if x.profile == 2 && (uc == nil || uc.GetPartitionID() == drctypes.ControlPartition) {
			continue
		}
		// do not create T2 timeout requests if shard has a change already in pipeline
		if x.state.IsChangeInProgress(uc.GetPartitionID(), uc.GetShardID()) != nil {
			continue
		}

		si := x.state.ShardInfo(uc.GetPartitionID(), uc.GetShardID())
		lastRootRound := uc.GetRootRoundNumber()
		if currentRound-lastRootRound >= t2TimeoutToRootRounds(si.T2Timeout, x.blockRate/2) {
			timedOutShards = append(timedOutShards, uc)
		}
	}
	return timedOutShards, nil
}

func t2TimeoutToRootRounds(t2Timeout time.Duration, blockRate time.Duration) uint64 {
	return uint64(t2Timeout/blockRate) + 1 /* #nosec G115 its unlikely that t2Timeout/blockRate exceeds uint64 max value */
}

// GetT2TimeoutsView is GetT2Timeouts for the proposal of currentRound with every shard's previous UC, T2 and pending state
// taken from the view resolved for it (purpose timeout), so all shards of one proposal are judged under one snapshot. The
// exclusions are kept: only shards with a UC time out, none with a change in its pipeline, none of the control partition. A
// target round before the previous UC's round is refused before the subtraction. Time is elapsed root rounds only: weights and
// the assignment never enter. A shard whose view cannot be resolved is reported in the returned error and never timed out
// from other state; the rest are still returned.
func (x *PartitionTimeoutGenerator) GetT2TimeoutsView(currentRound uint64, res ViewResolver) ([]*types.UnicityCertificate, error) {
	var errs []error
	ucs := x.state.GetCertificates()
	timedOutShards := make([]*types.UnicityCertificate, 0, len(ucs))
	for _, uc := range ucs {
		if uc == nil {
			continue
		}
		if x.profile == 2 && uc.GetPartitionID() == drctypes.ControlPartition {
			continue
		}
		pID, sID := uc.GetPartitionID(), uc.GetShardID()
		if x.state.IsChangeInProgress(pID, sID) != nil {
			continue
		}
		view, err := res.ResolveView(pID, sID, currentRound, storage.PurposeTimeout)
		if err != nil {
			errs = append(errs, fmt.Errorf("resolving the view of %s-%s for round %d: %w", pID, sID, currentRound, err))
			continue
		}
		if view.HasPendingChange() {
			continue
		}
		prev, err := view.PreviousUC()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		last := prev.GetRootRoundNumber()
		if currentRound < last {
			errs = append(errs, fmt.Errorf("round %d is before the previous UC round %d of %s-%s: %w", currentRound, last, pID, sID, storage.ErrStaleRequestContext))
			continue
		}
		if currentRound-last >= t2TimeoutToRootRounds(view.T2Timeout(), x.blockRate/2) {
			timedOutShards = append(timedOutShards, prev)
		}
	}
	return timedOutShards, errors.Join(errs...)
}
