package consensus

import (
	"context"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// retainedRequest is the aggregated request of one shard an ingress root holds until the verifier says it is stale (#886 S3). A forward lost
// with a dying round is sent again at the next: T2 being a multiple of the leader cycle otherwise brings every shard retry to the same
// losing phase. It is separate from the proposal buffer, which a proposal clears: neither a transport acknowledgement nor inclusion in an
// uncommitted proposal is a reason to let go of it.
type retainedRequest struct {
	msg    *abdrc.IrChangeReqMsg // signed once: every send carries the shard's proof byte for byte
	sentAt uint64                // the last round it was sent or buffered in: one send per entry per round
}

type retainedVerdict int

const (
	retainedValid retainedVerdict = iota
	// retainedUnknown is a request that cannot be judged right now, or one in the way of a pending change: kept.
	retainedUnknown
	retainedStale
)

// judgeRetained asks the verifier about a request against the current authenticated state. Only a verdict on the request itself lets go of
// it: the view-aware branch's stale context, or a refusal by the legacy verifier with the shard's state in hand. A view that cannot be
// resolved, a state that is not there yet and a change pending in the pipeline say nothing about the request.
func (x *ConsensusManager) judgeRetained(req *drctypes.IRChangeReq) (retainedVerdict, error) {
	round := x.pacemaker.GetCurrentRound() + 1
	if err := x.refuseFrozenIR(req); err != nil {
		return retainedStale, err
	}
	if x.viewResolver == nil {
		_, err := x.irReqVerifier.VerifyRequest(round, req)
		switch {
		case err == nil:
			return retainedValid, nil
		case errors.Is(err, ErrRequestStateUnavailable):
			return retainedUnknown, err
		}
		return retainedStale, err
	}
	view, err := x.viewResolver.ResolveView(req.Partition, req.Shard, round, storage.PurposeCertify)
	if err != nil {
		return retainedUnknown, err
	}
	_, err = x.irReqVerifier.VerifyIRChangeReqView(view, req)
	return viewVerdict(err), err
}

// viewVerdict reads the view-aware verifier: only a stale context is a verdict on the request. A change pending in the pipeline, its own
// among them while it sits in an uncommitted proposal, is why the copy exists.
func viewVerdict(err error) retainedVerdict {
	switch {
	case err == nil:
		return retainedValid
	case errors.Is(err, storage.ErrStaleRequestContext):
		return retainedStale
	}
	return retainedUnknown
}

// retainRequest takes a verified shard request into retention and sends it. The first valid request of a shard stays until it is stale: a
// different one is not a reason to replace it, as IrReqBuffer does not.
func (x *ConsensusManager) retainRequest(ctx context.Context, req *drctypes.IRChangeReq) error {
	verdict, err := x.judgeRetained(req)
	if verdict == retainedStale {
		return fmt.Errorf("IR change request from partition %s: %w", req.Partition, err)
	}
	key := types.PartitionShardID{PartitionID: req.Partition, ShardID: req.Shard.Key()}
	if old, found := x.retained[key]; found {
		if v, _ := x.judgeRetained(old.msg.IrChangeReq); v != retainedStale {
			if sameRequest(old.msg.IrChangeReq, req) {
				return nil // duplicates of the held request: the next round sends it anyway
			}
			return fmt.Errorf("%w for partition %s-%s: a valid request is held", ErrEquivocation, req.Partition, req.Shard)
		}
	}
	msg := &abdrc.IrChangeReqMsg{Author: x.id.String(), IrChangeReq: req}
	if err := x.safety.Sign(x.trustBase.Load().Epoch, msg); err != nil {
		return fmt.Errorf("failed to sign IR change request from partition %s: %w", req.Partition, err)
	}
	entry := &retainedRequest{msg: msg}
	if x.retained == nil {
		x.retained = make(map[types.PartitionShardID]*retainedRequest)
	}
	x.retained[key] = entry
	x.sendRetained(ctx, key, entry)
	return nil
}

func sameRequest(a, b *drctypes.IRChangeReq) bool {
	if a.CertReason != b.CertReason || len(a.Requests) != len(b.Requests) {
		return false
	}
	for i := range a.Requests {
		if same, err := types.EqualIR(a.Requests[i].InputRecord, b.Requests[i].InputRecord); err != nil || !same {
			return false
		}
	}
	return true
}

// forwardRetained is the round-change half of retention: drop what the verifier says is stale, send the rest toward the known next leader.
func (x *ConsensusManager) forwardRetained(ctx context.Context) {
	for key, entry := range x.retained {
		verdict, err := x.judgeRetained(entry.msg.IrChangeReq)
		if verdict == retainedStale {
			x.log.DebugContext(ctx, "retained IR change request is stale, dropped", logger.Shard(entry.msg.IrChangeReq.Partition, entry.msg.IrChangeReq.Shard), logger.Error(err))
			delete(x.retained, key)
			continue
		}
		x.sendRetained(ctx, key, entry)
	}
}

// sendRetained sends the entry to the next leader, or buffers it if that is this node. An unknown next leader leaves it for a later round.
func (x *ConsensusManager) sendRetained(ctx context.Context, key types.PartitionShardID, entry *retainedRequest) {
	round := x.pacemaker.GetCurrentRound()
	if entry.sentAt == round {
		return
	}
	next, err := x.leaderAfter(round)
	if err != nil {
		if !errors.Is(err, drctypes.ErrHistoryUnavailable) {
			x.log.WarnContext(ctx, "no next leader for a retained IR change request", logger.Error(err))
		}
		return
	}
	entry.sentAt = round
	req := entry.msg.IrChangeReq
	if next == x.id {
		if err := x.bufferIRChange(req); err != nil && !errors.Is(err, ErrDuplicateChangeReq) {
			x.log.DebugContext(ctx, "retained IR change request not buffered", logger.Shard(req.Partition, req.Shard), logger.Error(err))
		}
		return
	}
	if err := x.net.Send(ctx, entry.msg, next); err != nil {
		x.log.WarnContext(ctx, "failed to send a retained IR change request", logger.Shard(req.Partition, req.Shard), logger.Error(err))
		return
	}
	x.log.DebugContext(ctx, fmt.Sprintf("IR change request forwarded to %s", next.ShortString()), logger.Shard(req.Partition, req.Shard))
}
