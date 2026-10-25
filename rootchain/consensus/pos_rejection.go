package consensus

import (
	"context"
	"slices"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The automatic RejectResult of an abandoned election result (contracts#73, briefs/73-reject-result-design.md). Every root with the
// election deployment runs the rejection builder (rootchain/posreject): it discovers the open result at each candidate parent and, once the
// result is due, offers the control to every root through the signed submission path and to its own proposals. The leader orders a ready,
// valid rejection at a quiet proposal opportunity, before a fresh Prepare: otherwise the automatic handoff planner could keep starving it.
// None of this is a validity rule; every voter judges the control by the full rule.

// rejectionProposer is the RejectResult builder of this chain's P85 services, nil when it has none.
func (x *ConsensusManager) rejectionProposer() storage.RejectProposer {
	if svc := x.blockStore.PosServices(); svc != nil {
		return svc.Rejections
	}
	return nil
}

// prepareRejection is called when a block has been added to the tree: it is the candidate parent of the next proposal, so the open result
// is looked at against the EVM state it certified, off the consensus loop. It never blocks and never fails the block.
func (x *ConsensusManager) prepareRejection(ctx context.Context, block *drctypes.BlockData) {
	rp := x.rejectionProposer()
	if rp == nil || block == nil {
		return
	}
	rc, ok, err := x.blockStore.RejectionParent(block.Round, block.Round+1)
	if err != nil {
		x.log.DebugContext(ctx, "no rejection parent", "round", block.Round, "error", err)
		return
	}
	if ok {
		rp.Prepare(rc)
	}
}

// forgetResolvedRejections ends the rejections of the results a committed block has resolved (by this rejection or otherwise): nothing more is
// proposed for them, even before the EVM imports the record.
func (x *ConsensusManager) forgetResolvedRejections() {
	rp := x.rejectionProposer()
	if rp == nil {
		return
	}
	for _, id := range rp.Pending() {
		if x.blockStore.RejectionCommitted(id) {
			rp.Resolved(id)
		}
	}
}

// readyRejection is this root's prepared rejection for the child of parentRound proposed at round, unless the branch has resolved it already.
func (x *ConsensusManager) readyRejection(parentRound, round uint64) (storage.PreparedRejection, bool) {
	rp := x.rejectionProposer()
	if rp == nil {
		return storage.PreparedRejection{}, false
	}
	rc, ok, err := x.blockStore.RejectionParent(parentRound, round)
	if err != nil || !ok {
		return storage.PreparedRejection{}, false
	}
	p, ok := rp.Ready(rc)
	if !ok || x.blockStore.RejectionResolved(parentRound, p.ResultID) {
		return storage.PreparedRejection{}, false
	}
	return p, true
}

// rejectionCandidates are the RejectResult controls a proposal at round on parentRound may order, this root's own first and then the
// submitted ones whose witness is held here, each with its witness retained.
func (x *ConsensusManager) rejectionCandidates(ctx context.Context, parentRound, round uint64) []drctypes.PosControl {
	var out []drctypes.PosControl
	if p, ok := x.readyRejection(parentRound, round); ok {
		if err := x.blockStore.StoreWitness(p.Witness); err != nil {
			x.log.WarnContext(ctx, "rejection witness not retained", "error", err)
		} else {
			out = append(out, p.Control)
		}
	}
	for _, s := range x.posQueue.pending(x.pacemaker.GetCurrentRound()) {
		if s.control.Op == drctypes.OpRejectResult && x.blockStore.HasWitness(s.witness) {
			out = append(out, s.control)
		}
	}
	return out
}

// orderRejection adds a RejectResult to the proposal, after the mandatory closures and before any Retirement, if one is ready and the root
// state accepts it in this very block (trial execution). A proposal that orders a handoff record takes none: the executor applies the record
// first, and a live handoff is protected.
func (x *ConsensusManager) orderRejection(ctx context.Context, block *drctypes.BlockData, parentRound uint64) bool {
	return x.orderRejectionWith(ctx, block, parentRound, func(b *drctypes.BlockData) error { return x.blockStore.TrialExecute(b, x.irReqVerifier) })
}

func (x *ConsensusManager) orderRejectionWith(ctx context.Context, block *drctypes.BlockData, parentRound uint64, trialExecute func(*drctypes.BlockData) error) bool {
	if len(block.Payload.HandoffRecords) != 0 || len(block.Payload.PosControls) >= drctypes.MaxPosControls ||
		slices.ContainsFunc(block.Payload.PosControls, func(c drctypes.PosControl) bool { return c.Op == drctypes.OpRejectResult }) {
		return false
	}
	return x.addRejection(ctx, block, x.rejectionCandidates(ctx, parentRound, block.Round), trialExecute)
}

// addRejection is orderRejectionWith once the candidates are known: the first one the whole block accepts in a trial execution is placed.
func (x *ConsensusManager) addRejection(ctx context.Context, block *drctypes.BlockData, candidates []drctypes.PosControl, trialExecute func(*drctypes.BlockData) error) bool {
	for i, c := range candidates {
		if i == maxPosTrials {
			return false
		}
		c.OrderingEpoch, c.OrderingRound = block.Epoch, block.Round
		trial := *block
		payload := *block.Payload
		payload.PosControls = insertRejection(payload.PosControls, c)
		trial.Payload = &payload
		if err := trialExecute(&trial); err != nil {
			x.log.InfoContext(ctx, "rejection left out of this proposal: the root state refuses it", "error", err)
			continue
		}
		block.Payload = trial.Payload
		return true
	}
	return false
}

// preferRejection reports whether a ready rejection would be valid in a child of parentRound at round that orders no handoff record: an
// honest leader then orders it before starting another unsigned Prepare. Only a rejection the root state accepts in this very round wins, so
// a rejection that is not valid can never hold a Prepare back.
func (x *ConsensusManager) preferRejection(ctx context.Context, parentRound, round uint64, parentQC *drctypes.QuorumCert) bool {
	return x.preferRejectionWith(ctx, parentRound, round, parentQC, func(b *drctypes.BlockData) error { return x.blockStore.TrialExecute(b, x.irReqVerifier) })
}

func (x *ConsensusManager) preferRejectionWith(ctx context.Context, parentRound, round uint64, parentQC *drctypes.QuorumCert, trialExecute func(*drctypes.BlockData) error) bool {
	if x.rejectionProposer() == nil && x.posQueue.len() == 0 {
		return false
	}
	parent, err := x.blockStore.Block(parentRound)
	if err != nil {
		return false
	}
	closures, err := x.blockStore.ClosureControls(parentRound, x.trustBase.Load().Epoch, round)
	if err != nil {
		return false
	}
	block := &drctypes.BlockData{Version: types.Version(storage.ProfileHandoff), Author: x.id.String(), Round: round, Epoch: x.trustBase.Load().Epoch,
		Timestamp: proposalTimestamp(types.NewTimestamp(), parent.BlockData.Timestamp),
		Payload:   &drctypes.Payload{Version: storage.ProfileHandoff, PosControls: closures}, Qc: parentQC}
	if x.orderRejectionWith(ctx, block, parentRound, trialExecute) {
		x.log.InfoContext(ctx, "a due election result is rejected before a fresh Prepare is ordered", "round", round)
		return true
	}
	return false
}

// insertRejection returns the controls with the RejectResult placed after every CloseLiability and before every Retirement, the only order
// the payload accepts.
func insertRejection(controls []drctypes.PosControl, c drctypes.PosControl) []drctypes.PosControl {
	at := len(controls)
	for i, o := range controls {
		if o.Op != drctypes.OpCloseLiability {
			at = i
			break
		}
	}
	return slices.Insert(append([]drctypes.PosControl(nil), controls...), at, c)
}
