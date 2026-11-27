package consensus

import (
	"context"
	"slices"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

const (
	// maxRetirementsPerBlock bounds the Retirements the proposer adds to one block, maxRetirementTrials the trial executions it spends on them.
	maxRetirementsPerBlock = 4
	maxRetirementTrials    = 4
)

// SetRetirementProposer attaches the Retirement builder before consensus starts.
func (x *ConsensusManager) SetRetirementProposer(rp storage.RetirementProposer) {
	x.blockStore().PosServices().Retirements = rp
}

// retirementProposer is the automated Retirement builder, nil when disabled.
func (x *ConsensusManager) retirementProposer() storage.RetirementProposer {
	if svc := x.blockStore().PosServices(); svc != nil {
		return svc.Retirements
	}
	return nil
}

// prepareRetirements is called when a block has been added to the tree: it is the candidate parent of the next proposal, so the proofs of the
// pending Retirement requests are collected against the EVM state it certified, off the consensus loop. It never blocks and never fails the
// block: a Retirement that is not ready when the next leader proposes is simply left for a later parent.
func (x *ConsensusManager) prepareRetirements(ctx context.Context, block *drctypes.BlockData) {
	rp := x.retirementProposer()
	if rp == nil || block == nil {
		return
	}
	parent, ok, err := x.blockStore().RetirementParent(block.Round, block.Round+1)
	if err != nil {
		x.log.DebugContext(ctx, "no retirement parent", "round", block.Round, "error", err)
		return
	}
	if ok {
		rp.Prepare(parent)
	}
}

// forgetOrderedRetirements ends the requests a committed block has ordered.
func (x *ConsensusManager) forgetOrderedRetirements() {
	if rp := x.retirementProposer(); rp != nil {
		forgetOrdered(rp, x.blockStore().RetirementCommitted)
	}
}

func forgetOrdered(rp storage.RetirementProposer, committed func(id, generation uint64) bool) {
	for _, k := range rp.Pending() {
		if committed(k.ID, k.Generation) {
			rp.Ordered(k.ID, k.Generation)
		}
	}
}

// orderRetirements adds the prepared Retirements for exactly this proposal's parent to the block, after the mandatory closures and the
// submitted controls. Each one is stamped with the block's position, its witness retained (the proposer's own validation reads it back by
// hash) and the whole block trial-executed: a Retirement the root state refuses (liability anchor not yet reached, a handoff in flight, the
// record cap) is left out of this proposal and never blocks it. Nothing here is a condition of the proposal.
func (x *ConsensusManager) orderRetirements(ctx context.Context, block *drctypes.BlockData, parentRound uint64) {
	rp := x.retirementProposer()
	if rp == nil {
		return
	}
	x.orderRetirementsWith(ctx, block, parentRound, rp, func(b *drctypes.BlockData) error { return x.blockStore().TrialExecute(b, x.irReqVerifier) })
}

func (x *ConsensusManager) orderRetirementsWith(ctx context.Context, block *drctypes.BlockData, parentRound uint64, rp storage.RetirementProposer,
	trialExecute func(*drctypes.BlockData) error) {
	parent, ok, err := x.blockStore().RetirementParent(parentRound, block.Round)
	if err != nil || !ok {
		return
	}
	x.addRetirements(ctx, block, parentRound, parent, rp, trialExecute)
}

// addRetirements is orderRetirementsWith once the parent's tuple is known.
func (x *ConsensusManager) addRetirements(ctx context.Context, block *drctypes.BlockData, parentRound uint64, parent storage.EVMParent,
	rp storage.RetirementProposer, trialExecute func(*drctypes.BlockData) error) {
	trials := 0
	added := 0
	for _, p := range rp.Ready(parent, maxRetirementsPerBlock) {
		if added == maxRetirementsPerBlock || trials == maxRetirementTrials || len(block.Payload.PosControls) >= drctypes.MaxPosControls {
			return
		}
		if x.blockStore().RetirementOrdered(parentRound, p.ID, p.Generation) {
			continue // this branch already ordered it: committing is a few rounds away
		}
		if slices.ContainsFunc(block.Payload.PosControls, func(c drctypes.PosControl) bool {
			return c.Op == drctypes.OpRetirement && c.RetirementKey() == p.Control.RetirementKey()
		}) {
			continue // an operator submitted the same one
		}
		trials++
		if err := x.blockStore().StoreWitness(p.Witness); err != nil {
			x.log.WarnContext(ctx, "retirement witness not retained", "id", p.ID, "generation", p.Generation, "error", err)
			continue
		}
		c := p.Control
		c.OrderingEpoch, c.OrderingRound = block.Epoch, block.Round
		trial := *block
		payload := *block.Payload
		payload.PosControls = insertRetirement(payload.PosControls, c)
		trial.Payload = &payload
		if err := trialExecute(&trial); err != nil {
			x.log.InfoContext(ctx, "retirement left out of this proposal: the root state refuses it", "id", p.ID, "generation", p.Generation, "error", err)
			continue
		}
		block.Payload = trial.Payload
		added++
	}
}

// insertRetirement places the control after closures and rejections and before rule support, PoP requests and handoff views.
func insertRetirement(controls []drctypes.PosControl, c drctypes.PosControl) []drctypes.PosControl {
	out := append([]drctypes.PosControl(nil), controls...)
	key := c.RetirementKey()
	for i, o := range out {
		switch o.Op {
		case drctypes.OpRetirement:
			k := o.RetirementKey()
			if slices.Compare(k[:], key[:]) > 0 {
				return slices.Insert(out, i, c)
			}
		case drctypes.OpRuleSupport, drctypes.OpPoPRequest, drctypes.OpHandoffView:
			return slices.Insert(out, i, c)
		}
	}
	return append(out, c)
}
