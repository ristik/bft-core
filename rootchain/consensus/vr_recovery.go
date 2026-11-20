package consensus

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The VR exact-recovery proposal path (#1221).
//
// A VR chain orders the records of its ordinary primaries from the verified view certificate (vrRecordsForRound, Freeze v5). When such a
// primary has committed and the successor J' does not acknowledge it, the only way back is the exact recovery to K, which carries no fresh
// proofs and no readiness (H3 supersession, VR design 8.2-8.3). The root already validates and projects it; this file is the missing
// proposer. A root operator asks for it (the plan endpoint, PlanVRRecovery) and every root holds the same unsigned plan as its intent,
// exactly as for any V3 handoff. The leader then orders the Prepare for that intent, J''s current ROOT quorum endorses it (the unchanged
// endorsement precondition), and the Freeze v3 companion (KindRecovery, exact K) and H follow through the same code as a non-VR chain.
//
// Nothing here is consensus: the request is a volatile local intent, the eligibility is re-judged from the parent block at every
// proposal, and a recovery the chain no longer needs (J' acknowledged first) is dropped. There is no timer.

// ErrVRRecoveryIneligible reports a recovery request the committed state does not support.
var ErrVRRecoveryIneligible = errors.New("VR recovery: not eligible")

// recoveryEligible is the pure eligibility rule: the candidate is the exact recovery of the committed, unacknowledged primary of lctx, K
// is the retained authorization's committee, and the one permitted recovery is unused.
func recoveryEligible(c evmassign.Candidate, lctx evmassign.LifecycleContext, installed *types.PartitionDescriptionRecord) error {
	if c.Kind != evmassign.KindRecovery {
		return fmt.Errorf("%w: the candidate is not a recovery", ErrVRRecoveryIneligible)
	}
	if lctx.Pending == 0 || lctx.Head == nil {
		return fmt.Errorf("%w: no committed unacknowledged primary", ErrVRRecoveryIneligible)
	}
	if lctx.CommittedRecoveries != 0 {
		return fmt.Errorf("%w: %w", ErrVRRecoveryIneligible, evmassign.ErrRecoveryUsed)
	}
	lc, _, _, _, err := evmassign.DeriveRecovery(*lctx.Head, installed)
	if err != nil {
		return errors.Join(ErrVRRecoveryIneligible, err)
	}
	want, err := evmassign.IdentitiesDigest(lc.Identities)
	if err != nil {
		return errors.Join(ErrVRRecoveryIneligible, err)
	}
	got, err := evmassign.IdentitiesDigest(c.Identities)
	if err != nil {
		return errors.Join(ErrVRRecoveryIneligible, err)
	}
	if want != got || !bytes.Equal(lc.ReplacedAssignment, c.ReplacedAssignment) {
		return fmt.Errorf("%w: the candidate is not the one derived from the committed primary", ErrVRRecoveryIneligible)
	}
	if err := evmassign.VerifyLifecycle(c, lctx); err != nil {
		return errors.Join(ErrVRRecoveryIneligible, err)
	}
	return nil
}

// designatedEVMShardAt is the unique EVM shard of a block's state, with its installed configuration.
func (x *ConsensusManager) designatedEVMShardAt(parent *storage.ExecutedBlock) (*storage.ShardInfo, *types.PartitionDescriptionRecord, error) {
	configs, err := x.orchestration.ShardConfigs(parent.GetRound())
	if err != nil {
		return nil, nil, err
	}
	var found *storage.ShardInfo
	var conf *types.PartitionDescriptionRecord
	for key, si := range parent.ShardState.States {
		c := configs[key]
		if si == nil || si.IR == nil || c == nil || c.PartitionTypeID != storage.EVMPartitionTypeID {
			continue
		}
		if found != nil {
			return nil, nil, ErrHandoffApproval
		}
		found, conf = si, c
	}
	if found == nil {
		return nil, nil, ErrHandoffApproval
	}
	return found, conf, nil
}

// vrRecoveryEligibleAt judges the held plan's candidate against the committed block the Prepare would be ordered on.
func (x *ConsensusManager) vrRecoveryEligibleAt(parent *storage.ExecutedBlock, c evmassign.Candidate) error {
	si, installed, err := x.designatedEVMShardAt(parent)
	if err != nil {
		return errors.Join(ErrVRRecoveryIneligible, err)
	}
	if si.TR.Epoch == si.IR.Epoch {
		return fmt.Errorf("%w: the pending assignment is acknowledged", ErrVRRecoveryIneligible)
	}
	lctx, err := storage.LifecycleFor(x.orchestration, si.PartitionID, si.ShardID, si.IR.Epoch, installed)
	if err != nil {
		return errors.Join(ErrVRRecoveryIneligible, err)
	}
	return recoveryEligible(c, lctx, installed)
}

// isRecoveryPlan reports whether a plan's candidate preimage is an exact recovery.
func isRecoveryPlan(plan abdrc.HandoffApprovalMsg) (evmassign.Candidate, bool) {
	if len(plan.CandidatePreimage) == 0 {
		return evmassign.Candidate{}, false
	}
	c, err := evmassign.DecodeCandidate(plan.CandidatePreimage)
	if err != nil || c.Kind != evmassign.KindRecovery {
		return evmassign.Candidate{}, false
	}
	return c, true
}

// dropRecoveryIntent forgets the held intent when it is a recovery of attempt (the pending condition is gone, or it was never eligible).
func (x *ConsensusManager) dropRecoveryIntent(checked abdrc.HandoffApprovalMsg) {
	x.handoffMu.Lock()
	defer x.handoffMu.Unlock()
	// only the instance that was judged: a replacement request that arrived meanwhile is kept
	if in := x.handoffIntent; in != nil && in.Attempt == checked.Attempt && bytes.Equal(in.Candidate, checked.Candidate) && bytes.Equal(in.Body, checked.Body) {
		if _, ok := isRecoveryPlan(*in); ok {
			x.handoffIntent = nil
		}
	}
}

// heldRecoveryBody reports whether the Prepare in the control state is the one of a recovery plan this root holds (with endorsements:
// the intent is retired when its Prepare commits): the Freeze and H of that Prepare follow the exact-recovery path. A root that lost the plan (a restart) orders nothing
// for it, and the Prepare lapses; the operator requests again.
func (x *ConsensusManager) heldRecoveryBody(control *evmroot.ControlState) bool {
	previous, err := storage.DecodeOrderedHandoffRecord(control.RecordBytes)
	if err != nil {
		return false
	}
	x.handoffMu.Lock()
	defer x.handoffMu.Unlock()
	for _, p := range x.handoffPlans {
		if bytes.Equal(p.body.id[:], previous.NextBodyID) && p.plan.Attempt == previous.Attempt {
			_, ok := isRecoveryPlan(p.plan)
			return ok
		}
	}
	return false
}

// vrRecoveryIntentOK is the check the Prepare branch repeats on the intent it loads itself: on a VR chain only an eligible recovery plan is
// ordered there, whatever replaced the intent since vrRecoveryRoute judged it.
func (x *ConsensusManager) vrRecoveryIntentOK(parent *storage.ExecutedBlock, intent abdrc.HandoffApprovalMsg) bool {
	c, ok := isRecoveryPlan(intent)
	if !ok {
		return false
	}
	eligible := x.vrRecoveryEligibleAt
	if x.vr != nil && x.vr.recoveryEligible != nil {
		eligible = x.vr.recoveryEligible
	}
	return eligible(parent, c) == nil
}

// vrRecoveryRoute says whether the leader orders the records of a VR chain's round from a held exact-recovery plan instead of the verified
// view certificate. Before a Prepare it re-judges the plan at the parent block (a committed, unacknowledged primary on this P, the one
// recovery unused, K from the retained authorization, the successor derived by DeriveRecovery) and drops a plan that is no longer
// eligible; once the Prepare is committed the EVM is frozen and the plan the Prepare names carries on.
func (x *ConsensusManager) vrRecoveryRoute(parent *storage.ExecutedBlock, control *evmroot.ControlState, round uint64) bool {
	if control == nil {
		return false
	}
	lapsed := storage.PrepareLapsed(control, round)
	switch {
	case control.Phase == "endorsed", control.Phase == "prepared" && !lapsed:
		held := x.heldRecoveryBody(control)
		if held {
			x.log.Info("VR recovery: the leader follows the exact recovery", "round", round, "phase", control.Phase, "attempt", control.Attempt)
		}
		return held
	case control.Phase != "idle" && control.Phase != "aborted" && !lapsed:
		return false
	}
	attempt := uint64(0)
	if control.Phase != "idle" {
		if control.Attempt == ^uint64(0) {
			return false
		}
		attempt = control.Attempt + 1
	}
	intent := x.pendingIntent(attempt)
	if intent == nil {
		return false
	}
	c, ok := isRecoveryPlan(*intent)
	if !ok {
		return false
	}
	eligible := x.vrRecoveryEligibleAt
	if x.vr != nil && x.vr.recoveryEligible != nil {
		eligible = x.vr.recoveryEligible
	}
	if err := eligible(parent, c); err != nil {
		x.log.Info("VR recovery: the request is dropped", "round", round, "attempt", attempt, "reason", err)
		x.dropRecoveryIntent(*intent)
		return false
	}
	x.log.Info("VR recovery: the leader orders the Prepare of the exact recovery", "round", round, "attempt", attempt)
	return true
}

// PlanVRRecovery is the operator request for the exact recovery of the committed, unacknowledged primary of a VR chain: it derives the
// plan (the successor committee is K of the retained authorization; nothing is chosen by the caller) and registers it as this root's
// intent, like PlanHandoffV3. The operator hands the returned plan to every root (AcceptHandoffIntent) and, once the Prepare is
// committed, has each endorse it (EndorseHandoff), unchanged from any V3 handoff. It refuses when no recovery is eligible now.
func (x *ConsensusManager) PlanVRRecovery() (abdrc.HandoffApprovalMsg, error) {
	var out abdrc.HandoffApprovalMsg
	err := x.operator(func() (err error) {
		out, err = x.opPlanVRRecovery()
		return err
	})
	return out, err
}

func (x *ConsensusManager) opPlanVRRecovery() (abdrc.HandoffApprovalMsg, error) {
	if x.vr == nil {
		return abdrc.HandoffApprovalMsg{}, fmt.Errorf("%w: not enabled", ErrVRHandoff)
	}
	state, err := x.blockStore().GetState()
	if err != nil {
		return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
	}
	return x.planVRRecoveryAt(state)
}

// planVRRecoveryAt is PlanVRRecovery against a given committed state.
func (x *ConsensusManager) planVRRecoveryAt(state *abdrc.StateMsg) (abdrc.HandoffApprovalMsg, error) {
	if state == nil || state.CommittedHead == nil || state.CommittedHead.Block == nil {
		return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
	}
	old := x.trustBase.Load()
	if old == nil || old.Epoch == ^uint64(0) {
		return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
	}
	shard, installed, err := x.installedEVMFromState(state, nil, true)
	if err != nil {
		return abdrc.HandoffApprovalMsg{}, err
	}
	if !pendingAssignmentAck(shard) {
		return abdrc.HandoffApprovalMsg{}, errors.Join(ErrVRHandoff, ErrVRRecoveryIneligible, errors.New("no unacknowledged primary"))
	}
	lctx, err := storage.LifecycleFor(x.orchestration, shard.Partition, shard.Shard, shard.IR.Epoch, installed)
	if err != nil || lctx.Head == nil || lctx.Head.Candidate.Authorization == nil {
		return abdrc.HandoffApprovalMsg{}, errors.Join(ErrVRHandoff, ErrVRRecoveryIneligible, err)
	}
	if lctx.CommittedRecoveries != 0 {
		return abdrc.HandoffApprovalMsg{}, errors.Join(ErrVRHandoff, ErrVRRecoveryIneligible, evmassign.ErrRecoveryUsed)
	}
	// the successor root committee is exactly K (identities, keys, effective weights) at the next root epoch
	next := *old
	next.Epoch = old.Epoch + 1
	next.RootNodes = make([]*types.NodeInfo, 0, len(lctx.Head.Candidate.Authorization.K))
	for _, id := range lctx.Head.Candidate.Authorization.K {
		next.RootNodes = append(next.RootNodes, &types.NodeInfo{NodeID: id.RootNodeID, SigKey: bytes.Clone(id.RootKey), Stake: id.Weight})
	}
	plan, err := x.buildHandoffPlanV3FromState(&next, state, &evmassign.Proposal{Kind: evmassign.KindRecovery, Supersede: true}, nil)
	if err != nil {
		return abdrc.HandoffApprovalMsg{}, err
	}
	c, ok := isRecoveryPlan(plan)
	if !ok {
		return abdrc.HandoffApprovalMsg{}, errors.Join(ErrVRHandoff, ErrVRRecoveryIneligible)
	}
	if err := recoveryEligible(c, lctx, installed); err != nil {
		return abdrc.HandoffApprovalMsg{}, errors.Join(ErrVRHandoff, err)
	}
	x.setHandoffIntent(plan)
	return plan, nil
}
