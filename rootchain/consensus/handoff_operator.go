package consensus

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

var (
	ErrHandoffApproval = errors.New("root handoff: invalid operator approval")
	// ErrEndorseBeforePrepare refuses an endorsement while no Prepare of the planned attempt is in this validator's committed
	// state: validators endorse the state the Prepare froze, never a state they merely expect.
	ErrEndorseBeforePrepare = errors.New("root handoff: endorsement requested before the handoff is prepared")
	// ErrEndorsedParentMismatch refuses an endorsement naming a frozen parent other than the one bound at Prepare.
	ErrEndorsedParentMismatch = errors.New("root handoff: endorsed frozen parent is not the parent bound at Prepare")
	// ErrEndorsedPlanMismatch refuses an endorsement whose body or attempt is not the one the ordered Prepare names.
	ErrEndorsedPlanMismatch = errors.New("root handoff: endorsed plan is not the prepared one")
	// ErrPrepareLapsed refuses an endorsement for a Prepare whose freeze has lapsed: that attempt is dead, and only a plan for the
	// NEXT attempt can still be endorsed (the operator re-plans; it waits for that Prepare like for any other).
	ErrPrepareLapsed = errors.New("root handoff: the Prepare's freeze has lapsed")
	// ErrEndorseAfterFreeze refuses an endorsement once the handoff is already frozen (Freeze ordered) or committed: nothing is left to
	// endorse, and waiting for a Prepare would never end.
	ErrEndorseAfterFreeze    = errors.New("root handoff: the handoff is already frozen or committed")
	ErrHandoffAbortTarget    = errors.New("root handoff abort: target does not match authenticated control state")
	ErrHandoffAbortSignature = errors.New("root handoff abort: invalid old-validator signature")
	ErrHandoffAbortCache     = errors.New("root handoff abort: approval cache full or conflicting")
)

const maxPendingHandoffAborts = 4

type handoffAbortKey struct {
	network, epoch, attempt uint64
	predecessor             [32]byte
}

type pendingHandoffAbort struct {
	target     abdrc.HandoffAbortTarget
	signatures map[string]hex.Bytes
	weight     uint64
}

// SubmitHandoffAbort is the operator-only local signing path. Network peers
// can relay an approval but cannot cause this validator to create one.
func (x *ConsensusManager) SubmitHandoffAbort(ctx context.Context, target abdrc.HandoffAbortTarget) (abdrc.HandoffAbortStatus, error) {
	status, record, err := x.handoffAbortStatus(target)
	if err != nil {
		return abdrc.HandoffAbortStatus{}, err
	}
	if status.State == "committed" {
		return status, nil
	}
	if status.State != "pending" {
		return abdrc.HandoffAbortStatus{}, ErrHandoffAbortTarget
	}
	domain, err := storage.AbortEndorsementBytes(record)
	if err != nil {
		return abdrc.HandoffAbortStatus{}, ErrHandoffAbortTarget
	}
	signature, err := x.safety.signer.SignBytes(domain)
	if err != nil {
		return abdrc.HandoffAbortStatus{}, fmt.Errorf("%w: %v", ErrHandoffAbortSignature, err)
	}
	msg := &abdrc.HandoffAbortApprovalMsg{Network: target.Network, OldEpoch: target.OldEpoch,
		PredecessorBodyID: bytes.Clone(target.PredecessorBodyID), Attempt: target.Attempt,
		NextBodyID: bytes.Clone(target.NextBodyID), Signer: x.id.String(), Signature: signature}
	if err := x.onHandoffAbortApprovalMsg(msg); err != nil {
		return abdrc.HandoffAbortStatus{}, err
	}
	// The local signature is cached before broadcast, so this request remains
	// submitted if peers are temporarily unavailable. Retries are idempotent.
	sendCtx := context.WithoutCancel(ctx)
	for _, validator := range x.Validators() {
		if validator == x.id {
			continue
		}
		if err := x.net.Send(sendCtx, msg, validator); err != nil {
			x.log.WarnContext(ctx, "could not disseminate root handoff abort approval", "validator", validator.String(), "error", err)
		}
	}
	status.State = "pending"
	return status, nil
}

// HandoffAbortStatus reads committed control state only; pending approvals are
// not exposed as a cancellation result.
func (x *ConsensusManager) HandoffAbortStatus(target abdrc.HandoffAbortTarget) (abdrc.HandoffAbortStatus, error) {
	status, _, err := x.handoffAbortStatus(target)
	return status, err
}

func (x *ConsensusManager) handoffAbortStatus(target abdrc.HandoffAbortTarget) (abdrc.HandoffAbortStatus, evmroot.OrderedHandoffRecord, error) {
	status := abdrc.HandoffAbortStatus{Target: target, State: "unknown"}
	if _, err := handoffAbortKeyFor(target); err != nil {
		return status, evmroot.OrderedHandoffRecord{}, err
	}
	state, err := x.blockStore.GetState()
	if err != nil || state == nil || state.CommittedHead == nil || state.CommittedHead.Control == nil || state.CommittedHead.Block == nil {
		return status, evmroot.OrderedHandoffRecord{}, ErrHandoffAbortTarget
	}
	control := state.CommittedHead.Control
	if !controlMatchesAbortTarget(control, target) {
		return status, evmroot.OrderedHandoffRecord{}, ErrHandoffAbortTarget
	}
	record, err := storage.DecodeOrderedHandoffRecord(control.RecordBytes)
	if err != nil || !recordMatchesAbortTarget(record, target) {
		return status, evmroot.OrderedHandoffRecord{}, ErrHandoffAbortTarget
	}
	blockID, err := state.CommittedHead.Block.Hash(crypto.SHA256)
	if err != nil {
		return status, evmroot.OrderedHandoffRecord{}, ErrHandoffAbortTarget
	}
	status.CommittedRootID = fmt.Sprintf("0x%x", blockID)
	status.CommittedRootRound = state.CommittedHead.Block.GetRound()
	status.RecordID = fmt.Sprintf("0x%x", record.ID())
	status.OrderedRound = control.OrderedRound
	switch control.Phase {
	case "prepared", "endorsed":
		trust := x.trustBase.Load()
		if trust == nil || uint64(trust.NetworkID) != target.Network || trust.Epoch != target.OldEpoch {
			return status, evmroot.OrderedHandoffRecord{}, ErrHandoffAbortTarget
		}
		status.State = "pending"
	case "aborted":
		status.State = "committed"
	case "committed":
		status.State = "too_late"
	default:
		return status, evmroot.OrderedHandoffRecord{}, ErrHandoffAbortTarget
	}
	return status, record, nil
}

func handoffAbortKeyFor(target abdrc.HandoffAbortTarget) (handoffAbortKey, error) {
	if target.OldEpoch == 0 ||
		len(target.PredecessorBodyID) != 32 || bytes.Equal(target.PredecessorBodyID, make([]byte, 32)) ||
		len(target.NextBodyID) != 32 || bytes.Equal(target.NextBodyID, make([]byte, 32)) {
		return handoffAbortKey{}, ErrHandoffAbortTarget
	}
	var predecessor [32]byte
	copy(predecessor[:], target.PredecessorBodyID)
	return handoffAbortKey{network: target.Network, epoch: target.OldEpoch, attempt: target.Attempt,
		predecessor: predecessor}, nil
}

func controlMatchesAbortTarget(control *evmroot.ControlState, target abdrc.HandoffAbortTarget) bool {
	return control != nil && control.Network == target.Network && control.Epoch == target.OldEpoch &&
		control.Attempt == target.Attempt && bytes.Equal(control.PredecessorBodyID, target.PredecessorBodyID)
}

func recordMatchesAbortTarget(record evmroot.OrderedHandoffRecord, target abdrc.HandoffAbortTarget) bool {
	return record.Network == target.Network && record.Epoch == target.OldEpoch && record.Attempt == target.Attempt &&
		bytes.Equal(record.PredecessorBodyID, target.PredecessorBodyID) && bytes.Equal(record.NextBodyID, target.NextBodyID)
}

func (x *ConsensusManager) onHandoffAbortApprovalMsg(msg *abdrc.HandoffAbortApprovalMsg) error {
	if msg == nil || msg.Signer == "" || len(msg.Signer) > 512 || len(msg.Signature) == 0 || len(msg.Signature) > 1024 {
		return ErrHandoffAbortSignature
	}
	target := abdrc.HandoffAbortTarget{Network: msg.Network, OldEpoch: msg.OldEpoch,
		PredecessorBodyID: msg.PredecessorBodyID, Attempt: msg.Attempt, NextBodyID: msg.NextBodyID}
	key, err := handoffAbortKeyFor(target)
	if err != nil {
		return err
	}
	status, record, err := x.handoffAbortStatus(target)
	if err != nil || status.State != "pending" {
		return ErrHandoffAbortTarget
	}
	domain, err := storage.AbortEndorsementBytes(record)
	if err != nil {
		return ErrHandoffAbortSignature
	}
	trust := x.trustBase.Load()
	weight, err := trust.VerifySignature(domain, msg.Signature, msg.Signer)
	if err != nil || weight == 0 {
		return ErrHandoffAbortSignature
	}
	x.handoffMu.Lock()
	defer x.handoffMu.Unlock()
	if x.handoffAborts == nil {
		x.handoffAborts = make(map[handoffAbortKey]*pendingHandoffAbort)
	}
	pending := x.handoffAborts[key]
	if pending == nil {
		// Only the attempt named by authenticated current control can receive
		// approvals; discard any approvals for earlier, no-longer-live attempts.
		for stale := range x.handoffAborts {
			if stale != key {
				delete(x.handoffAborts, stale)
			}
		}
		if len(x.handoffAborts) >= maxPendingHandoffAborts {
			return ErrHandoffAbortCache
		}
		pending = &pendingHandoffAbort{target: target, signatures: make(map[string]hex.Bytes)}
		x.handoffAborts[key] = pending
	} else if !bytes.Equal(pending.target.NextBodyID, target.NextBodyID) {
		return ErrHandoffAbortCache
	}
	if prior, exists := pending.signatures[msg.Signer]; exists {
		if !bytes.Equal(prior, msg.Signature) {
			return ErrHandoffAbortCache
		}
		return nil
	}
	sum, err := quorumweight.Add(pending.weight, weight)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrHandoffAbortSignature, err)
	}
	pending.signatures[msg.Signer] = bytes.Clone(msg.Signature)
	pending.weight = sum
	return nil
}

type pendingHandoff struct {
	plan            abdrc.HandoffApprovalMsg
	body            planBody
	record          evmroot.OrderedHandoffRecord
	signatures      map[string]hex.Bytes
	abortSignatures map[string]hex.Bytes
	weight          uint64
}

func (x *ConsensusManager) handoffPredecessor() ([]byte, error) {
	if x.params.NetworkProfileVersion != storage.ProfileHandoff || x.recoveryHistory == nil {
		return nil, ErrHandoffApproval
	}
	current := x.trustBase.Load()
	if current == nil {
		return nil, ErrHandoffApproval
	}
	if x.q3 != nil && current.Epoch > 1 {
		if entry, ok := x.q3.Activated(current.Epoch); ok { // a verified activation's identity is its V3 body's, from the Q3 history
			id := entry.BodyID()
			return bytes.Clone(id[:]), nil
		}
	}
	prior, err := x.recoveryHistory.ByEpoch(current.Epoch)
	if err != nil {
		return nil, err
	}
	if prior.V2 != nil {
		return bytes.Clone(prior.BodyID[:]), nil
	}
	if prior.V1 == nil {
		return nil, ErrHandoffApproval
	}
	return prior.V1.Hash(crypto.SHA256)
}

// plannedAttempt is the attempt number the next handoff uses, given the control state at a block round: 0 on a fresh chain, the
// next number after an abort or after a Prepare whose freeze lapsed. Any other phase has a handoff in progress.
func plannedAttempt(control *evmroot.ControlState, round uint64) (uint64, error) {
	switch {
	case control == nil:
		return 0, ErrHandoffApproval
	case control.Phase == "idle":
		return 0, nil
	case control.Phase == "aborted" || storage.PrepareLapsed(control, round):
		if control.Attempt == ^uint64(0) {
			return 0, ErrHandoffApproval
		}
		return control.Attempt + 1, nil
	}
	return 0, ErrHandoffApproval
}

// intentSummary is the body's state summary. It binds the network, predecessor and attempt only: the pre-freeze snapshot the older
// design bound (a committed round, its root hash and the frozen parent) is fixed by the Prepare record, which comes AFTER the plan,
// and the Freeze record's FrozenID commits to the Prepare-bound parent.
func intentSummary(network uint64, predecessor []byte, attempt uint64) []byte {
	zero := make([]byte, 32)
	return evmroot.D4PreFreezeSummary(network, predecessor, attempt, 0, zero, zero)
}

// PlanHandoff builds the plan of a handoff from this validator's committed checkpoint and registers it as the validator's intent:
// the unsigned message the leader orders a Prepare for. It binds no EVM parent. Every old validator is given the same message
// (AcceptHandoffIntent) and endorses it only after the Prepare is committed (EndorseHandoff).
func (x *ConsensusManager) PlanHandoff(next *types.RootTrustBaseV1, proposal *evmassign.Proposal) (abdrc.HandoffApprovalMsg, error) {
	state, err := x.blockStore.GetState()
	if err != nil {
		return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
	}
	plan, err := x.buildHandoffPlanFromState(next, state, proposal)
	if err != nil {
		return abdrc.HandoffApprovalMsg{}, err
	}
	x.setHandoffIntent(plan)
	return plan, nil
}

// AcceptHandoffIntent registers a plan another validator's operator endpoint built, after checking everything about it that needs
// no signature and no EVM state: the body, the candidate, the attempt this chain expects next.
func (x *ConsensusManager) AcceptHandoffIntent(plan abdrc.HandoffApprovalMsg) error {
	if plan.Signer != "" || len(plan.Signature) != 0 || len(plan.AbortSignature) != 0 || len(plan.FrozenParent) != 0 {
		return ErrHandoffApproval
	}
	state, err := x.blockStore.GetState()
	if err != nil || state == nil || state.CommittedHead == nil || state.CommittedHead.Block == nil {
		return ErrHandoffApproval
	}
	attempt, err := plannedAttempt(state.CommittedHead.Control, state.CommittedHead.Block.Round)
	if err != nil || plan.Attempt != attempt {
		return ErrHandoffApproval
	}
	if _, _, err := x.checkPlanBody(&plan); err != nil {
		return err
	}
	x.setHandoffIntent(plan)
	return nil
}

func (x *ConsensusManager) setHandoffIntent(plan abdrc.HandoffApprovalMsg) {
	x.handoffMu.Lock()
	defer x.handoffMu.Unlock()
	cloned := plan
	cloned.Body, cloned.Candidate = bytes.Clone(plan.Body), bytes.Clone(plan.Candidate)
	cloned.CandidatePreimage = bytes.Clone(plan.CandidatePreimage)
	cloned.Receipts = bytes.Clone(plan.Receipts)
	x.handoffIntent = &cloned
}

// retireIntent forgets the held intent once its attempt is spent: a Prepare (or an Abort) of that attempt or a later one is in the
// control state. A Prepare is ordered at most once per intent, so a lapse or an Abort leaves no plan behind that a leader could
// order another unendorsed Prepare for; the operator must plan again, for the next attempt.
func (x *ConsensusManager) retireIntent(control *evmroot.ControlState) {
	if control == nil || control.Phase == "idle" {
		return
	}
	x.handoffMu.Lock()
	defer x.handoffMu.Unlock()
	if x.handoffIntent != nil && x.handoffIntent.Attempt <= control.Attempt {
		x.handoffIntent = nil
	}
}

// pendingIntent is the held intent for the given attempt, or nil. An intent for another attempt or another epoch is dead.
func (x *ConsensusManager) pendingIntent(attempt uint64) *abdrc.HandoffApprovalMsg {
	x.handoffMu.Lock()
	defer x.handoffMu.Unlock()
	if x.handoffIntent == nil || x.handoffIntent.Attempt != attempt {
		return nil
	}
	cloned := *x.handoffIntent
	return &cloned
}

func (x *ConsensusManager) buildHandoffPlanFromState(next *types.RootTrustBaseV1, state *abdrc.StateMsg, proposal *evmassign.Proposal) (abdrc.HandoffApprovalMsg, error) {
	old := x.trustBase.Load()
	if old == nil || next == nil || old.Epoch == ^uint64(0) || next.Epoch != old.Epoch+1 || next.NetworkID != old.NetworkID {
		return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
	}
	predecessor, err := x.handoffPredecessor()
	if err != nil {
		return abdrc.HandoffApprovalMsg{}, err
	}
	if state == nil || state.CommittedHead == nil || state.CommittedHead.Block == nil || state.CommittedHead.Block.Epoch != old.Epoch ||
		state.CommittedHead.CommitQc == nil || state.CommittedHead.CommitQc.LedgerCommitInfo == nil {
		return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
	}
	round := state.CommittedHead.Block.Round
	attempt, err := plannedAttempt(state.CommittedHead.Control, round)
	if err != nil {
		return abdrc.HandoffApprovalMsg{}, err
	}
	if round == 0 || round > ^uint64(0)-16 {
		return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
	}
	members := make(evmroot.WeightSet, 0, len(next.RootNodes))
	var memberWeight quorumweight.Tally
	for _, node := range next.RootNodes {
		if node == nil || node.Stake != 1 {
			return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
		}
		if memberWeight.Add(node.NodeID, node.Stake) != nil {
			return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
		}
		members = append(members, evmroot.Member{StakingID: node.NodeID, NodeID: node.NodeID,
			ConsensusKey: bytes.Clone(node.SigKey), Weight: node.Stake})
	}
	rootThreshold, err := quorumweight.Threshold(memberWeight.Weight())
	if err != nil {
		return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
	}
	sort.Slice(members, func(i, j int) bool { return members[i].NodeID < members[j].NodeID })
	candidateWire, err := types.Cbor.Marshal([]any{"UNICITY_D4_OPERATOR_CANDIDATE", uint64(1), members})
	if err != nil {
		return abdrc.HandoffApprovalMsg{}, err
	}
	candidate := sha256.Sum256(candidateWire)
	var preimage []byte
	if proposal != nil {
		preimage, candidate, err = x.buildAssignmentCandidate(old, next, predecessor, attempt, state, proposal)
		if err != nil {
			return abdrc.HandoffApprovalMsg{}, err
		}
	} else if err := x.refuseRootChangeWhileAckPending(state, nil); err != nil {
		return abdrc.HandoffApprovalMsg{}, err
	} else if err := x.refuseUncoupledCommitteeChange(old, next, state, nil); err != nil {
		return abdrc.HandoffApprovalMsg{}, err
	}
	aMin := round + 16
	body := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: uint64(old.NetworkID), Epoch: next.Epoch,
		EarliestActivation: aMin, Members: members, RootThreshold: rootThreshold,
		StateSummary:     intentSummary(uint64(old.NetworkID), predecessor, attempt),
		ChangeRecordHash: evmroot.D4CandidateContextHash(uint64(old.NetworkID), predecessor, attempt, candidate[:], aMin)}
	if old.Epoch == 1 {
		body.PredecessorHash, err = evmroot.FirstV2PredecessorHash(evmroot.V1Anchor{Version: 1,
			NetworkID: uint64(old.NetworkID), Epoch: old.Epoch, HashIncludingSigs: predecessor})
		if err != nil {
			return abdrc.HandoffApprovalMsg{}, err
		}
	} else {
		body.PredecessorHash = predecessor
	}
	if err := body.Validate(); err != nil {
		return abdrc.HandoffApprovalMsg{}, err
	}
	return abdrc.HandoffApprovalMsg{Body: body.Encode(), Candidate: candidate[:], ActivationRound: aMin, Attempt: attempt,
		CandidatePreimage: preimage}, nil
}

// pendingAssignmentAck reports whether the shard's technical record already
// names an assignment epoch whose acknowledgement the input record has not
// certified.
func pendingAssignmentAck(shard abdrc.ShardInfo) bool {
	return shard.IR != nil && shard.IRTR.Epoch != shard.IR.Epoch
}

// installedEVMFromState selects the unique certified EVM shard in the committed
// checkpoint and, when withConfig is set, its authenticated configuration at the
// checkpoint's root round. With a parent it is the shard whose certified IR is that
// parent (after the Prepare: the shard the root froze); with none (before the
// Prepare, when no parent is bound yet) it is the designated EVM shard by type.
func (x *ConsensusManager) installedEVMFromState(state *abdrc.StateMsg, parent []byte, withConfig bool) (abdrc.ShardInfo, *types.PartitionDescriptionRecord, error) {
	var found *abdrc.ShardInfo
	if state == nil || state.CommittedHead == nil || state.CommittedHead.Block == nil {
		return abdrc.ShardInfo{}, nil, ErrHandoffApproval
	}
	var byType map[types.PartitionShardID]*types.PartitionDescriptionRecord
	if parent == nil {
		configs, err := x.orchestration.ShardConfigs(state.CommittedHead.Block.Round)
		if err != nil {
			return abdrc.ShardInfo{}, nil, ErrHandoffApproval
		}
		byType = configs
	}
	for i := range state.CommittedHead.ShardInfo {
		shard := &state.CommittedHead.ShardInfo[i]
		if shard.IR == nil {
			continue
		}
		var selected bool
		if parent == nil {
			conf := byType[types.PartitionShardID{PartitionID: shard.Partition, ShardID: shard.Shard.Key()}]
			selected = conf != nil && conf.PartitionTypeID == storage.EVMPartitionTypeID
		} else {
			selected = bytes.Equal(shard.IR.BlockHash, parent)
		}
		if selected {
			if found != nil {
				return abdrc.ShardInfo{}, nil, ErrHandoffApproval
			}
			found = shard
		}
	}
	if found == nil {
		return abdrc.ShardInfo{}, nil, ErrHandoffApproval
	}
	if !withConfig {
		return *found, nil, nil
	}
	configs, err := x.orchestration.ShardConfigs(state.CommittedHead.Block.Round)
	if err != nil {
		return abdrc.ShardInfo{}, nil, ErrHandoffApproval
	}
	conf := configs[types.PartitionShardID{PartitionID: found.Partition, ShardID: found.Shard.Key()}]
	if conf == nil {
		return abdrc.ShardInfo{}, nil, ErrHandoffApproval
	}
	return *found, conf, nil
}

// refuseRootChangeWhileAckPending applies the normal acknowledgement
// prerequisite to a root-only handoff: an installed EVM assignment without a
// certified acknowledgement admits only a supersession.
func (x *ConsensusManager) refuseRootChangeWhileAckPending(state *abdrc.StateMsg, parent []byte) error {
	shard, _, err := x.installedEVMFromState(state, parent, false)
	if err != nil {
		return err
	}
	if pendingAssignmentAck(shard) {
		return fmt.Errorf("%w: %w", ErrHandoffApproval, storage.ErrAssignmentAckPending)
	}
	return nil
}

// refuseUncoupledCommitteeChange is the planner's early refusal of what block validation refuses authoritatively
// (storage.verifyFreezeAssignment): a root-only handoff that changes the committee on a chain that requires coupling.
func (x *ConsensusManager) refuseUncoupledCommitteeChange(old, next *types.RootTrustBaseV1, state *abdrc.StateMsg, parent []byte) error {
	_, installed, err := x.installedEVMFromState(state, parent, true)
	if err != nil || !evmassign.CouplingRequired(installed) {
		// An unavailable configuration is not a reason to refuse here: the planner is only the early refusal, and block
		// validation (which always has the installed configuration) decides.
		return nil
	}
	oldRoot, err := rootMembers(old.RootNodes)
	if err != nil {
		return err
	}
	nextRoot, err := rootMembers(next.RootNodes)
	if err != nil {
		return err
	}
	if !evmassign.SameCommittee(oldRoot, nextRoot) {
		return errors.Join(ErrHandoffApproval, evmassign.ErrCoupling)
	}
	return nil
}

func rootMembers(nodes []*types.NodeInfo) ([]evmassign.RootMember, error) {
	out := make([]evmassign.RootMember, 0, len(nodes))
	for _, n := range nodes {
		if n == nil {
			return nil, ErrHandoffApproval
		}
		out = append(out, evmassign.RootMember{NodeID: n.NodeID, Key: bytes.Clone(n.SigKey), Weight: n.Stake})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out, nil
}

func popContext(network uint64, predecessor []byte, attempt uint64) (evmassign.PoPContext, error) {
	c := evmassign.PoPContext{Network: network, Attempt: attempt}
	if len(predecessor) != 32 {
		return c, ErrHandoffApproval
	}
	copy(c.Predecessor[:], predecessor)
	return c, nil
}

// buildAssignmentCandidate assembles the one candidate byte sequence for an
// EVM-only rotation. It refuses before any endorsement is signed when the
// possession proofs are missing or wrong, the installed assignment has an
// unacknowledged successor, or the root members change as well.
func (x *ConsensusManager) buildAssignmentCandidate(old, next *types.RootTrustBaseV1, predecessor []byte, attempt uint64,
	state *abdrc.StateMsg, proposal *evmassign.Proposal) ([]byte, [32]byte, error) {
	return x.buildAssignmentCandidateWith(evmassign.UnitRules, old, next, predecessor, attempt, state, proposal)
}

// buildAssignmentCandidateWith is buildAssignmentCandidate with the successor's validator weights checked under the rules r: the unit
// rules for a V2 plan, the weighted rules for a V3 plan.
func (x *ConsensusManager) buildAssignmentCandidateWith(rules evmassign.Rules, old, next *types.RootTrustBaseV1, predecessor []byte, attempt uint64,
	state *abdrc.StateMsg, proposal *evmassign.Proposal) ([]byte, [32]byte, error) {
	var none [32]byte
	oldRoot, err := rootMembers(old.RootNodes)
	if err != nil {
		return nil, none, err
	}
	nextRoot, err := rootMembers(next.RootNodes)
	if err != nil {
		return nil, none, err
	}
	shard, installed, err := x.installedEVMFromState(state, nil, true)
	if err != nil {
		return nil, none, err
	}
	var supersedes *evmassign.Supersession
	pending := pendingAssignmentAck(shard)
	switch {
	case pending && !proposal.Supersede:
		return nil, none, fmt.Errorf("%w: %w", ErrHandoffApproval, storage.ErrAssignmentAckPending)
	case !pending && proposal.Supersede:
		return nil, none, fmt.Errorf("%w: no unacknowledged assignment to supersede", ErrHandoffApproval)
	case pending:
		// Bind the committed chain this replacement extends, read from this
		// validator's own committed history and the acknowledged base at P.
		chain, err := storage.CommittedChain(x.orchestration, shard.Partition, shard.Shard, shard.IR.Epoch)
		if err != nil || len(chain.Steps) == 0 {
			return nil, none, errors.Join(ErrHandoffApproval, storage.ErrSupersessionInvalid, err)
		}
		// The early refusal of what root block validation would refuse (storage.verifySupersession): no plan, so no Prepare, is ever
		// built for a supersession that would make the unacknowledged chain longer than handoff.MaxSupersessionSpan.
		if err := storage.CheckSupersessionChainLength(len(chain.Steps)); err != nil {
			return nil, none, errors.Join(ErrHandoffApproval, storage.ErrSupersessionInvalid, err)
		}
		if supersedes, err = chain.Supersession(); err != nil {
			return nil, none, errors.Join(ErrHandoffApproval, err)
		}
	}
	succ, err := evmassign.NewSuccessor(installed, proposal.Validators)
	if err != nil {
		return nil, none, errors.Join(ErrHandoffApproval, err)
	}
	pop, err := popContext(uint64(old.NetworkID), predecessor, attempt)
	if err != nil {
		return nil, none, err
	}
	candidate, err := evmassign.NewCandidateWith(rules, pop, nextRoot, installed, succ, proposal.PoPs, supersedes, proposal.Bindings, proposal.Changes)
	if err != nil {
		return nil, none, errors.Join(ErrHandoffApproval, err)
	}
	if err := evmassign.VerifyInstalledWith(rules, candidate, succ, installed, oldRoot); err != nil {
		return nil, none, errors.Join(ErrHandoffApproval, err)
	}
	if _, err := evmassign.ValidateChanges(candidate.Changes, candidate.SourceRef, pop, evmroot.D4ControlPartition); err != nil {
		return nil, none, errors.Join(ErrHandoffApproval, err)
	}
	if err := x.verifyChangesAgainstState(candidate, pop, state); err != nil {
		return nil, none, errors.Join(ErrHandoffApproval, err)
	}
	raw, err := candidate.Encode()
	if err != nil {
		return nil, none, errors.Join(ErrHandoffApproval, err)
	}
	return raw, sha256.Sum256(raw), nil
}

// verifyChangesAgainstState checks the aggregator validator replacements of a candidate against this validator's committed
// checkpoint: each target is an existing non-EVM shard, the change replaces exactly its installed configuration, and its last
// replacement is acknowledged. A supersession carries none. The possession proofs were verified with the binding.
func (x *ConsensusManager) verifyChangesAgainstState(c evmassign.Candidate, _ evmassign.PoPContext, state *abdrc.StateMsg) error {
	if len(c.Changes) == 0 {
		return nil
	}
	if c.Supersedes != nil {
		return fmt.Errorf("%w: a supersession carries no aggregator changes", evmassign.ErrChange)
	}
	if state == nil || state.CommittedHead == nil || state.CommittedHead.Block == nil {
		return ErrHandoffApproval
	}
	configs, err := x.orchestration.ShardConfigs(state.CommittedHead.Block.Round)
	if err != nil {
		return ErrHandoffApproval
	}
	for _, ch := range c.Changes {
		if ch.Kind != evmassign.ChangeReplaceShardValidators {
			return evmassign.ErrUnsupportedChange
		}
		r, succ, err := evmassign.DecodeReplaceShardValidators(ch.Payload)
		if err != nil {
			return err
		}
		var shard *abdrc.ShardInfo
		for i := range state.CommittedHead.ShardInfo {
			si := &state.CommittedHead.ShardInfo[i]
			if si.Partition == succ.PartitionID && si.Shard.Equal(succ.ShardID) {
				shard = si
			}
		}
		if shard == nil || shard.IR == nil {
			return fmt.Errorf("%w: shard %d does not exist", evmassign.ErrChange, succ.PartitionID)
		}
		key := types.PartitionShardID{PartitionID: succ.PartitionID, ShardID: succ.ShardID.Key()}
		if err := evmassign.VerifyChangeInstalled(evmassign.DecodedChange{Replace: r, Successor: succ}, configs[key]); err != nil {
			return err
		}
		if pendingAssignmentAck(*shard) {
			return fmt.Errorf("%w: shard %d has an unacknowledged configuration", storage.ErrAssignmentAckPending, succ.PartitionID)
		}
	}
	return nil
}

// verifyApprovalAssignment re-checks the candidate preimage of an approval
// that carries one. It needs no EVM state, so it is independent of local timing.
func (x *ConsensusManager) verifyApprovalAssignment(msg *abdrc.HandoffApprovalMsg, body planBody,
	predecessor []byte, old *types.RootTrustBaseV1) (evmassign.Candidate, error) {
	if len(msg.CandidatePreimage) == 0 {
		return evmassign.Candidate{}, nil
	}
	pop, err := popContext(body.network, predecessor, msg.Attempt)
	if err != nil {
		return evmassign.Candidate{}, err
	}
	ctx := evmassign.BindingContext{PoPContext: pop, Digest: msg.Candidate, ControlPartition: evmroot.D4ControlPartition, Rules: body.assignmentRules()}
	for _, m := range body.members {
		ctx.SuccessorRoot = append(ctx.SuccessorRoot, evmassign.RootMember{NodeID: m.NodeID, Key: bytes.Clone(m.Key), Weight: m.Weight})
	}
	c, _, err := evmassign.VerifyBinding(msg.CandidatePreimage, ctx)
	if err != nil {
		return evmassign.Candidate{}, errors.Join(ErrHandoffApproval, err)
	}
	return c, nil
}

// checkPlanBody is everything about a plan, an unsigned intent or a signed approval alike, that needs neither a signature nor EVM
// state: the body against this chain's epoch and predecessor, the candidate preimage, and the summaries that tie the body to the
// attempt and the candidate. Nothing in it names a frozen parent: the root binds that at the Prepare.
func (x *ConsensusManager) checkPlanBody(msg *abdrc.HandoffApprovalMsg) (planBody, []byte, error) {
	if msg == nil || len(msg.Body) == 0 || len(msg.Body) > 1<<20 || len(msg.Candidate) != 32 || msg.ActivationRound == 0 {
		return planBody{}, nil, ErrHandoffApproval
	}
	body, err := x.decodePlanBody(msg.Body)
	if err != nil {
		return body, nil, err
	}
	old := x.trustBase.Load()
	if old == nil || old.Epoch == ^uint64(0) || body.epoch != old.Epoch+1 || body.network != uint64(old.NetworkID) ||
		body.earliest > msg.ActivationRound {
		return body, nil, ErrHandoffApproval
	}
	predecessor, err := x.handoffPredecessor()
	if err != nil {
		return body, nil, err
	}
	link, err := x.planPredecessorLink(body.version, predecessor)
	if err != nil {
		return body, nil, err
	}
	if _, err := x.verifyApprovalAssignment(msg, body, predecessor, old); err != nil {
		return body, nil, err
	}
	if !bytes.Equal(body.predecessorHash, link) ||
		!bytes.Equal(body.stateSummary, intentSummary(body.network, predecessor, msg.Attempt)) ||
		!bytes.Equal(body.changeRecordHash, evmroot.D4CandidateContextHash(body.network, predecessor, msg.Attempt, msg.Candidate, body.earliest)) {
		return body, nil, ErrHandoffApproval
	}
	// V3 readiness: every successor member declared itself ready for exactly this body, attempt and candidate; a V2 plan carries none
	if body.version == 3 {
		if err := x.q3.FreezeRules().VerifyReceipts(msg.Body, msg.Receipts, msg.Attempt, msg.Candidate); err != nil {
			return body, nil, errors.Join(ErrHandoffApproval, err)
		}
	} else if len(msg.Receipts) != 0 {
		return body, nil, ErrHandoffApproval
	}
	return body, predecessor, nil
}

func (x *ConsensusManager) validateHandoffApproval(msg *abdrc.HandoffApprovalMsg) (*pendingHandoff, uint64, error) {
	if msg == nil || len(msg.FrozenParent) != 32 || msg.Signer == "" || len(msg.Signature) == 0 || len(msg.AbortSignature) == 0 {
		return nil, 0, ErrHandoffApproval
	}
	body, predecessor, err := x.checkPlanBody(msg)
	if err != nil {
		return nil, 0, err
	}
	old := x.trustBase.Load()
	id := body.id
	frozen := evmroot.D4FrozenID(id[:], body.stateSummary, msg.FrozenParent, msg.Candidate, msg.Attempt, predecessor)
	record := evmroot.OrderedHandoffRecord{Network: body.network, Epoch: old.Epoch, Attempt: msg.Attempt,
		OrderedRound: 1, ActivationRound: msg.ActivationRound, PredecessorBodyID: predecessor,
		NextBodyID: id[:], FrozenID: frozen, Kind: "freeze"}
	domain, err := storage.EndorsementBytes(record)
	if err != nil {
		return nil, 0, err
	}
	weight, err := old.VerifySignature(domain, msg.Signature, msg.Signer)
	if err != nil || weight == 0 {
		return nil, 0, ErrHandoffApproval
	}
	abortDomain, err := storage.AbortEndorsementBytes(record)
	if err != nil {
		return nil, 0, err
	}
	abortWeight, err := old.VerifySignature(abortDomain, msg.AbortSignature, msg.Signer)
	if err != nil || abortWeight != weight {
		return nil, 0, ErrHandoffApproval
	}
	return &pendingHandoff{plan: *msg, body: body, record: record}, weight, nil
}

// EndorseHandoff is called by the local operator endpoint on each validator.
// It signs one immutable candidate and disseminates that approval through the
// root network; no validator signs merely because another peer asked it to.
// The endorsement commits to the frozen parent the ROOT bound when it ordered
// the Prepare, so it is refused until that Prepare is in this validator's
// committed state, and the plan may name no other parent.
func (x *ConsensusManager) EndorseHandoff(ctx context.Context, plan abdrc.HandoffApprovalMsg) error {
	state, err := x.blockStore.GetState()
	if err != nil {
		return ErrHandoffApproval
	}
	return x.endorseHandoffAtState(ctx, plan, state)
}

func (x *ConsensusManager) endorseHandoffAtState(ctx context.Context, plan abdrc.HandoffApprovalMsg, state *abdrc.StateMsg) error {
	if plan.Signer != "" || len(plan.Signature) != 0 || len(plan.AbortSignature) != 0 {
		return ErrHandoffApproval
	}
	if state == nil || state.CommittedHead == nil || state.CommittedHead.Block == nil ||
		state.CommittedHead.CommitQc == nil || state.CommittedHead.CommitQc.LedgerCommitInfo == nil || state.CommittedHead.Control == nil {
		return ErrHandoffApproval
	}
	control := state.CommittedHead.Control
	switch {
	case control.Phase == "endorsed" || control.Phase == "committed" || control.Phase == "frozen":
		return fmt.Errorf("%w: %w (control phase %q)", ErrHandoffApproval, ErrEndorseAfterFreeze, control.Phase)
	case control.Phase == "aborted" && control.Attempt >= plan.Attempt, control.Phase == "prepared" && control.Attempt > plan.Attempt:
		// A plan for an attempt that is already over: no Prepare for it will ever come.
		return fmt.Errorf("%w: %w (control is at attempt %d, the plan is for %d)", ErrHandoffApproval, ErrEndorsedPlanMismatch, control.Attempt, plan.Attempt)
	case control.Phase != "prepared" || control.Attempt < plan.Attempt:
		// Idle, aborted, or an older Prepare (possibly lapsed) still in the way: the plan's own Prepare has yet to be committed.
		return fmt.Errorf("%w: %w (control phase %q, attempt %d, plan for %d)", ErrHandoffApproval, ErrEndorseBeforePrepare, control.Phase, control.Attempt, plan.Attempt)
	case storage.PrepareLapsed(control, state.CommittedHead.Block.Round):
		return fmt.Errorf("%w: %w", ErrHandoffApproval, ErrPrepareLapsed)
	}
	prepared, err := storage.DecodeOrderedHandoffRecord(control.RecordBytes)
	if err != nil {
		return ErrHandoffApproval
	}
	if len(plan.FrozenParent) != 0 && !bytes.Equal(plan.FrozenParent, control.FrozenParent) {
		return fmt.Errorf("%w: %w", ErrHandoffApproval, ErrEndorsedParentMismatch)
	}
	// What the endorser signs is the Prepare-bound state, never a parent or an activation the caller supplied.
	plan.FrozenParent = bytes.Clone(control.FrozenParent)
	plan.ActivationRound = prepared.ActivationRound
	body, err := x.decodePlanBody(plan.Body)
	if err != nil {
		return ErrHandoffApproval
	}
	if id := body.id; !bytes.Equal(id[:], prepared.NextBodyID) || plan.Attempt != control.Attempt {
		return fmt.Errorf("%w: %w", ErrHandoffApproval, ErrEndorsedPlanMismatch)
	}
	certifiedParents := 0
	for _, shard := range state.CommittedHead.ShardInfo {
		if shard.IR != nil && bytes.Equal(shard.IR.BlockHash, plan.FrozenParent) {
			certifiedParents++
		}
	}
	if certifiedParents != 1 {
		return ErrHandoffApproval
	}
	plan.Signer = x.id.String()
	if len(plan.CandidatePreimage) != 0 {
		if err := x.verifyEndorsedAssignmentInstalled(plan, body.assignmentRules(), state); err != nil {
			return err
		}
	} else if err := x.refuseRootChangeWhileAckPending(state, plan.FrozenParent); err != nil {
		return err
	}
	// The domain is independent of the record's eventual ordering round.
	predecessor, err := x.handoffPredecessor()
	if err != nil {
		return err
	}
	id := body.id
	frozen := evmroot.D4FrozenID(id[:], body.stateSummary, plan.FrozenParent, plan.Candidate, plan.Attempt, predecessor)
	record := evmroot.OrderedHandoffRecord{Network: body.network, Epoch: x.trustBase.Load().Epoch,
		Attempt: plan.Attempt, OrderedRound: 1, ActivationRound: plan.ActivationRound,
		PredecessorBodyID: predecessor, NextBodyID: id[:], FrozenID: frozen, Kind: "freeze"}
	domain, err := storage.EndorsementBytes(record)
	if err != nil {
		return err
	}
	plan.Signature, err = x.safety.signer.SignBytes(domain)
	if err != nil {
		return err
	}
	abortDomain, err := storage.AbortEndorsementBytes(record)
	if err != nil {
		return err
	}
	plan.AbortSignature, err = x.safety.signer.SignBytes(abortDomain)
	if err != nil {
		return err
	}
	if _, _, err := x.validateHandoffApproval(&plan); err != nil {
		return err
	}
	if err := x.onHandoffApprovalMsg(ctx, &plan); err != nil {
		return err
	}
	// The root network sends asynchronously. Keep the bounded protocol send
	// alive after the operator's HTTP request has returned.
	sendCtx := context.WithoutCancel(ctx)
	for _, validator := range x.Validators() {
		if err := x.net.Send(sendCtx, &plan, validator); err != nil {
			x.log.WarnContext(ctx, "could not disseminate root handoff endorsement", "validator", validator.String(), "error", err)
		}
	}
	return nil
}

// verifyEndorsedAssignmentInstalled is the signer's own decision: the candidate
// must replace exactly the assignment installed in this validator's committed
// checkpoint, which must have a certified acknowledgement.
func (x *ConsensusManager) verifyEndorsedAssignmentInstalled(plan abdrc.HandoffApprovalMsg, rules evmassign.Rules, state *abdrc.StateMsg) error {
	c, err := evmassign.DecodeCandidate(plan.CandidatePreimage)
	if err != nil {
		return errors.Join(ErrHandoffApproval, err)
	}
	succ, err := c.Successor()
	if err != nil {
		return errors.Join(ErrHandoffApproval, err)
	}
	shard, installed, err := x.installedEVMFromState(state, plan.FrozenParent, true)
	if err != nil {
		return err
	}
	if pendingAssignmentAck(shard) && c.Supersedes == nil {
		return fmt.Errorf("%w: %w", ErrHandoffApproval, storage.ErrAssignmentAckPending)
	}
	if !pendingAssignmentAck(shard) && c.Supersedes != nil {
		return fmt.Errorf("%w: %w", ErrHandoffApproval, storage.ErrSupersessionInvalid)
	}
	if err := x.verifyChangesAgainstState(c, evmassign.PoPContext{}, state); err != nil {
		return errors.Join(ErrHandoffApproval, err)
	}
	var currentRoot []evmassign.RootMember
	if old := x.trustBase.Load(); old != nil {
		if currentRoot, err = rootMembers(old.RootNodes); err != nil {
			return err
		}
	}
	if currentRoot == nil {
		return ErrHandoffApproval // the EVM-only refusal needs the old committee
	}
	if err := evmassign.VerifyInstalledWith(rules, c, succ, installed, currentRoot); err != nil {
		return errors.Join(ErrHandoffApproval, err)
	}
	return nil
}

// boundPrepare is the frozen parent and activation round of the Prepare of the given attempt in this validator's committed state,
// when that Prepare is committed here.
func (x *ConsensusManager) boundPrepare(attempt uint64) ([]byte, uint64, bool) {
	state, err := x.blockStore.GetState()
	if err != nil || state == nil || state.CommittedHead == nil || state.CommittedHead.Control == nil {
		return nil, 0, false
	}
	control := state.CommittedHead.Control
	if control.Phase != "prepared" || control.Attempt != attempt {
		return nil, 0, false
	}
	prepared, err := storage.DecodeOrderedHandoffRecord(control.RecordBytes)
	if err != nil {
		return nil, 0, false
	}
	return bytes.Clone(control.FrozenParent), prepared.ActivationRound, true
}

func (x *ConsensusManager) onHandoffApprovalMsg(_ context.Context, msg *abdrc.HandoffApprovalMsg) error {
	plan, weight, err := x.validateHandoffApproval(msg)
	if err != nil {
		return err
	}
	// An endorsement naming a parent or an activation other than the Prepare's is rejected on its own, so a single faulty validator
	// cannot occupy the plan's slot with a wrong one and keep the honest quorum from assembling until the lapse.
	boundParent, boundActivation, bound := x.boundPrepare(msg.Attempt)
	if bound && (!bytes.Equal(msg.FrozenParent, boundParent) || msg.ActivationRound != boundActivation) {
		return errors.Join(ErrHandoffApproval, ErrEndorsedParentMismatch)
	}
	id := plan.body.id
	x.handoffMu.Lock()
	defer x.handoffMu.Unlock()
	if x.handoffPlans == nil {
		x.handoffPlans = make(map[[32]byte]*pendingHandoff)
	}
	stored := x.handoffPlans[id]
	if stored != nil && bound && (!bytes.Equal(stored.plan.FrozenParent, boundParent) || stored.plan.ActivationRound != boundActivation) {
		// The slot was taken before the Prepare was committed here, by an endorsement that does not match it: forget that one.
		delete(x.handoffPlans, id)
		stored = nil
	}
	if stored == nil {
		if len(x.handoffPlans) >= 4 {
			if msg.Signer != x.id.String() {
				return ErrHandoffApproval
			}
			removed := false
			for candidate, pending := range x.handoffPlans {
				if _, locallyApproved := pending.signatures[x.id.String()]; !locallyApproved {
					delete(x.handoffPlans, candidate)
					removed = true
					break
				}
			}
			if !removed {
				return ErrHandoffApproval
			}
		}
		stored = plan
		stored.signatures = make(map[string]hex.Bytes)
		stored.abortSignatures = make(map[string]hex.Bytes)
		x.handoffPlans[id] = stored
	} else if !bytes.Equal(stored.plan.Body, msg.Body) || !bytes.Equal(stored.plan.FrozenParent, msg.FrozenParent) ||
		!bytes.Equal(stored.plan.Candidate, msg.Candidate) || !bytes.Equal(stored.plan.CandidatePreimage, msg.CandidatePreimage) ||
		stored.plan.ActivationRound != msg.ActivationRound ||
		stored.plan.Attempt != msg.Attempt {
		return ErrHandoffApproval
	}
	if _, exists := stored.signatures[msg.Signer]; exists {
		return nil
	}
	sum, err := quorumweight.Add(stored.weight, weight)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrHandoffApproval, err)
	}
	stored.signatures[msg.Signer] = bytes.Clone(msg.Signature)
	stored.abortSignatures[msg.Signer] = bytes.Clone(msg.AbortSignature)
	stored.weight = sum
	return nil
}

func (x *ConsensusManager) readyHandoff(attempt ...uint64) (*pendingHandoff, error) {
	x.handoffMu.Lock()
	defer x.handoffMu.Unlock()
	threshold := x.trustBase.Load().QuorumThreshold
	for _, plan := range x.handoffPlans {
		if quorumweight.Reached(plan.weight, threshold) && (len(attempt) == 0 || plan.plan.Attempt == attempt[0]) {
			copyPlan := *plan
			copyPlan.signatures = make(map[string]hex.Bytes, len(plan.signatures))
			copyPlan.abortSignatures = make(map[string]hex.Bytes, len(plan.abortSignatures))
			for signer, sig := range plan.signatures {
				copyPlan.signatures[signer] = bytes.Clone(sig)
				copyPlan.abortSignatures[signer] = bytes.Clone(plan.abortSignatures[signer])
			}
			return &copyPlan, nil
		}
	}
	return nil, fmt.Errorf("%w: insufficient endorsements", ErrHandoffApproval)
}

// handoffRecordsForRound uses the authenticated parent control state. A Prepare is ordered for this validator's held intent (an
// unsigned plan from its operator, spent by that one Prepare); Freeze needs a quorum of endorsements of the Prepare-bound state;
// the records are ordered in separate rounds on the same certified branch.
func (x *ConsensusManager) handoffRecordsForRound(round uint64, parentQC *rctypes.QuorumCert) ([][]byte, error) {
	if parentQC == nil {
		return nil, nil
	}
	parent, err := x.blockStore.Block(parentQC.GetRound())
	if err != nil || parent == nil || parent.ShardState.Control == nil {
		return nil, nil
	}
	control := parent.ShardState.Control
	x.retireIntent(control)
	if control.Phase == "committed" {
		return nil, nil
	}
	// An explicit old-set quorum abort has priority over every volatile plan
	// lookup. The ordered parent record is the authority for the exact attempt,
	// so this still works after restart has cleared handoffPlans.
	// The committed phase is unreachable past the guard above. Keep it in this
	// branch so removing that guard would let stale quorum approvals build Abort.
	if control.Phase == "prepared" || control.Phase == "endorsed" || control.Phase == "committed" {
		previous, decodeErr := storage.DecodeOrderedHandoffRecord(control.RecordBytes)
		if decodeErr == nil {
			target := abdrc.HandoffAbortTarget{Network: previous.Network, OldEpoch: previous.Epoch,
				PredecessorBodyID: previous.PredecessorBodyID, Attempt: previous.Attempt, NextBodyID: previous.NextBodyID}
			if signatures, ready := x.readyHandoffAbort(target); ready {
				return abortHandoffRecords(round, previous, signatures)
			}
		}
	}
	// A Prepare whose freeze lapsed is dead: no Freeze is ordered for it, and once the cooldown has passed the leader may start the
	// next attempt exactly as after an abort.
	lapsed := storage.PrepareLapsed(control, round)
	if lapsed && !storage.PrepareMayFollowLapse(control, round) {
		return nil, nil
	}
	expectedAttempt := uint64(0)
	if control.Phase == "aborted" || lapsed {
		if control.Attempt == ^uint64(0) {
			return nil, ErrHandoffApproval
		}
		expectedAttempt = control.Attempt + 1
	} else if control.Phase != "idle" {
		expectedAttempt = control.Attempt
	}
	phase := control.Phase
	if lapsed {
		phase = "aborted"
	}
	if phase == "idle" || phase == "aborted" {
		// Prepare comes FIRST: it freezes the EVM and the root binds the frozen parent in the same record, so nothing the operator
		// or the endorsers do afterwards can race the EVM. It is ordered for the operator's intent: unsigned (a Prepare carries no
		// signatures; PrepareFreezeLapseRounds bounds what a faulty leader can do with one) and naming no parent. The
		// endorsements follow, after this validator's committed state shows the Prepare.
		intent := x.pendingIntent(expectedAttempt)
		if intent == nil {
			return nil, nil
		}
		return x.prepareRecordFor(*intent, control, round)
	}
	plan, err := x.readyHandoff(expectedAttempt)
	if err != nil {
		return nil, nil
	}
	record := plan.record
	record.OrderedRound = round
	switch phase {
	case "prepared":
		previous, err := storage.DecodeOrderedHandoffRecord(control.RecordBytes)
		if err != nil || !bytes.Equal(previous.NextBodyID, record.NextBodyID) || previous.Attempt != record.Attempt {
			return nil, nil
		}
		if !bytes.Equal(plan.plan.FrozenParent, control.FrozenParent) {
			// Endorsers sign only the Prepare-bound parent, so this is unreachable with honest endorsers; never order a Freeze
			// block validation would refuse (storage.ErrFreezeParentUnbound).
			return nil, nil
		}
		if reason := x.frozenParentLoss(parent, plan.plan.FrozenParent, plan.plan.FrozenParent); reason != "" {
			x.logHandoffAbort("freeze", round, previous.Attempt, reason, plan.plan.FrozenParent, parent)
			return abortHandoffRecords(round, previous, plan.abortSignatures)
		}
		record.ActivationRound = previous.ActivationRound
		record.Kind = "freeze"
		record.SuccessorTRHash = make([]byte, 32)
		var companion []byte
		if plan.body.version == 3 {
			companion, err = (storage.FreezeV3Authorization{Version: 3, Body: bytes.Clone(plan.plan.Body),
				Parent: bytes.Clone(plan.plan.FrozenParent), Candidate: bytes.Clone(plan.plan.Candidate),
				Preimage: bytes.Clone(plan.plan.CandidatePreimage), Receipts: bytes.Clone(plan.plan.Receipts), Signatures: plan.signatures}).Bytes()
		} else if len(plan.plan.CandidatePreimage) != 0 {
			companion, err = (storage.FreezeAssignmentAuthorization{Version: 2, Body: bytes.Clone(plan.plan.Body),
				Parent: bytes.Clone(plan.plan.FrozenParent), Candidate: bytes.Clone(plan.plan.Candidate),
				Preimage: bytes.Clone(plan.plan.CandidatePreimage), Signatures: plan.signatures}).Bytes()
		} else {
			companion, err = (storage.FreezeAuthorization{Version: 1, Body: bytes.Clone(plan.plan.Body),
				Parent: bytes.Clone(plan.plan.FrozenParent), Candidate: bytes.Clone(plan.plan.Candidate),
				Signatures: plan.signatures}).Bytes()
		}
		if err != nil {
			return nil, err
		}
		return [][]byte{record.Bytes(), companion}, nil
	case "endorsed":
		previous, err := storage.DecodeOrderedHandoffRecord(control.RecordBytes)
		if err != nil || !bytes.Equal(previous.NextBodyID, record.NextBodyID) || previous.Attempt != record.Attempt {
			return nil, nil
		}
		if reason := x.frozenParentLoss(parent, plan.plan.FrozenParent, control.FrozenParent); reason != "" {
			x.logHandoffAbort("commit", round, previous.Attempt, reason, control.FrozenParent, parent)
			return abortHandoffRecords(round, previous, plan.abortSignatures)
		}
		activation, ok := storage.CommitActivationRound(previous.ActivationRound, round)
		if !ok {
			return nil, ErrHandoffApproval
		}
		record.ActivationRound = activation
		key, err := x.blockStore.CertifiedEVMShardAt(parent.GetRound(), control.FrozenParent)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrHandoffApproval, err)
		}
		shard := parent.ShardState.States[key]
		if len(plan.plan.CandidatePreimage) != 0 {
			// An assignment-bearing H commits the technical record the successor
			// configuration installs, not the retiring one.
			record.SuccessorTRHash, err = storage.AssignmentSuccessorTRHash(shard, plan.plan.CandidatePreimage, record.ActivationRound, x.params.HashAlgorithm)
		} else {
			record.SuccessorTRHash, err = shard.TR.Hash()
		}
		if err != nil {
			return nil, err
		}
		record.Kind = "commit"
		return [][]byte{record.Bytes()}, nil
	default:
		return nil, nil
	}
}

func (x *ConsensusManager) readyHandoffAbort(target abdrc.HandoffAbortTarget) (map[string]hex.Bytes, bool) {
	key, err := handoffAbortKeyFor(target)
	if err != nil {
		return nil, false
	}
	trust := x.trustBase.Load()
	if trust == nil {
		return nil, false
	}
	x.handoffMu.Lock()
	defer x.handoffMu.Unlock()
	pending := x.handoffAborts[key]
	if pending == nil || !bytes.Equal(pending.target.NextBodyID, target.NextBodyID) || !quorumweight.Reached(pending.weight, trust.QuorumThreshold) {
		return nil, false
	}
	signatures := make(map[string]hex.Bytes, len(pending.signatures))
	for signer, signature := range pending.signatures {
		signatures[signer] = bytes.Clone(signature)
	}
	return signatures, true
}

// frozenParentLoss names why a prepared or endorsed handoff can no longer proceed on its frozen parent, or returns "" when it
// can: the endorsed parent differs from the plan, the parent block's shard IR is no longer that block (the shard certified
// a newer one), or the frozen parent is not in the committed state.
func (x *ConsensusManager) frozenParentLoss(parent *storage.ExecutedBlock, planned, frozen []byte) string {
	switch {
	case !bytes.Equal(frozen, planned):
		return "the endorsed frozen parent differs from the plan"
	case !parentHasFrozenShard(parent, frozen):
		return "the shard's certified IR in the parent block is no longer the frozen parent (a newer EVM block was certified)"
	case !x.blockStore.CommittedFrozenParent(frozen):
		return "the frozen parent is not in the committed state"
	}
	return ""
}

func (x *ConsensusManager) logHandoffAbort(phase string, round, attempt uint64, reason string, frozen []byte, parent *storage.ExecutedBlock) {
	var shards []string
	if parent != nil {
		for key, shard := range parent.ShardState.States {
			if shard != nil && shard.IR != nil {
				shards = append(shards, fmt.Sprintf("%s=%x", key.PartitionID, shard.IR.BlockHash))
			}
		}
	}
	sort.Strings(shards)
	x.log.Info("root handoff abort ordered", "phase", phase, "round", round, "attempt", attempt, "reason", reason,
		"frozenParent", fmt.Sprintf("%x", frozen), "parentBlockShardIRs", strings.Join(shards, ","))
}

func parentHasFrozenShard(parent *storage.ExecutedBlock, frozenParent []byte) bool {
	if parent == nil || len(frozenParent) != 32 {
		return false
	}
	found := 0
	for _, shard := range parent.ShardState.States {
		if shard != nil && shard.IR != nil && bytes.Equal(shard.IR.BlockHash, frozenParent) {
			found++
		}
	}
	return found == 1
}

// prepareRecordFor is the Prepare record for the held intent at the given round. Its activation round leaves the whole endorsement
// window (PrepareFreezeLapseRounds) and the usual margin before activation, so a Freeze ordered as late as the window allows can
// still be committed before the handoff activates.
func (x *ConsensusManager) prepareRecordFor(intent abdrc.HandoffApprovalMsg, control *evmroot.ControlState, round uint64) ([][]byte, error) {
	body, err := x.decodePlanBody(intent.Body)
	if err != nil || body.epoch != control.Epoch+1 {
		return nil, nil
	}
	predecessor, err := x.handoffPredecessor()
	if err != nil {
		return nil, nil
	}
	if round > ^uint64(0)-storage.PrepareActivationFloorRounds {
		return nil, ErrHandoffApproval
	}
	id := body.id
	record := evmroot.OrderedHandoffRecord{Network: body.network, Epoch: control.Epoch, Attempt: intent.Attempt, OrderedRound: round,
		ActivationRound: intent.ActivationRound, PredecessorBodyID: predecessor, NextBodyID: id[:], Kind: "prepare",
		FrozenID: make([]byte, 32), SuccessorTRHash: make([]byte, 32)}
	if floor := round + storage.PrepareActivationFloorRounds; record.ActivationRound < floor {
		record.ActivationRound = floor
	}
	return [][]byte{record.Bytes()}, nil
}

func abortHandoffRecords(round uint64, previous evmroot.OrderedHandoffRecord, signatures map[string]hex.Bytes) ([][]byte, error) {
	if len(signatures) == 0 {
		return nil, ErrHandoffApproval
	}
	previous.Kind = "abort"
	previous.OrderedRound = round
	proof, err := (storage.AbortAuthorization{Version: 1, Signatures: signatures}).Bytes()
	if err != nil {
		return nil, err
	}
	return [][]byte{previous.Bytes(), proof}, nil
}

// EVMAssignmentContext is what every successor key signs a possession proof over
// besides the assignment itself, plus the installed assignment the proposal
// replaces. It is read from the committed checkpoint and carries no authority:
// each endorser re-derives the same values before it signs. It names no frozen
// parent: the root binds that at the Prepare, after the proofs are collected.
type EVMAssignmentContext struct {
	Network     uint64                            `json:"network"`
	Predecessor hex.Bytes                         `json:"predecessor"`
	Attempt     uint64                            `json:"attempt"`
	Installed   *types.PartitionDescriptionRecord `json:"installed"`
	Pending     bool                              `json:"acknowledgementPending"`
}

// EVMAssignmentContext reports the possession-proof context for the next handoff. A successor key holder signs
// evmassign.PoPMessage for exactly this network, predecessor and attempt; a stale or different context is refused later.
func (x *ConsensusManager) EVMAssignmentContext() (EVMAssignmentContext, error) {
	state, err := x.blockStore.GetState()
	if err != nil || state == nil || state.CommittedHead == nil || state.CommittedHead.Block == nil || state.CommittedHead.Control == nil {
		return EVMAssignmentContext{}, ErrHandoffApproval
	}
	attempt, err := plannedAttempt(state.CommittedHead.Control, state.CommittedHead.Block.Round)
	if err != nil {
		return EVMAssignmentContext{}, err
	}
	predecessor, err := x.handoffPredecessor()
	if err != nil {
		return EVMAssignmentContext{}, err
	}
	shard, installed, err := x.installedEVMFromState(state, nil, true)
	if err != nil {
		return EVMAssignmentContext{}, err
	}
	return EVMAssignmentContext{Network: uint64(x.orchestration.NetworkID()), Predecessor: predecessor, Attempt: attempt,
		Installed: installed, Pending: pendingAssignmentAck(shard)}, nil
}
