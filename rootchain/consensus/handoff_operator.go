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
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

var (
	ErrHandoffApproval       = errors.New("root handoff: invalid operator approval")
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
	if ^uint64(0)-pending.weight < weight {
		return ErrHandoffAbortSignature
	}
	pending.signatures[msg.Signer] = bytes.Clone(msg.Signature)
	pending.weight += weight
	return nil
}

type pendingHandoff struct {
	plan            abdrc.HandoffApprovalMsg
	body            evmroot.TrustBaseBodyV2
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

// BuildHandoffPlan fixes a pre-freeze snapshot and next committee before any
// signature is collected. A caller submits this identical plan locally to
// each old validator; each signer decides independently whether to endorse.
func (x *ConsensusManager) BuildHandoffPlan(next *types.RootTrustBaseV1, frozenParent []byte) (abdrc.HandoffApprovalMsg, error) {
	return x.BuildHandoffPlanEVM(next, frozenParent, nil)
}

// BuildHandoffPlanEVM is BuildHandoffPlan for an EVM-only rotation. A non-nil
// proposal carries the successor validators and their possession proofs; the
// root members must stay identical, because M3 refuses a combined change.
func (x *ConsensusManager) BuildHandoffPlanEVM(next *types.RootTrustBaseV1, frozenParent []byte, proposal *evmassign.Proposal) (abdrc.HandoffApprovalMsg, error) {
	if !x.blockStore.HighQCFrozenParent(frozenParent) {
		return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
	}
	state, err := x.blockStore.GetState()
	if err != nil {
		return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
	}
	return x.buildHandoffPlanFromState(next, frozenParent, state, proposal)
}

// BuildAndEndorseHandoff uses one committed checkpoint for the proposed plan
// and this validator's endorsement. Root rounds may advance between separate
// operator HTTP calls while the shard remains live.
func (x *ConsensusManager) BuildAndEndorseHandoff(ctx context.Context, next *types.RootTrustBaseV1, frozenParent []byte) (abdrc.HandoffApprovalMsg, error) {
	return x.BuildAndEndorseHandoffEVM(ctx, next, frozenParent, nil)
}

// BuildAndEndorseHandoffEVM is BuildAndEndorseHandoff with an optional EVM
// assignment proposal.
func (x *ConsensusManager) BuildAndEndorseHandoffEVM(ctx context.Context, next *types.RootTrustBaseV1, frozenParent []byte, proposal *evmassign.Proposal) (abdrc.HandoffApprovalMsg, error) {
	if !x.blockStore.HighQCFrozenParent(frozenParent) {
		return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
	}
	state, err := x.blockStore.GetState()
	if err != nil {
		return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
	}
	plan, err := x.buildHandoffPlanFromState(next, frozenParent, state, proposal)
	if err != nil {
		return abdrc.HandoffApprovalMsg{}, err
	}
	if err := x.endorseHandoffAtState(ctx, plan, state); err != nil {
		return abdrc.HandoffApprovalMsg{}, err
	}
	return plan, nil
}

func (x *ConsensusManager) buildHandoffPlanFromState(next *types.RootTrustBaseV1, frozenParent []byte, state *abdrc.StateMsg, proposal *evmassign.Proposal) (abdrc.HandoffApprovalMsg, error) {
	old := x.trustBase.Load()
	if old == nil || next == nil || old.Epoch == ^uint64(0) || next.Epoch != old.Epoch+1 ||
		next.NetworkID != old.NetworkID || len(frozenParent) != 32 || bytes.Equal(frozenParent, make([]byte, 32)) {
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
	if state.CommittedHead.Control == nil ||
		(state.CommittedHead.Control.Phase != "idle" && state.CommittedHead.Control.Phase != "aborted") {
		return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
	}
	attempt := uint64(0)
	if state.CommittedHead.Control.Phase == "aborted" {
		if state.CommittedHead.Control.Attempt == ^uint64(0) {
			return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
		}
		attempt = state.CommittedHead.Control.Attempt + 1
	}
	certifiedParents := 0
	for _, shard := range state.CommittedHead.ShardInfo {
		if shard.IR != nil && bytes.Equal(shard.IR.BlockHash, frozenParent) {
			certifiedParents++
		}
	}
	if certifiedParents != 1 {
		return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
	}
	round := state.CommittedHead.Block.Round
	root := state.CommittedHead.CommitQc.LedgerCommitInfo.Hash
	if len(root) != 32 || round == 0 || round > ^uint64(0)-16 {
		return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
	}
	members := make(evmroot.WeightSet, 0, len(next.RootNodes))
	for _, node := range next.RootNodes {
		if node == nil || node.Stake != 1 {
			return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
		}
		members = append(members, evmroot.Member{StakingID: node.NodeID, NodeID: node.NodeID,
			ConsensusKey: bytes.Clone(node.SigKey), Weight: node.Stake})
	}
	sort.Slice(members, func(i, j int) bool { return members[i].NodeID < members[j].NodeID })
	candidateWire, err := types.Cbor.Marshal([]any{"UNICITY_D4_OPERATOR_CANDIDATE", uint64(1), members})
	if err != nil {
		return abdrc.HandoffApprovalMsg{}, err
	}
	candidate := sha256.Sum256(candidateWire)
	var preimage []byte
	if proposal != nil {
		preimage, candidate, err = x.buildAssignmentCandidate(old, next, predecessor, attempt, frozenParent, state, proposal)
		if err != nil {
			return abdrc.HandoffApprovalMsg{}, err
		}
	} else if err := x.refuseRootChangeWhileAckPending(state, frozenParent); err != nil {
		return abdrc.HandoffApprovalMsg{}, err
	} else if err := x.refuseUncoupledCommitteeChange(old, next, state, frozenParent); err != nil {
		return abdrc.HandoffApprovalMsg{}, err
	}
	aMin := round + 16
	body := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: uint64(old.NetworkID), Epoch: next.Epoch,
		EarliestActivation: aMin, Members: members, RootThreshold: evmroot.RootQuorumThreshold(uint64(len(members))),
		StateSummary:     evmroot.D4PreFreezeSummary(uint64(old.NetworkID), predecessor, attempt, round, root, frozenParent),
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
	return abdrc.HandoffApprovalMsg{Body: body.Encode(), FrozenParent: bytes.Clone(frozenParent),
		Candidate: candidate[:], PreFreezeRound: round, PreFreezeRoot: bytes.Clone(root),
		ActivationRound: aMin, Attempt: attempt, CandidatePreimage: preimage}, nil
}

// pendingAssignmentAck reports whether the shard's technical record already
// names an assignment epoch whose acknowledgement the input record has not
// certified.
func pendingAssignmentAck(shard abdrc.ShardInfo) bool {
	return shard.IR != nil && shard.IRTR.Epoch != shard.IR.Epoch
}

// installedEVMFromState selects the unique certified shard with the frozen
// parent in the committed checkpoint and, when withConfig is set, its
// authenticated configuration at the checkpoint's root round.
func (x *ConsensusManager) installedEVMFromState(state *abdrc.StateMsg, parent []byte, withConfig bool) (abdrc.ShardInfo, *types.PartitionDescriptionRecord, error) {
	var found *abdrc.ShardInfo
	if state == nil || state.CommittedHead == nil || state.CommittedHead.Block == nil {
		return abdrc.ShardInfo{}, nil, ErrHandoffApproval
	}
	for i := range state.CommittedHead.ShardInfo {
		if shard := &state.CommittedHead.ShardInfo[i]; shard.IR != nil && bytes.Equal(shard.IR.BlockHash, parent) {
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

func popContext(network uint64, predecessor []byte, attempt uint64, parent []byte) (evmassign.PoPContext, error) {
	c := evmassign.PoPContext{Network: network, Attempt: attempt}
	if len(predecessor) != 32 || len(parent) != 32 {
		return c, ErrHandoffApproval
	}
	copy(c.Predecessor[:], predecessor)
	copy(c.Parent[:], parent)
	return c, nil
}

// buildAssignmentCandidate assembles the one candidate byte sequence for an
// EVM-only rotation. It refuses before any endorsement is signed when the
// possession proofs are missing or wrong, the installed assignment has an
// unacknowledged successor, or the root members change as well.
func (x *ConsensusManager) buildAssignmentCandidate(old, next *types.RootTrustBaseV1, predecessor []byte, attempt uint64,
	parent []byte, state *abdrc.StateMsg, proposal *evmassign.Proposal) ([]byte, [32]byte, error) {
	var none [32]byte
	oldRoot, err := rootMembers(old.RootNodes)
	if err != nil {
		return nil, none, err
	}
	nextRoot, err := rootMembers(next.RootNodes)
	if err != nil {
		return nil, none, err
	}
	shard, installed, err := x.installedEVMFromState(state, parent, true)
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
		if supersedes, err = chain.Supersession(); err != nil {
			return nil, none, errors.Join(ErrHandoffApproval, err)
		}
	}
	succ, err := evmassign.NewSuccessor(installed, proposal.Validators)
	if err != nil {
		return nil, none, errors.Join(ErrHandoffApproval, err)
	}
	pop, err := popContext(uint64(old.NetworkID), predecessor, attempt, parent)
	if err != nil {
		return nil, none, err
	}
	candidate, err := evmassign.NewCandidate(pop, nextRoot, installed, succ, proposal.PoPs, supersedes, proposal.Bindings)
	if err != nil {
		return nil, none, errors.Join(ErrHandoffApproval, err)
	}
	if err := evmassign.VerifyInstalled(candidate, succ, installed, oldRoot); err != nil {
		return nil, none, errors.Join(ErrHandoffApproval, err)
	}
	raw, err := candidate.Encode()
	if err != nil {
		return nil, none, errors.Join(ErrHandoffApproval, err)
	}
	return raw, sha256.Sum256(raw), nil
}

// verifyApprovalAssignment re-checks the candidate preimage of an approval
// that carries one. It needs no EVM state, so it is independent of local timing.
func (x *ConsensusManager) verifyApprovalAssignment(msg *abdrc.HandoffApprovalMsg, body evmroot.TrustBaseBodyV2,
	predecessor []byte, old *types.RootTrustBaseV1) (evmassign.Candidate, error) {
	if len(msg.CandidatePreimage) == 0 {
		return evmassign.Candidate{}, nil
	}
	pop, err := popContext(body.NetworkID, predecessor, msg.Attempt, msg.FrozenParent)
	if err != nil {
		return evmassign.Candidate{}, err
	}
	ctx := evmassign.BindingContext{PoPContext: pop, Digest: msg.Candidate}
	for _, m := range body.Members {
		ctx.SuccessorRoot = append(ctx.SuccessorRoot, evmassign.RootMember{NodeID: m.NodeID, Key: bytes.Clone(m.ConsensusKey), Weight: m.Weight})
	}
	c, _, err := evmassign.VerifyBinding(msg.CandidatePreimage, ctx)
	if err != nil {
		return evmassign.Candidate{}, errors.Join(ErrHandoffApproval, err)
	}
	return c, nil
}

func (x *ConsensusManager) validateHandoffApproval(msg *abdrc.HandoffApprovalMsg) (*pendingHandoff, uint64, error) {
	if msg == nil || len(msg.Body) == 0 || len(msg.Body) > 1<<20 || len(msg.FrozenParent) != 32 ||
		len(msg.Candidate) != 32 || len(msg.PreFreezeRoot) != 32 || msg.PreFreezeRound == 0 ||
		msg.ActivationRound == 0 || msg.Signer == "" || len(msg.Signature) == 0 || len(msg.AbortSignature) == 0 {
		return nil, 0, ErrHandoffApproval
	}
	body, err := storage.DecodeHandoffBody(msg.Body)
	if err != nil {
		return nil, 0, ErrHandoffApproval
	}
	old := x.trustBase.Load()
	if old == nil || old.Epoch == ^uint64(0) || body.Epoch != old.Epoch+1 || body.NetworkID != uint64(old.NetworkID) ||
		body.EarliestActivation > msg.ActivationRound {
		return nil, 0, ErrHandoffApproval
	}
	predecessor, err := x.handoffPredecessor()
	if err != nil {
		return nil, 0, err
	}
	link := predecessor
	if old.Epoch == 1 {
		link, err = evmroot.FirstV2PredecessorHash(evmroot.V1Anchor{Version: 1,
			NetworkID: uint64(old.NetworkID), Epoch: old.Epoch, HashIncludingSigs: predecessor})
		if err != nil {
			return nil, 0, err
		}
	}
	if _, err := x.verifyApprovalAssignment(msg, body, predecessor, old); err != nil {
		return nil, 0, err
	}
	if !bytes.Equal(body.PredecessorHash, link) ||
		!bytes.Equal(body.StateSummary, evmroot.D4PreFreezeSummary(body.NetworkID, predecessor, msg.Attempt, msg.PreFreezeRound, msg.PreFreezeRoot, msg.FrozenParent)) ||
		!bytes.Equal(body.ChangeRecordHash, evmroot.D4CandidateContextHash(body.NetworkID, predecessor, msg.Attempt, msg.Candidate, body.EarliestActivation)) {
		return nil, 0, ErrHandoffApproval
	}
	id := body.Identity()
	frozen := evmroot.D4FrozenID(id[:], body.StateSummary, msg.FrozenParent, msg.Candidate, msg.Attempt, predecessor)
	record := evmroot.OrderedHandoffRecord{Network: body.NetworkID, Epoch: old.Epoch, Attempt: msg.Attempt,
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
func (x *ConsensusManager) EndorseHandoff(ctx context.Context, plan abdrc.HandoffApprovalMsg) error {
	if !x.blockStore.HighQCFrozenParent(plan.FrozenParent) {
		return ErrHandoffApproval
	}
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
		state.CommittedHead.CommitQc == nil || state.CommittedHead.CommitQc.LedgerCommitInfo == nil ||
		state.CommittedHead.Control == nil ||
		(state.CommittedHead.Control.Phase != "idle" && state.CommittedHead.Control.Phase != "aborted") ||
		plan.PreFreezeRound != state.CommittedHead.Block.Round ||
		!bytes.Equal(plan.PreFreezeRoot, state.CommittedHead.CommitQc.LedgerCommitInfo.Hash) {
		return ErrHandoffApproval
	}
	expectedAttempt := uint64(0)
	if state.CommittedHead.Control.Phase == "aborted" {
		if state.CommittedHead.Control.Attempt == ^uint64(0) {
			return ErrHandoffApproval
		}
		expectedAttempt = state.CommittedHead.Control.Attempt + 1
	}
	if plan.Attempt != expectedAttempt {
		return ErrHandoffApproval
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
		if err := x.verifyEndorsedAssignmentInstalled(plan, state); err != nil {
			return err
		}
	} else if err := x.refuseRootChangeWhileAckPending(state, plan.FrozenParent); err != nil {
		return err
	}
	// The domain is independent of the record's eventual ordering round.
	body, err := storage.DecodeHandoffBody(plan.Body)
	if err != nil {
		return err
	}
	predecessor, err := x.handoffPredecessor()
	if err != nil {
		return err
	}
	id := body.Identity()
	frozen := evmroot.D4FrozenID(id[:], body.StateSummary, plan.FrozenParent, plan.Candidate, plan.Attempt, predecessor)
	record := evmroot.OrderedHandoffRecord{Network: body.NetworkID, Epoch: x.trustBase.Load().Epoch,
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
func (x *ConsensusManager) verifyEndorsedAssignmentInstalled(plan abdrc.HandoffApprovalMsg, state *abdrc.StateMsg) error {
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
	var currentRoot []evmassign.RootMember
	if old := x.trustBase.Load(); old != nil {
		if currentRoot, err = rootMembers(old.RootNodes); err != nil {
			return err
		}
	}
	if currentRoot == nil {
		return ErrHandoffApproval // the EVM-only refusal needs the old committee
	}
	if err := evmassign.VerifyInstalled(c, succ, installed, currentRoot); err != nil {
		return errors.Join(ErrHandoffApproval, err)
	}
	return nil
}

func (x *ConsensusManager) onHandoffApprovalMsg(_ context.Context, msg *abdrc.HandoffApprovalMsg) error {
	plan, weight, err := x.validateHandoffApproval(msg)
	if err != nil {
		return err
	}
	id := plan.body.Identity()
	x.handoffMu.Lock()
	defer x.handoffMu.Unlock()
	if x.handoffPlans == nil {
		x.handoffPlans = make(map[[32]byte]*pendingHandoff)
	}
	stored := x.handoffPlans[id]
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
		stored.plan.PreFreezeRound != msg.PreFreezeRound || !bytes.Equal(stored.plan.PreFreezeRoot, msg.PreFreezeRoot) || stored.plan.Attempt != msg.Attempt {
		return ErrHandoffApproval
	}
	if _, exists := stored.signatures[msg.Signer]; exists {
		return nil
	}
	stored.signatures[msg.Signer] = bytes.Clone(msg.Signature)
	stored.abortSignatures[msg.Signer] = bytes.Clone(msg.AbortSignature)
	stored.weight += weight
	return nil
}

// dropHandoffPlan forgets the cached endorsed plan of a body so it is neither retried nor left to order a stale Prepare.
func (x *ConsensusManager) dropHandoffPlan(bodyID []byte) {
	x.handoffMu.Lock()
	defer x.handoffMu.Unlock()
	for id, plan := range x.handoffPlans {
		if bytes.Equal(plan.record.NextBodyID, bodyID) {
			delete(x.handoffPlans, id)
		}
	}
}

func (x *ConsensusManager) readyHandoff(attempt ...uint64) (*pendingHandoff, error) {
	x.handoffMu.Lock()
	defer x.handoffMu.Unlock()
	threshold := x.trustBase.Load().QuorumThreshold
	for _, plan := range x.handoffPlans {
		if plan.weight >= threshold && (len(attempt) == 0 || plan.plan.Attempt == attempt[0]) {
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

// handoffRecordsForRound uses the authenticated parent control state. Only a
// quorum-approved body can enter a proposal, and the three D4 records are
// ordered in separate rounds on the same certified branch.
func (x *ConsensusManager) handoffRecordsForRound(round uint64, parentQC *rctypes.QuorumCert) ([][]byte, error) {
	if parentQC == nil {
		return nil, nil
	}
	parent, err := x.blockStore.Block(parentQC.GetRound())
	if err != nil || parent == nil || parent.ShardState.Control == nil {
		return nil, nil
	}
	control := parent.ShardState.Control
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
	expectedAttempt := uint64(0)
	if control.Phase == "aborted" {
		if control.Attempt == ^uint64(0) {
			return nil, ErrHandoffApproval
		}
		expectedAttempt = control.Attempt + 1
	} else if control.Phase != "idle" {
		expectedAttempt = control.Attempt
	}
	plan, err := x.readyHandoff(expectedAttempt)
	if err != nil {
		return nil, nil
	}
	record := plan.record
	record.OrderedRound = round
	switch control.Phase {
	case "idle", "aborted":
		// Prepare freezes the EVM shard from this record onward, so it is ordered only while the plan's frozen parent is still the
		// certified EVM IR in this branch. If the EVM certified a newer block since the plan was endorsed the plan is stale: drop it
		// (nothing is frozen, the operator re-plans from the current parent) instead of ordering a Prepare whose Freeze would abort.
		if !parentHasFrozenShard(parent, plan.plan.FrozenParent) {
			x.dropHandoffPlan(plan.record.NextBodyID)
			x.log.Info("root handoff outcome", "phase", "dropped", "attempt", plan.plan.Attempt, "rootEpoch", control.Epoch, "rootRound", parentQC.GetRound(),
				"reason", "the plan's frozen parent is no longer the certified EVM IR in this branch", "frozenParent", fmt.Sprintf("%x", plan.plan.FrozenParent))
			return nil, nil
		}
		record.Kind = "prepare"
		if round > ^uint64(0)-8 {
			return nil, ErrHandoffApproval
		}
		if record.ActivationRound < round+8 {
			record.ActivationRound = round + 8
		}
		record.FrozenID = make([]byte, 32)
		record.SuccessorTRHash = make([]byte, 32)
		return [][]byte{record.Bytes()}, nil
	case "prepared":
		previous, err := storage.DecodeOrderedHandoffRecord(control.RecordBytes)
		if err != nil || !bytes.Equal(previous.NextBodyID, record.NextBodyID) || previous.Attempt != record.Attempt {
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
		if len(plan.plan.CandidatePreimage) != 0 {
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
		record.ActivationRound = previous.ActivationRound
		if round > ^uint64(0)-8 {
			return nil, ErrHandoffApproval
		}
		if record.ActivationRound < round+8 {
			record.ActivationRound = round + 8
		}
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
	if pending == nil || !bytes.Equal(pending.target.NextBodyID, target.NextBodyID) || pending.weight < trust.QuorumThreshold {
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
// each endorser re-derives the same values before it signs.
type EVMAssignmentContext struct {
	Network      uint64                            `json:"network"`
	Predecessor  hex.Bytes                         `json:"predecessor"`
	Attempt      uint64                            `json:"attempt"`
	FrozenParent hex.Bytes                         `json:"frozenParent"`
	Installed    *types.PartitionDescriptionRecord `json:"installed"`
	Pending      bool                              `json:"acknowledgementPending"`
}

// EVMAssignmentContext reports the possession-proof context for a proposal that freezes
// frozenParent now. A successor key holder signs evmassign.PoPMessage for exactly this
// network, predecessor, attempt and parent; a stale or different context is refused later.
func (x *ConsensusManager) EVMAssignmentContext(frozenParent []byte) (EVMAssignmentContext, error) {
	if !x.blockStore.HighQCFrozenParent(frozenParent) {
		return EVMAssignmentContext{}, ErrHandoffApproval
	}
	state, err := x.blockStore.GetState()
	if err != nil || state == nil || state.CommittedHead == nil || state.CommittedHead.Control == nil {
		return EVMAssignmentContext{}, ErrHandoffApproval
	}
	control := state.CommittedHead.Control
	if control.Phase != "idle" && control.Phase != "aborted" {
		return EVMAssignmentContext{}, ErrHandoffApproval
	}
	attempt := uint64(0)
	if control.Phase == "aborted" {
		if control.Attempt == ^uint64(0) {
			return EVMAssignmentContext{}, ErrHandoffApproval
		}
		attempt = control.Attempt + 1
	}
	predecessor, err := x.handoffPredecessor()
	if err != nil {
		return EVMAssignmentContext{}, err
	}
	shard, installed, err := x.installedEVMFromState(state, frozenParent, true)
	if err != nil {
		return EVMAssignmentContext{}, err
	}
	return EVMAssignmentContext{Network: uint64(x.orchestration.NetworkID()), Predecessor: predecessor, Attempt: attempt,
		FrozenParent: bytes.Clone(frozenParent), Installed: installed, Pending: pendingAssignmentAck(shard)}, nil
}
