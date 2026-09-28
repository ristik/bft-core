package consensus

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

var ErrHandoffApproval = errors.New("root handoff: invalid operator approval")

type pendingHandoff struct {
	plan       abdrc.HandoffApprovalMsg
	body       evmroot.TrustBaseBodyV2
	record     evmroot.OrderedHandoffRecord
	signatures map[string]hex.Bytes
	weight     uint64
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
	state, err := x.blockStore.GetState()
	if err != nil {
		return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
	}
	return x.buildHandoffPlanFromState(next, frozenParent, state)
}

func (x *ConsensusManager) buildHandoffPlanFromState(next *types.RootTrustBaseV1, frozenParent []byte, state *abdrc.StateMsg) (abdrc.HandoffApprovalMsg, error) {
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
	if state.CommittedHead.Control == nil || state.CommittedHead.Control.Phase != "idle" {
		return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
	}
	certifiedParent := false
	for _, shard := range state.CommittedHead.ShardInfo {
		if shard.IR != nil && bytes.Equal(shard.IR.BlockHash, frozenParent) {
			certifiedParent = true
			break
		}
	}
	if !certifiedParent {
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
	aMin := round + 16
	body := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: uint64(old.NetworkID), Epoch: next.Epoch,
		EarliestActivation: aMin, Members: members, RootThreshold: evmroot.RootQuorumThreshold(uint64(len(members))),
		StateSummary:     evmroot.D4PreFreezeSummary(uint64(old.NetworkID), predecessor, 0, round, root, frozenParent),
		ChangeRecordHash: evmroot.D4CandidateContextHash(uint64(old.NetworkID), predecessor, 0, candidate[:], aMin)}
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
		ActivationRound: aMin}, nil
}

func (x *ConsensusManager) validateHandoffApproval(msg *abdrc.HandoffApprovalMsg) (*pendingHandoff, uint64, error) {
	if msg == nil || len(msg.Body) == 0 || len(msg.Body) > 1<<20 || len(msg.FrozenParent) != 32 ||
		len(msg.Candidate) != 32 || len(msg.PreFreezeRoot) != 32 || msg.PreFreezeRound == 0 ||
		msg.Attempt != 0 || msg.ActivationRound == 0 || msg.Signer == "" || len(msg.Signature) == 0 {
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
	return &pendingHandoff{plan: *msg, body: body, record: record}, weight, nil
}

// EndorseHandoff is called by the local operator endpoint on each validator.
// It signs one immutable candidate and disseminates that approval through the
// root network; no validator signs merely because another peer asked it to.
func (x *ConsensusManager) EndorseHandoff(ctx context.Context, plan abdrc.HandoffApprovalMsg) error {
	if plan.Signer != "" || len(plan.Signature) != 0 {
		return ErrHandoffApproval
	}
	plan.Signer = x.id.String()
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
		x.handoffPlans[id] = stored
	} else if !bytes.Equal(stored.plan.Body, msg.Body) || !bytes.Equal(stored.plan.FrozenParent, msg.FrozenParent) ||
		!bytes.Equal(stored.plan.Candidate, msg.Candidate) || stored.plan.ActivationRound != msg.ActivationRound ||
		stored.plan.PreFreezeRound != msg.PreFreezeRound || !bytes.Equal(stored.plan.PreFreezeRoot, msg.PreFreezeRoot) || stored.plan.Attempt != msg.Attempt {
		return ErrHandoffApproval
	}
	if _, exists := stored.signatures[msg.Signer]; exists {
		return nil
	}
	stored.signatures[msg.Signer] = bytes.Clone(msg.Signature)
	stored.weight += weight
	return nil
}

func (x *ConsensusManager) readyHandoff() (*pendingHandoff, error) {
	x.handoffMu.Lock()
	defer x.handoffMu.Unlock()
	threshold := x.trustBase.Load().QuorumThreshold
	for _, plan := range x.handoffPlans {
		if plan.weight >= threshold {
			copyPlan := *plan
			copyPlan.signatures = make(map[string]hex.Bytes, len(plan.signatures))
			for signer, sig := range plan.signatures {
				copyPlan.signatures[signer] = bytes.Clone(sig)
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
	plan, err := x.readyHandoff()
	if err != nil {
		return nil, nil
	}
	record := plan.record
	record.OrderedRound = round
	switch control.Phase {
	case "idle", "aborted":
		if control.Phase == "aborted" {
			return nil, nil
		} // a new attempt needs fresh approvals
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
		record.ActivationRound = previous.ActivationRound
		record.Kind = "freeze"
		record.SuccessorTRHash = make([]byte, 32)
		companion, err := (storage.FreezeAuthorization{Version: 1, Body: bytes.Clone(plan.plan.Body),
			Parent: bytes.Clone(plan.plan.FrozenParent), Candidate: bytes.Clone(plan.plan.Candidate),
			Signatures: plan.signatures}).Bytes()
		if err != nil {
			return nil, err
		}
		return [][]byte{record.Bytes(), companion}, nil
	case "endorsed":
		previous, err := storage.DecodeOrderedHandoffRecord(control.RecordBytes)
		if err != nil || !bytes.Equal(previous.NextBodyID, record.NextBodyID) || previous.Attempt != record.Attempt {
			return nil, nil
		}
		record.ActivationRound = previous.ActivationRound
		if round > ^uint64(0)-8 {
			return nil, ErrHandoffApproval
		}
		if record.ActivationRound < round+8 {
			record.ActivationRound = round + 8
		}
		if len(parent.ShardState.States) != 1 {
			return nil, ErrHandoffApproval
		}
		for _, shard := range parent.ShardState.States {
			if shard == nil {
				return nil, ErrHandoffApproval
			}
			record.SuccessorTRHash, err = shard.TR.Hash()
			if err != nil {
				return nil, err
			}
		}
		record.Kind = "commit"
		return [][]byte{record.Bytes()}, nil
	default:
		return nil, nil
	}
}
