package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-go-base/types"
)

// planBody is what the operator pipeline reads of a plan's successor body of either version: its identity and the facts the Prepare,
// the endorsements and the Freeze are bound to. A version-3 body carries the exact member weights and the protocol tuple; a version-2
// body is unit-weight.
type planBody struct {
	version            uint64
	id                 [32]byte
	network, epoch     uint64
	earliest           uint64
	members            []evmassign.RootMember
	stateSummary       []byte
	changeRecordHash   []byte
	predecessorHash    []byte
	weightedAssignment bool // the successor EVM assignment is validated under the weighted rules
}

// decodePlanBody reads a plan body. A version-3 body is accepted only by a manager wired to a verified Q3 history; the history's rule set
// validates it in full. Anything else is a version-2 body, as before.
func (x *ConsensusManager) decodePlanBody(raw []byte) (planBody, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return planBody{}, ErrHandoffApproval
	}
	if v, err := q3format.Version(raw); err == nil && v == q3format.BodyVersion {
		if x.q3 == nil {
			return planBody{}, fmt.Errorf("%w: a V3 body without a Q3 history", ErrHandoffApproval)
		}
		b, err := x.q3.FreezeRules().VerifyBody(raw)
		if err != nil {
			return planBody{}, errors.Join(ErrHandoffApproval, err)
		}
		return planBody{version: 3, id: b.ID, network: b.Network, epoch: b.Epoch, earliest: b.EarliestActivation, members: b.Members,
			stateSummary: b.StateSummary, changeRecordHash: b.ChangeRecordHash, predecessorHash: b.PredecessorHash, weightedAssignment: true}, nil
	}
	body, err := storage.DecodeHandoffBody(raw)
	if err != nil {
		return planBody{}, ErrHandoffApproval
	}
	members := make([]evmassign.RootMember, len(body.Members))
	for i, m := range body.Members {
		members[i] = evmassign.RootMember{NodeID: m.NodeID, Key: bytes.Clone(m.ConsensusKey), Weight: m.Weight}
	}
	return planBody{version: 2, id: body.Identity(), network: body.NetworkID, epoch: body.Epoch, earliest: body.EarliestActivation, members: members,
		stateSummary: body.StateSummary, changeRecordHash: body.ChangeRecordHash, predecessorHash: body.PredecessorHash}, nil
}

// assignmentRules is the validator weight rule set of the successor EVM assignment of a plan.
func (b planBody) assignmentRules() evmassign.Rules {
	if b.weightedAssignment {
		return weightvalidation.EVMRules(weightvalidation.ModeWeighted)
	}
	return evmassign.UnitRules
}

// currentBodyVersion is the version of the body of the epoch this validator is the committee of: 1 for the genesis, 3 for a verified Q3
// activation, 2 for the V2 lineage.
func (x *ConsensusManager) currentBodyVersion() uint64 {
	current := x.trustBase.Load()
	switch {
	case current == nil:
		return 0
	case current.Epoch == 1:
		return 1
	case x.q3 != nil:
		if _, ok := x.q3.Activated(current.Epoch); ok {
			return q3format.BodyVersion
		}
	}
	return 2
}

// planPredecessorLink is the predecessor hash a successor body of the given version must carry, for the epoch this validator is the
// committee of and the predecessor identity handoffPredecessor returned.
func (x *ConsensusManager) planPredecessorLink(version uint64, predecessor []byte) ([]byte, error) {
	old := x.trustBase.Load()
	if old == nil {
		return nil, ErrHandoffApproval
	}
	if version == q3format.BodyVersion {
		if x.q3 == nil {
			return nil, ErrHandoffApproval
		}
		return x.q3.FreezeRules().Prior(uint64(old.NetworkID), old.Epoch, x.currentBodyVersion(), predecessor)
	}
	if x.currentBodyVersion() == q3format.BodyVersion { // a V3 epoch has V3 successors only
		return nil, ErrHandoffApproval
	}
	if old.Epoch == 1 {
		return evmroot.FirstV2PredecessorHash(evmroot.V1Anchor{Version: 1, NetworkID: uint64(old.NetworkID), Epoch: old.Epoch, HashIncludingSigs: predecessor})
	}
	return predecessor, nil
}

// V3Candidate is the unsigned half of a V3 plan: the body, candidate digest and attempt every successor member must declare itself ready
// for, before any readiness receipt exists. The operator derives it from a validator's committed state, collects one receipt per
// member over exactly it, and hands the receipts back to PlanHandoffV3.
type V3Candidate struct {
	Body              q3format.BodyV3
	Candidate         [32]byte
	CandidatePreimage []byte
	Attempt           uint64
	ActivationRound   uint64
}

// PlanV3Candidate derives the V3 body and candidate of the next epoch's committee with its exact weights and, for a coupled change, the
// successor EVM assignment mirroring them. It registers nothing.
func (x *ConsensusManager) PlanV3Candidate(next *types.RootTrustBaseV1, proposal *evmassign.Proposal) (V3Candidate, error) {
	if x.q3 == nil {
		return V3Candidate{}, fmt.Errorf("%w: no Q3 history", ErrHandoffApproval)
	}
	state, err := x.blockStore.GetState()
	if err != nil {
		return V3Candidate{}, ErrHandoffApproval
	}
	c, err := x.v3CandidateFromState(next, state, proposal)
	if err != nil {
		return V3Candidate{}, err
	}
	x.v3Planned.Store(&c)
	// The candidate this validator derived is the one its operator will have the entity attest readiness for: the staged value a
	// readiness check compares with the candidate a receipt binds. It is a report of what this node holds, not an authority.
	x.q3Staged.Store(&Q3Staged{CandidateDigest: c.Candidate, BodyID: c.Body.Identity(), Attempt: c.Attempt})
	return c, nil
}

// Q3Staged is the candidate this validator last derived for its operator.
type Q3Staged struct {
	CandidateDigest [32]byte
	BodyID          [32]byte
	Attempt         uint64
}

// Q3Status is what this validator reports about itself for a readiness check: the chain it is bound to and the candidate it has staged.
// Staged is nil when no candidate was derived.
type Q3Status struct {
	Network     uint64
	Genesis     [32]byte
	Staged      *Q3Staged
	ActiveEpoch uint64
}

// Q3Status reports the chain this node's verified history is rooted in, the staged candidate and the installed epoch.
func (x *ConsensusManager) Q3Status() (Q3Status, error) {
	if x.q3 == nil {
		return Q3Status{}, fmt.Errorf("%w: no Q3 history", ErrHandoffApproval)
	}
	cfg, err := x.q3.ProtocolConfig()
	if err != nil {
		return Q3Status{}, err
	}
	return Q3Status{Network: cfg.Network, Genesis: cfg.Genesis, Staged: x.q3Staged.Load(), ActiveEpoch: x.InstalledRootEpoch()}, nil
}

// ErrV3CandidateSuperseded is returned when the candidate the members signed readiness for is not the one this validator would derive any
// more: the attempt it was derived for is over.
var ErrV3CandidateSuperseded = errors.New("consensus: the V3 candidate was derived for another attempt")

// PlanHandoffV3 builds the plan of a coupled V3 handoff from the candidate PlanV3Candidate derived and the readiness receipts of every
// successor member, and registers it as this validator's intent exactly as PlanHandoff does. The receipts are checked against the body and
// attempt this validator derived itself, so no Prepare is ever built for a candidate a member did not declare itself ready for.
func (x *ConsensusManager) PlanHandoffV3(next *types.RootTrustBaseV1, proposal *evmassign.Proposal, receipts []byte) (abdrc.HandoffApprovalMsg, error) {
	if x.q3 == nil {
		return abdrc.HandoffApprovalMsg{}, fmt.Errorf("%w: no Q3 history", ErrHandoffApproval)
	}
	state, err := x.blockStore.GetState()
	if err != nil {
		return abdrc.HandoffApprovalMsg{}, ErrHandoffApproval
	}
	plan, err := x.buildHandoffPlanV3FromState(next, state, proposal, receipts)
	if err != nil {
		return abdrc.HandoffApprovalMsg{}, err
	}
	x.setHandoffIntent(plan)
	return plan, nil
}

func (x *ConsensusManager) buildHandoffPlanV3FromState(next *types.RootTrustBaseV1, state *abdrc.StateMsg, proposal *evmassign.Proposal, receipts []byte) (abdrc.HandoffApprovalMsg, error) {
	c, err := x.v3CandidateFromState(next, state, proposal)
	if err != nil {
		return abdrc.HandoffApprovalMsg{}, err
	}
	// The receipts are bound to the exact body the members were asked about, and its earliest activation and change record depend on the
	// committed round it was derived at. The candidate derived here carries the SAME digest when it is the same candidate, so the body
	// is the one derived then, not a rebuild at the current round; only a candidate of another attempt is refused as superseded.
	if staged := x.v3Planned.Load(); staged != nil && staged.Candidate == c.Candidate {
		if staged.Attempt != c.Attempt {
			return abdrc.HandoffApprovalMsg{}, errors.Join(ErrHandoffApproval, ErrV3CandidateSuperseded)
		}
		c = *staged
	}
	raw := c.Body.Encode()
	if err := x.q3.FreezeRules().VerifyReceipts(raw, receipts, c.Attempt, c.Candidate[:]); err != nil {
		return abdrc.HandoffApprovalMsg{}, errors.Join(ErrHandoffApproval, err)
	}
	return abdrc.HandoffApprovalMsg{Body: raw, Candidate: c.Candidate[:], ActivationRound: c.ActivationRound, Attempt: c.Attempt,
		CandidatePreimage: c.CandidatePreimage, Receipts: bytes.Clone(receipts)}, nil
}

func (x *ConsensusManager) v3CandidateFromState(next *types.RootTrustBaseV1, state *abdrc.StateMsg, proposal *evmassign.Proposal) (V3Candidate, error) {
	none := V3Candidate{}
	old := x.trustBase.Load()
	if old == nil || next == nil || old.Epoch == ^uint64(0) || next.Epoch != old.Epoch+1 || next.NetworkID != old.NetworkID {
		return none, ErrHandoffApproval
	}
	predecessor, err := x.handoffPredecessor()
	if err != nil {
		return none, err
	}
	if state == nil || state.CommittedHead == nil || state.CommittedHead.Block == nil || state.CommittedHead.Block.Epoch != old.Epoch ||
		state.CommittedHead.CommitQc == nil || state.CommittedHead.CommitQc.LedgerCommitInfo == nil {
		return none, ErrHandoffApproval
	}
	round := state.CommittedHead.Block.Round
	attempt, err := plannedAttempt(state.CommittedHead.Control, round)
	if err != nil {
		return none, err
	}
	if round == 0 || round > ^uint64(0)-16 {
		return none, ErrHandoffApproval
	}
	members := make(evmroot.WeightSet, 0, len(next.RootNodes))
	for _, node := range next.RootNodes {
		if node == nil {
			return none, ErrHandoffApproval
		}
		members = append(members, evmroot.Member{StakingID: node.NodeID, NodeID: node.NodeID, ConsensusKey: bytes.Clone(node.SigKey), Weight: node.Stake})
	}
	sort.Slice(members, func(i, j int) bool { return members[i].NodeID < members[j].NodeID })
	var total quorumweight.Tally
	for _, m := range members {
		if total.Add(m.NodeID, m.Weight) != nil {
			return none, ErrHandoffApproval
		}
	}
	threshold, err := quorumweight.Threshold(total.Weight())
	if err != nil {
		return none, ErrHandoffApproval
	}
	// a V3 change of the committee that the installed EVM configuration requires coupled is a coupled change: the assignment mirrors it
	var candidate [32]byte
	var preimage []byte
	if proposal != nil {
		if preimage, candidate, err = x.buildAssignmentCandidateWith(weightvalidation.EVMRules(weightvalidation.ModeWeighted), old, next, predecessor, attempt, state, proposal); err != nil {
			return none, err
		}
	} else {
		if err := x.refuseRootChangeWhileAckPending(state, nil); err != nil {
			return none, err
		}
		if err := x.refuseUncoupledCommitteeChange(old, next, state, nil); err != nil {
			return none, err
		}
		if candidate, err = evmroot.D4OperatorCandidateDigest(members); err != nil {
			return none, err
		}
	}
	cfg, err := x.q3.ProtocolConfig()
	if err != nil {
		return none, errors.Join(ErrHandoffApproval, err)
	}
	aMin := round + 16
	link, err := x.planPredecessorLink(q3format.BodyVersion, predecessor)
	if err != nil {
		return none, err
	}
	body := q3format.BodyV3{Network: uint64(old.NetworkID), Epoch: next.Epoch, EarliestActivation: aMin, Members: members, RootThreshold: threshold,
		StateSummary:     intentSummary(uint64(old.NetworkID), predecessor, attempt),
		ChangeRecordHash: evmroot.D4CandidateContextHash(uint64(old.NetworkID), predecessor, attempt, candidate[:], aMin),
		PredecessorHash:  link, Config: cfg}
	if err := body.Validate(); err != nil {
		return none, errors.Join(ErrHandoffApproval, err)
	}
	return V3Candidate{Body: body, Candidate: candidate, CandidatePreimage: preimage, Attempt: attempt, ActivationRound: aMin}, nil
}

// StageV3Candidate records a candidate another of this chain's validators derived (PlanV3Candidate) as the one this validator's operator
// is about to have the entity attest readiness for. It checks what needs no signature and no EVM state: the body is a valid V3 body of
// this chain's protocol tuple, the next epoch of the one installed here. The plan itself is checked in full, against this validator's own
// state, when it is endorsed; staging only reports what this node holds.
func (x *ConsensusManager) StageV3Candidate(body []byte, candidate [32]byte, attempt uint64) error {
	if x.q3 == nil {
		return fmt.Errorf("%w: no Q3 history", ErrHandoffApproval)
	}
	b, err := q3format.DecodeBody(body)
	if err != nil {
		return errors.Join(ErrHandoffApproval, err)
	}
	cfg, err := x.q3.ProtocolConfig()
	if err != nil {
		return errors.Join(ErrHandoffApproval, err)
	}
	old := x.trustBase.Load()
	if old == nil || b.Config != cfg || b.Network != uint64(old.NetworkID) || b.Epoch != old.Epoch+1 {
		return fmt.Errorf("%w: the candidate is not the next epoch of this chain", ErrHandoffApproval)
	}
	x.q3Staged.Store(&Q3Staged{CandidateDigest: candidate, BodyID: b.Identity(), Attempt: attempt})
	return nil
}
