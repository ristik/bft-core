package evmroot

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// D4 epoch-handoff state machine. Executable model of the ordered root
// transition prepare -> freeze -> endorse -> commit -> activate ->
// acknowledge, plus committed-abort, from governance.tex §"root handoff".
//
// The model's job is to make two safety properties checkable by
// exploration:
//
//   - no two effective successors for one epoch, and
//   - no root round at which both the old and the new assignment may
//     authorise a governance block (no overlap, no gap),
//
// while never requiring a signed message to commit to state that is not
// yet known at the moment it is signed.
//
// Normative source: docs/design/d4-epoch-handoff-state-machine.md,
// docs/adr/0006-epoch-handoff-state-machine.md. Issue:
// https://github.com/ristik/bft-core/issues/6

// Phase is the handoff state. Progress is strictly Prepared -> Frozen ->
// Endorsed -> Committed -> Activated -> Acknowledged; Aborted is reachable
// only from a pre-Committed phase.
type Phase uint8

const (
	PhaseIdle Phase = iota
	PhasePrepared
	PhaseFrozen
	PhaseEndorsed
	PhaseCommitted
	PhaseActivated
	PhaseAcknowledged
	PhaseAborted
)

func (p Phase) String() string {
	return [...]string{"idle", "prepared", "frozen", "endorsed", "committed", "activated", "acknowledged", "aborted"}[p]
}

// AssignmentID names which validator set may authorise a governance block.
type AssignmentID string

const (
	OldAssignment AssignmentID = "old"
	NewAssignment AssignmentID = "new"
)

// Candidate is the committed election candidate (appendix-evm.tex
// §"Candidate Record"), reduced to what the handoff state machine needs.
type Candidate struct {
	Network         uint64
	NextEpoch       uint64
	Attempt         uint64 // j — attempt number; a new attempt after an abort is j+1
	PredecessorHash []byte // h_e — the current trust-base body identity
	MinActivation   uint64 // A_min — earliest activation bound, NOT the actual round
	MembersHash     []byte // hash of the complete identity/key/weight records
}

// PipelineDepth is the root-consensus pipeline depth: a commit QC decided
// at root round r is final at r + PipelineDepth. The committed activation
// round must be at least commitRound + PipelineDepth so the commit is final
// before it is reached.
const PipelineDepth uint64 = 3

// Handoff is the durable state of one in-progress handoff.
type Handoff struct {
	Phase       Phase
	Candidate   Candidate
	ProtocolVer uint64

	// Set at Freeze:
	FrozenSummary []byte // frozen root state summary — determined by the handoff, not a local clock
	LastEVMParent []byte // last certified EVM block hash the new assignment resumes from
	BodyIdentity  []byte // identity of the constructed next trust-base body (D3 v2, witness-free)

	// Set at Endorse:
	EndorsementWeight uint64 // old-epoch unique signer weight on the endorsement
	EndorsementDomain SigDomain

	// Set at Commit:
	CommitRound     uint64 // root round at which the endorsed handoff was committed
	ActivationRound uint64 // A* — the actual boundary, fixed here, >= MinActivation and >= CommitRound+PipelineDepth
	SuccessorTRHash []byte // successor technical record

	// Set at Acknowledge:
	AckEVMRound uint64 // EVM block round whose system op acknowledged the handoff

	AbortReason string
}

// SigDomain is the set of fields a phase's signed message binds. The model
// asserts that no field names state unknown at signing time (see
// FieldsAreKnown).
type SigDomain struct {
	Phase           string
	Network         uint64
	ProtocolVer     uint64
	PredecessorHash []byte
	Attempt         uint64
	BodyIdentity    []byte // known from Freeze onward
	MinActivation   uint64 // known from the candidate
	ActivationRound uint64 // 0 until Commit — MUST be 0 in the endorsement domain
	SuccessorTRHash []byte // nil until Commit
}

var (
	errPhase          = errors.New("d4: transition not allowed from this phase")
	errActivationRoot = errors.New("d4: activation round below MinActivation or not final under pipelining")
	errNoCommit       = errors.New("d4: cannot activate without a committed handoff record")
	errEndorseWeight  = errors.New("d4: endorsement weight below the old root threshold")
	errFutureState    = errors.New("d4: signed domain binds state not known at signing time")
)

// NewHandoff starts an Idle handoff for a candidate.
func NewHandoff(c Candidate, protocolVer uint64) *Handoff {
	return &Handoff{Phase: PhaseIdle, Candidate: c, ProtocolVer: protocolVer}
}

// Prepare commits the prepare record under the old root quorum: admission
// of new old-assignment governance proposals is closed and in-flight work
// is drained or cancelled. Only from Idle.
func (h *Handoff) Prepare() error {
	if h.Phase != PhaseIdle {
		return errPhase
	}
	h.Phase = PhasePrepared
	return nil
}

// Freeze records the last certified EVM block/state and the frozen root
// state summary, and constructs the next trust-base body. Only from
// Prepared.
func (h *Handoff) Freeze(frozenSummary, lastEVMParent []byte, body TrustBaseBodyV2) error {
	if h.Phase != PhasePrepared {
		return errPhase
	}
	h.FrozenSummary = frozenSummary
	h.LastEVMParent = lastEVMParent
	id := body.Identity()
	h.BodyIdentity = id[:]
	h.Phase = PhaseFrozen
	return nil
}

// EndorsementDomainFor returns the exact field set the endorsement
// signature binds. It never includes ActivationRound or SuccessorTRHash —
// those are unknown until Commit.
func (h *Handoff) EndorsementDomainFor() SigDomain {
	return SigDomain{
		Phase:           "endorse",
		Network:         h.Candidate.Network,
		ProtocolVer:     h.ProtocolVer,
		PredecessorHash: h.Candidate.PredecessorHash,
		Attempt:         h.Candidate.Attempt,
		BodyIdentity:    h.BodyIdentity,
		MinActivation:   h.Candidate.MinActivation,
		ActivationRound: 0,
		SuccessorTRHash: nil,
	}
}

// Endorse records old-validator endorsement of the agreed body. weight is
// the old-epoch unique signer weight; oldThreshold is D3's ⌊2W/3⌋+1 for the
// outgoing assignment. Only from Frozen.
func (h *Handoff) Endorse(weight, oldThreshold uint64) error {
	if h.Phase != PhaseFrozen {
		return errPhase
	}
	dom := h.EndorsementDomainFor()
	if !FieldsAreKnown(dom) {
		return errFutureState
	}
	if weight < oldThreshold {
		return errEndorseWeight
	}
	h.EndorsementWeight = weight
	h.EndorsementDomain = dom
	h.Phase = PhaseEndorsed
	return nil
}

// Commit commits the endorsed handoff under the old consensus rules,
// binding the new body, the actual activation boundary and the successor
// technical record. commitRound is the root round of this commit;
// activationRound is A*. Only from Endorsed.
func (h *Handoff) Commit(commitRound, activationRound uint64, successorTRHash []byte) error {
	if h.Phase != PhaseEndorsed {
		return errPhase
	}
	if activationRound < h.Candidate.MinActivation || activationRound < commitRound+PipelineDepth {
		return errActivationRoot
	}
	h.CommitRound = commitRound
	h.ActivationRound = activationRound
	h.SuccessorTRHash = successorTRHash
	h.Phase = PhaseCommitted
	return nil
}

// Activate lets the new root set resume from the certified handoff state.
// observedRootRound is the certified root round the new set has imported.
// It is allowed only from Committed and only once observedRootRound has
// reached the committed A* — never because a locally submitted trust base's
// proposed start round was reached.
func (h *Handoff) Activate(observedRootRound uint64) error {
	if h.Phase != PhaseCommitted {
		if h.Phase == PhasePrepared || h.Phase == PhaseFrozen || h.Phase == PhaseEndorsed {
			return errNoCommit // an incomplete prepare cannot activate
		}
		return errPhase
	}
	if observedRootRound < h.ActivationRound {
		return fmt.Errorf("d4: observed root round %d has not reached committed activation round %d", observedRootRound, h.ActivationRound)
	}
	h.Phase = PhaseActivated
	return nil
}

// Acknowledge records that the first new-assignment governance block's
// system operation acknowledged the handoff, closing the old assignment's
// liabilities. Only from Activated.
func (h *Handoff) Acknowledge(evmRound uint64) error {
	if h.Phase != PhaseActivated {
		return errPhase
	}
	h.AckEVMRound = evmRound
	h.Phase = PhaseAcknowledged
	return nil
}

// Abort is the old-quorum committed abort of an incomplete prepare. Allowed
// only before Commit. After it, this attempt (j) is dead; a replacement
// needs attempt j+1 and the same predecessor.
func (h *Handoff) Abort(reason string) error {
	switch h.Phase {
	case PhasePrepared, PhaseFrozen, PhaseEndorsed:
		h.Phase = PhaseAborted
		h.AbortReason = reason
		return nil
	default:
		return errPhase
	}
}

// Authorized reports which assignment may authorise a governance block
// whose imported root round is observedRootRound. This is the function the
// safety exploration checks for overlap and gaps.
//
//   - Before a committed handoff (or after an abort): always the old set.
//   - From Committed onward: old for rounds strictly below A*, new for
//     rounds at or above A*. There is no round assigned to both and none
//     assigned to neither.
func (h *Handoff) Authorized(observedRootRound uint64) AssignmentID {
	switch h.Phase {
	case PhaseCommitted, PhaseActivated, PhaseAcknowledged:
		if observedRootRound >= h.ActivationRound {
			return NewAssignment
		}
		return OldAssignment
	default:
		return OldAssignment
	}
}

// FieldsAreKnown reports whether every field in a signed domain is known at
// the time that phase signs. For the endorsement phase, ActivationRound and
// SuccessorTRHash must be zero/nil — binding them there would be a
// signature over state fixed only at Commit.
func FieldsAreKnown(d SigDomain) bool {
	if d.Phase == "endorse" {
		return d.ActivationRound == 0 && d.SuccessorTRHash == nil && len(d.BodyIdentity) == 32
	}
	if d.Phase == "commit" {
		// At commit, A* is known and bounded by pipelining; the successor
		// TR is constructed now. Nothing here is future EVM state.
		return d.ActivationRound != 0 && len(d.SuccessorTRHash) > 0
	}
	return true
}

// CommitDomainFor returns the field set the commit signature binds.
func (h *Handoff) CommitDomainFor() SigDomain {
	return SigDomain{
		Phase:           "commit",
		Network:         h.Candidate.Network,
		ProtocolVer:     h.ProtocolVer,
		PredecessorHash: h.Candidate.PredecessorHash,
		Attempt:         h.Candidate.Attempt,
		BodyIdentity:    h.BodyIdentity,
		MinActivation:   h.Candidate.MinActivation,
		ActivationRound: h.ActivationRound,
		SuccessorTRHash: h.SuccessorTRHash,
	}
}

// sampleBody builds a representative next trust-base body for the model.
func sampleHandoffBody(predecessor []byte) TrustBaseBodyV2 {
	ws := d3Assignment()
	w, _ := ws.TotalWeight()
	return TrustBaseBodyV2{
		Version: 2, NetworkID: 3, Epoch: 8, EpochStart: 0, // EpochStart fixed by the committed handoff, not here
		Members: ws, RootThreshold: RootQuorumThreshold(w),
		StateSummary: rep(0x5A, 32), ChangeRecordHash: sha256Slice([]byte("candidate-8-attempt-0")),
		PredecessorHash: predecessor,
	}
}

func sha256Slice(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
