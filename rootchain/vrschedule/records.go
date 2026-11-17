package vrschedule

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The leader's handoff records of a planned certificate (stage 5 and 6): the Prepare at the quiet control state, the Freeze v5 at the
// prepared one, H at the endorsed one. The executor judges each exactly as it judges any other leader's.

// PreparePlan is a complete verified certificate of the current intent with the rule-support evidence its Freeze carries.
type PreparePlan struct {
	Intent      [32]byte
	Epoch       uint64
	Attempt     uint64
	Predecessor []byte
	Result      vrschema.Word
	Body        q3format.BodyV3
	Certificate vrschema.ViewCertificate
	RuleSupport vrschema.RuleSupportEvidence
}

// ErrRecord reports a record the plan cannot make at this control state.
var ErrRecord = errors.New("vrschedule: no handoff record for this control state")

// PrepareRecord is the Prepare of the plan at round: its body's identity and an activation round at the floor or the body's earliest
// activation, whichever is later.
func PrepareRecord(p PreparePlan, control *evmroot.ControlState, round uint64) ([]byte, error) {
	if control == nil || round > ^uint64(0)-storage.PrepareActivationFloorRounds {
		return nil, ErrRecord
	}
	id := p.Body.Identity()
	r := evmroot.OrderedHandoffRecord{Network: control.Network, Epoch: control.Epoch, Attempt: p.Attempt, OrderedRound: round,
		ActivationRound: max(p.Body.EarliestActivation, round+storage.PrepareActivationFloorRounds), PredecessorBodyID: bytes.Clone(p.Predecessor),
		NextBodyID: id[:], Kind: "prepare", FrozenID: make([]byte, 32), SuccessorTRHash: make([]byte, 32)}
	return r.Bytes(), nil
}

// FreezeRecord is the Freeze of the prepared plan at round with its Freeze v5 companion (the certificate, the rule-support evidence and the
// witness over VR at the frozen parent).
func FreezeRecord(p PreparePlan, control *evmroot.ControlState, round uint64, witness []byte) ([][]byte, error) {
	if control == nil || control.Phase != "prepared" || len(control.FrozenParent) != 32 {
		return nil, ErrRecord
	}
	previous, err := storage.DecodeOrderedHandoffRecord(control.RecordBytes)
	id := p.Body.Identity()
	if err != nil || previous.Attempt != p.Attempt || !bytes.Equal(previous.NextBodyID, id[:]) {
		return nil, ErrRecord
	}
	cd := sha256.Sum256(p.Certificate.Assembly.Candidate)
	r := previous
	r.Kind, r.OrderedRound, r.SuccessorTRHash = "freeze", round, make([]byte, 32)
	r.FrozenID = evmroot.D4FrozenID(id[:], p.Body.StateSummary, control.FrozenParent, cd[:], p.Attempt, control.PredecessorBodyID)
	companion, err := vrschema.FreezeV5{Candidate: p.Certificate.Assembly.Candidate, Certificate: p.Certificate, RuleSupport: p.RuleSupport, Witness: witness}.Encode()
	if err != nil {
		return nil, err
	}
	return [][]byte{r.Bytes(), companion}, nil
}

// CommitRecord is H of the endorsed plan at round: the activation round no nearer than the margin, and the successor technical record the
// candidate's assignment derives over the frozen shard.
func CommitRecord(p PreparePlan, control *evmroot.ControlState, round uint64, frozen *storage.ShardInfo, hash crypto.Hash) ([]byte, error) {
	if control == nil || control.Phase != "endorsed" || frozen == nil {
		return nil, ErrRecord
	}
	previous, err := storage.DecodeOrderedHandoffRecord(control.RecordBytes)
	id := p.Body.Identity()
	if err != nil || previous.Attempt != p.Attempt || !bytes.Equal(previous.NextBodyID, id[:]) {
		return nil, ErrRecord
	}
	activation, ok := storage.CommitActivationRound(previous.ActivationRound, round)
	if !ok {
		return nil, ErrRecord
	}
	tr, err := storage.AssignmentSuccessorTRHash(frozen, p.Certificate.Assembly.Candidate, activation, hash)
	if err != nil {
		return nil, err
	}
	r := previous
	r.Kind, r.OrderedRound, r.ActivationRound, r.SuccessorTRHash = "commit", round, activation, tr
	return r.Bytes(), nil
}

// VerifyPlan verifies a complete view certificate of the derived intent in full, exactly as Freeze validity will judge it (design section
// 5.3.5): the assembly is the intent's candidate with valid PoPs, signed by its view's assembler among the incumbents, the view is
// committed, and every successor's readiness is valid over the derived body and trust base. It returns the plan the leader orders.
func VerifyPlan(d Derived, incumbents map[string][]byte, committedView uint64, c vrschema.ViewCertificate) (PreparePlan, error) {
	cand, err := vrhandoff.VerifyAssembly(d.Intent, c.Assembly)
	if err != nil {
		return PreparePlan{}, err
	}
	body, err := vrhandoff.DeriveBody(d.Intent, d.RootEpoch, sha256.Sum256(c.Assembly.Candidate), d.Body)
	if err != nil {
		return PreparePlan{}, err
	}
	_, tb, err := vrhandoff.TrustBase(d.Intent, d.RootEpoch)
	if err != nil {
		return PreparePlan{}, err
	}
	if err := vradmit.VerifyCertificate(vradmit.CertificateInput{Certificate: c, IntentDigest: d.Digest, CommittedView: committedView, Incumbents: incumbents,
		CandidateBytes: c.Assembly.Candidate, Successors: cand.Identities, Body: body, Attempt: d.Intent.Attempt, TrustBaseBytes: tb}); err != nil {
		return PreparePlan{}, err
	}
	return PreparePlan{Intent: d.Digest, Epoch: d.RootEpoch, Attempt: d.Intent.Attempt, Predecessor: bytes.Clone(d.Intent.PredecessorBodyID),
		Result: vrschema.Word(cand.SourceRef), Body: body, Certificate: c}, nil
}

// LeaderStep is what a leader orders for a plan over a parent block: the records (none when Reason says why not) and their kind.
type LeaderStep struct {
	Kind    string // "prepare", "freeze", "commit", or "" when nothing is ordered
	Records [][]byte
	Reason  string
}

// LeaderRecords is the leader's handoff record of a VR chain for a plan over the parent block (design 5.3.1 stages 5 and 6): the Prepare
// of the plan's attempt at a quiet control state whose stored backoff attempt is that one, then its Freeze v5 once the Prepare bound the
// frozen parent (the witness is read there), then H. A plan of another epoch, predecessor, attempt or body orders nothing (its intent
// died); a Prepare whose lapse has not cooled down orders nothing. The attempt and body are checked before the witness is read. A due
// rejection's priority over a Prepare is the caller's.
func LeaderRecords(p PreparePlan, parent *storage.ExecutedBlock, round uint64, evm types.PartitionShardID, witness func(p, root [32]byte) ([]byte, error),
	hash crypto.Hash) (LeaderStep, error) {
	if parent == nil || parent.ShardState.Control == nil {
		return LeaderStep{Reason: "no control state"}, nil
	}
	control := parent.ShardState.Control
	if p.Epoch != control.Epoch {
		return LeaderStep{Reason: "the plan is of another epoch (its intent died)"}, nil
	}
	lapsed := storage.PrepareLapsed(control, round)
	if lapsed && !storage.PrepareMayFollowLapse(control, round) {
		return LeaderStep{Reason: "a lapsed Prepare's cooldown"}, nil
	}
	id := p.Body.Identity()
	switch {
	case control.Phase == "idle" || control.Phase == "aborted" || lapsed:
		attempt, ok, err := vradmit.PlannedAttempt(control, round)
		if err != nil {
			return LeaderStep{}, err
		}
		if !ok || attempt != p.Attempt {
			return LeaderStep{Reason: "the plan is of another attempt"}, nil
		}
		// the attempt must be the stored backoff identity: a Prepare in the block whose end opens its attempt is refused
		if s, err := vradmit.DecodeRootState(control.VR); err != nil || s.Backoff.Epoch != control.Epoch || s.Backoff.Attempt != attempt {
			return LeaderStep{Reason: "the attempt is not opened yet"}, nil
		}
		raw, err := PrepareRecord(p, control, round)
		if err != nil {
			return LeaderStep{}, err
		}
		return LeaderStep{Kind: "prepare", Records: [][]byte{raw}}, nil
	case control.Phase == "prepared", control.Phase == "endorsed":
		previous, err := storage.DecodeOrderedHandoffRecord(control.RecordBytes)
		if err != nil {
			return LeaderStep{}, err
		}
		if previous.Attempt != p.Attempt || !bytes.Equal(previous.NextBodyID, id[:]) {
			return LeaderStep{Reason: "another attempt or body is prepared"}, nil
		}
		si := parent.ShardState.States[evm]
		if si == nil || si.IR == nil || len(control.FrozenParent) != 32 || !bytes.Equal(si.IR.BlockHash, control.FrozenParent) || len(si.IR.Hash) != 32 {
			return LeaderStep{Reason: "the EVM shard does not certify the frozen parent"}, nil
		}
		if control.Phase == "endorsed" {
			raw, err := CommitRecord(p, control, round, si, hash)
			if err != nil {
				return LeaderStep{}, err
			}
			return LeaderStep{Kind: "commit", Records: [][]byte{raw}}, nil
		}
		w, err := witness([32]byte(control.FrozenParent), [32]byte(si.IR.Hash))
		if err != nil {
			return LeaderStep{}, fmt.Errorf("the Freeze witness at the frozen parent: %w", err)
		}
		records, err := FreezeRecord(p, control, round, w)
		if err != nil {
			return LeaderStep{}, err
		}
		return LeaderStep{Kind: "freeze", Records: records}, nil
	}
	return LeaderStep{Reason: "a handoff is in flight (" + control.Phase + ")"}, nil
}
