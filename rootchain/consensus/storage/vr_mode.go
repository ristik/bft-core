package storage

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
	"github.com/unicitynetwork/bft-core/q3format"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Validator-registry (VR) mode of the block executor (VT-05a part 2, ristik/bft-core#1145; design sections 4, 5 and 8). A chain is in VR
// mode exactly when its control state carries the VR root state (evmroot.ControlState.VR, from genesis): the mode switch is the pointer
// the generation pins, never a flag of the running root. A chain without it (P85) executes exactly as before.
//
// In VR mode:
//   - the root controls are UNICITY_VR_CONTROL ops 1 to 5 (P85 controls are refused, and VR controls on a P85 chain);
//   - a primary Freeze carries the Freeze v5 companion and is admitted by vradmit.VerifyRegistryOutput over the VR witness at the frozen
//     parent, with the shard acknowledgement gate; a recovery Freeze is the exact-recovery V3 companion, as before; Freeze v4, legacy
//     and root-only companions are refused;
//   - the acknowledgement projects Ack/RecoveryAck and the Boundary, a RejectResult v2 OutputRejected and SessionClosed, a HolderRetirement
//     v2 the holder-scoped record;
//   - the closure duty is always on;
//   - the backoff state machine (section 5.5) runs on every committed block: PR at a Prepare, FZ at a primary Freeze, HV at a HandoffView,
//     and the Open step at the end of the block.

var (
	// ErrVRMode reports a block that mixes the modes: a P85 control or companion on a VR chain, a VR control on a P85 chain, or a VR chain
	// without the services that judge it.
	ErrVRMode = errors.New("validator-registry mode")
	// ErrVRControlRefused reports a VR-mode control that fails verification.
	ErrVRControlRefused = errors.New("VR root control refused")
	// ErrVRFreeze reports a Freeze a VR chain refuses: a companion other than Freeze v5 or an exact-recovery V3 one, or a Freeze v5 whose
	// derived intent, body or frozen commitment does not match the record.
	ErrVRFreeze = errors.New("VR Freeze refused")
	// ErrVRUnavailable reports a judgment whose committed-history input (the derivable intent, the committed schedule) is not available
	// at this root: unavailable, never false, so the block cannot be voted until it is.
	ErrVRUnavailable = errors.New("VR input unavailable")
)

// VRStateAuthority verifies the VR witnesses against a certified EVM state root (rootchain/vrstate.Authority implements it; storage cannot
// import the readers, which import it through evmstate).
type VRStateAuthority interface {
	// VerifyOutput is the Freeze v5 witness: exactly VR, at the pinned address and code hash.
	VerifyOutput(witness []byte, stateRoot [32]byte, resultID vrschema.Word) (vradmit.OutputState, error)
	// VerifyReject is the RejectResult v2 witness: VR and the SealRegistry's progress.
	VerifyReject(witness []byte, stateRoot [32]byte, resultID vrschema.Word) (vradmit.RejectState, error)
	// VerifyRetirement is the three-account HolderRetirement witness; blockProgress and inFlight are the carrying block's root facts.
	VerifyRetirement(witness []byte, stateRoot [32]byte, h vrschema.HolderRetirement, blockProgress uint64, inFlight bool) (vrschema.RetirementWitness, error)
}

// VRIntentQuery is the committed root state an intent is derived over (design section 5.3.1 stages 0 and 1): the control state the
// block starts from, the committed backoff, the block's epoch and round, and the EVM state certified in the parent. Candidate is the
// assembled candidate v6 a Freeze carries (nil for a HandoffView).
type VRIntentQuery struct {
	Control        *evmroot.ControlState
	Backoff        vrschema.HandoffBackoff
	Epoch, Round   uint64
	LatestEVMRoot  [32]byte
	LatestEVMBlock []byte
	LatestEVMOK    bool
	Candidate      []byte
}

// VRIntent is the derivable intent of the stored attempt: its digest, the committed UC time of its anchor block (openTime(0)), and, for a
// Freeze, the successor body derived from it and the signing bytes of the successor trust base the readiness signs.
type VRIntent struct {
	Digest [32]byte
	// AnchorRound is the intent's anchor round, max(source.certRootRound, attemptOpenRound): view 0 opens at that block, and a root holds
	// the opening once that block is committed. AnchorUCTime is its committed UC time.
	AnchorRound  uint64
	AnchorUCTime uint64
	Body         q3format.BodyV3
	TrustBase    []byte
}

// VRIntents derives the intent from committed history and the VR proof (VT-05b's vrhandoff.DeriveIntent; a pure function of committed
// state, like ClosureAuthority). ok is false when no intent is derivable: no source, or the source is no longer Published and open at the
// latest certified EVM block. An error is unavailable, never false.
type VRIntents interface {
	Intent(q VRIntentQuery) (VRIntent, bool, error)
}

// VRSchedule is the root's committed activation schedule (VT-07a), root-latched entries included.
type VRSchedule interface {
	Committed(epoch uint64) ([]vrschema.Activation, error)
}

// VRServices are the collaborators of the VR-mode executor. Deployment names the VR generation (root network, VR's network and chain id
// words, its address and code hash). State verifies the witnesses; Intents and Schedule read committed history. A nil Schedule is the empty
// schedule; a nil Intents refuses every HandoffView and Freeze v5 (fail closed).
type VRServices struct {
	Deployment vradmit.Deployment
	State      VRStateAuthority
	Intents    VRIntents
	Schedule   VRSchedule
}

// domain is the deployment the VR-domain digests use: VR's network and chain id words, with VR's address as the deployment address
// (design section 5.6, op 1).
func (s *VRServices) domain() evmassign.Deployment {
	return evmassign.Deployment{NetworkWord: s.Deployment.NetworkWord, ChainID: s.Deployment.ChainID, Custody: s.Deployment.Registry}
}

func (s *VRServices) schedule(epoch uint64) ([]vrschema.Activation, error) {
	if s.Schedule == nil {
		return nil, nil
	}
	a, err := s.Schedule.Committed(epoch)
	if err != nil {
		return nil, errors.Join(ErrVRUnavailable, err)
	}
	return a, nil
}

// vrStep is the VR root state of the block being executed, loaded from the parent's control state and written back at the end of the block.
type vrStep struct {
	on      bool
	raw     []byte
	state   vradmit.RootState
	changed bool
	// frozen is the primary Freeze v5 this block admitted: what the store retains once the block is added.
	frozen *vrRetention
	// intent is the intent the Freeze authority derived for this block's Freeze, reused by its admission.
	intent *VRIntent
	fv5    *vrschema.FreezeV5
}

// vrRetention is what the store retains for an admitted Freeze v5: the successor body (derived, never carried), the merged readiness
// receipts, the v5 view of the candidate (which the install, lifecycle and acknowledgement paths read) and the canonical v6 bytes.
type vrRetention struct {
	Body, Receipts, V5, V6 []byte
}

// loadVR reads the VR root state of a control state; off on a P85 chain.
func loadVR(c *evmroot.ControlState) (vrStep, error) {
	if c == nil || len(c.VR) == 0 {
		return vrStep{}, nil
	}
	s, err := vradmit.DecodeRootState(c.VR)
	if err != nil {
		return vrStep{}, errors.Join(ErrVRMode, err)
	}
	return vrStep{on: true, raw: c.VR, state: s}, nil
}

func (v *vrStep) set(s vradmit.RootState) { v.state, v.changed = s, true }

// store writes the state into c, this block's private copy of the control state.
func (v *vrStep) store(c *evmroot.ControlState) error {
	if !v.on || c == nil {
		return nil
	}
	if v.changed {
		raw, err := v.state.Encode()
		if err != nil {
			return errors.Join(ErrVRMode, err)
		}
		v.raw, v.changed = raw, false
	}
	c.VR = v.raw
	return nil
}

// vrCommitteeSize is the assembler count of the epoch committee (the incumbents), or the stored one when the authority names none.
func vrCommitteeSize(authority handoffAuthority, stored uint32) uint32 {
	if authority != nil {
		if n := len(authority.CurrentRoot()); n > 0 && n <= vrschema.MaxCommittee {
			return uint32(n)
		}
	}
	return stored
}

// endBlock is the Open step, once at the end of every executed block, after all records and controls.
func (v *vrStep) endBlock(epoch, round uint64, after *evmroot.ControlState, authority handoffAuthority) error {
	if !v.on {
		return nil
	}
	next, err := v.state.EndBlock(epoch, round, vradmit.ControlOf(after), vrCommitteeSize(authority, v.state.Backoff.N))
	if err != nil {
		return errors.Join(ErrVRMode, err)
	}
	// the Open step changes only the backoff and the attempt's times: an unchanged block leaves the committed encoding as it was
	if !backoffEqual(next.Backoff, v.state.Backoff) || next.OpenUCTime != v.state.OpenUCTime || next.PrepareUCTime != v.state.PrepareUCTime {
		v.set(next)
	}
	return nil
}

func backoffEqual(a, b vrschema.HandoffBackoff) bool {
	x, err1 := a.Encode()
	y, err2 := b.Encode()
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

// prepare is PR: a committed Prepare of the stored attempt (design section 5.5.2). A Prepare of any other attempt is refused, which is
// the control-validation half of the plannedAttempt alignment: the next attempt exists only from the block after the Open step created it.
func (v *vrStep) prepare(epoch, attempt, ucTime uint64) error {
	if !v.on {
		return nil
	}
	next, err := v.state.ApplyPrepare(epoch, attempt, ucTime)
	if err != nil {
		return errors.Join(ErrHandoffRecord, ErrVRMode, err)
	}
	v.set(next)
	return nil
}

// vrFreezeAuthority is the handoff authority of a VR chain: a Freeze v5 companion is judged here (the derived intent and body, the frozen
// commitment), an exact-recovery V3 companion by the base authority as before, and every other companion is refused. A Freeze v5 carries
// no old-set endorsement: the incumbents' agreement is the block's own certificate over a Freeze every voter re-derives (section 5.3.5).
type vrFreezeAuthority struct {
	handoffAuthority
	vr     *vrStep
	svc    *VRServices
	query  VRIntentQuery
	parent []byte // the frozen parent the Prepare bound
}

// vrBodyLinker is the predecessor hash a successor body of the epoch carries (v1HandoffAuthority with V3 rules implements it).
type vrBodyLinker interface {
	vrSuccessorLink(network, epoch uint64) ([]byte, error)
}

func (a *v1HandoffAuthority) vrSuccessorLink(network, epoch uint64) ([]byte, error) {
	if a.v3 == nil {
		return nil, ErrFreezeV3Disabled
	}
	return a.v3.Prior(network, epoch, a.priorVersion, a.predecessor)
}

func (a *vrFreezeAuthority) VerifyFreeze(r evmroot.OrderedHandoffRecord, companion []byte) ([]byte, error) {
	if fv, err := vrschema.DecodeFreezeV5(companion); err == nil {
		return a.verifyV5(r, fv)
	}
	fc, err := ParseFreezeCompanion(companion)
	if err != nil || fc.Version != freezeV3Version || len(fc.Preimage) == 0 {
		return nil, fmt.Errorf("%w: a VR chain admits Freeze v5 and the exact-recovery V3 companion only", ErrVRFreeze)
	}
	if c, err := evmassign.DecodeCandidate(fc.Preimage); err != nil || c.Kind != evmassign.KindRecovery {
		return nil, fmt.Errorf("%w: a V3 companion on a VR chain is an exact recovery only", ErrVRFreeze)
	}
	return a.handoffAuthority.VerifyFreeze(r, companion)
}

func (a *vrFreezeAuthority) verifyV5(r evmroot.OrderedHandoffRecord, fv vrschema.FreezeV5) ([]byte, error) {
	if a.svc == nil || a.svc.Intents == nil {
		return nil, fmt.Errorf("%w: no intent derivation", ErrVRMode)
	}
	if len(a.parent) != 32 || r.Epoch == ^uint64(0) {
		return nil, fmt.Errorf("%w: no frozen parent bound", ErrVRFreeze)
	}
	q := a.query
	q.Candidate = fv.Candidate
	in, ok, err := a.svc.Intents.Intent(q)
	if err != nil {
		return nil, errors.Join(ErrVRUnavailable, err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: no intent is derivable for the attempt", ErrVRFreeze)
	}
	body := in.Body
	if err := body.Validate(); err != nil {
		return nil, errors.Join(ErrVRFreeze, err)
	}
	cd := sha256.Sum256(fv.Candidate)
	id := body.Identity()
	switch {
	case body.Network != r.Network || body.Epoch != r.Epoch+1 || body.EarliestActivation > r.ActivationRound:
		return nil, fmt.Errorf("%w: the derived body is not the successor of this epoch at this activation", ErrVRFreeze)
	case !bytes.Equal(id[:], r.NextBodyID):
		return nil, fmt.Errorf("%w: the record names another successor body than the derived one", ErrVRFreeze)
	case !bytes.Equal(body.ChangeRecordHash, evmroot.D4CandidateContextHash(r.Network, r.PredecessorBodyID, r.Attempt, cd[:], body.EarliestActivation)):
		return nil, fmt.Errorf("%w: the body does not commit to the certified candidate", ErrVRFreeze)
	case !bytes.Equal(r.FrozenID, evmroot.D4FrozenID(r.NextBodyID, body.StateSummary, a.parent, cd[:], r.Attempt, r.PredecessorBodyID)):
		return nil, fmt.Errorf("%w: the frozen commitment", ErrVRFreeze)
	}
	linker, ok := a.handoffAuthority.(vrBodyLinker)
	if !ok {
		return nil, fmt.Errorf("%w: the authority cannot link a successor body", ErrVRFreeze)
	}
	link, err := linker.vrSuccessorLink(r.Network, r.Epoch)
	if err != nil || !bytes.Equal(body.PredecessorHash, link) {
		return nil, errors.Join(ErrVRFreeze, errors.New("the derived body does not link to the current epoch"), err)
	}
	a.vr.intent, a.vr.fv5 = &in, &fv
	return bytes.Clone(a.parent), nil
}

// admitV5 is the executor half of a primary Freeze v5 in its own block (design section 5.2): VR proven at the frozen parent, the committed
// root state at the Freeze block, and the certificate the authority already matched to the derived intent. It runs the FZ transition and
// stages the Boundary.
func (x *ExecutedBlock) admitV5(v *vrStep, pos *posStep, svc *VRServices, r evmroot.OrderedHandoffRecord, block *rctypes.BlockData, frozen *ShardInfo,
	installed *types.PartitionDescriptionRecord, states map[types.PartitionShardID]*ShardInfo, confs map[types.PartitionShardID]*types.PartitionDescriptionRecord,
	orchestration Orchestration, authority handoffAuthority, epochKey types.PartitionShardID) error {
	fv, in := v.fv5, v.intent
	if fv == nil || in == nil {
		return fmt.Errorf("%w: the Freeze v5 was not derived", ErrVRFreeze)
	}
	if frozen == nil || frozen.IR == nil || len(frozen.IR.Hash) != 32 || installed == nil || svc.State == nil {
		return errors.Join(ErrHandoffRecord, ErrVRMode)
	}
	cand, err := vrschema.DecodeCandidateV6(fv.Candidate)
	if err != nil {
		return errors.Join(ErrHandoffRecord, ErrVRFreeze, err)
	}
	if cand.Kind != evmassign.KindPrimary || len(cand.SourceRef) != 32 {
		return fmt.Errorf("%w: a Freeze v5 carries a primary registry candidate", ErrVRFreeze)
	}
	if pending := frozen.TR.Epoch != frozen.IR.Epoch; pending && cand.Supersedes == nil {
		return ErrAssignmentAckPending
	}
	result := vrschema.Word(cand.SourceRef)
	var root [32]byte
	copy(root[:], frozen.IR.Hash)
	state, err := svc.State.VerifyOutput(fv.Witness, root, result)
	if err != nil {
		return errors.Join(ErrHandoffRecord, ErrVRFreeze, err)
	}
	lctx, err := LifecycleFor(orchestration, frozen.PartitionID, frozen.ShardID, frozen.IR.Epoch, installed)
	if err != nil {
		return errors.Join(ErrHandoffRecord, err)
	}
	schedule, err := svc.schedule(block.Epoch)
	if err != nil {
		return err
	}
	acked := map[vrschema.ShardKey]bool{}
	for _, si := range states {
		if si != nil && si.IR != nil {
			acked[vrschema.ShardKey{Partition: uint32(si.PartitionID), Shard: string(si.ShardID.Bytes())}] = si.TR.Epoch == si.IR.Epoch
		}
	}
	current := authority.CurrentRoot()
	incumbents := make(map[string][]byte, len(current))
	for _, m := range current {
		incumbents[m.NodeID] = m.Key
	}
	committedView := uint64(0)
	if b := v.state.Backoff; bytes.Equal(b.Intent, in.Digest[:]) {
		committedView = b.LastView
	}
	var successorRoot []evmassign.RootMember
	for _, m := range in.Body.Members {
		successorRoot = append(successorRoot, evmassign.RootMember{NodeID: m.NodeID, Key: m.ConsensusKey, Weight: m.Weight})
	}
	vc := evmassign.VerifyContext{BindingContext: evmassign.BindingContext{ControlPartition: evmroot.D4ControlPartition, SuccessorRoot: successorRoot,
		PoPContext: evmassign.PoPContext{Network: r.Network, Attempt: r.Attempt}, Rules: weightvalidation.EVMRules(weightvalidation.ModeWeighted)},
		Current: installed, CurrentRoot: current}
	copy(vc.Predecessor[:], r.PredecessorBodyID)
	verified, err := vradmit.VerifyRegistryOutput(vradmit.Admission{
		Deployment: svc.Deployment, Candidate: cand, State: state, Acknowledged: v.state.Acknowledged, Resolved: pos.state.IsResolved(result),
		Verify: vc, Lifecycle: lctx,
		Fold: vradmit.FoldContext{Network: r.Network, SuccessorRootEpoch: r.Epoch + 1, Installed: confs, EVMPartition: epochKey.PartitionID,
			ControlPartition: evmroot.D4ControlPartition, Schedule: schedule}.Input(),
		Acked: acked, EVMAcked: frozen.TR.Epoch == frozen.IR.Epoch, PrepareUCTime: v.state.PrepareUCTime,
		Support: vradmit.SupportInput{Table: v.state.Support, Evidence: fv.RuleSupport},
		Certificate: vradmit.CertificateInput{Certificate: fv.Certificate, IntentDigest: in.Digest, CommittedView: committedView, Incumbents: incumbents,
			Successors: cand.Identities, Body: in.Body, Attempt: r.Attempt, TrustBaseBytes: in.TrustBase},
	})
	if err != nil {
		return errors.Join(ErrHandoffRecord, ErrVRFreeze, err)
	}
	if cand.Supersedes != nil {
		if err := verifySupersession(cand.Supersedes, frozen, orchestration); err != nil {
			return err
		}
	}
	// FZ, at the certificate's view (section 5.5.2), and the staged Boundary of this result
	next, err := v.state.ApplyFreeze(block.Epoch, r.Attempt, fv.Certificate.Assembly.Slot)
	if err != nil {
		return errors.Join(ErrHandoffRecord, ErrVRMode, err)
	}
	staged, err := vradmit.MaterializeJ(vradmit.SupportTable{}, fv.Certificate.Readiness, cand.Identities)
	if err != nil {
		return errors.Join(ErrHandoffRecord, ErrVRFreeze, err)
	}
	var body [32]byte
	copy(body[:], r.NextBodyID)
	next.StagedBody, next.StagedResult, next.StagedBitmap, next.StagedSupport = body, result, vrschema.RejectedBitmap(cand.RegistryChanges), staged
	v.set(next)
	// what the store retains: the body, the merged receipts, the v5 view the install paths read, and the canonical v6 bytes
	receipts := make([]q3format.Receipt, 0, len(fv.Certificate.Readiness))
	for i, rd := range fv.Certificate.Readiness {
		rc, err := vrschema.ReadinessReceipt(rd.Receipt, cand.Identities[i].RootNodeID)
		if err != nil {
			return errors.Join(ErrHandoffRecord, err)
		}
		receipts = append(receipts, rc)
	}
	rs, err := q3format.EncodeReceipts(receipts)
	if err != nil {
		return errors.Join(ErrHandoffRecord, err)
	}
	v5, err := verified.V5.Encode()
	if err != nil {
		return errors.Join(ErrHandoffRecord, err)
	}
	v.frozen = &vrRetention{Body: in.Body.Encode(), Receipts: rs, V5: v5, V6: bytes.Clone(fv.Candidate)}
	return nil
}

// abortVR projects a committed Abort on a VR chain from the branch's own state (design section 4.3 item 4, S2a): the Abort of the attempt
// whose Freeze v5 staged a primary, before its H, closes that primary's result once (SessionClosed) and clears the staging. A pre-Freeze
// Abort finds nothing staged, and a recovery Abort names another body than the staged primary (which stays staged for its
// acknowledgement), so neither closes R. Nothing retained locally is consulted.
func (p *posStep) abortVR(v *vrStep, r evmroot.OrderedHandoffRecord, round, timestamp uint64) error {
	s := v.state
	if s.StagedBody == ([32]byte{}) || !bytes.Equal(s.StagedBody[:], r.NextBodyID) {
		return nil
	}
	for _, h := range p.state.Pending {
		if h.BodyID == s.StagedBody {
			return nil // committed (an Abort after H is refused before this point)
		}
	}
	if !p.state.IsResolved(s.StagedResult) {
		next, rec, err := p.state.SessionClosed(s.StagedResult, round, timestamp)
		if err != nil {
			return errors.Join(ErrPosSource, err)
		}
		p.set(next)
		p.records = append(p.records, rec)
	}
	s.StagedBody, s.StagedResult, s.StagedBitmap, s.StagedSupport = [32]byte{}, vrschema.Word{}, 0, vradmit.SupportTable{}
	v.set(s)
	return nil
}

// ackVR projects the acknowledgement of the pending handoffs of a VR generation: Ack or RecoveryAck immediately followed by the result's
// Boundary (design sections 4.1 and 4.3). The Boundary's rejectedBitmap is the staged primary's, and the acknowledged result moves to it.
// The support table materializes J's commitments on a primary acknowledgement and keeps K's bindings on a recovered one (section 7.3).
func (p *posStep) ackVR(v *vrStep, candidates candidateSource, round, timestamp, evmEpoch uint64) error {
	if !p.pendingAck() {
		return nil
	}
	if candidates == nil {
		return fmt.Errorf("%w: no retained candidates to project the acknowledgement", ErrPosSource)
	}
	s := v.state
	if s.StagedBody != p.state.Pending[0].BodyID {
		return fmt.Errorf("%w: the acknowledged primary is not the staged one", ErrPosSource)
	}
	var result, assignment [32]byte
	var installed []evmassign.Identity
	for i, h := range p.state.Pending {
		preimage, err := candidates.HandoffCandidate(h.BodyID[:])
		if err != nil || len(preimage) == 0 {
			return errors.Join(ErrPosSource, fmt.Errorf("candidate of pending handoff %d unavailable", i), err)
		}
		c, err := evmassign.DecodeCandidate(preimage)
		if err != nil {
			return errors.Join(ErrPosSource, err)
		}
		if i == 0 {
			result = c.ResultID()
		} else if c.ResultID() != result {
			return fmt.Errorf("%w: the recovery names another election result than its primary", ErrPosSource)
		}
		if assignment, err = c.AssignmentID(); err != nil {
			return errors.Join(ErrPosSource, err)
		}
		installed = c.Identities
	}
	if result != s.StagedResult {
		return fmt.Errorf("%w: the acknowledged result is not the staged one", ErrPosSource)
	}
	recovered := len(p.state.Pending) == 2
	next, recs, err := p.state.AckBoundary(round, timestamp, result, assignment, evmEpoch, s.StagedBitmap)
	if err != nil {
		return errors.Join(ErrPosSource, err)
	}
	p.set(next)
	p.records = append(p.records, recs...)
	// a recovered Boundary keeps K installed, whose bindings stay the acknowledged committee; a primary one materializes J's own commitments
	s.Support = s.Support.Prune(installed)
	if !recovered {
		if s.Support, err = s.Support.Add(s.StagedSupport.Entries...); err != nil {
			return errors.Join(ErrPosSource, err)
		}
	}
	s.Acknowledged = result
	s.StagedBody, s.StagedResult, s.StagedBitmap, s.StagedSupport = [32]byte{}, vrschema.Word{}, 0, vradmit.SupportTable{}
	v.set(s)
	return nil
}

// vrCommittee reads the acknowledged committee of the designated EVM shard from committed history, and with it every binding rule support
// may name: the acknowledged committee followed by the latest pending step's identities (a pending K, or J awaiting its acknowledgement).
func vrCommittee(state ShardStates, confs map[types.PartitionShardID]*types.PartitionDescriptionRecord, orchestration Orchestration) func() ([]evmassign.Identity, []evmassign.Identity, error) {
	return func() ([]evmassign.Identity, []evmassign.Identity, error) {
		key, found, err := frozenEVMShard(state, confs)
		if err != nil || !found {
			return nil, nil, errors.Join(ErrVRMode, errors.New("no designated EVM shard"), err)
		}
		si := state.States[key]
		if si == nil || si.IR == nil {
			return nil, nil, fmt.Errorf("%w: the EVM shard has no certified state", ErrVRMode)
		}
		lctx, err := LifecycleFor(orchestration, si.PartitionID, si.ShardID, si.IR.Epoch, confs[key])
		if err != nil {
			return nil, nil, err
		}
		all := append([]evmassign.Identity(nil), lctx.Incumbent...)
		if lctx.Head != nil {
			all = append(all, lctx.Head.Candidate.Identities...)
		}
		return lctx.Incumbent, all, nil
	}
}

// retainVRFreeze retains what an admitted Freeze v5 leaves for the successor's delivery and for the later blocks of this handoff: the body
// and receipts (as a V3 companion's), the v5 view under the candidate key and the v6 bytes under their own.
func (x *BlockStore) retainVRFreeze(block *rctypes.BlockData, f *vrRetention) error {
	record, err := decodeOrderedRecord(block.Payload.HandoffRecords[0])
	if err != nil || record.Kind != "freeze" {
		return ErrHandoffRecord
	}
	archive, ok := x.storage.(interface {
		StoreHandoffBody([]byte, []byte) error
		StoreHandoffReceipts([]byte, []byte) error
		StoreHandoffCandidate([]byte, []byte) error
		StoreHandoffVRCandidate([]byte, []byte) error
	})
	if !ok {
		return fmt.Errorf("%w: Freeze v5 retention unavailable", ErrHandoffRecord)
	}
	if err := errors.Join(archive.StoreHandoffBody(record.NextBodyID, f.Body), archive.StoreHandoffReceipts(record.NextBodyID, f.Receipts),
		archive.StoreHandoffCandidate(record.NextBodyID, f.V5), archive.StoreHandoffVRCandidate(record.NextBodyID, f.V6)); err != nil {
		return fmt.Errorf("retaining the admitted Freeze v5: %w", err)
	}
	return nil
}

// CommittedVRState is the VR root state of the committed root block; ok is false on a chain that is not in VR mode.
func (x *BlockStore) CommittedVRState() (vradmit.RootState, bool, error) {
	o, ok, err := x.committedVR(false)
	return o.State, ok, err
}

// VROpening is what the committed root block says about the opening of the current view: the committed VR root state, the committed
// round, and, while no view of the attempt is committed, the intent derivable over the committed state (its anchor round says whether the
// opening of view 0 is itself committed). It is read from the committed root only, never from a speculatively executed block.
type VROpening struct {
	State          vradmit.RootState
	CommittedRound uint64
	Intent         VRIntent
	IntentOK       bool
}

// CommittedVROpening is the VROpening of the committed root block; ok is false on a chain that is not in VR mode.
func (x *BlockStore) CommittedVROpening() (VROpening, bool, error) {
	return x.committedVR(true)
}

func (x *BlockStore) committedVR(derive bool) (VROpening, bool, error) {
	if x.profile != ProfileHandoff {
		return VROpening{}, false, nil
	}
	root := x.tree().Root()
	if root == nil || root.ShardState.Control == nil || len(root.ShardState.Control.VR) == 0 {
		return VROpening{}, false, nil
	}
	s, err := vradmit.DecodeRootState(root.ShardState.Control.VR)
	if err != nil {
		return VROpening{}, false, err
	}
	o := VROpening{State: s, CommittedRound: root.GetRound()}
	x.lock.RLock()
	svc := x.pos
	x.lock.RUnlock()
	if !derive || s.Backoff.LastView != 0 || svc == nil || svc.Registry == nil || svc.Registry.Intents == nil {
		return o, true, nil
	}
	confs, err := x.orchestration.ShardConfigs(root.GetRound())
	if err != nil {
		return o, true, err
	}
	latestRoot, latestBlock, latestOK := certifiedEVM(root.ShardState, confs)
	o.Intent, o.IntentOK, err = svc.Registry.Intents.Intent(VRIntentQuery{Control: root.ShardState.Control, Backoff: s.Backoff, Epoch: root.BlockData.Epoch,
		Round: root.GetRound(), LatestEVMRoot: latestRoot, LatestEVMBlock: latestBlock, LatestEVMOK: latestOK})
	return o, true, err
}

// HandoffViewOf is the HandoffView a block carries, if any (at most one, by the payload rule).
func HandoffViewOf(b *rctypes.BlockData) (*rctypes.ViewContext, bool) {
	if b == nil || b.Payload == nil {
		return nil, false
	}
	for _, c := range b.Payload.PosControls {
		if c.Registry && c.Op == rctypes.OpHandoffView && c.View != nil {
			return c.View, true
		}
	}
	return nil, false
}
