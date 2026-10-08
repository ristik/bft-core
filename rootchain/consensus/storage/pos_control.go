package storage

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

// The P85 root controls the executor orders after a block's certifications (briefs/p85-pr1c-control-records.md section 5). CloseLiability
// is verified here against facts a ClosureAuthority extracts from the retained terminal bundle; the executor itself checks the control
// against those facts, against the root's own state (is this epoch's closure outstanding, was H ordered at this round) and against the
// digests it derives from the frozen identity records. Nothing in a control is taken on its submitter's word.

var (
	// ErrPosControls reports a control in a block of a chain that has no P85 services (deployment, terminal authority, witnesses).
	ErrPosControls = errors.New("P85 root controls are not enabled on this chain")
	// ErrPosControlRefused reports a control that fails verification.
	ErrPosControlRefused = errors.New("P85 root control refused")
	// ErrClosureMissing reports a block that leaves a closed epoch's CloseLiability outstanding: the closure of every awaiting epoch is
	// mandatory in the block whose ordinary round ends the handoff's freeze, and in every block after it.
	ErrClosureMissing = errors.New("P85 mandatory CloseLiability missing")
	// ErrNotLatestEVM reports a control that names an EVM state other than the one certified in the parent block.
	ErrNotLatestEVM = errors.New("P85 control: P is not the latest EVM state certified in the parent")
	// ErrHandoffInFlight reports a Retirement while a handoff could still reference the generation.
	ErrHandoffInFlight = errors.New("P85 control: a handoff is in flight")
	// ErrResolvedResult reports a primary candidate whose Election result the log already closed or acknowledged.
	ErrResolvedResult = errors.New("P85: the election result is already resolved")
	// ErrPrimaryProofMissing reports a primary candidate on a chain that judges them whose Freeze companion carries no EVM proof.
	ErrPrimaryProofMissing = errors.New("P85: the primary candidate carries no EVM proof")
	// ErrPrimaryProofUnexpected reports an EVM proof on a Freeze this chain does not judge against the EVM (a recovery, or a chain
	// without the election pinned).
	ErrPrimaryProofUnexpected = errors.New("P85: the Freeze carries an EVM proof nothing would check")
	// ErrPrimaryProofRefused reports an EVM proof that does not show the candidate's result published and current.
	ErrPrimaryProofRefused = errors.New("P85: the primary candidate's EVM proof is refused")
	// ErrWitnessUnavailable reports a control whose retained witness is not available: unavailable, never false, so the block cannot
	// be voted until it is.
	ErrWitnessUnavailable = errors.New("P85 control witness unavailable")
)

// ClosureFacts are what an authenticated terminal bundle establishes about a closed epoch.
type ClosureFacts struct {
	ClosedEpoch  uint64
	BundleID     [32]byte // handoffdelivery.SemanticIdentity of the verified bundle
	HRecordID    [32]byte // the committed H record
	HRound       uint64   // H.OrderedRound
	TerminalRoot [32]byte // the verified old proof's root-consensus state root
	AssignmentID [32]byte // the assignment hash of the EVM assignment H terminates
	Closed       []evmassign.Identity
}

// ClosureAuthority verifies the retained canonical bundle bytes of a closed epoch against the historical authority of that epoch
// (terminal proof, state availability) and returns the facts. It is a pure function of the witness and committed history.
//
// Closed and AssignmentID must be the frozen identity records, and the assignment hash, of the assignment H terminates, authenticated by
// the verified bundle: the executor derives the closure's exposure and key-history digests from Closed, so an authority that reports
// anything else (the current nominations, the successor's records, records the bundle does not commit to) makes the closure unsound.
type ClosureAuthority interface {
	VerifyClosure(witness []byte, closedEpoch uint64) (ClosureFacts, error)
}

// ClosureProposer builds the CloseLiability control, with its retained witness, for a closed epoch: the proposer's side of the
// mandatory inclusion. It fails (unavailable) when the terminal bundle is not at hand, and then no ordinary block can be proposed.
type ClosureProposer interface {
	// Closure returns the control and the canonical witness bytes whose SHA-256 it commits to.
	Closure(epoch, orderingEpoch, orderingRound uint64) (rctypes.PosControl, []byte, error)
}

// WitnessSource returns the retained witness bytes by their SHA-256.
type WitnessSource interface {
	Witness(hash [32]byte) ([]byte, error)
}

// RetirementFacts are what certified custody and registry state at P establish about one identity generation, proven from one state
// root (briefs/p85-pr1c-control-records.md section 3). The authority reports them; the executor decides.
type RetirementFacts struct {
	ID, Generation     uint64
	RefDigest          [32]byte // custody's exposureChain, verbatim
	MaxLiabilityAnchor uint64
	Requested          bool // retirementRequested at P
	NotImported        bool // the generation has not been retired in the registry
	NoLiveExposures    bool // liveExposures is zero
	NoLotReferences    bool // every bounded generation lot has refCount zero
	RecordsCaughtUp    bool // custody.recordCursor equals registry.recordCount, which equals its authenticated target count
}

// RejectFacts are what certified Election and custody state at P establish about an unresolved result.
type RejectFacts struct {
	ResultID           [32]byte
	Attempt            uint64
	Unresolved         bool // the session is open and its assignment still only reserved
	NoInstalledSession bool // the session extends the last acknowledged assignment: no other session was installed over it
}

// EVMStateAuthority verifies EVM storage-proof witnesses against a certified state root.
//
// The state root is the one the root itself holds as the EVM shard's certified state hash (the input record's Hash is the EVM state
// root), so a witness is only ever judged against a root the root already authenticated.
type EVMStateAuthority interface {
	VerifyRetirement(witness []byte, stateRoot [32]byte, id, generation uint64) (RetirementFacts, error)
	VerifyReject(witness []byte, stateRoot [32]byte, resultID [32]byte, attempt uint64) (RejectFacts, error)
}

// PrimaryAuthority verifies the storage-proof witness of a published primary candidate (the election and custody state at the frozen
// parent) against the EVM state root the root certified.
type PrimaryAuthority interface {
	VerifyPrimary(witness []byte, stateRoot [32]byte, resultID [32]byte) (evmassign.PrimaryFacts, error)
}

// PosDeployment is the custody deployment this root's controls name: the root network id, and custody's network word, chain id and address,
// and the Election module (zero on a deployment whose roots do not judge primary candidates against the EVM).
type PosDeployment struct {
	RootNetwork uint64
	evmassign.Deployment
	Election [20]byte
}

// PosServices are the collaborators of the control executor. A chain without them refuses every control.
type PosServices struct {
	Deployment PosDeployment
	Authority  ClosureAuthority
	Witnesses  WitnessSource
	EVM        EVMStateAuthority
	Proposer   ClosureProposer
	// Primary, when set together with Deployment.Election, makes the EVM proof of a primary candidate a condition of its Freeze: the
	// companion must be version 4 and carry a proof that evmassign.VerifyPrimary accepts against the frozen parent's state root.
	Primary PrimaryAuthority
}

// RequiresPrimaryProof reports whether Freeze admission demands the EVM proof of a primary candidate on this chain.
func (s *PosServices) RequiresPrimaryProof() bool {
	return s != nil && s.Primary != nil && s.Deployment.Election != ([20]byte{})
}

// mandatory reports whether this chain enforces the closure duty: it has the authority to verify a closure with.
func (s *PosServices) mandatory() bool { return s != nil && s.Authority != nil }

// posEnv is the root state a control is validated against, frozen before the block's own certifications are processed.
type posEnv struct {
	// Control is the handoff control state after this block's handoff record.
	Control *evmroot.ControlState
	// LatestEVMRoot is the EVM state root certified in the parent block (the shard input record's Hash) and LatestEVMBlock its block hash,
	// nil when the latest round was quiet (a quiet input record carries no block hash): the only P a Retirement or RejectResult may name.
	LatestEVMRoot  [32]byte
	LatestEVMBlock []byte
	LatestEVMOK    bool
	// InFlight reports a prepared or endorsed handoff, or a committed one not yet acknowledged.
	InFlight bool
}

// maxBlockRecords is the most records one root block may project, Ack and Abort projections included.
const maxBlockRecords = rootrecords.MaxImport

// controls executes the block's PosControls in payload order. It returns the control state a RejectResult replaced, or nil.
func (p *posStep) controls(block *rctypes.BlockData, svc *PosServices, env posEnv) (*evmroot.ControlState, error) {
	if len(block.Payload.PosControls) == 0 {
		return nil, errors.Join(p.recordCap(), p.closuresDone(svc))
	}
	if !p.on || svc == nil || svc.Authority == nil || svc.Witnesses == nil {
		return nil, ErrPosControls
	}
	var replaced *evmroot.ControlState
	for i, c := range block.Payload.PosControls {
		if c.Network != svc.Deployment.RootNetwork || c.ChainID != svc.Deployment.ChainID || c.Custody != svc.Deployment.Custody ||
			c.OrderingEpoch != block.Epoch || c.OrderingRound != block.Round {
			return nil, fmt.Errorf("%w: control %d names another deployment, epoch or round than this block", ErrPosControlRefused, i)
		}
		var err error
		switch c.Op {
		case rctypes.OpCloseLiability:
			err = p.closeLiability(c, block, svc)
		case rctypes.OpRetirement:
			err = p.retire(c, block, svc, env)
		case rctypes.OpRejectResult:
			var control *evmroot.ControlState
			if control, err = p.reject(c, block, svc, env); err == nil {
				replaced, env.Control = control, control
			}
		default:
			err = fmt.Errorf("%w: unknown op %d", ErrPosControlRefused, c.Op)
		}
		if err != nil {
			return nil, fmt.Errorf("control %d: %w", i, err)
		}
	}
	return replaced, errors.Join(p.recordCap(), p.closuresDone(svc))
}

// closuresDone refuses a block that leaves a closure outstanding on a chain that enforces the duty. The closures come first in the
// payload, so by the end of the controls every awaiting epoch is closed or the block is invalid.
func (p *posStep) closuresDone(svc *PosServices) error {
	if p.on && svc.mandatory() && len(p.state.Awaiting) > 0 {
		return fmt.Errorf("%w: epoch %d", ErrClosureMissing, p.state.Awaiting[0].Epoch)
	}
	return nil
}

func (p *posStep) recordCap() error {
	if len(p.records) > maxBlockRecords {
		return fmt.Errorf("%w: %d records in one block", ErrPosControlRefused, len(p.records))
	}
	return nil
}

// witnessOf fetches the retained witness the control commits to; unavailable is not false.
func witnessOf(c rctypes.PosControl, svc *PosServices) ([]byte, error) {
	witness, err := svc.Witnesses.Witness(c.WitnessHash)
	if err != nil || len(witness) == 0 {
		return nil, errors.Join(ErrWitnessUnavailable, err)
	}
	if sum := sha256.Sum256(witness); sum != c.WitnessHash {
		return nil, fmt.Errorf("%w: the retained witness is not the one the control commits to", ErrPosControlRefused)
	}
	return witness, nil
}

// certifiedState checks that the named EVM state is the latest the parent certified. The state root is what the proofs are checked
// against; the block hash is only named when the parent's round certified a block, and is the zero word otherwise (an unauthenticated
// field is fixed, not free).
func certifiedState(blockHash, stateRoot [32]byte, svc *PosServices, env posEnv) error {
	if svc.EVM == nil {
		return ErrPosControls
	}
	if !env.LatestEVMOK || stateRoot != env.LatestEVMRoot {
		return errors.Join(ErrPosControlRefused, ErrNotLatestEVM)
	}
	var want [32]byte
	copy(want[:], env.LatestEVMBlock)
	if blockHash != want {
		return errors.Join(ErrPosControlRefused, ErrNotLatestEVM, errors.New("the block hash is not the certified block's"))
	}
	return nil
}

func (p *posStep) retire(c rctypes.PosControl, block *rctypes.BlockData, svc *PosServices, env posEnv) error {
	var ref [32]byte
	id, ok1 := word64(c.Data[0:32])
	generation, ok2 := word64(c.Data[32:64])
	copy(ref[:], c.Data[64:96])
	if !ok1 || !ok2 {
		return fmt.Errorf("%w: retirement id or generation is not a uint64", ErrPosControlRefused)
	}
	if env.InFlight {
		return errors.Join(ErrPosControlRefused, ErrHandoffInFlight)
	}
	if err := certifiedState(c.Retire.EVMBlockHash, c.Retire.EVMStateRoot, svc, env); err != nil {
		return err
	}
	witness, err := witnessOf(c, svc)
	if err != nil {
		return err
	}
	f, err := svc.EVM.VerifyRetirement(witness, c.Retire.EVMStateRoot, id, generation)
	if err != nil {
		return errors.Join(ErrPosControlRefused, err)
	}
	switch {
	case f.ID != id || f.Generation != generation:
		return fmt.Errorf("%w: the proof is of another identity generation", ErrPosControlRefused)
	case f.RefDigest != ref:
		return fmt.Errorf("%w: refDigest is not custody's exposure chain at P", ErrPosControlRefused)
	case !f.Requested:
		return fmt.Errorf("%w: no retirement was requested at P", ErrPosControlRefused)
	case !f.NotImported:
		return fmt.Errorf("%w: the generation is already retired in the registry", ErrPosControlRefused)
	case !f.NoLiveExposures || !f.NoLotReferences:
		return fmt.Errorf("%w: the generation still has exposures or lot references at P", ErrPosControlRefused)
	case !f.RecordsCaughtUp:
		return fmt.Errorf("%w: custody has not applied the registry's records at P", ErrPosControlRefused)
	}
	next, rec, err := p.state.Retire(id, generation, ref, f.MaxLiabilityAnchor, block.Round, block.Timestamp)
	if err != nil {
		return errors.Join(ErrPosControlRefused, err)
	}
	p.set(next)
	if rec != nil {
		p.records = append(p.records, *rec)
	}
	return nil
}

// reject terminates an Election result that never reached a Prepare: SessionClosed, and the attempt cursor moves past it.
func (p *posStep) reject(c rctypes.PosControl, block *rctypes.BlockData, svc *PosServices, env posEnv) (*evmroot.ControlState, error) {
	ctl := env.Control
	if ctl == nil {
		return nil, ErrPosControls
	}
	var resultID [32]byte
	copy(resultID[:], c.Data[0:32])
	next := uint64(0)
	switch ctl.Phase {
	case "idle":
	case "aborted":
		if ctl.Attempt == ^uint64(0) {
			return nil, fmt.Errorf("%w: attempt cursor exhausted", ErrPosControlRefused)
		}
		next = ctl.Attempt + 1
	default:
		return nil, fmt.Errorf("%w: a handoff is %s: only an Abort ends it", ErrPosControlRefused, ctl.Phase)
	}
	switch {
	case len(p.state.Pending) > 0:
		return nil, fmt.Errorf("%w: a committed primary awaits its acknowledgement; the open result is its recovery", ErrPosControlRefused)
	case !bytes.Equal(c.Reject.PredecessorBodyID[:], ctl.PredecessorBodyID):
		return nil, fmt.Errorf("%w: another predecessor than the root's authority", ErrPosControlRefused)
	case c.Reject.Attempt != next:
		return nil, fmt.Errorf("%w: attempt %d is not the next attempt %d", ErrPosControlRefused, c.Reject.Attempt, next)
	}
	if err := certifiedState(c.Reject.EVMBlockHash, c.Reject.EVMStateRoot, svc, env); err != nil {
		return nil, err
	}
	witness, err := witnessOf(c, svc)
	if err != nil {
		return nil, err
	}
	f, err := svc.EVM.VerifyReject(witness, c.Reject.EVMStateRoot, resultID, c.Reject.Attempt)
	if err != nil {
		return nil, errors.Join(ErrPosControlRefused, err)
	}
	switch {
	case f.ResultID != resultID:
		return nil, fmt.Errorf("%w: the proof is of another result", ErrPosControlRefused)
	case f.Attempt != c.Reject.Attempt:
		return nil, fmt.Errorf("%w: the session is of another attempt", ErrPosControlRefused)
	case !f.Unresolved:
		return nil, fmt.Errorf("%w: the result is already resolved", ErrPosControlRefused)
	case !f.NoInstalledSession:
		return nil, fmt.Errorf("%w: a competing session is installed", ErrPosControlRefused)
	}
	state, rec, err := p.state.SessionClosed(resultID, block.Round, block.Timestamp)
	if err != nil {
		return nil, errors.Join(ErrPosControlRefused, err)
	}
	p.set(state)
	p.records = append(p.records, rec)
	return &evmroot.ControlState{Network: ctl.Network, Epoch: ctl.Epoch, PredecessorBodyID: bytes.Clone(ctl.PredecessorBodyID), Attempt: next,
		Phase: "aborted", OrderedRound: block.Round, PreviousDigest: ctl.Digest()}, nil
}

// abort projects the close of an Election result by a committed D4 Abort. Only the abort of a primary candidate whose Freeze retained it
// closes a session: the abort of a recovery attempt only advances that attempt, and an abort before any candidate was retained has no
// result to name (the open result then ends by RejectResult).
func (p *posStep) abort(candidates candidateSource, r evmroot.OrderedHandoffRecord, round, timestamp uint64) error {
	if !p.on || candidates == nil {
		return nil
	}
	preimage, err := candidates.HandoffCandidate(r.NextBodyID)
	if err != nil {
		return errors.Join(ErrPosSource, err)
	}
	if len(preimage) == 0 {
		return nil
	}
	c, err := evmassign.DecodeCandidate(preimage)
	if err != nil {
		return errors.Join(ErrPosSource, err)
	}
	if c.Kind != evmassign.KindPrimary {
		return nil
	}
	if p.state.IsResolved(c.ResultID()) {
		return nil // already closed or acknowledged: a repeat projects nothing (custody would refuse it and block the log)
	}
	next, rec, err := p.state.SessionClosed(c.ResultID(), round, timestamp)
	if err != nil {
		return errors.Join(ErrPosSource, err)
	}
	p.set(next)
	p.records = append(p.records, rec)
	return nil
}

// ClosureData is the ABI payload of a Closure record: (bytes32 assignmentID, uint64 hRound, bytes32 hRecordID, bytes32 terminalRoot,
// bytes32 exposureDigest, bytes32 keyHistoryDigest), 192 bytes.
type ClosureData struct {
	AssignmentID                     [32]byte
	HRound                           uint64
	HRecordID, TerminalRoot          [32]byte
	ExposureDigest, KeyHistoryDigest [32]byte
}

// Encode is the exact ABI encoding.
func (d ClosureData) Encode() []byte {
	out := make([]byte, 0, 192)
	out = append(out, d.AssignmentID[:]...)
	hr := make([]byte, 32)
	for i := 0; i < 8; i++ {
		hr[31-i] = byte(d.HRound >> (8 * i))
	}
	out = append(out, hr...)
	out = append(out, d.HRecordID[:]...)
	out = append(out, d.TerminalRoot[:]...)
	out = append(out, d.ExposureDigest[:]...)
	return append(out, d.KeyHistoryDigest[:]...)
}

// DecodeClosureData parses exactly 192 bytes with the round word's high bits zero.
func DecodeClosureData(b []byte) (d ClosureData, err error) {
	if len(b) != 192 {
		return d, fmt.Errorf("closure data is %d bytes, not 192", len(b))
	}
	round, ok := word64(b[32:64])
	if !ok {
		return d, errors.New("closure data H round is not a uint64")
	}
	copy(d.AssignmentID[:], b[0:32])
	d.HRound = round
	copy(d.HRecordID[:], b[64:96])
	copy(d.TerminalRoot[:], b[96:128])
	copy(d.ExposureDigest[:], b[128:160])
	copy(d.KeyHistoryDigest[:], b[160:192])
	return d, nil
}

func word64(w []byte) (uint64, bool) {
	if !bytes.Equal(w[:24], make([]byte, 24)) {
		return 0, false
	}
	var v uint64
	for _, b := range w[24:] {
		v = v<<8 | uint64(b)
	}
	return v, true
}

func (p *posStep) closeLiability(c rctypes.PosControl, block *rctypes.BlockData, svc *PosServices) error {
	epoch := c.Close.ClosedEpoch
	hRound, awaiting := p.state.HRoundAwaiting(epoch)
	if !awaiting {
		return fmt.Errorf("%w: no closure is outstanding for epoch %d", ErrPosControlRefused, epoch)
	}
	d, err := DecodeClosureData(c.Data)
	if err != nil {
		return errors.Join(ErrPosControlRefused, err)
	}
	assignmentID, hRecordID, terminalRoot, exposureDigest, keyDigest, dataRound := d.AssignmentID, d.HRecordID, d.TerminalRoot, d.ExposureDigest, d.KeyHistoryDigest, d.HRound

	witness, err := witnessOf(c, svc)
	if err != nil {
		return err
	}
	facts, err := svc.Authority.VerifyClosure(witness, epoch)
	if err != nil {
		return errors.Join(ErrPosControlRefused, err)
	}
	switch {
	case facts.ClosedEpoch != epoch:
		return fmt.Errorf("%w: the bundle closes epoch %d, not %d", ErrPosControlRefused, facts.ClosedEpoch, epoch)
	case facts.BundleID != c.Close.BundleSemanticID:
		return fmt.Errorf("%w: another bundle than the one the control names", ErrPosControlRefused)
	case facts.HRecordID != hRecordID:
		return fmt.Errorf("%w: another H record", ErrPosControlRefused)
	case facts.HRound != dataRound || dataRound != hRound:
		return fmt.Errorf("%w: H round %d (control), %d (bundle), %d (root)", ErrPosControlRefused, dataRound, facts.HRound, hRound)
	case facts.TerminalRoot != terminalRoot:
		return fmt.Errorf("%w: another terminal root", ErrPosControlRefused)
	case facts.AssignmentID != assignmentID:
		return fmt.Errorf("%w: another assignment", ErrPosControlRefused)
	}
	wantExposure, err := evmassign.AssignmentExposureDigest(svc.Deployment.Deployment, facts.AssignmentID, facts.Closed)
	if err != nil {
		return errors.Join(ErrPosControlRefused, err)
	}
	wantKeys, err := evmassign.KeyHistoryDigest(facts.Closed)
	if err != nil {
		return errors.Join(ErrPosControlRefused, err)
	}
	if exposureDigest != wantExposure || keyDigest != wantKeys {
		return fmt.Errorf("%w: the closure digests are not those of the closed assignment's identity records", ErrPosControlRefused)
	}
	next, rec, err := p.state.Close(epoch, c.Data, block.Round, block.Timestamp)
	if err != nil {
		return errors.Join(ErrPosControlRefused, err)
	}
	p.set(next)
	p.records = append(p.records, rec)
	return nil
}

// handoffInFlight reports whether a handoff could still reference an identity generation: a prepared or endorsed one, a committed one
// whose freeze has not ended or whose acknowledgement is pending.
func handoffInFlight(p posStep, c *evmroot.ControlState) bool {
	if p.on && (p.state.Frozen || len(p.state.Pending) > 0) {
		return true
	}
	return c != nil && (c.Phase == "prepared" || c.Phase == "endorsed" || c.Phase == "committed")
}

// refuseResolved refuses a primary Freeze whose Election result the log has already resolved: its Abort would project a second
// SessionClosed and its commit a second Ack, and custody refuses both.
func (p *posStep) refuseResolved(companion []byte) error {
	if !p.on || len(companion) == 0 {
		return nil
	}
	fc, err := ParseFreezeCompanion(companion)
	if err != nil || len(fc.Preimage) == 0 {
		return nil // judged by the freeze admission itself
	}
	c, err := evmassign.DecodeCandidate(fc.Preimage)
	if err != nil || c.Kind != evmassign.KindPrimary {
		return nil
	}
	if p.state.IsResolved(c.ResultID()) {
		return errors.Join(ErrHandoffRecord, ErrResolvedResult)
	}
	return nil
}
