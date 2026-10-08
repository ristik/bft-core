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
	PredecessorBodyID  [32]byte
	Attempt            uint64
	Unresolved         bool // the result is Reserved or Published, not resolved
	NoInstalledSession bool // no competing installed session
}

// EVMStateAuthority verifies EVM storage-proof witnesses against a certified state root.
type EVMStateAuthority interface {
	// StateRoot is the state root of a certified EVM block, from retained verified history.
	StateRoot(blockHash [32]byte) ([32]byte, error)
	VerifyRetirement(witness []byte, stateRoot [32]byte, id, generation uint64) (RetirementFacts, error)
	VerifyReject(witness []byte, stateRoot [32]byte) (RejectFacts, error)
}

// PosDeployment is the custody deployment this root's controls name: the root network id, and custody's network word, chain id and address.
type PosDeployment struct {
	RootNetwork uint64
	evmassign.Deployment
}

// PosServices are the collaborators of the control executor. A chain without them refuses every control.
type PosServices struct {
	Deployment PosDeployment
	Authority  ClosureAuthority
	Witnesses  WitnessSource
	EVM        EVMStateAuthority
}

// posEnv is the root state a control is validated against, frozen before the block's own certifications are processed.
type posEnv struct {
	// Control is the handoff control state after this block's handoff record.
	Control *evmroot.ControlState
	// LatestEVM is the EVM block hash certified in the parent block: the only P a Retirement or RejectResult may name.
	LatestEVM   [32]byte
	LatestEVMOK bool
	// InFlight reports a prepared or endorsed handoff, or a committed one not yet acknowledged.
	InFlight bool
}

// maxBlockRecords is the most records one root block may project, Ack and Abort projections included.
const maxBlockRecords = rootrecords.MaxImport

// controls executes the block's PosControls in payload order. It returns the control state a RejectResult replaced, or nil.
func (p *posStep) controls(block *rctypes.BlockData, svc *PosServices, env posEnv) (*evmroot.ControlState, error) {
	if len(block.Payload.PosControls) == 0 {
		return nil, p.recordCap()
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
	return replaced, p.recordCap()
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

// certifiedState checks that the named EVM state is the latest the parent certified and returns its authenticated root.
func certifiedState(blockHash, stateRoot [32]byte, svc *PosServices, env posEnv) error {
	if svc.EVM == nil {
		return ErrPosControls
	}
	if !env.LatestEVMOK || blockHash != env.LatestEVM {
		return fmt.Errorf("%w: P is not the latest EVM state certified in the parent", ErrPosControlRefused)
	}
	root, err := svc.EVM.StateRoot(blockHash)
	if err != nil {
		return errors.Join(ErrWitnessUnavailable, err)
	}
	if root != stateRoot {
		return fmt.Errorf("%w: the state root is not the certified block's", ErrPosControlRefused)
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
	if err := certifiedState(c.Retire.EVMBlockHash, c.Retire.EVMStateRoot, svc, env); err != nil {
		return err
	}
	if env.InFlight {
		return fmt.Errorf("%w: a handoff is in flight; its obligations may reference the generation", ErrPosControlRefused)
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
	f, err := svc.EVM.VerifyReject(witness, c.Reject.EVMStateRoot)
	if err != nil {
		return nil, errors.Join(ErrPosControlRefused, err)
	}
	switch {
	case f.ResultID != resultID:
		return nil, fmt.Errorf("%w: the proof is of another result", ErrPosControlRefused)
	case f.PredecessorBodyID != c.Reject.PredecessorBodyID || f.Attempt != c.Reject.Attempt:
		return nil, fmt.Errorf("%w: the result is bound to another predecessor or attempt", ErrPosControlRefused)
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
	next, rec, err := p.state.SessionClosed(c.ResultID(), round, timestamp)
	if err != nil {
		return errors.Join(ErrPosSource, err)
	}
	p.set(next)
	p.records = append(p.records, rec)
	return nil
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
	// ClosureData: (assignmentID, hRound, hRecordID, terminalRoot, exposureDigest, keyHistoryDigest)
	var assignmentID, hRecordID, terminalRoot, exposureDigest, keyDigest [32]byte
	copy(assignmentID[:], c.Data[0:32])
	copy(hRecordID[:], c.Data[64:96])
	copy(terminalRoot[:], c.Data[96:128])
	copy(exposureDigest[:], c.Data[128:160])
	copy(keyDigest[:], c.Data[160:192])
	dataRound, _ := word64(c.Data[32:64]) // the width was checked by the control codec

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
