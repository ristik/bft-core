package storage

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
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
}

func (p *posStep) controls(block *rctypes.BlockData, svc *PosServices) error {
	if len(block.Payload.PosControls) == 0 {
		return nil
	}
	if !p.on || svc == nil || svc.Authority == nil || svc.Witnesses == nil {
		return ErrPosControls
	}
	for i, c := range block.Payload.PosControls {
		if c.Network != svc.Deployment.RootNetwork || c.ChainID != svc.Deployment.ChainID || c.Custody != svc.Deployment.Custody ||
			c.OrderingEpoch != block.Epoch || c.OrderingRound != block.Round {
			return fmt.Errorf("%w: control %d names another deployment, epoch or round than this block", ErrPosControlRefused, i)
		}
		switch c.Op {
		case rctypes.OpCloseLiability:
			if err := p.closeLiability(c, block, svc); err != nil {
				return fmt.Errorf("control %d: %w", i, err)
			}
		default:
			return fmt.Errorf("%w: control %d: op %d is not executed yet", ErrPosControlRefused, i, c.Op)
		}
	}
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

	witness, err := svc.Witnesses.Witness(c.WitnessHash)
	if err != nil || len(witness) == 0 {
		return errors.Join(ErrWitnessUnavailable, err)
	}
	if sum := sha256.Sum256(witness); sum != c.WitnessHash {
		return fmt.Errorf("%w: the retained witness is not the one the control commits to", ErrPosControlRefused)
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
