package consensus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

const (
	// maxPosSubmissions bounds the controls waiting to be ordered, maxPosSubmissionsPerSigner those of one validator.
	maxPosSubmissions          = 32
	maxPosSubmissionsPerSigner = 4
	// posSubmissionTTL is how many rounds a submission waits. A Retirement or RejectResult is proved against the latest certified EVM
	// state, so a submission that waits for long is stale anyway: the submitter proves again.
	posSubmissionTTL = 120
	// maxPosTrials bounds the trial executions of one proposal.
	maxPosTrials = 4
)

// ErrPosSubmission reports a control submission that is refused.
var ErrPosSubmission = errors.New("P85 control submission refused")

type posSubmission struct {
	control drctypes.PosControl
	signer  string
	witness [32]byte
	expires uint64
	key     []byte
}

// posSubmissions are the validators' submitted Retirement and RejectResult controls waiting for a leader to order them.
type posSubmissions struct {
	mu    sync.Mutex
	items []posSubmission
}

func (p *posSubmissions) add(s posSubmission, now uint64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(now)
	perSigner := 0
	for _, it := range p.items {
		if bytes.Equal(it.key, s.key) {
			return nil // the same control again: submitting is idempotent
		}
		if it.signer == s.signer {
			perSigner++
		}
	}
	if len(p.items) >= maxPosSubmissions || perSigner >= maxPosSubmissionsPerSigner {
		return fmt.Errorf("%w: the submission queue is full", ErrPosSubmission)
	}
	p.items = append(p.items, s)
	return nil
}

func (p *posSubmissions) expireLocked(now uint64) {
	kept := p.items[:0]
	for _, it := range p.items {
		if it.expires >= now {
			kept = append(kept, it)
		}
	}
	p.items = kept
}

// pending are the waiting submissions, oldest first.
func (p *posSubmissions) pending(now uint64) []posSubmission {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(now)
	return append([]posSubmission(nil), p.items...)
}

func (p *posSubmissions) drop(key []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	kept := p.items[:0]
	for _, it := range p.items {
		if !bytes.Equal(it.key, key) {
			kept = append(kept, it)
		}
	}
	p.items = kept
}

func (p *posSubmissions) len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.items)
}

// SubmitPosControl is the operator entry: this validator offers a Retirement or RejectResult control, with the witness its hash commits
// to, for a leader to order. The witness is retained here, where the leader and the voters pull it from; the control is signed with this
// validator's root key and sent to every root node, this one included.
func (x *ConsensusManager) SubmitPosControl(ctx context.Context, control drctypes.PosControl, witness []byte) error {
	if sha256.Sum256(witness) != control.WitnessHash {
		return fmt.Errorf("%w: the witness is not the one the control commits to", ErrPosSubmission)
	}
	if err := x.checkSubmittable(control); err != nil {
		return err
	}
	if err := x.blockStore.StoreWitness(witness); err != nil {
		return fmt.Errorf("%w: %w", ErrPosSubmission, err)
	}
	domain, err := abdrc.PosControlSigningBytes(control)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPosSubmission, err)
	}
	signature, err := x.safety.signer.SignBytes(domain)
	if err != nil {
		return fmt.Errorf("%w: signing: %w", ErrPosSubmission, err)
	}
	msg := &abdrc.PosControlSubmissionMsg{Control: control, Signer: x.id.String(), Signature: signature}
	if err := x.onPosControlSubmission(ctx, msg); err != nil {
		return err
	}
	sendCtx := context.WithoutCancel(ctx)
	for _, validator := range x.Validators() {
		if validator == x.id {
			continue
		}
		if err := x.net.Send(sendCtx, msg, validator); err != nil {
			x.log.WarnContext(ctx, "could not send the control submission", "validator", validator.String(), "error", err)
		}
	}
	return nil
}

// checkSubmittable is the state-free check of a submitted control: an op validators submit, on this chain's deployment, with no ordering
// position yet (the block that orders it stamps its own).
func (x *ConsensusManager) checkSubmittable(c drctypes.PosControl) error {
	svc := x.blockStore.PosServices()
	switch {
	case svc == nil || svc.Authority == nil:
		return fmt.Errorf("%w: this root has no P85 deployment", ErrPosSubmission)
	case c.Op != drctypes.OpRetirement && c.Op != drctypes.OpRejectResult:
		return fmt.Errorf("%w: op %d is not submitted (the closure is built by the proposer)", ErrPosSubmission, c.Op)
	case c.OrderingEpoch != 0 || c.OrderingRound != 0:
		return fmt.Errorf("%w: a submitted control names no ordering position", ErrPosSubmission)
	case c.Network != svc.Deployment.RootNetwork || c.ChainID != svc.Deployment.ChainID || c.Custody != svc.Deployment.Custody:
		return fmt.Errorf("%w: the control names another deployment", ErrPosSubmission)
	}
	if err := c.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrPosSubmission, err)
	}
	return nil
}

func (x *ConsensusManager) onPosControlSubmission(_ context.Context, msg *abdrc.PosControlSubmissionMsg) error {
	if msg == nil || msg.Signer == "" || len(msg.Signer) > 512 || len(msg.Signature) == 0 || len(msg.Signature) > 1024 {
		return fmt.Errorf("%w: malformed", ErrPosSubmission)
	}
	if err := x.checkSubmittable(msg.Control); err != nil {
		return err
	}
	domain, err := msg.SigningBytes()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPosSubmission, err)
	}
	if weight, err := x.trustBase.Load().VerifySignature(domain, msg.Signature, msg.Signer); err != nil || weight == 0 {
		return fmt.Errorf("%w: not signed by a root validator of this epoch", ErrPosSubmission)
	}
	now := x.pacemaker.GetCurrentRound()
	return x.posQueue.add(posSubmission{control: msg.Control, signer: msg.Signer, witness: msg.Control.WitnessHash,
		expires: now + posSubmissionTTL, key: domain}, now)
}

// orderSubmittedControl appends to the block the oldest submitted control that makes it a valid block, if any. The leader pulls the
// witness from the submitter, stamps the control with the block's position and executes the block as a trial: a control the state
// refuses (stale EVM state, already retired, ...) is dropped, never proposed, so a bad submission cannot cost the round its proposal.
func (x *ConsensusManager) orderSubmittedControl(ctx context.Context, block *drctypes.BlockData) {
	x.orderSubmittedControlWith(ctx, block, func(b *drctypes.BlockData) error { return x.blockStore.TrialExecute(b, x.irReqVerifier) })
}

func (x *ConsensusManager) orderSubmittedControlWith(ctx context.Context, block *drctypes.BlockData, trialExecute func(*drctypes.BlockData) error) {
	now := x.pacemaker.GetCurrentRound()
	trials := 0
	for _, s := range x.posQueue.pending(now) {
		if trials == maxPosTrials {
			return
		}
		trials++
		c := s.control
		c.OrderingEpoch, c.OrderingRound = block.Epoch, block.Round
		probe := &drctypes.BlockData{Author: s.signer, Epoch: block.Epoch, Round: block.Round, Payload: &drctypes.Payload{PosControls: []drctypes.PosControl{c}}}
		if err := x.fetchWitnesses(ctx, x.blockStore, probe); err != nil {
			x.log.WarnContext(ctx, "submitted control skipped: its witness cannot be pulled", "submitter", s.signer, "error", err)
			continue // the submitter may be unreachable for a moment: keep it until it expires
		}
		trial := *block
		payload := *block.Payload
		payload.PosControls = append(append([]drctypes.PosControl(nil), payload.PosControls...), c)
		trial.Payload = &payload
		if err := trialExecute(&trial); err != nil {
			x.log.WarnContext(ctx, "submitted control dropped: the root state refuses it", "submitter", s.signer, "op", c.Op, "error", err)
			x.posQueue.drop(s.key)
			continue
		}
		block.Payload = trial.Payload
		return
	}
}
