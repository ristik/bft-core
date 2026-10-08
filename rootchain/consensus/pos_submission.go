package consensus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

const (
	// maxPosSubmissions bounds the controls waiting to be ordered, maxPosSubmissionsPerSigner those of one validator.
	maxPosSubmissions          = 32
	maxPosSubmissionsPerSigner = 4
	// posSubmissionTTL is how many rounds a submission waits. A Retirement or RejectResult is proved against the latest certified EVM
	// state, so a submission that waits for long is stale anyway: the submitter proves again.
	posSubmissionTTL = 120
	// maxPosTrials bounds the trial executions of one proposal, maxPosPrefetches the witness pulls in flight.
	maxPosTrials     = 4
	maxPosPrefetches = 4
)

// ErrPosSubmission reports a control submission that is refused.
var ErrPosSubmission = errors.New("P85 control submission refused")

type posSubmission struct {
	control drctypes.PosControl
	signer  string
	witness [32]byte
	epoch   uint64
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
	epoch := x.trustBase.Load().Epoch
	domain, err := abdrc.PosControlSigningBytes(control, epoch)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPosSubmission, err)
	}
	signature, err := x.safety.signer.SignBytes(domain)
	if err != nil {
		return fmt.Errorf("%w: signing: %w", ErrPosSubmission, err)
	}
	msg := &abdrc.PosControlSubmissionMsg{Control: control, Epoch: epoch, Signer: x.id.String(), Signature: signature}
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
	if msg.Epoch != x.trustBase.Load().Epoch {
		return fmt.Errorf("%w: signed for root epoch %d, this is epoch %d", ErrPosSubmission, msg.Epoch, x.trustBase.Load().Epoch)
	}
	domain, err := msg.SigningBytes()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPosSubmission, err)
	}
	if weight, err := x.trustBase.Load().VerifySignature(domain, msg.Signature, msg.Signer); err != nil || weight == 0 {
		return fmt.Errorf("%w: not signed by a root validator of this epoch", ErrPosSubmission)
	}
	now := x.pacemaker.GetCurrentRound()
	sub := posSubmission{control: msg.Control, signer: msg.Signer, witness: msg.Control.WitnessHash, epoch: msg.Epoch,
		expires: now + posSubmissionTTL, key: domain}
	store := x.blockStore
	if store.HasWitness(sub.witness) {
		return x.posQueue.add(sub, now)
	}
	// The leader never pulls over the network while it builds a proposal: the witness is fetched here, off the consensus loop, and a
	// submission whose witness could not be had is dropped (the operator submits again).
	if x.witnesses == nil {
		return fmt.Errorf("%w: this root cannot fetch the submitter's witness", ErrPosSubmission)
	}
	if x.posPrefetching.Add(1) > maxPosPrefetches {
		x.posPrefetching.Add(-1)
		return fmt.Errorf("%w: too many witnesses are being fetched", ErrPosSubmission)
	}
	if err := x.posQueue.add(sub, now); err != nil {
		x.posPrefetching.Add(-1)
		return err
	}
	go func() {
		defer x.posPrefetching.Add(-1)
		x.prefetchPosWitness(store, sub)
	}()
	return nil
}

// prefetchPosWitness pulls the witness of a queued submission from its submitter (then the other root nodes), within the same bounds
// as the voters' pull, and drops the submission when it cannot be had. It runs off the consensus loop.
func (x *ConsensusManager) prefetchPosWitness(store *storage.BlockStore, s posSubmission) {
	budget := 5 * time.Second
	if x.params != nil && x.params.LocalTimeout > 0 {
		budget = x.params.LocalTimeout / 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	author := &drctypes.BlockData{Author: s.signer, Epoch: s.epoch}
	data, err := x.witnesses(ctx, s.witness, x.witnessPeers(author), storage.WitnessBound(s.control.Op))
	if err == nil && sha256.Sum256(data) != s.witness {
		err = errors.New("the fetched bytes are not the committed witness")
	}
	if err == nil {
		err = store.StoreWitness(data)
	}
	if err != nil {
		x.log.Warn("submitted control dropped: its witness cannot be had", "submitter", s.signer, "error", err)
		x.posQueue.drop(s.key)
	}
}

// orderSubmittedControl appends to the block the oldest submitted control that makes it a valid block, if any. Only a submission whose
// witness is already held here is considered (nothing is pulled while a proposal is built); the leader stamps the control with the
// block's position and executes the block as a trial: a control the state refuses (stale EVM state, already retired, ...) is dropped,
// never proposed, so a bad submission cannot cost the round its proposal.
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
		if !x.blockStore.HasWitness(s.witness) {
			continue // still being fetched (or dropped soon): not a candidate yet
		}
		trials++
		c := s.control
		c.OrderingEpoch, c.OrderingRound = block.Epoch, block.Round
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
