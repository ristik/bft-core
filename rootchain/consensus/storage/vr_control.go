package storage

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// The VR-mode root controls (design section 5.6, schema section 8): ops 1 to 5 under UNICITY_VR_CONTROL, executed in payload order after
// the block's certifications, against the VR root state the block started from.

// vrEnv is the VR half of a control's environment: the step, the services, the acknowledged committee (and any pending K) the controls
// are judged against, and the intent query HandoffView derives over.
type vrEnv struct {
	step *vrStep
	svc  *VRServices
	// committee is the acknowledged committee followed by the pending steps' identities (the bindings rule support may name); acked the
	// acknowledged committee alone.
	committee func() (acked, all []evmassign.Identity, err error)
	query     VRIntentQuery
}

// vrControl executes one VR-mode control. It returns the control state a RejectResult replaced, or nil.
func (p *posStep) vrControl(i int, c rctypes.PosControl, block *rctypes.BlockData, svc *PosServices, env posEnv) (*evmroot.ControlState, error) {
	if !env.vrOn() || svc.Registry == nil {
		return nil, fmt.Errorf("%w: a VR control on a chain that is not in VR mode", ErrVRMode)
	}
	d := svc.Registry.Deployment
	if c.Network != d.RootNetwork || c.ChainID != d.ChainID || c.Custody != d.Registry || c.OrderingEpoch != block.Epoch || c.OrderingRound != block.Round {
		return nil, fmt.Errorf("%w: control %d names another deployment, epoch or round than this block", ErrVRControlRefused, i)
	}
	switch c.Op {
	case rctypes.OpCloseLiability:
		return nil, p.closeLiabilityIn(c, block, svc, svc.Registry.domain())
	case rctypes.OpRetirement:
		return nil, p.holderRetire(c, block, svc, env)
	case rctypes.OpRejectResult:
		return p.rejectV2(c, block, svc, env)
	case rctypes.OpRuleSupport:
		return nil, p.ruleSupport(c, block, svc, env)
	case rctypes.OpHandoffView:
		return nil, p.handoffView(c, block, svc, env)
	}
	return nil, fmt.Errorf("%w: unknown op %d", ErrVRControlRefused, c.Op)
}

// holderRetire is control op 2 v2 (design section 3.9.3): the three-account witness at the EVM state the parent certified, the frozen check
// order, then the holder-scoped record once.
func (p *posStep) holderRetire(c rctypes.PosControl, block *rctypes.BlockData, svc *PosServices, env posEnv) error {
	h, err := vrschema.DecodeHolderRetirement(c.Data)
	if err != nil {
		return errors.Join(ErrVRControlRefused, err)
	}
	if svc.Registry.State == nil {
		return fmt.Errorf("%w: no VR witness verifier", ErrVRMode)
	}
	if err := certifiedState(c.Retire.EVMBlockHash, c.Retire.EVMStateRoot, svc, env); err != nil {
		return errors.Join(ErrVRControlRefused, err)
	}
	witness, err := witnessOf(c, svc)
	if err != nil {
		return err
	}
	progress, err := p.state.Progress(block.Round)
	if err != nil {
		return errors.Join(ErrVRControlRefused, err)
	}
	w, err := svc.Registry.State.VerifyRetirement(witness, c.Retire.EVMStateRoot, h, progress, env.InFlight)
	if err != nil {
		return errors.Join(ErrVRControlRefused, err)
	}
	if err := vradmit.VerifyRetirement(w, h); err != nil {
		return errors.Join(ErrVRControlRefused, err)
	}
	next, rec, err := p.state.HolderRetire(h.Holder, h.ID, h.Generation, h.RefDigest, w.Facts.MaxLiabilityAnchor, block.Round, block.Timestamp)
	if err != nil {
		return errors.Join(ErrVRControlRefused, err)
	}
	p.set(next)
	if rec != nil {
		p.records = append(p.records, *rec)
	}
	return nil
}

// rejectV2 is control op 3 v2 (design section 5.6): ordered only at a quiet control state, for an unresolved result, naming the root's
// authority and next attempt and the EVM state the parent certified; the witness's due table gives the reason. It projects OutputRejected
// and then SessionClosed and aborts the root's attempt, exactly as the P85 rejection does.
func (p *posStep) rejectV2(c rctypes.PosControl, block *rctypes.BlockData, svc *PosServices, env posEnv) (*evmroot.ControlState, error) {
	ctl := env.Control
	if ctl == nil || svc.Registry.State == nil || env.vr == nil {
		return nil, fmt.Errorf("%w: no control state or VR witness verifier", ErrVRMode)
	}
	data, err := vrschema.DecodeOutputRejected(c.Data)
	if err != nil {
		return nil, errors.Join(ErrVRControlRefused, err)
	}
	next, err := rejectNext(ctl, block.Round)
	if err != nil {
		return nil, errors.Join(ErrVRControlRefused, err)
	}
	switch {
	case len(p.state.Pending) > 0:
		return nil, errors.Join(ErrVRControlRefused, ErrRejectNotQuiet, errors.New("a committed handoff awaits its acknowledgement"))
	case p.state.Frozen:
		return nil, errors.Join(ErrVRControlRefused, ErrRejectNotQuiet, errors.New("the progress tracker is frozen at an H"))
	case p.state.IsResolved(data.ResultID):
		return nil, errors.Join(ErrVRControlRefused, ErrResolvedResult)
	case !bytes.Equal(c.Reject.PredecessorBodyID[:], ctl.PredecessorBodyID):
		return nil, fmt.Errorf("%w: another predecessor than the root's authority", ErrVRControlRefused)
	case c.Reject.Attempt != next:
		return nil, errors.Join(ErrVRControlRefused, ErrRejectAttempt, fmt.Errorf("attempt %d is not the next attempt %d", c.Reject.Attempt, next))
	}
	if err := certifiedState(c.Reject.EVMBlockHash, c.Reject.EVMStateRoot, svc, env); err != nil {
		return nil, errors.Join(ErrVRControlRefused, err)
	}
	witness, err := witnessOf(c, svc)
	if err != nil {
		return nil, err
	}
	s, err := svc.Registry.State.VerifyReject(witness, c.Reject.EVMStateRoot, data.ResultID)
	if err != nil {
		return nil, errors.Join(ErrVRControlRefused, err)
	}
	acked, _, err := env.vr.committee()
	if err != nil {
		return nil, errors.Join(ErrVRUnavailable, err)
	}
	kd, err := vradmit.MembersDigestOf(acked)
	if err != nil {
		return nil, errors.Join(ErrVRControlRefused, err)
	}
	if err := vradmit.VerifyReject(s, data, svc.Registry.Deployment, env.vr.step.state.Acknowledged, kd); err != nil {
		return nil, errors.Join(ErrVRControlRefused, err)
	}
	state, recs, err := p.state.RejectOutput(data.ResultID, data.Reason, data.MemberID, data.ReadyBitmap, block.Round, block.Timestamp)
	if err != nil {
		return nil, errors.Join(ErrVRControlRefused, err)
	}
	p.set(state)
	p.records = append(p.records, recs...)
	return &evmroot.ControlState{Network: ctl.Network, Epoch: ctl.Epoch, PredecessorBodyID: bytes.Clone(ctl.PredecessorBodyID), Attempt: next,
		Phase: "aborted", OrderedRound: block.Round, PreviousDigest: ctl.Digest(), UnackedParent: bytes.Clone(ctl.UnackedParent)}, nil
}

// ruleSupport is control op 4 (root-only, no record): commitments by the exact current bindings of the acknowledged committee or a pending
// K, for rules of the committed schedule, enter the committed support table.
func (p *posStep) ruleSupport(c rctypes.PosControl, block *rctypes.BlockData, svc *PosServices, env posEnv) error {
	if env.vr == nil {
		return ErrVRMode
	}
	_, members, err := env.vr.committee()
	if err != nil {
		return errors.Join(ErrVRUnavailable, err)
	}
	schedule := env.vr.step.state.Schedule
	cs := make([]vrschema.SupportCommitment, len(c.Support))
	for i, x := range c.Support {
		cs[i] = vrschema.SupportCommitment{Network: x.Network, StakingID: x.StakingID, Generation: x.Generation, RootKeyHash: x.RootKeyHash, BindingRef: x.BindingRef,
			RuleID: x.RuleID, ReleaseDigest: x.ReleaseDigest, Sig: x.Sig}
	}
	v := env.vr.step
	table, err := vradmit.ApplyRuleSupport(v.state.Support, svc.Registry.Deployment.RootNetwork, cs, members, schedule)
	if err != nil {
		return errors.Join(ErrVRControlRefused, err)
	}
	next := v.state
	next.Support = table
	v.set(next)
	return nil
}

// handoffView is control op 5 (root-only, no record): the replay rule over the committed backoff and the derivable intent, then the HV
// transition. The live-vote residence rule is not evaluated here: it is a voting policy, never a validity rule.
func (p *posStep) handoffView(c rctypes.PosControl, block *rctypes.BlockData, svc *PosServices, env posEnv) error {
	if env.vr == nil || svc.Registry.Intents == nil {
		return fmt.Errorf("%w: no intent derivation", ErrVRMode)
	}
	v := env.vr.step
	q := env.vr.query
	q.Backoff = v.state.Backoff
	in, ok, err := svc.Registry.Intents.Intent(q)
	if err != nil {
		return errors.Join(ErrVRUnavailable, err)
	}
	views := 0
	for _, x := range block.Payload.PosControls {
		if x.Registry && x.Op == rctypes.OpHandoffView {
			views++
		}
	}
	intent := c.View.IntentDigest
	next, err := v.state.ApplyHandoffView(intent[:], c.View.View, vradmit.ViewEnv{IntentDerivable: ok && in.Digest == intent,
		AnchorUCTime: in.AnchorUCTime, InBlock: views, BlockUCTime: block.Timestamp})
	if err != nil {
		return errors.Join(ErrVRControlRefused, err)
	}
	v.set(next)
	return nil
}
