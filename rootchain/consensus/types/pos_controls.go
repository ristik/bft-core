package types

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
)

// PosControl is one P85 root control carried in the fourth payload collection: CloseLiability (a), Retirement (b) or RejectResult (c).
// The canonical item is
//
//	["UNICITY_P85_CONTROL", network, chainID, custody, orderingEpoch, orderingRound, op, context, data, witnessHash]
//
// with chainID a 32-byte unsigned big-endian word, custody bstr20, data the exact ABI words of the record payload and witnessHash the
// SHA-256 of the retained witness bytes (never carried in the payload). The context is a CBOR array whose shape the op fixes. Every
// size, ordering and canonical-encoding rule that needs no state is enforced here; proof checks and lifecycle rules belong to the
// executor (docs/design/h3-evm-assignment.md, briefs/p85-pr1c-control-records.md sections 2-5).
type PosControl struct {
	Network                      uint64
	ChainID                      [32]byte
	Custody                      [20]byte
	OrderingEpoch, OrderingRound uint64
	Op                           uint64
	// Exactly the context of Op is set.
	Close  *CloseContext
	Retire *RetireContext
	Reject *RejectContext
	// Data is the ABI-encoded payload of the projected record: ClosureData (192 bytes), RetirementData (96) or SessionClosedData (32).
	Data        []byte
	WitnessHash [32]byte

	// Registry marks a validator-registry (VR) mode control (schema-v1 section 8, FD-10): the same ten-element shape under the tag
	// UNICITY_VR_CONTROL, Custody holding VR's address. Its ops are 1 CloseLiability (192-byte Closure), 2 HolderRetirement v2 (context
	// [evmBlockHash, evmStateRoot], 128-byte HolderRetirement), 3 RejectResult v2 (the RejectResult context, 128-byte OutputRejected),
	// 4 RuleSupport (Support, no data, zero witness hash) and 5 HandoffView (View, no data, zero witness hash). The item encoding is
	// vrschema.EncodeVRControl's (a cross-check test pins it; rctypes cannot import vrschema, which depends on it).
	Registry bool
	Support  []SupportCommitment
	View     *ViewContext
}

// SupportCommitment is one rule-support commitment of a RuleSupport control: [network, stakingID, generation, rootKeyHash, ruleId,
// releaseDigest, sig], field for field vrschema.SupportCommitment.
type SupportCommitment struct {
	_             struct{} `cbor:",toarray"`
	Network       uint64
	StakingID     []byte
	Generation    uint64
	RootKeyHash   []byte
	RuleID        []byte
	ReleaseDigest []byte
	Sig           []byte
}

// ViewContext is the context [intentDigest, view] of HandoffView.
type ViewContext struct {
	IntentDigest [32]byte
	View         uint64
}

// CloseContext is the context [closedEpoch, bundleSemanticID] of CloseLiability.
type CloseContext struct {
	ClosedEpoch      uint64
	BundleSemanticID [32]byte
}

// RetireContext is the context [evmBlockHash, evmStateRoot] of Retirement: the certified EVM post-state the proofs are checked against.
type RetireContext struct{ EVMBlockHash, EVMStateRoot [32]byte }

// RejectContext is the context [predecessorBodyID, attempt, evmBlockHash, evmStateRoot] of RejectResult. Attempt is the root's handoff
// attempt (the next one of its control state), never Election's attempt counter (contracts#73).
type RejectContext struct {
	PredecessorBodyID          [32]byte
	Attempt                    uint64
	EVMBlockHash, EVMStateRoot [32]byte
}

const (
	PosControlTag = "UNICITY_P85_CONTROL"

	OpCloseLiability uint64 = 1
	OpRetirement     uint64 = 2
	OpRejectResult   uint64 = 3

	// VRControlTag is the tag of a VR-mode control; op 2 is HolderRetirement v2 and op 3 RejectResult v2 under it.
	VRControlTag         = "UNICITY_VR_CONTROL"
	OpRuleSupport uint64 = 4
	OpHandoffView uint64 = 5

	// MaxRuleSupportCommitments bounds one RuleSupport control (64, the rules of the support table).
	MaxRuleSupportCommitments = 64

	// MaxPosControls bounds the controls of one root block; the executor additionally caps the newly projected records at 32.
	MaxPosControls = 32
)

var (
	// ErrPosControl reports a control that is malformed, non-canonical or out of order.
	ErrPosControl = errors.New("invalid P85 root control")
)

// dataWidth is the exact ABI width of each op's record payload and uintMask the payload words that are uint64 (high bits zero).
func dataShape(op uint64, registry bool) []int {
	if registry {
		// the frozen record word types (vrschema.RecordWordTypes): 0 is bytes32, otherwise the integer's bit width, 1 a bool
		switch op {
		case OpCloseLiability:
			return []int{0, 64, 0, 0, 0, 0} // Closure (assignmentID, hRound, hRecordID, terminalRoot, exposureDigest, keyHistoryDigest)
		case OpRetirement:
			return []int{8, 64, 64, 0} // HolderRetirement (holder uint8, id, generation, refDigest)
		case OpRejectResult:
			return []int{0, 8, 64, 16} // OutputRejected (resultID, reason uint8, memberId, readyBitmap uint16)
		}
		return nil // RuleSupport, HandoffView: no data
	}
	switch op {
	case OpCloseLiability:
		return []int{0, 64, 0, 0, 0, 0} // (assignmentID, hRound, hRecordID, terminalRoot, exposureDigest, keyHistoryDigest)
	case OpRetirement:
		return []int{64, 64, 0} // (id, generation, refDigest)
	case OpRejectResult:
		return []int{0} // (resultID)
	}
	return nil
}

// wordFits reports a big-endian word whose value fits bits (every higher byte zero, and the top byte's spare bits zero); a bool word
// (bits 1) is exactly 0 or 1.
func wordFits(w []byte, bits int) bool {
	full := 32 - (bits+7)/8
	if !bytes.Equal(w[:full], make([]byte, full)) {
		return false
	}
	if r := bits % 8; r != 0 && w[full]>>r != 0 {
		return false
	}
	return true
}

func (c PosControl) contextValue() ([]any, error) {
	if c.Registry {
		return c.vrContextValue()
	}
	if c.Support != nil || c.View != nil {
		return nil, fmt.Errorf("%w: a P85 control carries a VR context", ErrPosControl)
	}
	switch {
	case c.Op == OpCloseLiability && c.Close != nil && c.Retire == nil && c.Reject == nil:
		return []any{c.Close.ClosedEpoch, c.Close.BundleSemanticID[:]}, nil
	case c.Op == OpRetirement && c.Retire != nil && c.Close == nil && c.Reject == nil:
		return []any{c.Retire.EVMBlockHash[:], c.Retire.EVMStateRoot[:]}, nil
	case c.Op == OpRejectResult && c.Reject != nil && c.Close == nil && c.Retire == nil:
		return []any{c.Reject.PredecessorBodyID[:], c.Reject.Attempt, c.Reject.EVMBlockHash[:], c.Reject.EVMStateRoot[:]}, nil
	}
	return nil, fmt.Errorf("%w: op %d does not match its context", ErrPosControl, c.Op)
}

func (c PosControl) vrContextValue() ([]any, error) {
	none := func(close, retire, reject, support, view bool) bool {
		return (c.Close != nil) == close && (c.Retire != nil) == retire && (c.Reject != nil) == reject && (c.Support != nil) == support && (c.View != nil) == view
	}
	switch {
	case c.Op == OpCloseLiability && none(true, false, false, false, false):
		return []any{c.Close.ClosedEpoch, c.Close.BundleSemanticID[:]}, nil
	case c.Op == OpRetirement && none(false, true, false, false, false):
		return []any{c.Retire.EVMBlockHash[:], c.Retire.EVMStateRoot[:]}, nil
	case c.Op == OpRejectResult && none(false, false, true, false, false):
		return []any{c.Reject.PredecessorBodyID[:], c.Reject.Attempt, c.Reject.EVMBlockHash[:], c.Reject.EVMStateRoot[:]}, nil
	case c.Op == OpRuleSupport && none(false, false, false, true, false):
		if len(c.Support) == 0 || len(c.Support) > MaxRuleSupportCommitments {
			return nil, fmt.Errorf("%w: %d rule-support commitments", ErrPosControl, len(c.Support))
		}
		for i, x := range c.Support {
			if len(x.StakingID) != 32 || len(x.RootKeyHash) != 32 || len(x.RuleID) != 32 || len(x.ReleaseDigest) != 32 || len(x.Sig) != 65 {
				return nil, fmt.Errorf("%w: rule-support commitment %d shape", ErrPosControl, i)
			}
			if i > 0 {
				p := c.Support[i-1]
				if k := bytes.Compare(p.StakingID, x.StakingID); k > 0 || (k == 0 && bytes.Compare(p.RuleID, x.RuleID) >= 0) {
					return nil, fmt.Errorf("%w: rule-support commitments not strictly ascending by (stakingID, ruleId)", ErrPosControl)
				}
			}
		}
		return []any{c.Support}, nil
	case c.Op == OpHandoffView && none(false, false, false, false, true):
		if c.View.IntentDigest == ([32]byte{}) || c.View.View == 0 {
			return nil, fmt.Errorf("%w: HandoffView of a zero intent or view 0", ErrPosControl)
		}
		return []any{c.View.IntentDigest[:], c.View.View}, nil
	}
	return nil, fmt.Errorf("%w: VR op %d does not match its context", ErrPosControl, c.Op)
}

func (c PosControl) tag() string {
	if c.Registry {
		return VRControlTag
	}
	return PosControlTag
}

// Validate is the stateless shape check: a known op with its context, the exact payload width, uint64 payload words within range.
func (c PosControl) Validate() error {
	if _, err := c.contextValue(); err != nil {
		return err
	}
	words := dataShape(c.Op, c.Registry)
	if len(c.Data) != 32*len(words) {
		return fmt.Errorf("%w: op %d payload is %d bytes, want %d", ErrPosControl, c.Op, len(c.Data), 32*len(words))
	}
	for j, bits := range words {
		if bits != 0 && !wordFits(c.Data[32*j:32*j+32], bits) {
			return fmt.Errorf("%w: payload word %d exceeds uint%d", ErrPosControl, j, bits)
		}
	}
	if c.Op == OpCloseLiability && c.Close.ClosedEpoch == 0 {
		return fmt.Errorf("%w: closed epoch zero", ErrPosControl)
	}
	if c.Registry && (c.Op == OpRuleSupport || c.Op == OpHandoffView) && c.WitnessHash != ([32]byte{}) {
		return fmt.Errorf("%w: a root-only control carries no witness", ErrPosControl)
	}
	return nil
}

// MarshalCBOR encodes the canonical ten-element item.
func (c PosControl) MarshalCBOR() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	ctx, _ := c.contextValue()
	data := c.Data
	if data == nil {
		data = []byte{}
	}
	return types.Cbor.Marshal([]any{c.tag(), c.Network, c.ChainID[:], c.Custody[:], c.OrderingEpoch, c.OrderingRound, c.Op, ctx, data, c.WitnessHash[:]})
}

func exactBytes(v any, n int) ([]byte, bool) {
	b, ok := v.([]byte)
	return b, ok && len(b) == n
}

// UnmarshalCBOR decodes one item and refuses every non-canonical form: a different arity, tag, width, an element of the wrong CBOR type,
// a null, a non-shortest integer or any trailing byte (the item must re-encode to exactly the bytes read).
func (c *PosControl) UnmarshalCBOR(data []byte) error {
	var f []any
	if err := types.Cbor.Unmarshal(data, &f); err != nil || len(f) != 10 {
		return fmt.Errorf("%w: item shape", ErrPosControl)
	}
	tag, ok := f[0].(string)
	if !ok || (tag != PosControlTag && tag != VRControlTag) {
		return fmt.Errorf("%w: tag", ErrPosControl)
	}
	var out PosControl
	out.Registry = tag == VRControlTag
	var good [9]bool
	out.Network, good[0] = f[1].(uint64)
	chain, ok := exactBytes(f[2], 32)
	good[1] = ok
	copy(out.ChainID[:], chain)
	custody, ok := exactBytes(f[3], 20)
	good[2] = ok
	copy(out.Custody[:], custody)
	out.OrderingEpoch, good[3] = f[4].(uint64)
	out.OrderingRound, good[4] = f[5].(uint64)
	out.Op, good[5] = f[6].(uint64)
	out.Data, good[6] = f[8].([]byte)
	witness, ok := exactBytes(f[9], 32)
	good[7] = ok
	copy(out.WitnessHash[:], witness)
	ctx, isArr := f[7].([]any)
	good[8] = isArr
	for _, g := range good {
		if !g {
			return fmt.Errorf("%w: field type", ErrPosControl)
		}
	}
	switch {
	case out.Op == OpCloseLiability && len(ctx) == 2:
		epoch, ok1 := ctx[0].(uint64)
		id, ok2 := exactBytes(ctx[1], 32)
		if !ok1 || !ok2 {
			return fmt.Errorf("%w: closure context", ErrPosControl)
		}
		out.Close = &CloseContext{ClosedEpoch: epoch}
		copy(out.Close.BundleSemanticID[:], id)
	case out.Op == OpRetirement && len(ctx) == 2:
		bh, ok1 := exactBytes(ctx[0], 32)
		sr, ok2 := exactBytes(ctx[1], 32)
		if !ok1 || !ok2 {
			return fmt.Errorf("%w: retirement context", ErrPosControl)
		}
		out.Retire = &RetireContext{}
		copy(out.Retire.EVMBlockHash[:], bh)
		copy(out.Retire.EVMStateRoot[:], sr)
	case out.Op == OpRejectResult && len(ctx) == 4:
		pb, ok1 := exactBytes(ctx[0], 32)
		attempt, ok2 := ctx[1].(uint64)
		bh, ok3 := exactBytes(ctx[2], 32)
		sr, ok4 := exactBytes(ctx[3], 32)
		if !ok1 || !ok2 || !ok3 || !ok4 {
			return fmt.Errorf("%w: rejection context", ErrPosControl)
		}
		out.Reject = &RejectContext{Attempt: attempt}
		copy(out.Reject.PredecessorBodyID[:], pb)
		copy(out.Reject.EVMBlockHash[:], bh)
		copy(out.Reject.EVMStateRoot[:], sr)
	case out.Registry && out.Op == OpRuleSupport && len(ctx) == 1:
		raw, err := types.Cbor.Marshal(ctx[0])
		if err != nil || types.Cbor.Unmarshal(raw, &out.Support) != nil || out.Support == nil {
			return fmt.Errorf("%w: rule-support context", ErrPosControl)
		}
	case out.Registry && out.Op == OpHandoffView && len(ctx) == 2:
		id, ok1 := exactBytes(ctx[0], 32)
		view, ok2 := ctx[1].(uint64)
		if !ok1 || !ok2 {
			return fmt.Errorf("%w: HandoffView context", ErrPosControl)
		}
		out.View = &ViewContext{View: view}
		copy(out.View.IntentDigest[:], id)
	default:
		return fmt.Errorf("%w: op %d", ErrPosControl, out.Op)
	}
	if len(out.Data) == 0 {
		out.Data = nil
	}
	if err := out.Validate(); err != nil {
		return err
	}
	again, err := out.MarshalCBOR()
	if err != nil || !bytes.Equal(again, data) {
		return fmt.Errorf("%w: not canonical", ErrPosControl)
	}
	*c = out
	return nil
}

// closureEpoch, retirementKey are the identities the ordering rule sorts and de-duplicates by.
// A P85 Retirement is keyed (0, id, generation), a VR HolderRetirement (holder, id, generation).
func (c PosControl) retirementKey() [3]uint64 {
	if c.Registry {
		return [3]uint64{beUint64(c.Data[24:32]), beUint64(c.Data[56:64]), beUint64(c.Data[88:96])}
	}
	return [3]uint64{0, beUint64(c.Data[24:32]), beUint64(c.Data[56:64])}
}

func beUint64(b []byte) (v uint64) {
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

// validatePosControls is the payload-level rule: at most MaxPosControls; every item valid; the mandatory closures first in strictly
// ascending closed epoch, then at most one RejectResult, then Retirements in strictly ascending (id, generation) (VR: (holder, id,
// generation)), then, in VR mode only, the RuleSupport controls and at most one HandoffView, last. Duplicates and any other order are
// refused, so the executor never has a tie to break; P85 and VR controls never share a block.
func validatePosControls(cs []PosControl) error {
	if len(cs) > MaxPosControls {
		return fmt.Errorf("%w: %d controls", ErrPosControl, len(cs))
	}
	group := func(op uint64) int {
		switch op {
		case OpCloseLiability:
			return 0
		case OpRejectResult:
			return 1
		case OpRetirement:
			return 2
		case OpRuleSupport:
			return 3
		}
		return 4
	}
	rejects, views := 0, 0
	for i, c := range cs {
		if err := c.Validate(); err != nil {
			return fmt.Errorf("control %d: %w", i, err)
		}
		if c.Registry != cs[0].Registry {
			return fmt.Errorf("%w: P85 and VR controls in one block", ErrPosControl)
		}
		if c.Op == OpHandoffView {
			if views++; views > 1 {
				return fmt.Errorf("%w: more than one HandoffView in a block", ErrPosControl)
			}
		}
		if c.Op == OpRejectResult {
			if rejects++; rejects > 1 {
				return fmt.Errorf("%w: more than one RejectResult in a block", ErrPosControl)
			}
		}
		if i == 0 {
			continue
		}
		p := cs[i-1]
		switch gp, gc := group(p.Op), group(c.Op); {
		case gc < gp:
			return fmt.Errorf("%w: control %d is out of group order", ErrPosControl, i)
		case gc == gp && c.Op == OpCloseLiability && c.Close.ClosedEpoch <= p.Close.ClosedEpoch:
			return fmt.Errorf("%w: closures must ascend by closed epoch without duplicates", ErrPosControl)
		case gc == gp && c.Op == OpRetirement && !lessKey(p.retirementKey(), c.retirementKey()):
			return fmt.Errorf("%w: retirements must ascend by (id, generation) without duplicates", ErrPosControl)
		}
	}
	return nil
}

func lessKey(a, b [3]uint64) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
