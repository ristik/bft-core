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
}

// CloseContext is the context [closedEpoch, bundleSemanticID] of CloseLiability.
type CloseContext struct {
	ClosedEpoch      uint64
	BundleSemanticID [32]byte
}

// RetireContext is the context [evmBlockHash, evmStateRoot] of Retirement: the certified EVM post-state the proofs are checked against.
type RetireContext struct{ EVMBlockHash, EVMStateRoot [32]byte }

// RejectContext is the context [predecessorBodyID, attempt, evmBlockHash, evmStateRoot] of RejectResult.
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

	// MaxPosControls bounds the controls of one root block; the executor additionally caps the newly projected records at 32.
	MaxPosControls = 32
)

var (
	// ErrPosControl reports a control that is malformed, non-canonical or out of order.
	ErrPosControl = errors.New("invalid P85 root control")
)

// dataWidth is the exact ABI width of each op's record payload and uintMask the payload words that are uint64 (high bits zero).
func dataShape(op uint64) (width int, uintMask uint) {
	switch op {
	case OpCloseLiability:
		return 192, 0b000010 // (assignmentID, hRound, hRecordID, terminalRoot, exposureDigest, keyHistoryDigest)
	case OpRetirement:
		return 96, 0b011 // (id, generation, refDigest)
	case OpRejectResult:
		return 32, 0 // (resultID)
	}
	return 0, 0
}

func (c PosControl) contextValue() ([]any, error) {
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

// Validate is the stateless shape check: a known op with its context, the exact payload width, uint64 payload words within range.
func (c PosControl) Validate() error {
	if _, err := c.contextValue(); err != nil {
		return err
	}
	width, mask := dataShape(c.Op)
	if len(c.Data) != width {
		return fmt.Errorf("%w: op %d payload is %d bytes, want %d", ErrPosControl, c.Op, len(c.Data), width)
	}
	for j := 0; j < width/32; j++ {
		if mask&(1<<j) != 0 && !bytes.Equal(c.Data[32*j:32*j+24], make([]byte, 24)) {
			return fmt.Errorf("%w: payload word %d exceeds uint64", ErrPosControl, j)
		}
	}
	if c.Op == OpCloseLiability && c.Close.ClosedEpoch == 0 {
		return fmt.Errorf("%w: closed epoch zero", ErrPosControl)
	}
	return nil
}

// MarshalCBOR encodes the canonical ten-element item.
func (c PosControl) MarshalCBOR() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	ctx, _ := c.contextValue()
	return types.Cbor.Marshal([]any{PosControlTag, c.Network, c.ChainID[:], c.Custody[:], c.OrderingEpoch, c.OrderingRound, c.Op, ctx, c.Data, c.WitnessHash[:]})
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
	if tag, ok := f[0].(string); !ok || tag != PosControlTag {
		return fmt.Errorf("%w: tag", ErrPosControl)
	}
	var out PosControl
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
	default:
		return fmt.Errorf("%w: op %d", ErrPosControl, out.Op)
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
func (c PosControl) retirementKey() [2]uint64 {
	return [2]uint64{beUint64(c.Data[24:32]), beUint64(c.Data[56:64])}
}

func beUint64(b []byte) (v uint64) {
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

// validatePosControls is the payload-level rule: at most MaxPosControls; every item valid; the mandatory closures first in strictly
// ascending closed epoch, then at most one RejectResult, then Retirements in strictly ascending (id, generation). Duplicates and any
// other order are refused, so the executor never has a tie to break.
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
		}
		return 2
	}
	rejects := 0
	for i, c := range cs {
		if err := c.Validate(); err != nil {
			return fmt.Errorf("control %d: %w", i, err)
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

func lessKey(a, b [2]uint64) bool { return a[0] < b[0] || a[0] == b[0] && a[1] < b[1] }
