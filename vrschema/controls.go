package vrschema

import (
	"bytes"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/unicitynetwork/bft-go-base/types"
)

// VRControl is one VR-mode root control in the fourth payload collection. It keeps the P85 control's ten-element shape under its own
// tag, so a VR-mode op is self-describing:
//
//	["UNICITY_VR_CONTROL", network, chainID, registry, orderingEpoch, orderingRound, op, context, data, witnessHash]
//
// with chainID a 32-byte big-endian word, registry the 20-byte VR address, data the exact ABI words of the first projected record and
// witnessHash the SHA-256 of the retained witness (32 zero bytes for the root-only ops 4 and 5, which carry no witness and no data).
type VRControl struct {
	Network                      uint64
	ChainID                      [32]byte
	Registry                     [20]byte
	OrderingEpoch, OrderingRound uint64
	Op                           uint64
	Context                      []any // op-specific, see ControlContext
	Data                         []byte
	WitnessHash                  [32]byte
}

// MaxRuleSupportCommitments bounds the commitments of one RuleSupport control.
const MaxRuleSupportCommitments = SupportRules

// ControlShapes are the frozen context and data shapes.
var ControlShapes = map[uint64]struct {
	Context string
	Data    int
	Records []uint8
}{
	OpCloseLiability:   {"[closedEpoch uint, bundleSemanticID bstr32]", 192, []uint8{RecClosure}},
	OpHolderRetirement: {"[evmBlockHash bstr32, evmStateRoot bstr32]", 128, []uint8{RecHolderRetirement}},
	OpRejectResult:     {"[predecessorBodyID bstr32, attempt uint, evmBlockHash bstr32, evmStateRoot bstr32]", 128, []uint8{RecOutputRejected, RecSessionClosed}},
	OpRuleSupport:      {"[commitments: 1..64 SupportCommitment, strictly ascending by (stakingID, ruleId)]", 0, nil},
	OpHandoffView:      {"[intentDigest bstr32, view uint >= 1]", 0, nil},
	OpPoPRequest:       {"[intentDigest bstr32]", 0, nil},
}

// RejectMissesShape is the optional fifth element of a RejectResult v2 context (#1319): the certified handoff-PoP misses of an expiry.
const RejectMissesShape = "misses: 1..16 MissCertificate, strictly ascending by stakingID"

type vrControlWire struct {
	_             struct{} `cbor:",toarray"`
	Tag           string
	Network       uint64
	ChainID       []byte
	Registry      []byte
	OrderingEpoch uint64
	OrderingRound uint64
	Op            uint64
	Context       cbor.RawMessage
	Data          []byte
	WitnessHash   []byte
}

type closeCtx struct {
	_      struct{} `cbor:",toarray"`
	Epoch  uint64
	Bundle []byte
}
type stateCtx struct {
	_         struct{} `cbor:",toarray"`
	BlockHash []byte
	StateRoot []byte
}
type rejectCtx struct {
	_         struct{} `cbor:",toarray"`
	Pred      []byte
	Attempt   uint64
	BlockHash []byte
	StateRoot []byte
}
type supportCtx struct {
	_           struct{} `cbor:",toarray"`
	Commitments []SupportCommitment
}
type rejectMissCtx struct {
	_         struct{} `cbor:",toarray"`
	Pred      []byte
	Attempt   uint64
	BlockHash []byte
	StateRoot []byte
	Misses    []MissCertificate
}
type requestCtx struct {
	_      struct{} `cbor:",toarray"`
	Intent []byte
}
type viewCtx struct {
	_      struct{} `cbor:",toarray"`
	Intent []byte
	View   uint64
}

// ControlContext is the typed context of one op.
type ControlContext struct {
	ClosedEpoch      uint64
	BundleSemanticID []byte
	EVMBlockHash     []byte
	EVMStateRoot     []byte
	Predecessor      []byte
	Attempt          uint64
	Commitments      []SupportCommitment
	IntentDigest     []byte
	View             uint64
	// Misses are a RejectResult's certified handoff-PoP misses (#1319): empty for an ordinary rejection, whose context keeps its four elements.
	Misses []MissCertificate
}

func (c ControlContext) wire(op uint64) (any, error) {
	switch op {
	case OpCloseLiability:
		if c.ClosedEpoch == 0 || !len32(c.BundleSemanticID) {
			return nil, ErrRange
		}
		return closeCtx{Epoch: c.ClosedEpoch, Bundle: c.BundleSemanticID}, nil
	case OpHolderRetirement:
		if !len32(c.EVMBlockHash, c.EVMStateRoot) {
			return nil, ErrLength
		}
		return stateCtx{BlockHash: c.EVMBlockHash, StateRoot: c.EVMStateRoot}, nil
	case OpRejectResult:
		if !len32(c.Predecessor, c.EVMBlockHash, c.EVMStateRoot) {
			return nil, ErrLength
		}
		if len(c.Misses) > 0 {
			if err := CheckMissCertificates(c.Misses); err != nil {
				return nil, err
			}
			return rejectMissCtx{Pred: c.Predecessor, Attempt: c.Attempt, BlockHash: c.EVMBlockHash, StateRoot: c.EVMStateRoot, Misses: c.Misses}, nil
		}
		return rejectCtx{Pred: c.Predecessor, Attempt: c.Attempt, BlockHash: c.EVMBlockHash, StateRoot: c.EVMStateRoot}, nil
	case OpRuleSupport:
		cs := c.Commitments
		if len(cs) < 1 || len(cs) > MaxRuleSupportCommitments {
			return nil, ErrRange
		}
		for i := range cs {
			if _, err := cs[i].SignedBytes(); err != nil || len(cs[i].Sig) != 65 {
				return nil, ErrLength
			}
			if i > 0 {
				k := bytes.Compare(cs[i-1].StakingID, cs[i].StakingID)
				if k > 0 || (k == 0 && bytes.Compare(cs[i-1].RuleID, cs[i].RuleID) >= 0) {
					return nil, ErrOrder
				}
			}
		}
		return supportCtx{Commitments: cs}, nil
	case OpHandoffView:
		if !len32(c.IntentDigest) || isZero(c.IntentDigest) || c.View == 0 {
			return nil, ErrRange
		}
		return viewCtx{Intent: c.IntentDigest, View: c.View}, nil
	case OpPoPRequest:
		if !len32(c.IntentDigest) || isZero(c.IntentDigest) {
			return nil, ErrRange
		}
		return requestCtx{Intent: c.IntentDigest}, nil
	}
	return nil, fmt.Errorf("%w: op %d", ErrUnknownKind, op)
}

// EncodeVRControl is the canonical item.
func EncodeVRControl(network uint64, chainID [32]byte, registry [20]byte, epoch, round, op uint64, ctx ControlContext, data []byte, witness [32]byte) ([]byte, error) {
	shape, ok := ControlShapes[op]
	if !ok {
		return nil, fmt.Errorf("%w: op %d", ErrUnknownKind, op)
	}
	w, err := ctx.wire(op)
	if err != nil {
		return nil, err
	}
	if len(data) != shape.Data {
		return nil, ErrLength
	}
	if len(shape.Records) > 0 {
		if err := CheckRecordPayload(shape.Records[0], data); err != nil {
			return nil, err
		}
	} else if witness != ([32]byte{}) {
		return nil, fmt.Errorf("%w: root-only op with a witness", ErrRange)
	}
	raw, err := types.Cbor.Marshal(w)
	if err != nil {
		return nil, err
	}
	if data == nil {
		data = []byte{}
	}
	return types.Cbor.Marshal(vrControlWire{Tag: VRControlTag, Network: network, ChainID: chainID[:], Registry: registry[:], OrderingEpoch: epoch,
		OrderingRound: round, Op: op, Context: raw, Data: data, WitnessHash: witness[:]})
}

// DecodeVRControl accepts exactly the canonical item and returns the op and its typed context.
func DecodeVRControl(b []byte) (uint64, ControlContext, []byte, error) {
	var w vrControlWire
	var c ControlContext
	if err := types.Cbor.Unmarshal(b, &w); err != nil || w.Tag != VRControlTag || len(w.ChainID) != 32 || len(w.Registry) != 20 || len(w.WitnessHash) != 32 {
		return 0, c, nil, ErrCanonical
	}
	var err error
	switch w.Op {
	case OpCloseLiability:
		var x closeCtx
		err = types.Cbor.Unmarshal(w.Context, &x)
		c.ClosedEpoch, c.BundleSemanticID = x.Epoch, x.Bundle
	case OpHolderRetirement:
		var x stateCtx
		err = types.Cbor.Unmarshal(w.Context, &x)
		c.EVMBlockHash, c.EVMStateRoot = x.BlockHash, x.StateRoot
	case OpRejectResult:
		var arity []cbor.RawMessage
		if err = types.Cbor.Unmarshal(w.Context, &arity); err == nil && len(arity) == 5 {
			var x rejectMissCtx
			err = types.Cbor.Unmarshal(w.Context, &x)
			c.Predecessor, c.Attempt, c.EVMBlockHash, c.EVMStateRoot, c.Misses = x.Pred, x.Attempt, x.BlockHash, x.StateRoot, x.Misses
		} else if err == nil {
			var x rejectCtx
			err = types.Cbor.Unmarshal(w.Context, &x)
			c.Predecessor, c.Attempt, c.EVMBlockHash, c.EVMStateRoot = x.Pred, x.Attempt, x.BlockHash, x.StateRoot
		}
	case OpRuleSupport:
		var x supportCtx
		err = types.Cbor.Unmarshal(w.Context, &x)
		c.Commitments = x.Commitments
	case OpHandoffView:
		var x viewCtx
		err = types.Cbor.Unmarshal(w.Context, &x)
		c.IntentDigest, c.View = x.Intent, x.View
	case OpPoPRequest:
		var x requestCtx
		err = types.Cbor.Unmarshal(w.Context, &x)
		c.IntentDigest = x.Intent
	default:
		return 0, c, nil, fmt.Errorf("%w: op %d", ErrUnknownKind, w.Op)
	}
	if err != nil {
		return 0, c, nil, ErrCanonical
	}
	var chain [32]byte
	var reg [20]byte
	var wh [32]byte
	copy(chain[:], w.ChainID)
	copy(reg[:], w.Registry)
	copy(wh[:], w.WitnessHash)
	again, err := EncodeVRControl(w.Network, chain, reg, w.OrderingEpoch, w.OrderingRound, w.Op, c, w.Data, wh)
	if err != nil {
		return 0, c, nil, err
	}
	if !bytes.Equal(again, b) {
		return 0, c, nil, ErrCanonical
	}
	return w.Op, c, w.Data, nil
}

// ProjectRejectResult is the record pair a RejectResult v2 projects from one control: OutputRejected(data), then SessionClosed(resultId).
func ProjectRejectResult(data []byte) ([][2]any, error) {
	return ProjectRejectResultMissed(data, PoPMissed{})
}

// ProjectRejectResultMissed is the projection with certified misses (#1319): OutputRejected(data), PoPMissed(missed) when its bitmap is
// nonzero, then SessionClosed(resultId).
func ProjectRejectResultMissed(data []byte, missed PoPMissed) ([][2]any, error) {
	o, err := DecodeOutputRejected(data)
	if err != nil {
		return nil, err
	}
	out := [][2]any{{RecOutputRejected, o.Encode()}}
	if missed.MissedBitmap != 0 {
		missed.ResultID = o.ResultID
		if o.Reason != RejExpired {
			return nil, fmt.Errorf("%w: certified misses outside an expiry", ErrRange)
		}
		out = append(out, [2]any{RecPoPMissed, missed.Encode()})
	}
	return append(out, [2]any{RecSessionClosed, o.ResultID[:]}), nil
}
