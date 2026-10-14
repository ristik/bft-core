package bridgeprofile

import (
	"bytes"
	"errors"
	"math/bits"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/b1ref"
)

// The direct-call gas gate (briefs/b1-any-age-contract.md section 5, protocol 4). Every term is the native price of a call the
// composing verifier makes, or a fixed allowance, computed from complete bounded scans; the contract, this oracle and the plug-ins
// implement the same formula. It is an admission rule, not a measured fit:
//
//	G_gate = 21,000 + 16*D_max + 80*B_env + G_kernel + G_batch + sum_i G_leaf(i) + 1,000,000 <= 7,000,000
//	D_max  = 4 + 128 + pad32(B_cfg) + pad32(B_env)
const (
	TxGasBudget      uint64 = 7_000_000 // ureth ordinary capacity
	GasReserve       uint64 = 1_000_000
	IntrinsicBase    uint64 = 21_000
	IntrinsicPerByte uint64 = 16
	// IntrinsicExecPerByte prices the composing verifier's own execution (ABI decode, scans, hashing, memory) per envelope byte:
	// measured 50 to 75 gas per envelope byte (contracts `TokenVerifier`, natives mocked), priced at 80.
	IntrinsicExecPerByte uint64 = 80
	B2Base               uint64 = 26_000
	B2PerByte            uint64 = 20
	B2PerLeaf            uint64 = 14_000
	// GasPerItem prices the composing verifier's CBOR preflight: 1,000 per bridge CBOR item J (contract section 5, contracts#39).
	GasPerItem uint64 = 1_000
	// rsmtRequestFixed is the 0x0102 request without siblings.
	rsmtRequestFixed uint64 = 136
)

func pad32(n uint64) uint64 { return (n + 31) &^ 31 }

// CallDataAllowance is D_max = 4 + 128 + pad32(B_cfg) + pad32(B_env): the canonical two-bytes-argument TokenVerifier call.
func CallDataAllowance(cfgBytes, envelopeBytes int) uint64 {
	return 4 + 128 + pad32(uint64(cfgBytes)) + pad32(uint64(envelopeBytes))
}

// IntrinsicGas is 21,000 + 16*D_max + 80*B_env.
func IntrinsicGas(cfgBytes, envelopeBytes int) uint64 {
	return IntrinsicBase + IntrinsicPerByte*CallDataAllowance(cfgBytes, envelopeBytes) + IntrinsicExecPerByte*uint64(envelopeBytes)
}

// KernelRequestBytes is B_kernel = len(abi.encode(uint8 op, bytes cfg, bytes payload)) = 160 + pad32(B_cfg) + pad32(B_history).
func KernelRequestBytes(cfgBytes, payload int) uint64 {
	return 96 + 32 + pad32(uint64(cfgBytes)) + 32 + pad32(uint64(payload))
}

// B2Gas is G_kernel = 26,000 + 20*B_kernel + 14,000*L for a request of the given size exporting leaves.
func B2Gas(requestBytes uint64, leaves int) uint64 {
	return B2Base + B2PerByte*requestBytes + B2PerLeaf*uint64(leaves)
}

// ScanAnchor applies the bridge's own bounds to one anchor before the batch is scanned: the UC and IR opening caps, and the
// anchor's shard equal to its certificate's (the native scan of the batch then requires exactly that shard's depth in siblings).
func ScanAnchor(a *Anchor) error {
	if len(a.UC) > MaxAnchorUCBytes || len(a.InputRecord) > MaxInputRecordBytes {
		return ErrInputTooLarge
	}
	var uc types.UnicityCertificate
	if err := types.Cbor.Unmarshal(a.UC, &uc); err != nil || !bytes.Equal(uc.ShardTreeCertificate.Shard.Bytes(), a.Shard) {
		return ErrAnchorAuth
	}
	return nil
}

// LeafPathGas bounds one leaf path (bitmap popcount equal to the sibling
// count, at most MaxRSMTSiblings) and prices its 0x0102 call.
func LeafPathGas(p LeafProof) (gas, steps uint64, err error) {
	pop := 0
	for _, x := range p.Bitmap {
		pop += bits.OnesCount8(x)
	}
	if pop != len(p.Siblings) {
		return 0, 0, ErrPathBitmap
	}
	if pop > MaxRSMTSiblings {
		return 0, 0, ErrTooManyPaths
	}
	return b1ref.RSMTGas(rsmtRequestFixed+32*uint64(pop), uint64(pop)), uint64(pop), nil
}

// Gate is the gate's terms. Steps is the cumulative path work: certificate steps over the distinct anchors plus RSMT siblings over
// every leaf, at most MaxPathSteps. J is the bridge CBOR item count and Items its charge, 1,000*J.
type Gate struct {
	Intrinsic, B2, Batch, RSMT, Items uint64
	Steps, J                          uint64
	Grouping                          b1ref.Grouping
}

// Total is the gated sum including the fixed reserve.
func (g Gate) Total() uint64 { return g.Intrinsic + g.Items + g.B2 + g.Batch + g.RSMT + GasReserve }

// BridgeItems is J for one canonical CBOR object: its item heads (tags and containers, scalar and string heads, every child and map
// key and value; the contents of a byte string are opaque). n is the budget left; an object that would exceed it is refused as soon
// as the next item would cross it (ErrTooManyItems).
func BridgeItems(b []byte, n int) (int, error) {
	s := scanner{b: b, native: true, tokens: MaxCBORItems - n}
	if _, err := s.item(0); err != nil {
		return 0, err
	}
	if s.pos != len(b) {
		return 0, ErrTrailing
	}
	return s.tokens - (MaxCBORItems - n), nil
}

// bridgeJ sums J over the Cfg, the policy body, every anchor UC and every anchor IR opening, each occurrence once, against the shared
// MaxBridgeItems budget. A malformed UC is an anchor-authentication failure and a malformed IR opening an IR shape failure, as later
// checks would class them; exceeding the budget is ErrTooManyItems.
func bridgeJ(cfg []byte, env *Envelope) (uint64, error) {
	left := MaxBridgeItems
	take := func(b []byte, malformed error) error {
		n, err := BridgeItems(b, left)
		if errors.Is(err, ErrTooManyItems) {
			return err
		}
		if err != nil {
			return malformed
		}
		left -= n
		return nil
	}
	if err := take(cfg, ErrShape); err != nil {
		return 0, err
	}
	if err := take(env.PolicyBody, ErrShape); err != nil {
		return 0, err
	}
	for i := range env.Anchors {
		if err := take(env.Anchors[i].UC, ErrAnchorAuth); err != nil {
			return 0, err
		}
		if err := take(env.Anchors[i].InputRecord, ErrIRShape); err != nil {
			return 0, err
		}
	}
	return uint64(MaxBridgeItems - left), nil
}

// computeGate prices a complete bounded envelope against budget: the one CERT_BATCH_V2 call over the anchor table is scanned and
// grouped by the reference (b1ref.Group), so its charge is exactly the native one.
func computeGate(cfg []byte, envelopeBytes int, kernelRequest uint64, env *Envelope, budget uint64) (Gate, error) {
	g := Gate{Intrinsic: IntrinsicGas(len(cfg), envelopeBytes), B2: B2Gas(kernelRequest, len(env.LeafProofs))}
	for j := range env.Anchors {
		if err := ScanAnchor(&env.Anchors[j]); err != nil {
			return Gate{}, err
		}
	}
	j, err := bridgeJ(cfg, env)
	if err != nil {
		return Gate{}, err
	}
	g.J, g.Items = j, GasPerItem*j
	grouping, err := b1ref.Group(CertBatchRequest(env.Anchors))
	if err != nil {
		return Gate{}, ErrAnchorAuth
	}
	g.Grouping, g.Batch, g.Steps = grouping, grouping.Gas, grouping.P
	for _, p := range env.LeafProofs {
		gas, steps, err := LeafPathGas(p)
		if err != nil {
			return Gate{}, err
		}
		g.RSMT += gas
		g.Steps += steps
	}
	if g.Steps > MaxPathSteps {
		return Gate{}, ErrTooManyPaths
	}
	if g.Total() > budget {
		return Gate{}, ErrGasBudget
	}
	return g, nil
}

// GateOf runs the composition up to and including the gate for an envelope
// against an explicit budget: framing, policy body, kernel, anchor table, gate.
// It makes no B1 call. The corpus uses it to publish the gate's components.
func GateOf(cfg *Cfg, op uint8, envelope []byte, budget uint64) (Gate, error) {
	env, err := DecodeEnvelope(envelope)
	if err != nil {
		return Gate{}, err
	}
	pol, err := CheckPolicyBody(cfg, env)
	if err != nil {
		return Gate{}, err
	}
	var res *Result
	if op == OpMint {
		res, err = VerifyMint(cfg, env.History)
	} else {
		res, err = VerifyReturn(cfg, env.History)
	}
	if err != nil {
		return Gate{}, err
	}
	sids := make([][32]byte, len(res.Leaves))
	for i, l := range res.Leaves {
		sids[i] = l.SID
	}
	if _, err := PlanAnchors(pol, env, sids); err != nil {
		return Gate{}, err
	}
	return computeGate(cfg.Bytes(), len(envelope), KernelRequestBytes(len(cfg.Bytes()), len(env.History)), env, budget)
}
