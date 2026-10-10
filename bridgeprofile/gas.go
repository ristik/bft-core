package bridgeprofile

import (
	"bytes"
	"math/bits"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/b1ref"
)

// The direct-call gas gate (interop.md "Direct-call gas gate"). Every term is the
// native price of a call the composing verifier makes, computed from complete
// bounded scans; the contract, this oracle and the plug-ins implement the same
// formula. It is an admission rule, not a measured fit.
const (
	TxGasBudget      uint64 = 7_000_000 // ureth ordinary capacity
	GasReserve       uint64 = 1_000_000
	IntrinsicBase    uint64 = 21_000
	IntrinsicPerByte uint64 = 16
	B2Base           uint64 = 26_000
	B2PerByte        uint64 = 20
	B2PerLeaf        uint64 = 14_000
	// ucRequestFixed is the single-claim 0x0100 request without shard and UC:
	// header(4) | partition(4) | shardLen(2) | 3*32 | ucLen(4).
	ucRequestFixed uint64 = 110
	// rsmtRequestFixed is the 0x0102 request without siblings.
	rsmtRequestFixed uint64 = 136
)

// IntrinsicGas is the direct-call bound for an envelope.
func IntrinsicGas(envelopeBytes int) uint64 {
	return IntrinsicBase + IntrinsicPerByte*uint64(envelopeBytes)
}

// KernelRequestBytes is len(abi.encode(uint8 op, bytes cfg, bytes payload)).
func KernelRequestBytes(cfgBytes, payload int) uint64 {
	pad := func(n int) uint64 { return (uint64(n) + 31) &^ 31 }
	return 96 + 32 + pad(cfgBytes) + 32 + pad(payload)
}

// B2Gas is the kernel charge for a request of the given size exporting leaves.
func B2Gas(requestBytes uint64, leaves int) uint64 {
	return B2Base + B2PerByte*requestBytes + B2PerLeaf*uint64(leaves)
}

// AnchorScan is the bounded scan of one anchor's certificate.
type AnchorScan struct {
	Request uint64 // single-claim 0x0100 request bytes
	Sigs    uint64
	Steps   uint64 // shard-tree siblings plus unicity steps
	Gas     uint64 // G_UC
}

// ScanAnchor bounds the anchor's UC and IR opening, applies the native
// certificate scan and requires exactly depth shard-tree siblings (the policy
// shard's own depth) before pricing the 0x0100 call.
func ScanAnchor(a *Anchor, depth int) (AnchorScan, error) {
	if len(a.UC) > MaxAnchorUCBytes || len(a.InputRecord) > MaxInputRecordBytes {
		return AnchorScan{}, ErrInputTooLarge
	}
	shape, err := b1ref.ScanUC(a.UC)
	if err != nil {
		return AnchorScan{}, ErrAnchorAuth
	}
	var uc types.UnicityCertificate
	if err := types.Cbor.Unmarshal(a.UC, &uc); err != nil || !bytes.Equal(uc.ShardTreeCertificate.Shard.Bytes(), a.Shard) ||
		len(uc.ShardTreeCertificate.SiblingHashes) != depth {
		return AnchorScan{}, ErrAnchorAuth
	}
	if shape.PathSteps > MaxPathSteps {
		return AnchorScan{}, ErrTooManyPaths
	}
	s := AnchorScan{Request: ucRequestFixed + uint64(len(a.Shard)) + uint64(len(a.UC)), Sigs: uint64(len(shape.SigLens)), Steps: shape.PathSteps}
	s.Gas = b1ref.UCGas(s.Request, s.Sigs, 1, s.Steps)
	return s, nil
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

// GasGate computes G_intrinsic + G_B2 + sum G_UC + sum G_RSMT + reserve and
// rejects with ErrGasBudget above the transaction budget. It also enforces the
// cumulative step cap over anchors and leaves, each anchor counted once.
type Gate struct {
	Intrinsic, B2, UC, RSMT uint64
	Steps                   uint64
}

// Total is the gated sum including the fixed reserve.
func (g Gate) Total() uint64 { return g.Intrinsic + g.B2 + g.UC + g.RSMT + GasReserve }

// computeGate prices a complete bounded envelope against budget.
func computeGate(envelopeBytes int, kernelRequest uint64, env *Envelope, pol Policy, budget uint64) (Gate, error) {
	g := Gate{Intrinsic: IntrinsicGas(envelopeBytes), B2: B2Gas(kernelRequest, len(env.LeafProofs))}
	for j := range env.Anchors {
		s, err := ScanAnchor(&env.Anchors[j], int(pol.Depth))
		if err != nil {
			return Gate{}, err
		}
		g.UC += s.Gas
		g.Steps += s.Steps
	}
	for _, p := range env.LeafProofs {
		gas, steps, err := LeafPathGas(p)
		if err != nil {
			return Gate{}, err
		}
		g.RSMT += gas
		g.Steps += steps
	}
	// Unreachable at the profile bounds (at most MaxAnchors*(1+MaxUnicitySteps) + MaxLeaves*MaxRSMTSiblings
	// steps); kept so that a later profile that raises the bounds cannot silently outgrow MaxPathSteps.
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
	return computeGate(len(envelope), KernelRequestBytes(len(cfg.Bytes()), len(env.History)), env, pol, budget)
}
