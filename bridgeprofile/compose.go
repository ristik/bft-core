package bridgeprofile

// B1 is the part of the B1 native-verification boundary the composing
// TokenVerifier uses. B1 needs no change for SDK 3.0.1: it authenticates a
// native (expectedStateRoot, expectedIRHash) claim and proves generic RSMT
// key/value membership; neither primitive assumes value == txHash. The leaf
// value is computed by the B2 relation and supplied by the composition.
type B1 interface {
	// AuthenticateAnchor is 0x0100: a native UC under admitted roots
	// authenticates the anchor's expectedStateRoot and expectedIRHash.
	AuthenticateAnchor(a *Anchor) error
	// VerifyMember is 0x0102: (key, raw 32-byte value) is a member under root
	// by exactly this path.
	VerifyMember(root, key, value [32]byte, p LeafProof) error
}

// Compose is the composing verifier of design section 6 as an executable
// oracle: framing and budgets, Cfg and policy body, the kernel result, the
// anchor table the exported leaves require, the direct-call gas gate, then B1
// authentication of every anchor (one single-claim call each), each anchor's
// IR opening and its time comparison for the leaves routed to it, then one
// 0x0102 call per ordered leaf against that leaf's own anchor root. Any
// failure rejects the whole proof.
func Compose(cfg *Cfg, op uint8, envelope []byte, b1 B1) (*Result, error) {
	if op != OpMint && op != OpReturn {
		return nil, ErrBadOperation
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	env, err := DecodeEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	pol, err := CheckPolicyBody(cfg, env)
	if err != nil {
		return nil, err
	}
	var res *Result
	if op == OpMint {
		res, err = VerifyMint(cfg, env.History)
	} else {
		res, err = VerifyReturn(cfg, env.History)
	}
	if err != nil {
		return nil, err
	}
	sids := make([][32]byte, len(res.Leaves))
	for i, l := range res.Leaves {
		sids[i] = l.SID
	}
	plan, err := PlanAnchors(pol, env, sids)
	if err != nil {
		return nil, err
	}
	if _, err := computeGate(len(envelope), KernelRequestBytes(len(cfg.Bytes()), len(env.History)), env, pol, TxGasBudget); err != nil {
		return nil, err
	}
	times := make([]uint64, len(env.Anchors))
	for j := range env.Anchors {
		a := &env.Anchors[j]
		if err := b1.AuthenticateAnchor(a); err != nil {
			return nil, ErrAnchorAuth
		}
		// The opening is trusted only now: B1 has authenticated the pair it hashes to.
		ir, err := OpenAnchor(a)
		if err != nil {
			return nil, err
		}
		times[j] = ir.Timestamp
	}
	for i, l := range res.Leaves {
		if l.ReferenceTime > times[plan.LeafAnchor[i]] {
			return nil, ErrIRTime
		}
	}
	for i, l := range res.Leaves {
		a := &env.Anchors[plan.LeafAnchor[i]]
		if err := b1.VerifyMember(a.ExpectedStateRoot, l.SID, l.Value, env.LeafProofs[i]); err != nil {
			return nil, ErrLeafProof
		}
	}
	return res, nil
}
