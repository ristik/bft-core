package s1gen

// single covers the positive single votes of both schemes and the structural
// recipes of the legacy relation.
func (g *gen) single(seed string) {
	w := g.w
	v1, v2 := w.view1(), w.view2()
	c := w.ctx()
	const fam = "Single vote"

	nc := w.sign(w.nc("v1", 150, 0x11))
	g.yes("s2.noncommitting.ok", fam, "scheme 2 non-committing vote: voting epoch 2, round 150", c, v2, nc)
	cm := w.sign(w.cm("v2", 150, 0x12, 149, 1, 0xc1))
	g.yes("s2.committing.ok", fam, "scheme 2 committing vote that commits epoch 1 state: reports voting epoch 2 and round 150, never the commit coordinates", c, v2, cm)
	g.yes("s2.committing.same-epoch.ok", fam, "committing vote whose commit epoch equals the voting epoch", c, v2, w.sign(w.cm("v3", 151, 0x13, 150, 2, 0xc2)))
	g.yes("s2.noncommitting.hash-bstr0.ok", fam, "empty commit hash (bstr0) of a non-committing vote maps to null in the preimage: same statement as the null form", c, v2,
		w.sign(func() *ev { e := w.nc("v1", 150, 0x11); e.hash = []byte{}; return e }()))
	g.yes("s2.noncommitting.v5.ok", fam, "the epoch 2 member that replaced the retired key", c, v2, w.sign(w.nc("v5", 150, 0x15)))

	// Signature forms of one statement.
	base := w.sign(w.nc("v1", 160, 0x21))
	sig := base.voteSig
	form := func(s []byte) *ev { e := base.cp(); e.voteSig = s; return e }
	g.yes("s2.sig.64.ok", fam, "64-byte r||s", c, v2, form(sig))
	g.yes("s2.sig.65-v0.ok", fam, "65-byte r||s||v with v=0", c, v2, form(withV(sig, 0)))
	g.yes("s2.sig.65-v1.ok", fam, "65-byte r||s||v with v=1: v is discarded, recovery parity is never matched", c, v2, form(withV(sig, 1)))
	g.yes("s2.sig.alt-nonce.ok", fam, "a different valid low-s signature of the same statement (explicit nonce)", c, v2, form(v2sign(w, "v1", base.pv, "alt")))
	cmv := w.sign(w.cm("v1", 160, 0x22, 159, 2, 0xc3))
	both := cmv.cp()
	both.voteSig, both.sealSig = withV(cmv.voteSig, 1), withV(cmv.sealSig, 0)
	g.yes("s2.committing.sig65.ok", fam, "committing vote with 65-byte vote and seal signatures", c, v2, both)

	// Scheme 1.
	l := w.sign(w.leg("v1", 50, 0x31))
	g.yes("s1.noncommitting.ok", fam, "legacy vote, null commit hash: historical verification only, domain and conflict identity zero", c, v1, l)
	g.yes("s1.noncommitting.retired-key.ok", fam, "key retired by epoch 2 but historically authorised in epoch 1", c, v1, w.sign(w.leg("v4", 50, 0x34)))
	lc := w.sign(w.legcm("v2", 51, 0x32, 50, 0xc4))
	g.yes("s1.committing.ok", fam, "legacy committing vote (seal carries a commit hash, round and epoch): one signature over the native seal bytes", c, v1, lc)
	le := w.leg("v1", 50, 0x31)
	le.hash = []byte{}
	le = w.sign(le)
	g.yes("s1.noncommitting.hash-bstr0.ok", fam, "legacy vote with an empty (bstr0) commit hash: native seal bytes differ from the null form, so does the content digest", c, v1, le)
	g.yes("s1.sig.65-v1.ok", fam, "legacy 65-byte signature with v=1", c, v1, func() *ev { e := l.cp(); e.voteSig = withV(l.voteSig, 1); return e }())
	g.yes("s1.replay-other-network.ok", fam, "scheme 1 replay on another network is accepted: N is the authenticated trust context, not a signed legacy binding", g.otherNetworkCtx(), g.otherNetworkView(), l)

	// Legacy relation failures, each isolated.
	g.no("s1.vote-info.timestamp-zero", fam, "native RoundInfo.IsValid: timestamp not set", c, v1, "ErrVoteInfo", w.sign(func() *ev { e := w.leg("v1", 50, 0x31); e.ts = 0; return e }()))
	g.no("s1.vote-info.parent-unassigned", fam, "native RoundInfo.IsValid: parent round zero with round above 1", c, v1, "ErrVoteInfo", w.sign(func() *ev { e := w.leg("v1", 50, 0x31); e.parent = 0; return e }()))
	g.no("s1.vote-info.parent-equals-round", fam, "native RoundInfo.IsValid: round must exceed the parent", c, v1, "ErrVoteInfo", w.sign(func() *ev { e := w.leg("v1", 50, 0x31); e.parent = 50; return e }()))
	g.no("s1.vote-info.round-zero", fam, "native RoundInfo.IsValid: round number not assigned", c.mut(1, func(e *EpochJSON) { e.Start = 0 }), v1, "ErrVoteInfo", w.sign(func() *ev { e := w.leg("v1", 0, 0x31); e.parent = 0; e.ts = 1000; return e }()))
	g.no("s1.seal-signature-present", fam, "scheme 1 requires a null seal signature", c, v1, "ErrSealSigForbidden", func() *ev { e := l.cp(); e.sealSig = l.voteSig; return e }())
	g.no("s1.binding.previous-hash", fam, "RoundInfo hash differs from the previous hash", c, v1, "ErrBinding", func() *ev { e := l.cp(); e.prev = flip(e.prev, 5); return e }())
	g.no("s1.binding.timestamp-altered", fam, "VoteInfo timestamp altered after signing: native RoundInfo covers it", c, v1, "ErrBinding", func() *ev { e := l.cp(); e.ts++; return e }())
	g.no("s1.binding.exec-altered", fam, "VoteInfo exec altered after signing", c, v1, "ErrBinding", func() *ev { e := l.cp(); e.exec[3] ^= 1; return e }())
	g.no("s1.binding.round-altered", fam, "VoteInfo round altered after signing", c, v1, "ErrBinding", func() *ev { e := l.cp(); e.round++; return e }())
	g.no("s1.signature.other-key", fam, "legacy vote signed by another member", c, v1, "ErrSigInvalid", func() *ev { e := l.cp(); e.voteSig = v2sign(w, "v2", l.pv, ""); return e }())
	g.no("s1.signature.altered-seal-bytes", fam, "legacy seal timestamp altered after signing: SigBytes differ", c, v1, "ErrSigInvalid", func() *ev { e := lc.cp(); e.sealTS++; return e }())
	g.no("s1.signature.vote-info-hash-as-message", fam, "signature over the previous hash instead of the native seal bytes (no invented prefix)", c, v1, "ErrSigInvalid", func() *ev { e := l.cp(); e.voteSig = v2sign(w, "v1", l.prev, ""); return e }())
	g.no("s1.scheme2-in-legacy-epoch", fam, "a scheme 2 vote claiming epoch 1, where the authenticated epoch is scheme 1", c, v1, "ErrSchemeEpoch", func() *ev { e := w.sign(w.nc("v1", 50, 0x11)); e.epoch = 1; return e }())
}

// otherNetworkView is the epoch 1 view of a second network with the same keys.
func (g *gen) otherNetworkView() viewSpec {
	return g.w.view1().with(func(v *viewSpec) { v.network = 10 })
}

func (g *gen) otherNetworkCtx() *ContextJSON {
	v := g.otherNetworkView()
	e := g.w.entry(v, 1, g.w.boundary, 1, [32]byte{})
	e.SigNetwork = 10
	return &ContextJSON{Network: 10, OpenEpoch: 2, Epochs: []EpochJSON{e}}
}

// v2sign signs msg with a validator of the world: label "" is RFC 6979, otherwise an explicit nonce.
func v2sign(w *world, id string, msg []byte, label string) []byte {
	if label == "" {
		return w.vals[id].sign(msg)
	}
	return w.vals[id].signNonce(msg, label)
}
