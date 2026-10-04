package s1gen

import "math/big"

// signatures covers signature canonicalization and the replay and substitution
// recipes of scheme 2. The statement is otherwise valid in every case.
func (g *gen) signatures() {
	w := g.w
	v2 := w.view2()
	c := w.ctx()
	const fam = "Signatures"
	base := w.sign(w.nc("v1", 150, 0x11))
	sig := base.voteSig
	with := func(s []byte) *ev { e := base.cp(); e.voteSig = s; return e }
	n := curveN
	half := new(big.Int).Rsh(n, 1)
	s := new(big.Int).SetBytes(sig[32:64])
	r := new(big.Int).SetBytes(sig[:32])

	g.no("sig.wrong-key", fam, "signature made by another member", c, v2, "ErrSigInvalid", with(v2sign(w, "v2", base.pv, "")))
	g.no("sig.byte-flipped", fam, "one signature byte flipped", c, v2, "ErrSigInvalid", with(flip(sig, 40)))
	g.no("sig.high-s", fam, "high-s twin of a valid signature is never normalized into acceptance", c, v2, "ErrSigRange", with(highS(sig)))
	g.no("sig.high-s.65", fam, "high-s twin with a recovery byte", c, v2, "ErrSigRange", with(withV(highS(sig), 0)))
	g.no("sig.s-half-plus-one", fam, "s = n/2 + 1 is the smallest high s", c, v2, "ErrSigRange", with(setRS(sig, r, new(big.Int).Add(half, big.NewInt(1)))))
	g.no("sig.s-half", fam, "s = n/2 is in range but does not verify", c, v2, "ErrSigInvalid", with(setRS(sig, r, half)))
	g.no("sig.r-zero", fam, "r = 0", c, v2, "ErrSigRange", with(setRS(sig, big.NewInt(0), s)))
	g.no("sig.s-zero", fam, "s = 0", c, v2, "ErrSigRange", with(setRS(sig, r, big.NewInt(0))))
	g.no("sig.r-n", fam, "r = n", c, v2, "ErrSigRange", with(setRS(sig, n, s)))
	g.no("sig.s-n", fam, "s = n", c, v2, "ErrSigRange", with(setRS(sig, r, n)))
	g.no("sig.r-above-n", fam, "r above n", c, v2, "ErrSigRange", with(setRS(sig, new(big.Int).Add(n, big.NewInt(1)), s)))

	// Signature encodings that are structural, not semantic.
	for _, tc := range []struct {
		id, desc, want string
		sig            []byte
	}{
		{"sig.malformed.empty", "empty signature byte string", "ErrSigShape", []byte{}},
		{"sig.malformed.63", "63-byte signature", "ErrSigShape", sig[:63]},
		{"sig.malformed.66", "66-byte signature", "ErrSigShape", append(append([]byte{}, sig...), 0, 0)},
		{"sig.malformed.v2", "65-byte signature with v=2", "ErrSigShape", withV(sig, 2)},
		{"sig.malformed.v255", "65-byte signature with v=255", "ErrSigShape", withV(sig, 255)},
		{"sig.malformed.high-s-bad-v", "high-s signature with an invalid v is malformed before it is false", "ErrSigShape", withV(highS(sig), 2)},
	} {
		g.bad(tc.id, fam, tc.desc, c, frame(v2.cbor(), with(tc.sig).enc()), tc.want)
	}
	cm := w.sign(w.cm("v1", 150, 0x11, 149, 1, 0xc1))
	badSeal := func(s []byte) []byte { e := cm.cp(); e.sealSig = s; return frame(v2.cbor(), e.enc()) }
	g.bad("sig.malformed.seal-empty", fam, "empty seal signature byte string", c, badSeal([]byte{}), "ErrSigShape")
	g.bad("sig.malformed.seal-63", fam, "63-byte seal signature", c, badSeal(cm.sealSig[:63]), "ErrSigShape")
	g.bad("sig.malformed.seal-v2", fam, "seal signature with v=2", c, badSeal(withV(cm.sealSig, 2)), "ErrSigShape")
	g.no("sig.seal.high-s", fam, "high-s seal signature", c, v2, "ErrSigRange", func() *ev { e := cm.cp(); e.sealSig = highS(cm.sealSig); return e }())

	// Domain substitution: the vote info and its hash are right, the signature is over another statement.
	g.no("replay.wrong-network-preimage", fam, "signature over a preimage built for another network", c, v2, "ErrSigInvalid",
		with(v2sign(w, "v1", base.preimage(w.net+1, w.genesis, base.prev), "")))
	og := newDRBG(w.seed, "replay/genesis").hash()
	g.no("replay.wrong-genesis-preimage", fam, "signature over a preimage built for another root genesis", c, v2, "ErrSigInvalid",
		with(v2sign(w, "v1", base.preimage(w.net, og, base.prev), "")))
	g.no("replay.timeout-domain-preimage", fam, "signature over the timeout domain string in the vote preimage", c, v2, "ErrSigInvalid",
		with(v2sign(w, "v1", cArr(cText(voteTag), cUint(w.net), cText(dt(w.genesis)), cBytes(base.prev), cNull, cUint(0)), "")))
	g.no("replay.timeout-preimage", fam, "signature of the same member over a timeout preimage", c, v2, "ErrSigInvalid",
		with(v2sign(w, "v1", timeoutPreimage(w.net, w.genesis, 2, 150, 149, "v1"), "")))
	g.no("replay.preimage-digest", fam, "signature over SHA256(preimage) is a double hash: the verifier hashes the preimage exactly once", c, v2, "ErrSigInvalid",
		with(v2sign(w, "v1", base.content[:], "")))
	g.no("replay.vote-info-signed", fam, "signature over VI instead of PV", c, v2, "ErrSigInvalid", with(v2sign(w, "v1", base.vi(w.net, w.genesis), "")))
	g.no("replay.seal-bytes-signed", fam, "signature over the native seal bytes instead of PV", c, v2, "ErrSigInvalid", with(v2sign(w, "v1", base.sealBytes(), "")))
}

// binding covers the vote info hash relation and post-signing alterations.
func (g *gen) binding() {
	w := g.w
	v2 := w.view2()
	c := w.ctx()
	const fam = "Binding"
	base := w.sign(w.nc("v1", 150, 0x11))
	cm := w.sign(w.cm("v1", 150, 0x11, 149, 1, 0xc1))
	edit := func(b *ev, f func(*ev)) *ev { e := b.cp(); f(e); return e }

	g.no("bind.previous-hash-flipped", fam, "previous hash differs from VH", c, v2, "ErrBinding", edit(base, func(e *ev) { e.prev = flip(e.prev, 0) }))
	other := w.sign(w.nc("v1", 151, 0x11))
	g.no("bind.previous-hash-swapped", fam, "previous hash of another round's vote info", c, v2, "ErrBinding", edit(base, func(e *ev) { e.prev = other.prev }))
	g.no("bind.round-altered", fam, "voting round altered after signing", c, v2, "ErrBinding", edit(base, func(e *ev) { e.round++ }))
	g.no("bind.parent-altered", fam, "parent round altered after signing", c, v2, "ErrBinding", edit(base, func(e *ev) { e.parent-- }))
	g.no("bind.exec-altered", fam, "executed state hash altered after signing", c, v2, "ErrBinding", edit(base, func(e *ev) { e.exec[31] ^= 1 }))
	g.no("bind.vote-info-swapped", fam, "VoteInfo of another vote under this vote's commit info", c, v2, "ErrBinding", edit(base, func(e *ev) { e.round, e.parent, e.exec = other.round, other.parent, other.exec }))
	g.no("bind.commit-hash-altered", fam, "commit hash altered after signing (the vote info hash is unchanged)", c, v2, "ErrSigInvalid", edit(cm, func(e *ev) { e.hash = flip(e.hash, 1) }))
	g.no("bind.commit-round-altered", fam, "commit round altered after signing", c, v2, "ErrSigInvalid", edit(cm, func(e *ev) { e.sealRound = 148 }))
	g.no("bind.seal-timestamp-altered", fam, "seal timestamp altered after signing: only the seal signature notices", c, v2, "ErrSigInvalid", edit(cm, func(e *ev) { e.sealTS++ }))
	g.no("bind.seal-network-altered", fam, "seal network altered after signing", c, v2, "ErrStatement", edit(cm, func(e *ev) { e.net++ }))
	g.no("bind.seal-epoch-altered", fam, "seal epoch altered after signing within the legal range", c, v2, "ErrSigInvalid", edit(cm, func(e *ev) { e.sealEpoch = 2 }))

	// Evidence of another network or genesis, signed consistently for that domain.
	foreign := newWorld(w.seed, w.net+1)
	foreign.vals = w.vals
	fe := foreign.sign(foreign.nc("v1", 150, 0x11))
	g.no("bind.foreign-network", fam, "a consistently signed vote of another network: the binding built from this context fails", c, v2, "ErrBinding", fe)
	fg := newWorld(w.seed, w.net)
	fg.genesis = newDRBG(w.seed, "replay/genesis").hash()
	fg.vals = w.vals
	g.no("bind.foreign-genesis", fam, "a consistently signed vote of another root genesis", c, v2, "ErrBinding", fg.sign(fg.nc("v1", 150, 0x11)))
}
