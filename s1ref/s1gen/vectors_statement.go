package s1gen

// statement covers Q1 statement rules of scheme 2 (design: "Apply Q1 statement
// rules"). Every case is validly signed over the bytes the generator builds, and
// the vote info hash matches, so only the named rule can fail.
func (g *gen) statement() {
	w := g.w
	v2 := w.view2()
	c := w.wide()
	const fam = "Statement rules"
	mk := func(f func(*ev)) *ev { e := w.nc("v1", 150, 0x11); f(e); return w.sign(e) }
	mc := func(f func(*ev)) *ev { e := w.cm("v1", 150, 0x11, 149, 1, 0xc1); f(e); return w.sign(e) }

	g.no("stmt.round-zero", fam, "voting round zero", c.mut(2, func(e *EpochJSON) { e.Start = 0 }), v2, "ErrStatement", mk(func(e *ev) { e.round, e.parent = 0, 0 }))
	g.no("stmt.parent-equals-round", fam, "parent round not below the voting round", c, v2, "ErrStatement", mk(func(e *ev) { e.parent = e.round }))
	g.no("stmt.parent-above-round", fam, "parent round above the voting round", c, v2, "ErrStatement", mk(func(e *ev) { e.parent = e.round + 1 }))
	g.yes("stmt.round-one-parent-zero.ok", fam, "smallest legal slot: round 1, parent 0 (scheme 2 does not apply the legacy parent rule)", c, v2, mk(func(e *ev) { e.round, e.parent = 1, 0 }))

	g.no("stmt.commit-round-equals-voting", fam, "commit round not below the voting round", c, v2, "ErrStatement", mc(func(e *ev) { e.sealRound = 150; e.sealTS = 5150 }))
	g.no("stmt.commit-round-above-voting", fam, "commit round above the voting round", c, v2, "ErrStatement", mc(func(e *ev) { e.sealRound = 151; e.sealTS = 5151 }))
	g.no("stmt.commit-hash-without-round", fam, "half-empty pair: commit hash with commit round 0", c, v2, "ErrStatement", mc(func(e *ev) { e.sealRound = 0 }))
	g.no("stmt.commit-round-without-hash-null", fam, "half-empty pair: commit round with a null hash", c, v2, "ErrStatement", mc(func(e *ev) { e.hash = nil }))
	g.no("stmt.commit-round-without-hash-empty", fam, "half-empty pair: commit round with an empty (bstr0) hash", c, v2, "ErrStatement", mc(func(e *ev) { e.hash = []byte{} }))
	g.no("stmt.commit-epoch-zero", fam, "committing vote with seal epoch zero", c, v2, "ErrStatement", mc(func(e *ev) { e.sealEpoch = 0 }))
	g.no("stmt.commit-epoch-above-voting", fam, "commit epoch above the voting epoch", c, v2, "ErrStatement", mc(func(e *ev) { e.sealEpoch = 3 }))
	g.no("stmt.commit-network", fam, "seal network is not N", c, v2, "ErrStatement", mc(func(e *ev) { e.net++ }))
	g.no("stmt.noncommit-seal-epoch", fam, "non-committing vote with a non-zero seal epoch", c, v2, "ErrStatement", mk(func(e *ev) { e.sealEpoch = 1 }))
	g.no("stmt.noncommit-seal-timestamp", fam, "non-committing vote with a non-zero seal timestamp", c, v2, "ErrStatement", mk(func(e *ev) { e.sealTS = 7 }))
	g.no("stmt.noncommit-seal-network", fam, "non-committing vote with a non-zero seal network", c, v2, "ErrStatement", mk(func(e *ev) { e.net = w.net }))
	g.no("stmt.noncommit-seal-signature", fam, "non-committing vote carrying a seal signature", c, v2, "ErrSealSigForbidden", func() *ev { e := mk(func(*ev) {}); e.sealSig = e.voteSig; return e }())
	g.no("stmt.commit-seal-signature-missing", fam, "committing vote without a seal signature", c, v2, "ErrSealSigMissing", func() *ev { e := mc(func(*ev) {}); e.sealSig = nil; return e }())
	g.no("stmt.commit-seal-signature-forged", fam, "seal signature made by another member's key", c, v2, "ErrSigInvalid", func() *ev { e := mc(func(*ev) {}); e.sealSig = v2sign(w, "v2", e.sealBytes(), ""); return e }())
	g.no("stmt.commit-seal-signature-timestamp", fam, "seal signature made over the same seal with another timestamp", c, v2, "ErrSigInvalid", func() *ev {
		e := mc(func(*ev) {})
		o := e.cp()
		o.sealTS++
		e.sealSig = v2sign(w, "v1", o.sealBytes(), "")
		return e
	}())
	g.no("stmt.commit-seal-signature-is-vote-signature", fam, "the vote signature reused as the seal signature", c, v2, "ErrSigInvalid", func() *ev { e := mc(func(*ev) {}); e.sealSig = e.voteSig; return e }())
}
