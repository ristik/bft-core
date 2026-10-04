package s1gen

import (
	"fmt"
	"strings"
)

// pairs covers the equivocation relation (count 2) and the resource shapes.
func (g *gen) pairs() {
	w := g.w
	v1, v2 := w.view1(), w.view2()
	c := w.ctx()
	const fam = "Equivocation pair"
	A := w.sign(w.nc("v1", 150, 0x11))
	B := w.sign(w.nc("v1", 150, 0x12))
	C := w.sign(w.nc("v1", 150, 0x13))
	both := func(id, desc string, a, b *ev) {
		g.yes(id+".ok", fam, desc, c, v2, a, b)
		g.yes(id+".reversed.ok", fam, desc+" (other order: identical output)", c, v2, b, a)
	}
	both("pair.exec", "same key, epoch and round, different executed state", A, B)
	both("pair.exec-alternate", "another conflicting pair in the same slot: identical conflict identity, different contents", A, C)
	both("pair.parent", "different parent round", w.sign(func() *ev { e := w.nc("v1", 150, 0x11); e.parent = 149; return e }()), w.sign(func() *ev { e := w.nc("v1", 150, 0x11); e.parent = 148; return e }()))
	both("pair.commit-hash", "different commit hash", w.sign(w.cm("v1", 150, 0x11, 149, 1, 0xc1)), w.sign(w.cm("v1", 150, 0x11, 149, 1, 0xc2)))
	both("pair.commit-round", "different commit round", w.sign(w.cm("v1", 150, 0x11, 149, 1, 0xc1)), w.sign(w.cm("v1", 150, 0x11, 148, 1, 0xc1)))
	both("pair.committing-vs-noncommitting", "a committing vote and a non-committing one", w.sign(w.cm("v1", 150, 0x11, 149, 1, 0xc1)), A)
	both("pair.seal-signatures", "two committing votes: both seal signatures are verified", w.sign(w.cm("v2", 150, 0x11, 149, 1, 0xc1)), w.sign(w.cm("v2", 150, 0x12, 149, 1, 0xc1)))

	// The same statement more than once is not equivocation.
	alt := A.cp()
	alt.voteSig = v2sign(w, "v1", A.pv, "pair-alt")
	g.no("pair.same-statement.alternate-signature", fam, "identical statement, independently generated low-s signature", c, v2, "ErrPairSameStatement", A, alt)
	for _, v := range []byte{0, 1} {
		x := A.cp()
		x.voteSig = withV(A.voteSig, v)
		g.no(fmt.Sprintf("pair.same-statement.recovery-%d", v), fam, "identical statement, signature with a recovery byte", c, v2, "ErrPairSameStatement", A, x)
	}
	g.no("pair.same-statement.identical-evidence", fam, "the same evidence twice", c, v2, "ErrPairSameStatement", A, A)
	cm := w.sign(w.cm("v1", 150, 0x11, 149, 1, 0xc1))
	cm2 := cm.cp()
	cm2.sealTS++
	cm2.sealSig = v2sign(w, "v1", cm2.sealBytes(), "")
	g.no("pair.same-statement.seal-timestamp", fam, "identical vote preimage, seal re-signed with another timestamp: seal-only changes never change the offence identity", c, v2, "ErrPairSameStatement", cm, cm2)
	empty := A.cp()
	empty.hash = []byte{}
	g.no("pair.same-statement.null-vs-empty-hash", fam, "null and empty commit hash of a non-committing vote map to the same preimage", c, v2, "ErrPairSameStatement", A, empty)

	// Different slot, signer, epoch or domain.
	g.no("pair.round", fam, "different voting rounds sharing committed state", c, v2, "ErrPairContext",
		w.sign(w.cm("v1", 150, 0x11, 149, 1, 0xc1)), w.sign(w.cm("v1", 151, 0x11, 149, 1, 0xc1)))
	g.no("pair.signer", fam, "different keys for one slot", c, v2, "ErrPairSigner", A, w.sign(w.nc("v2", 150, 0x12)))
	g.no("pair.epoch", fam, "second vote of another epoch than the carried view", c, v2, "ErrEpochMismatch", A, w.sign(func() *ev { e := w.nc("v1", 150, 0x12); e.epoch = 1; return e }()))
	fg := newWorld(w.seed, w.net)
	fg.genesis = newDRBG(w.seed, "pair/genesis").hash()
	g.no("pair.domain", fam, "second vote signed consistently for another root genesis", c, v2, "ErrBinding", A, fg.sign(fg.nc("v1", 150, 0x12)))
	g.no("pair.legacy-legacy", fam, "two valid legacy votes of one slot are never an offence", c, v1, "ErrPairScheme", w.sign(w.leg("v1", 50, 0x31)), w.sign(w.leg("v1", 50, 0x32)))
	l := w.sign(func() *ev { e := w.leg("v1", 150, 0x31); e.epoch = 2; return e }())
	g.no("pair.mixed.legacy-first", fam, "mixed schemes: the legacy vote fails the epoch's signing scheme", c, v2, "ErrSchemeEpoch", l, A)
	g.no("pair.mixed.legacy-second", fam, "mixed schemes, other order", c, v2, "ErrSchemeEpoch", A, l)
	bad := func(e *ev) *ev { x := e.cp(); x.voteSig = flip(x.voteSig, 7); return x }
	g.no("pair.first-false", fam, "first vote with a bad signature, second valid", c, v2, "ErrSigInvalid", bad(A), B)
	g.no("pair.second-false", fam, "second vote with a bad signature: the full charge, no discount", c, v2, "ErrSigInvalid", A, bad(B))
	g.no("pair.second-unknown-author", fam, "second vote by a retired key", c, v2, "ErrUnknownAuthor", A, w.sign(w.nc("v4", 150, 0x12)))
	g.no("pair.second-statement", fam, "second vote violating the statement rules", c, v2, "ErrStatement", A, w.sign(func() *ev { e := w.nc("v1", 150, 0x12); e.parent = 150; return e }()))
	g.no("pair.second-seal-missing", fam, "second committing vote without its seal signature", c, v2, "ErrSealSigMissing", A, func() *ev { e := w.sign(w.cm("v1", 150, 0x12, 149, 1, 0xc1)); e.sealSig = nil; return e }())
	g.no("pair.second-seal-forbidden", fam, "second non-committing vote with a seal signature", c, v2, "ErrSealSigForbidden", A, func() *ev { e := w.sign(w.nc("v1", 150, 0x12)); e.sealSig = e.voteSig; return e }())
}

// resources covers the member and evidence bounds and the exact formula charge.
func (g *gen) resources(seed string) {
	w := g.w
	const fam = "Resources"
	// 64 members with 128-byte node IDs: the largest admitted view.
	var ms []memberSpec
	vals := map[string]validator{}
	for i := 0; i < 64; i++ {
		id := fmt.Sprintf("m%02d", i) + strings.Repeat("x", 125)
		v := makeValidator(seed, id)
		vals[id] = v
		ms = append(ms, memberSpec{id: id, key: v.pub, weight: 1})
	}
	view := viewSpec{network: w.net, epoch: 2, kind: 2, body: w.body[2], members: ms}
	ctx := &ContextJSON{Network: uint16(w.net), OpenEpoch: 2, Epochs: []EpochJSON{w.entry(view, w.boundary, 0, 2, w.genesis)}}
	mk := func(i int, f func(*ev)) *ev {
		e := w.nc(ms[i].id, 150, 0x11)
		f(e)
		return w.signWith(e, vals[ms[i].id])
	}
	none := func(*ev) {}
	g.yes("res.members-64.single.ok", fam, "64 members with 128-byte node IDs, one vote", ctx, view, mk(5, none))
	a := mk(63, none)
	b := mk(63, func(e *ev) { e.exec[0] = 0x77 })
	g.yes("res.members-64.pair.ok", fam, "64 members, a pair", ctx, view, a, b)
	ca := mk(10, func(e *ev) { e.net, e.sealRound, e.sealEpoch, e.sealTS, e.hash = w.net, 149, 1, 5149, make([]byte, 32) })
	cb := mk(10, func(e *ev) {
		e.exec[0] = 0x78
		e.net, e.sealRound, e.sealEpoch, e.sealTS, e.hash = w.net, 149, 1, 5149, make([]byte, 32)
	})
	g.yes("res.members-64.pair-committing.ok", fam, "64 members, a pair of committing votes: four signatures (S=4), the largest charge shape", ctx, view, ca, cb)
	bad := cb.cp()
	bad.sealSig = flip(bad.sealSig, 9)
	g.no("res.members-64.invalid-last-signature", fam, "the last signature checked is bad: the full charge, no failure-position discount", ctx, view, "ErrSigInvalid", ca, bad)
	g.no("res.members-64.unknown-author", fam, "unknown author in a 64-member view: full charge", ctx, view, "ErrUnknownAuthor", func() *ev { e := mk(0, none); e.author = "nobody"; return e }())
}
