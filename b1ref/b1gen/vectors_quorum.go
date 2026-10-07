package b1gen

func (g *gen) quorum(seed string) {
	const fam = "Quorum"
	f := newFixture(seed, 4)
	pre := f.pre()
	q := f.vals[:3]
	cs := f.build("a", f.round, q, false)
	u := cs.get(1, "")
	run := func(id, desc, want string, x ucSpec, _ authoritySpec, pre PreState) {
		if want == "ErrSigFormat" {
			g.bad(id, fam, opUC, desc, newRequest(claimOf(x)).wire(), &pre, want)
		} else {
			g.ok(id, fam, opUC, desc, newRequest(claimOf(x)).wire(), pre, shapeOf(x), want, nil, nil)
		}
	}
	withSigs := func(sigs []entry) ucSpec { x := u; x.seal.sigs = sigs; return x }

	short := f.build("a", f.round, f.vals[:2], false).get(1, "")
	run("quorum.short", "one signer short of the threshold", "ErrQuorum", short, f.authority, pre)

	// duplicate wire map key: malformed.
	x := u
	x.sealBytes = u.seal.fields(cTextMapRaw([]entry{
		{u.seal.sigs[0].key, cBytes(u.seal.sigs[0].val)}, {u.seal.sigs[1].key, cBytes(u.seal.sigs[1].val)}, {u.seal.sigs[1].key, cBytes(u.seal.sigs[1].val)},
	}))
	g.bad("quorum.dup-map-key", fam, opUC, "duplicate signer key in the wire signature map", newRequest(claimOf(x)).wire(), &pre, "ErrDuplicateMapKey")

	mallory := makeValidator(seed, "mallory")
	run("quorum.unknown-signer", "honest quorum plus one signature from an unknown identity", "ErrUnknownSigner",
		withSigs(append(append([]entry{}, u.seal.sigs...), entry{"mallory", mallory.sign(u.seal.sigBytes(), false)})), f.authority, pre)
	wrong := f.vals[3].sign([]byte("not the seal"), false)
	run("quorum.bad-extra", "honest quorum plus one invalid signature from a known member", "ErrSigInvalid",
		withSigs(append(append([]entry{}, u.seal.sigs...), entry{f.vals[3].id, wrong})), f.authority, pre)

	// signature scalar and format perturbations on the first signature.
	mut := func(sig []byte) ucSpec {
		return withSigs(append([]entry{{u.seal.sigs[0].key, sig}}, u.seal.sigs[1:]...))
	}
	good := u.seal.sigs[0].val
	zero := make([]byte, 32)
	n32 := pad32(curveN)
	run("quorum.sig.r-zero", "r = 0", "ErrSigRange", mut(append(append([]byte{}, zero...), good[32:]...)), f.authority, pre)
	run("quorum.sig.s-zero", "s = 0", "ErrSigRange", mut(append(append([]byte{}, good[:32]...), zero...)), f.authority, pre)
	run("quorum.sig.r-n", "r = n", "ErrSigRange", mut(append(append([]byte{}, n32...), good[32:]...)), f.authority, pre)
	run("quorum.sig.high-s", "s replaced by n-s (high-s twin of a valid signature)", "ErrSigRange", mut(highS(good)), f.authority, pre)
	run("quorum.sig.short", "63-byte signature", "ErrSigFormat", mut(good[:63]), f.authority, pre)
	run("quorum.sig.v255", "65-byte signature with recovery byte 255 (B1 profile policy: the native verifier would accept it)", "ErrSigFormat", mut(append(append([]byte{}, good...), 255)), f.authority, pre)
	run("quorum.sig.v2", "65-byte signature with recovery byte 2 (B1 profile policy: the native verifier would accept it)", "ErrSigFormat", mut(append(append([]byte{}, good...), 2)), f.authority, pre)

	// recovery byte representation: both accepted, the byte is ignored.
	withV := f.build("a", f.round, q, true).get(1, "")
	g.ok("quorum.sig.v-present", fam, opUC, "65-byte r||s||v signatures", newRequest(claimOf(withV)).wire(), pre, shapeOf(withV), "", &withV.seal, nil)
	flipped := withV
	flipped.seal.sigs = append([]entry{}, withV.seal.sigs...)
	sig := append([]byte{}, flipped.seal.sigs[0].val...)
	sig[64] ^= 1
	flipped.seal.sigs[0] = entry{flipped.seal.sigs[0].key, sig}
	g.ok("quorum.sig.v-ignored", fam, opUC, "wrong recovery byte (0/1 swapped) is ignored like the native verifier", newRequest(claimOf(flipped)).wire(), pre, shapeOf(flipped), "", &flipped.seal, nil)

	// maximal authority: 64 members, exact threshold 43.
	big64 := newFixture(seed+"/64", 64)
	bp := big64.pre()
	bu := func(n int) ucSpec { return big64.build("a", big64.round, big64.vals[:n], false).get(1, "") }
	for _, c := range []struct {
		id, desc, want string
		n              int
	}{
		{"quorum.max.exact", "64 members, exactly the threshold of 43 signatures", "", 43},
		{"quorum.max.short", "64 members, 42 signatures", "ErrQuorum", 42},
		{"quorum.max.all", "64 members, 64 signatures (maximum)", "", 64},
	} {
		x := bu(c.n)
		g.ok(c.id, fam, opUC, c.desc, newRequest(claimOf(x)).wire(), bp, shapeOf(x), c.want, &x.seal, nil)
	}
}
