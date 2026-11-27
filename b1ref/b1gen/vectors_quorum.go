package b1gen

func (g *gen) quorum(seed string) {
	const fam = "Quorum"
	f := newFixture(seed, 4)
	pre := f.pre()
	q := f.vals[:3]
	cs := f.build("a", f.round, q, true)
	u := cs.get(1, "")
	// run adds a well-formed request (no signature shape is a structural failure any more): want is "" for a true verdict or the sentinel
	// of the first failing relation
	run := func(id, desc, want string, x ucSpec, pre PreState) {
		g.ok(id, fam, desc, req(claimOf(x)), pre, want, nil, nil)
	}
	withSigs := func(sigs []entry) ucSpec { x := u; x.seal.sigs = sigs; return x }
	extra := func(e entry) ucSpec { return withSigs(append(append([]entry{}, u.seal.sigs...), e)) }

	short := f.build("a", f.round, f.vals[:2], true).get(1, "")
	run("quorum.short", "one signer short of the threshold", "ErrQuorum", short, pre)

	// duplicate wire map key: malformed.
	x := u
	x.sealBytes = u.seal.fields(cTextMapRaw([]entry{
		{u.seal.sigs[0].key, cBytes(u.seal.sigs[0].val)}, {u.seal.sigs[1].key, cBytes(u.seal.sigs[1].val)}, {u.seal.sigs[1].key, cBytes(u.seal.sigs[1].val)},
	}))
	g.bad("quorum.dup-map-key", fam, "duplicate signer key in the wire signature map", req(claimOf(x)), &pre, "ErrDuplicateMapKey")

	// An extra that does not count never poisons an honest quorum, and never makes up for a missing one.
	mallory := makeValidator(seed, "mallory")
	unknown := entry{"mallory", mallory.sign(u.seal.sigBytes(), true)}
	run("quorum.unknown-signer", "honest quorum plus one signature from an unknown identity: the unknown ID counts zero", "", extra(unknown), pre)
	run("quorum.unknown-signer.short", "two honest signatures plus an unknown identity: still one signer short", "ErrQuorum",
		withSigs(append(append([]entry{}, short.seal.sigs...), unknown)), pre)
	wrong := f.vals[3].sign([]byte("not the seal"), true)
	run("quorum.bad-extra", "honest quorum plus one invalid signature from a known member: it counts zero", "", extra(entry{f.vals[3].id, wrong}), pre)
	run("quorum.bad-extra.short", "two honest signatures plus an invalid one from a known member", "ErrQuorum",
		withSigs(append(append([]entry{}, short.seal.sigs...), entry{f.vals[3].id, wrong})), pre)

	// Signature shape and scalar perturbations. Each is run twice: replacing a needed signature of the exact quorum (the member's weight is lost:
	// ErrQuorum), and as an extra signature of the fourth member beside an honest quorum (a zero-weight extra: valid).
	good := u.seal.sigs[0].val
	zero := make([]byte, 32)
	n32 := pad32(curveN)
	recov := func(v byte) []byte { return append(append([]byte{}, good[:64]...), v) }
	perturbed := []struct {
		id, desc string
		sig      []byte
	}{
		{"r-zero", "r = 0", append(append([]byte{}, zero...), good[32:]...)},
		{"s-zero", "s = 0", append(append([]byte{}, good[:32]...), zero...)},
		{"r-n", "r = n", append(append([]byte{}, n32...), good[32:]...)},
		{"high-s", "s replaced by n-s (high-s twin of a valid signature): never normalized into acceptance", highS(good)},
		{"high-s-twin", "the high-s twin (r, n-s, flipped recovery byte) of a valid signature: it recovers to the member's key but s is high, never normalized into acceptance", func() []byte { t := highS(good); t[64] ^= 1; return t }()},
		{"short", "63-byte signature", good[:63]},
		{"long", "66-byte signature", append(append([]byte{}, good...), 0)},
		{"compact", "the 64-byte compact form r||s of a valid signature is not a seal signature", good[:64]},
		{"v255", "65-byte signature with recovery byte 255", recov(255)},
		{"v27", "65-byte signature with recovery byte 27 (no Ethereum v)", recov(27)},
		{"v4", "65-byte signature with recovery byte 4", recov(4)},
		{"v2", "the valid signature with its recovery byte replaced by 2: recovery does not yield the member's key", recov(2)},
		{"v-flipped", "the valid signature with its recovery byte flipped (0/1 swapped): the supplied parity is binding", recov(good[64] ^ 1)},
	}
	for _, c := range perturbed {
		mut := withSigs(append([]entry{{u.seal.sigs[0].key, c.sig}}, u.seal.sigs[1:]...))
		run("quorum.sig."+c.id, c.desc+" as a needed signature", "ErrQuorum", mut, pre)
		run("quorum.sig."+c.id+".extra", c.desc+" as an extra beside an honest quorum", "", extra(entry{f.vals[3].id, c.sig}), pre)
	}
	// An empty signature value is a structural failure, as in upstream's own seal validation (UnicitySeal.IsValid) and the Rust SDK's seal shape
	// check: every other byte-string length is well formed and counts zero.
	emptySig := withSigs(append([]entry{{u.seal.sigs[0].key, nil}}, u.seal.sigs[1:]...))
	g.ok("quorum.sig.empty", fam, "an empty byte string as a signature: upstream's native seal validation refuses it", req(claimOf(emptySig)), pre, "ErrNativeInvalid", nil, nil)
	// An empty value beside a full quorum is the same structural failure, whether its ID is a member's or a stranger's (every other length is a
	// zero-weight witness; the empty one is refused by the native seal validation, which cannot be told apart from poisoning by design).
	run("quorum.empty-extra.known", "honest quorum plus an empty signature value under a member's ID: refused by the native seal validation", "ErrNativeInvalid",
		extra(entry{f.vals[3].id, nil}), pre)
	run("quorum.empty-extra.unknown", "honest quorum plus an empty signature value under an unknown ID: refused by the native seal validation", "ErrNativeInvalid",
		extra(entry{"mallory", nil}), pre)
	// An empty signer ID is refused by the same native validation, even with a real signature behind it.
	run("quorum.empty-id.extra", "honest quorum plus a real signature under an empty signer ID: refused by the native seal validation", "ErrNativeInvalid",
		extra(entry{"", u.seal.sigs[0].val}), pre)
	// aliases of the earlier ids whose meaning changed with the rule
	vflip := recov(good[64] ^ 1)
	run("quorum.sig.v-ignored", "wrong recovery byte (0/1 swapped) on a needed signature: the parity is not ignored, the member's weight is lost", "ErrQuorum",
		withSigs(append([]entry{{u.seal.sigs[0].key, vflip}}, u.seal.sigs[1:]...)), pre)
	allCompact := make([]entry, 0, len(u.seal.sigs))
	for _, e := range u.seal.sigs {
		allCompact = append(allCompact, entry{e.key, e.val[:64]})
	}
	run("quorum.sig.all-compact", "every signature in the 64-byte compact form: well formed, no weight", "ErrQuorum", withSigs(allCompact), pre)

	// the recovery byte is the real one
	withV := f.build("a", f.round, q, true).get(1, "")
	g.ok("quorum.sig.v-present", fam, "65-byte r||s||v signatures with the actual recovery ID", req(claimOf(withV)), pre, "", &withV.seal, nil)

	// genuine recovery IDs 2 and 3 (r + n is the x coordinate of R): constructed, the key of the fourth member is defined as the recovery result
	for _, id := range []int{2, 3} {
		kf := newFixture(seed, 4)
		base := kf.build("a", kf.round, kf.vals[:2], true).get(1, "")
		sig, pub := keylessMember(base.seal.sigBytes(), id)
		kf.vals[3] = validator{id: kf.vals[3].id, pub: pub}
		kf.authority = authorityOf(kf.network, kf.epoch, 2, kf.body, kf.vals)
		if err := checkSealSignatureFor(pub, sig, base.seal.sigBytes()); err != nil {
			panic("quorum: the constructed recovery ID " + decimal(id) + " signature does not verify: " + err.Error())
		}
		x := base
		x.seal.sigs = append(append([]entry{}, base.seal.sigs...), entry{kf.vals[3].id, sig})
		g.ok("quorum.sig.v"+decimal(id)+"-genuine", fam, "recovery ID "+decimal(id)+" that recovers to the member's key (r + n is R's x coordinate), the third signature of a 3-of-4 quorum",
			req(claimOf(x)), kf.pre(), "", &x.seal, nil)
		y := base
		bad := append([]byte{}, sig...)
		bad[64] = byte(id ^ 1) // same r, s with the other parity: recovers another key
		y.seal.sigs = append(append([]entry{}, base.seal.sigs...), entry{kf.vals[3].id, bad})
		g.ok("quorum.sig.v"+decimal(id)+"-parity-flipped", fam, "the genuine recovery ID "+decimal(id)+" signature with the other parity: another key, the quorum is one short", req(claimOf(y)),
			kf.pre(), "ErrQuorum", nil, nil)
	}

	// maximal authority: 16 members (the profile ceiling), exact threshold 11.
	big := newFixture(seed+"/16", 16)
	bp := big.pre()
	bu := func(n int) ucSpec { return big.build("a", big.round, big.vals[:n], true).get(1, "") }
	for _, c := range []struct {
		id, desc, want string
		n              int
	}{
		{"quorum.max.exact", "16 members, exactly the threshold of 11 signatures", "", 11},
		{"quorum.max.short", "16 members, 10 signatures", "ErrQuorum", 10},
		{"quorum.max.all", "16 members, 16 signatures (maximum)", "", 16},
	} {
		x := bu(c.n)
		g.ok(c.id, fam, c.desc, req(claimOf(x)), bp, c.want, &x.seal, nil)
	}
	// seventeen signatures exceed the per-seal bound, even from a seventeen-member set the registry could never admit
	over := newFixture(seed+"/17", 17)
	x17 := over.build("a", over.round, over.vals, true).get(1, "")
	g.bad("quorum.sigs-17", fam, "seventeen signatures in one seal", req(claimOf(x17)), &bp, "ErrTooManySigs")
}
