package b1gen

// structure covers claim cardinality, duplicate and conflicting claims, and the native input record and seal rules.
func (g *gen) structure(seed string) {
	const fam = "Native certificates"
	f := newFixture(seed, 4)
	pre := f.pre()
	q := f.vals[:3]
	cs := f.build("a", f.round, q, false)
	cs2 := f.build("a", f.round+1, q, false)
	keys := [][2]interface{}{{uint32(1), ""}, {uint32(2), "0"}, {uint32(2), "1"}, {uint32(3), ""}, {uint32(4), ""}, {uint32(5), ""}, {uint32(6), ""}, {uint32(7), ""}}
	var all []ucSpec
	for _, set := range []*certSet{cs, cs2} {
		for _, k := range keys {
			all = append(all, set.get(k[0].(uint32), k[1].(string)))
		}
	}
	g.ok("cert.batch.max-16.ok", fam, "sixteen claims, the maximum K: every shard under two seals of one epoch", req(claimsOf(all...)...), pre, "", nil, nil)
	r := newRequest(claimsOf(all...)...)
	r.claims = append(r.claims, claimOf(all[0]))
	g.bad("cert.batch.count-17", fam, "seventeen claims", r.wire(), &pre, "ErrCount")
	n17 := uint16(17)
	r = newRequest(claimOf(all[0]), claimOf(all[1]))
	r.count = &n17
	g.bad("cert.batch.count-field-17", fam, "count field 17 with two claims", r.wire(), &pre, "ErrCount")
	g.ok("cert.batch.duplicate.ok", fam, "an exact duplicate claim: allowed, evaluated once (A = 1)", req(claimOf(all[0]), claimOf(all[0])), pre, "", nil, nil)
	dupBad := claimOf(all[0])
	dupBad.stateRoot = flip32(dupBad.stateRoot)
	g.ok("cert.batch.same-uc-other-tuple", fam, "the same certificate claimed again with a different expected state root: a different claim, false",
		req(claimOf(all[0]), dupBad), pre, "ErrStateRoot", nil, nil)

	// native input record rules: block hash null although the state changed.
	x := all[0]
	x.ir.block = nil
	g.ok("cert.neg.ir-invalid", fam, "input record with a changed state hash but no block hash", req(claimOf(x)), pre, "ErrNativeInvalid", nil, nil)
	x = all[0]
	x.seal.timestamp = genesisTime - 1
	x.seal.signWith(q, false)
	g.ok("cert.neg.seal-timestamp", fam, "seal timestamp before the genesis minimum, re-signed", req(claimOf(x)), pre, "ErrNativeInvalid", nil, nil)

	// null and empty signature containers.
	sealWith := func(sigs []byte) ucSpec { y := all[0]; y.sealBytes = y.seal.fields(sigs); return y }
	g.ok("seal.sigs-null", fam, "null signatures are shaped but false", req(claimOf(sealWith(cNull))), pre, "ErrNativeInvalid", nil, nil)
	g.ok("seal.sigs-empty", fam, "signatures encoded as an empty map", req(claimOf(sealWith(cTextMap(nil)))), pre, "ErrNativeInvalid", nil, nil)
}
