package b1gen

// structure covers shared-call ordering and bounds, registry authority decoding and
// the native input record rules.
func (g *gen) structure(seed string) {
	const fam = "Native certificates"
	f := newFixture(seed, 4)
	pre := f.pre()
	q := f.vals[:3]
	cs := f.build("a", f.round, q, false)
	keys := [][2]interface{}{{uint32(1), ""}, {uint32(2), "0"}, {uint32(2), "1"}, {uint32(3), ""}, {uint32(4), ""}, {uint32(5), ""}, {uint32(6), ""}, {uint32(7), ""}}
	var all []ucSpec
	for _, k := range keys {
		all = append(all, cs.get(k[0].(uint32), k[1].(string)))
	}
	wire := func(us ...ucSpec) []byte {
		var c []claimSpec
		for _, u := range us {
			c = append(c, claimOf(u))
		}
		return newRequest(c...).wire()
	}
	seal := all[0].seal
	g.ok("cert.shared.max-8.ok", fam, opShared, "eight claims, the maximum", wire(all...), pre, shapeOf(all...), "", &seal, nil)
	n9 := uint16(9)
	r := newRequest(claimOf(all[0]), claimOf(all[1]))
	r.count = &n9
	g.bad("cert.shared.count-9", fam, opShared, "count 9", r.wire(), &pre, "ErrCount")
	g.ok("cert.shared.order", fam, opShared, "claims not sorted", wire(all[1], all[0]), pre, shapeOf(all[1], all[0]), "ErrClaimOrder", nil, nil)
	g.ok("cert.shared.order-shard", fam, opShared, "shards not sorted", wire(all[2], all[1]), pre, shapeOf(all[2], all[1]), "ErrClaimOrder", nil, nil)
	g.ok("cert.shared.duplicate", fam, opShared, "the same shard claimed twice", wire(all[0], all[0]), pre, shapeOf(all[0], all[0]), "ErrClaimOrder", nil, nil)

	// native input record rules: block hash null although the state changed.
	x := all[0]
	x.ir.block = nil
	g.ok("cert.neg.ir-invalid", fam, opUC, "input record with a changed state hash but no block hash", wire(x), pre, shapeOf(x), "ErrNativeInvalid", nil, nil)
	x = all[0]
	x.seal.timestamp = genesisTime - 1
	x.seal.signWith(q, false)
	g.ok("cert.neg.seal-timestamp", fam, opUC, "seal timestamp before the genesis minimum, re-signed", wire(x), pre, shapeOf(x), "ErrNativeInvalid", nil, nil)

	// null and empty signature containers.
	sealWith := func(sigs []byte) ucSpec { y := all[0]; y.sealBytes = y.seal.fields(sigs); return y }
	g.ok("seal.sigs-null", fam, opUC, "null signatures are shaped but false", wire(sealWith(cNull)), pre, shape{sigs: 0, claims: 1, steps: len(all[0].steps)}, "ErrNativeInvalid", nil, nil)
	g.ok("seal.sigs-empty", fam, opUC, "signatures encoded as an empty map", wire(sealWith(cTextMap(nil))), pre,
		shape{sigs: 0, claims: 1, steps: len(all[0].shardSibs) + len(all[0].steps)}, "ErrNativeInvalid", nil, nil)

}
