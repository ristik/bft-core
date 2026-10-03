package b1gen

// structure covers shared-call ordering and bounds, trust view decoding and
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
		return newRequest(f.view.cbor(), c...).wire()
	}
	seal := all[0].seal
	g.ok("cert.shared.max-8.ok", fam, opShared, "eight claims, the maximum", wire(all...), pre, shapeOf(f.view, all...), "", &seal, nil)
	n9 := uint16(9)
	r := newRequest(f.view.cbor(), claimOf(all[0]), claimOf(all[1]))
	r.count = &n9
	g.bad("cert.shared.count-9", fam, opShared, "count 9", r.wire(), &pre, "ErrCount")
	g.bad("cert.shared.order", fam, opShared, "claims not sorted by (partition, shard bytes)", wire(all[1], all[0]), &pre, "ErrClaimOrder")
	g.bad("cert.shared.order-shard", fam, opShared, "shards of one partition out of byte order", wire(all[2], all[1]), &pre, "ErrClaimOrder")
	g.ok("cert.shared.duplicate", fam, opShared, "the same shard claimed twice", wire(all[0], all[0]), pre, shapeOf(f.view, all[0], all[0]), "ErrDuplicateClaim", nil, nil)

	// native input record rules: block hash null although the state changed.
	x := all[0]
	x.ir.block = nil
	g.ok("cert.neg.ir-invalid", fam, opUC, "input record with a changed state hash but no block hash", wire(x), pre, shapeOf(f.view, x), "ErrNativeInvalid", nil, nil)
	x = all[0]
	x.seal.timestamp = genesisTime - 1
	x.seal.signWith(q, false)
	g.ok("cert.neg.seal-timestamp", fam, opUC, "seal timestamp before the genesis minimum, re-signed", wire(x), pre, shapeOf(f.view, x), "ErrNativeInvalid", nil, nil)

	// null and empty signature containers.
	sealWith := func(sigs []byte) ucSpec { y := all[0]; y.sealBytes = y.seal.fields(sigs); return y }
	g.bad("seal.sigs-null", fam, opUC, "signatures encoded as null", wire(sealWith(cNull)), &pre, "ErrShape")
	g.ok("seal.sigs-empty", fam, opUC, "signatures encoded as an empty map", wire(sealWith(cTextMap(nil))), pre,
		shape{members: 4, sigs: 0, claims: 1, steps: len(all[0].shardSibs) + len(all[0].steps)}, "ErrNativeInvalid", nil, nil)

	// trust view decoding.
	members := func(ms ...[]byte) []byte { return cArr(ms...) }
	mem := func(id string, pub []byte) []byte { return cArr(cText(id), cBytes(pub), cUint(1)) }
	m0, m1, m2 := mem("node00", f.vals[0].pub), mem("node01", f.vals[1].pub), mem("node02", f.vals[2].pub)
	view := func(version uint64, network uint64, kind uint64, ms []byte) []byte {
		return cArr(cUint(version), cUint(network), cUint(f.epoch), cUint(kind), cBytes(f.body[:]), ms)
	}
	for _, c := range []struct {
		id, desc, want string
		v              []byte
	}{
		{"view.order", "members not sorted by node ID", "ErrViewOrder", view(1, 3, 2, members(m1, m0, m2))},
		{"view.key", "member key that is not a secp256k1 point", "ErrViewKey", view(1, 3, 2, members(m0, mem("node01", append([]byte{0x05}, make([]byte, 32)...))))},
		{"view.kind", "unknown source kind 3", "ErrViewKind", view(1, 3, 3, members(m0, m1, m2))},
		{"view.empty", "no members", "ErrViewEmpty", view(1, 3, 2, members())},
		{"view.version", "view version 2", "ErrVersion", view(2, 3, 2, members(m0, m1, m2))},
		{"view.network-65536", "network that does not fit the native NetworkID", "ErrShape", view(1, 65536, 2, members(m0, m1, m2))},
		{"view.shape", "member with two fields", "ErrShape", view(1, 3, 2, members(cArr(cText("node00"), cBytes(f.vals[0].pub))))},
	} {
		g.bad(c.id, fam, opUC, c.desc, newRequest(c.v, claimOf(all[0])).wire(), &pre, c.want)
	}
}
