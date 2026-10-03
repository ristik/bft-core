package b1gen

func (g *gen) resources(seed string) {
	const fam = "Gas/resources"
	f := newFixture(seed, 4)
	pre := f.pre()
	cs := f.build("a", f.round, f.vals, false) // all four sign
	u := cs.get(1, "")
	req := func(x ucSpec) []byte { return newRequest(f.view.cbor(), claimOf(x)).wire() }
	g.ok("gas.4sigs.valid", fam, opUC, "four valid signatures: the reference charge", req(u), pre, shapeOf(f.view, u), "", &u.seal, nil)
	last := u
	last.seal.sigs = append([]entry{}, u.seal.sigs...)
	n := len(last.seal.sigs) - 1
	last.seal.sigs[n] = entry{last.seal.sigs[n].key, f.vals[0].sign([]byte("other"), false)}
	g.ok("gas.4sigs.last-invalid", fam, opUC, "invalid last signature charges the same as the valid call", req(last), pre, shapeOf(f.view, last), "ErrSigInvalid", nil, nil)

	c := claimOf(u)
	vl := uint32(0xffffffff)
	r := newRequest(f.view.cbor(), c)
	r.viewLen = &vl
	g.bad("res.view-length-u32max", fam, opUC, "view length 2^32-1", r.wire(), &pre, "ErrViewTooLarge")
	ul := uint32(0xffffffff)
	cc := c
	cc.ucLen = &ul
	g.bad("res.uc-length-u32max", fam, opUC, "certificate length 2^32-1", newRequest(f.view.cbor(), cc).wire(), &pre, "ErrUCTooLarge")
	sl := uint16(0xffff)
	cc = c
	cc.shardLen = &sl
	g.bad("res.shard-length-u16max", fam, opUC, "shard length 65535", newRequest(f.view.cbor(), cc).wire(), &pre, "ErrShardTooDeep")
	cc = c
	ul2 := uint32(len(c.uc) + 1)
	cc.ucLen = &ul2
	g.bad("res.uc-length-past-end", fam, opUC, "certificate length one past the end of input", newRequest(f.view.cbor(), cc).wire(), &pre, "ErrTruncated")
}
