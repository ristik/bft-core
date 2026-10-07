package b1gen

func (g *gen) resources(seed string) {
	const fam = "Gas/resources"
	f := newFixture(seed, 4)
	pre := f.pre()
	cs := f.build("a", f.round, f.vals, false) // all four sign
	u := cs.get(1, "")
	req := func(x ucSpec) []byte { return newRequest(claimOf(x)).wire() }
	g.ok("gas.4sigs.valid", fam, opUC, "four valid signatures: the reference charge", req(u), pre, shapeOf(u), "", &u.seal, nil)
	last := u
	last.seal.sigs = append([]entry{}, u.seal.sigs...)
	n := len(last.seal.sigs) - 1
	last.seal.sigs[n] = entry{last.seal.sigs[n].key, f.vals[0].sign([]byte("other"), false)}
	g.ok("gas.4sigs.last-invalid", fam, opUC, "invalid last signature charges the same as the valid call", req(last), pre, shapeOf(last), "ErrSigInvalid", nil, nil)

	c := claimOf(u)
	ul := uint32(0xffffffff)
	cc := c
	cc.ucLen = &ul
	g.bad("res.uc-length-u32max", fam, opUC, "certificate length 2^32-1", newRequest(cc).wire(), &pre, "ErrUCTooLarge")
	sl := uint16(0xffff)
	cc = c
	cc.shardLen = &sl
	g.bad("res.shard-length-u16max", fam, opUC, "shard length 65535", newRequest(cc).wire(), &pre, "ErrShardTooDeep")
	cc = c
	ul2 := uint32(len(c.uc) + 1)
	cc.ucLen = &ul2
	g.bad("res.uc-length-past-end", fam, opUC, "certificate length one past the end of input", newRequest(cc).wire(), &pre, "ErrTruncated")
}
