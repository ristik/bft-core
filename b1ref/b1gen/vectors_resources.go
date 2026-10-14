package b1gen

import "fmt"

// resources: the frozen price schedule (contract section 5; vectors plan family G) and the length-field bounds.
func (g *gen) resources(seed string) {
	const fam = "Gas/resources"
	f := newFixture(seed, 4)
	pre := f.pre()
	cs := f.build("a", f.round, f.vals, false) // all four sign
	u := cs.get(1, "")
	g.ok("gas.4sigs.valid", fam, "four valid signatures: the reference charge", req(claimOf(u)), pre, "", &u.seal, nil)
	last := u
	last.seal.sigs = append([]entry{}, u.seal.sigs...)
	n := len(last.seal.sigs) - 1
	last.seal.sigs[n] = entry{last.seal.sigs[n].key, f.vals[0].sign([]byte("other"), false)}
	g.ok("gas.4sigs.last-invalid", fam, "invalid last signature charges the same as the valid call", req(claimOf(last)), pre, "ErrSigInvalid", nil, nil)

	// the per-epoch term is the 16-member ceiling whatever the entry's size: the same request shape against 1, 4 and 16 members
	for _, members := range []int{1, 4, 16} {
		fx := newFixture(fmt.Sprintf("%s/ceiling-%d", seed, members), members)
		x := fx.build("a", fx.round, fx.vals, false).get(1, "")
		g.ok(fmt.Sprintf("price.epoch-ceiling.%d-members", members), fam, fmt.Sprintf("an epoch of %d members is charged at the 16-member ceiling", members),
			req(claimOf(x)), fx.pre(), "", nil, nil)
	}

	// unusable epochs are charged like any other: sixteen distinct epochs above the tip, no entry read
	h := NewHistory(seed, 0)
	var far []claimSpec
	for i := 0; i < 16; i++ {
		far = append(far, claimOf(h.uc(hseal(uint64(100+i), 9000, "far"), 1, "")))
	}
	g.ok("price.unusable-epochs.16", fam, "sixteen distinct epochs above the tip: E = 16 charged, false without any entry read", req(far...), h.Pre(), "ErrEpochNotUsable", nil, nil)

	// the most expensive structurally admitted batch this corpus builds: sixteen seals of sixteen signatures over sixteen
	// 16-member epochs, each claim with a 256-bit shard (256 siblings) and 32 Unicity steps
	g.worst(seed)

	c := claimOf(u)
	ul := uint32(0xffffffff)
	cc := c
	cc.ucLen = &ul
	g.bad("res.uc-length-u32max", fam, "certificate length 2^32-1", req(cc), &pre, "ErrUCTooLarge")
	sl := uint16(0xffff)
	cc = c
	cc.shardLen = &sl
	g.bad("res.shard-length-u16max", fam, "shard length 65535", req(cc), &pre, "ErrShardTooDeep")
	cc = c
	ul2 := uint32(len(c.uc) + 1)
	cc.ucLen = &ul2
	g.bad("res.uc-length-past-end", fam, "certificate length one past the end of input", req(cc), &pre, "ErrTruncated")
}

// worst builds the maximal batch: K = E = S = A = 16, Q = 256, P = 16*(256+32).
func (g *gen) worst(seed string) {
	const fam = "Gas/resources"
	base := newFixture(seed+"/worst", 16)
	p := base.registryBase()
	p.GenesisEpoch, p.ImportedTip, p.Origin, p.ClockRound = 0, 15, 15, 20_000
	var claims []claimSpec
	shard := ""
	for i := 0; i < 256; i++ {
		shard += string('0' + byte(i%2))
	}
	for e := uint64(0); e < 16; e++ {
		end := uint64(0)
		if e < 15 {
			end = 1000 * (e + 2)
		}
		p.Epochs = append(p.Epochs, base.epochWords(base.authority, e, 1000*(e+1), end, e == 0))
		f := *base
		f.epoch, f.round = e, 1000*(e+1)+500
		x := customUC(&f, 9, shard, randSibs(fmt.Sprintf("%s/%d", seed, e), 256), randSteps(fmt.Sprintf("%s/%d", seed, e), 32, 9), f.vals)
		claims = append(claims, claimOf(x))
	}
	g.ok("price.worst.k16", fam, "the maximal batch: sixteen 16-member epochs, sixteen seals of sixteen signatures, depth-256 shards with 32 steps",
		req(claims...), p, "", nil, nil)
}
