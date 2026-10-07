package b1gen

// Frozen caller cases from the A′ v4 table, independently encoded here.
func (g *gen) aprime(seed string) {
	const fam = "Paths/encoding"
	f := newFixture(seed, 4)
	pre := f.pre()
	cs := f.build("a", f.round, f.vals[:3], false)
	u := cs.get(1, "")
	for _, n := range []int{0, 63, 66} {
		x := u
		x.seal.sigs = append([]entry(nil), u.seal.sigs...)
		x.seal.sigs[0].val = make([]byte, n)
		g.bad("frozen.signature-length-"+decimal(n), fam, opUC, "unsupported signature length", newRequest(claimOf(x)).wire(), &pre, "ErrSigFormat")
	}
	// Null value is distinct from a null collection: the value is malformed.
	x := u
	x.sealBytes = u.seal.fields(cTextMap([]entry{{"node00", cNull}}))
	g.bad("frozen.signature-null", fam, opUC, "required signature value is null", newRequest(claimOf(x)).wire(), &pre, "ErrShape")
	// Earlier false tuple/path never masks a malformed final certificate.
	first := claimOf(u)
	first.stateRoot = flip32(first.stateRoot)
	last := claimOf(cs.get(3, ""))
	last.uc = []byte{0xf6}
	g.bad("frozen.malformed-last", fam, opShared, "false first claim, malformed final claim", newRequest(first, last).wire(), &pre, "ErrShape")
	g.bad("frozen.unsorted-malformed-last", fam, opShared, "unsorted earlier claims, malformed final claim", newRequest(claimOf(cs.get(2, "0")), first, last).wire(), &pre, "ErrShape")
	// Null and empty collections are canonical distinct encodings of zero steps.
	simple := customUC(f, 9, "", nil, nil, f.vals[:3])
	c := claimOf(simple)
	shardEmpty := cTag(tagShard, cArr(cUint(1), cBytes(shardBits("")), cArr()))
	shardNull := cTag(tagShard, cArr(cUint(1), cBytes(shardBits("")), cNull))
	utcEmpty := cTag(tagUTC, cArr(cUint(1), cUint(9), cArr()))
	utcNull := cTag(tagUTC, cArr(cUint(1), cUint(9), cNull))
	for _, tc := range []struct {
		id               string
		old, replacement []byte
	}{{"shard", shardEmpty, shardNull}, {"unicity", utcEmpty, utcNull}} {
		raw := withReplaced(c, tc.old, tc.replacement)
		g.ok("frozen.null-"+tc.id, fam, opUC, "null path collection is zero steps", newRequest(raw).wire(), pre, shapeOf(simple), "", &simple.seal, nil)
	}
	badShard := cs.get(2, "0")
	cc := claimOf(badShard)
	old := cTag(tagShard, cArr(cUint(1), cBytes(shardBits("0")), cArr(cBytes(badShard.shardSibs[0][:]))))
	replacement := cTag(tagShard, cArr(cUint(1), cBytes(shardBits("0")), cNull))
	sh := shapeOf(badShard)
	sh.steps--
	g.ok("frozen.null-siblings-depth-one", fam, opUC, "zero sibling collection with nonzero depth is false", newRequest(withReplaced(cc, old, replacement)).wire(), pre, sh, "ErrNativeInvalid", nil, nil)
	// A malformed required sibling hash remains an exceptional error.
	replacement = cTag(tagShard, cArr(cUint(1), cBytes(shardBits("0")), cArr(cNull)))
	g.bad("frozen.null-sibling-value", fam, opUC, "required sibling hash is null", newRequest(withReplaced(cc, old, replacement)).wire(), &pre, "ErrShape")
	// Weighted relation: total 10, threshold 7, same root keys across configs.
	for _, tc := range []struct {
		id      string
		weights []uint64
		n       int
		want    string
	}{
		{"below", []uint64{4, 2, 2, 2}, 2, "ErrQuorum"},
		{"at", []uint64{4, 3, 2, 1}, 2, ""},
		{"above", []uint64{4, 4, 1, 1}, 2, ""},
	} {
		authority := f.authority
		authority.members = append([]authorityMember(nil), f.authority.members...)
		for i, w := range tc.weights {
			authority.members[i].weight = w
		}
		uc := f.build("a", f.round, f.vals[:tc.n], false).get(1, "")
		g.ok("weighted."+tc.id, "Quorum", opUC, "weighted threshold boundary", newRequest(claimOf(uc)).wire(), f.preForAuthority(authority), shapeOf(uc), tc.want, &uc.seal, nil)
	}
}
func decimal(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte(n%10) + '0'
		n /= 10
	}
	return string(b[i:])
}
