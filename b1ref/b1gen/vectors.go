package b1gen

import "crypto/sha256"

// Build generates the whole manifest from a seed. It is a pure function of the
// seed: same seed, same bytes.
func Build(seed string) *Manifest {
	g := &gen{m: &Manifest{Format: FormatVersion, Seed: seed, Pins: Pins, Notes: Notes}}
	g.certificates(seed)
	g.structure(seed)
	g.quorum(seed)
	g.anyAge(seed)
	g.registryFamily(seed)
	g.reuse(seed)
	g.topology(seed)
	g.encoding(seed)
	g.resources(seed)
	g.worked(seed)
	g.aprime(seed)
	g.rsmt(seed)
	g.m.Deferred = []Deferred{
		{"Registry lifecycle", "append/close/replay, preload and catch-up beyond B, interrupted preload, reorg, no whole-history scan", "dev: b1state/rootinput and the contract's section preload; this corpus starts from installed state"},
		{"Gas/resources", "cold reads, empty caches, wall-clock and the measured price review", "dev3: native EVM benchmarks; prices here are the frozen contract schedule"},
		{"Bridge", "leaf/anchor coverage, the composing gate and token-level histories", "dev2: contracts and plug-ins; this corpus gives the B1 batch verdicts they build on"},
	}
	return g.m
}

type gen struct{ m *Manifest }

const (
	opBatch  = "CERT_BATCH_V2"
	opMember = "RSMT_MEMBER_V1"
)

// ok adds a structurally valid request with its verdict: want is "" for true or the sentinel naming the first failing check.
// Gas, grouping and (for a true batch) the work counters are derived here from the request bytes and the pre-state.
func (g *gen) ok(id, fam, desc string, req []byte, pre PreState, want string, seal *sealSpec, inter map[string]string) {
	pre.render()
	gr, os := grouping(req)
	valid := want == ""
	v := Vector{ID: id, Family: fam, Op: opBatch, Description: desc, PreState: &pre, Request: hx(req), Intermediate: inter,
		Expected: Expected{Status: "ok", Valid: &valid, Sentinel: want, Output: hx(outputWords(2, valid)), Gas: batchGas(gr), Grouping: &gr}}
	if valid {
		v.Expected.Counters = counters(gr, os, &pre)
	}
	if seal != nil {
		d := sha256.Sum256(seal.sigBytes())
		v.SealSigBytes, v.SealDigest = hx(seal.sigBytes()), hx(d[:])
	}
	g.m.Vectors = append(g.m.Vectors, v)
}

// registry adds a structurally valid request that must fail as an infrastructure error after the full debit.
func (g *gen) registry(id, fam, desc string, req []byte, pre PreState, want string) {
	pre.render()
	gr, _ := grouping(req)
	g.m.Vectors = append(g.m.Vectors, Vector{ID: id, Family: fam, Op: opBatch, Description: desc, PreState: &pre, Request: hx(req),
		Expected: Expected{Status: "registry", Sentinel: want, Gas: batchGas(gr), Grouping: &gr}})
}

// bad adds a malformed request: a precompile halt naming the sentinel.
func (g *gen) bad(id, fam, desc string, req []byte, pre *PreState, want string) {
	if pre != nil {
		p := *pre
		p.render()
		pre = &p
	}
	g.m.Vectors = append(g.m.Vectors, Vector{ID: id, Family: fam, Op: opBatch, Description: desc, PreState: pre, Request: hx(req),
		Expected: Expected{Status: "error", Sentinel: want}})
}

// counters is the work of a valid batch: one entry load per distinct epoch, one key parse per member of those entries, one
// signature loop per distinct seal, one check per signature, and one binding and fold per distinct claim.
func counters(gr Grouping, os []occ, pre *PreState) map[string]int {
	members := 0
	seen := map[uint64]bool{}
	for _, o := range os {
		if seen[o.epoch] {
			continue
		}
		seen[o.epoch] = true
		for _, e := range pre.Epochs {
			if e.Epoch == o.epoch {
				members += len(e.Members)
			}
		}
	}
	return map[string]int{"epoch-load": int(gr.E), "key-parse": members, "quorum": int(gr.S), "signature": int(gr.Q), "claim": int(gr.A), "fold": int(gr.A)}
}

func inter(cs *certSet, u ucSpec) map[string]string {
	sr := shardLeaf(u.ir, u.tr, u.conf)
	return map[string]string{
		"shardLeaf": hex32(sr), "shardTreeRoot": hex32(cs.shardRoot[u.part]), "unicityTreeRoot": hex32(cs.treeRoot),
		"irDigest": hex32(sha256.Sum256(u.ir.cbor())),
	}
}

func flip(b []byte, i int) []byte { c := append([]byte{}, b...); c[i] ^= 0x01; return c }

func flip32(h [32]byte) [32]byte { h[0] ^= 0x01; return h }

// req is a CERT_BATCH_V2 request of the given claims.
func req(claims ...claimSpec) []byte { return newRequest(claims...).wire() }

func claimsOf(us ...ucSpec) []claimSpec {
	var c []claimSpec
	for _, u := range us {
		c = append(c, claimOf(u))
	}
	return c
}

func (g *gen) certificates(seed string) {
	const fam = "Native certificates"
	f := newFixture(seed, 4)
	pre := f.pre()
	q := f.vals[:3] // threshold 4-(4-1)/3 = 3
	cs := f.build("a", f.round, q, false)
	u := cs.get(1, "")

	seal := u.seal
	g.ok("cert.single.ok", fam, "single shard, one seal, quorum 3 of 4", req(claimOf(u)), pre, "", &seal, inter(cs, u))

	var all []ucSpec
	for _, k := range [][2]interface{}{{uint32(1), ""}, {uint32(2), "0"}, {uint32(2), "1"}, {uint32(3), ""}} {
		all = append(all, cs.get(k[0].(uint32), k[1].(string)))
	}
	g.ok("cert.shared.ok", fam, "four claims over three partitions and two shards, one common seal", req(claimsOf(all...)...), pre, "", &seal, inter(cs, all[1]))
	g.ok("cert.uc.shard.ok", fam, "two-shard partition, shard 1", req(claimOf(all[2])), pre, "", &seal, inter(cs, all[2]))
	g.ok("cert.unsorted.ok", fam, "claims in no particular order: input order is accepted as supplied", req(claimsOf(all[3], all[0], all[2], all[1])...), pre, "", &seal, nil)

	// repeated IR: the same IR certified again at a later root round.
	rep := f.build("a", f.round+3, q, false).get(1, "")
	g.ok("cert.repeat-ir.ok", fam, "repeat UC: identical input record under a later seal", req(claimOf(rep)), pre, "", &rep.seal, nil)

	// distinct valid quorum subsets of the same statement: different complete seals, each its own quorum group.
	subA := f.build("a", f.round, f.vals[:3], false).get(1, "")
	subB := f.build("a", f.round, f.vals[1:], false).get(1, "")
	g.ok("cert.subset-a.ok", fam, "quorum subset {0,1,2}", req(claimOf(subA)), pre, "", &subA.seal, nil)
	g.ok("cert.subset-b.ok", fam, "quorum subset {1,2,3}", req(claimOf(subB)), pre, "", &subB.seal, nil)
	g.ok("cert.mixed-subsets.ok", fam, "claims whose seals carry different quorum subsets: two seal groups, both valid",
		req(claimOf(subA), claimOf(cs.get(2, "0")), claimOf(f.build("a", f.round, f.vals[1:], false).get(3, ""))), pre, "", nil, nil)
	full4 := f.build("a", f.round, f.vals, false)
	g.ok("cert.sigcount-3-4.ok", fam, "seals with 3 then 4 signatures: two groups, Q = 7",
		req(claimOf(subA), claimOf(full4.get(3, ""))), pre, "", nil, nil)

	// single perturbations.
	reseal := func(mod func(*sealSpec)) ucSpec {
		x := u
		mod(&x.seal)
		x.seal.signWith(q, false)
		return x
	}
	bad := func(id, desc, want string, c claimSpec) { g.ok(id, fam, desc, req(c), pre, want, nil, nil) }
	x := reseal(func(s *sealSpec) { s.network = 4 })
	bad("cert.neg.network", "seal network changed and re-signed", "ErrNetwork", claimOf(x))
	c := claimOf(u)
	c.part = 2
	bad("cert.neg.partition", "claim partition differs from the certificate", "ErrPartition", c)
	c = claimOf(cs.get(2, "0"))
	c.shardWire = shardBits("1")
	bad("cert.neg.shard-bit", "claim shard bit flipped", "ErrShard", c)
	c = claimOf(u)
	c.conf = flip32(c.conf)
	bad("cert.neg.config", "claim shard configuration hash flipped", "ErrShardConf", c)
	x = u
	x.tr = flip32(x.tr)
	c = claimOf(u)
	c.uc = x.cbor()
	bad("cert.neg.trhash", "TRHash flipped inside the certificate", "ErrTreeRoot", c)
	x = u
	x.ir.state = flip(x.ir.state, 0)
	bad("cert.neg.ir-state", "IR state hash flipped inside the certificate", "ErrTreeRoot", claimOf(x))
	c = claimOf(u)
	c.stateRoot = flip32(c.stateRoot)
	bad("cert.neg.expected-state", "expectedStateRoot flipped", "ErrStateRoot", c)
	c = claimOf(u)
	c.irHash = flip32(c.irHash)
	bad("cert.neg.expected-ir", "expectedIRHash flipped", "ErrIRHash", c)
	x = u
	x.seal.root = flip32(x.seal.root)
	bad("cert.neg.root", "seal tree root flipped (unsigned)", "ErrTreeRoot", claimOf(x))
	x = reseal(func(s *sealSpec) { s.epoch = 6 })
	bad("cert.neg.epoch", "seal epoch below the genesis epoch, re-signed", "ErrEpochBeforeGenesis", claimOf(x))
	x = u
	x.seal.timestamp++
	bad("cert.neg.signed-byte", "one signed seal byte changed after signing", "ErrSigInvalid", claimOf(x))
	x = u
	x.seal.sigs = append([]entry{}, u.seal.sigs...)
	other := makeValidator(seed, "intruder-key")
	x.seal.sigs[0] = entry{u.seal.sigs[0].key, other.sign(u.seal.sigBytes(), false)}
	bad("cert.neg.signer-key", "a signature made by a key other than the named member's", "ErrSigInvalid", claimOf(x))
	rawReq := rawConcatRequest(f, cs, q)
	g.ok("cert.neg.raw-concat-fold", fam, "shard fold computed as raw SHA256(left||right) instead of CBOR operands", rawReq, pre, "ErrTreeRoot", nil, nil)
}

// rawConcatRequest builds a UC for shard 2/0 whose unicity tree was built from
// a shard root folded with raw concatenation.
func rawConcatRequest(f *fixture, cs *certSet, q []validator) []byte {
	u := cs.get(2, "0")
	leaf := shardLeaf(u.ir, u.tr, u.conf)
	badRoot := shardFold(leaf, "0", u.shardSibs, true)
	var key [4]byte
	key[3] = 2
	leaves := []imtLeaf{}
	for p := uint32(1); p <= uint32(len(scheme)); p++ {
		l := imtLeaf{key: [4]byte{0, 0, 0, byte(p)}}
		sr := cs.shardRoot[p]
		if p == 2 {
			sr = badRoot
		}
		l.data = sum(cBytes(sr[:]))
		leaves = append(leaves, l)
	}
	root := imtBuild(leaves)
	u.seal.root = root.hash
	u.steps = root.path(key)
	u.seal.signWith(q, false)
	return req(claimOf(u))
}
