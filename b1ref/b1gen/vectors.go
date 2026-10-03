package b1gen

import "crypto/sha256"

// Build generates the whole manifest from a seed. It is a pure function of the
// seed: same seed, same bytes.
func Build(seed string) *Manifest {
	g := &gen{m: &Manifest{Format: FormatVersion, Seed: seed, Pins: Pins, Notes: Notes, OpenItems: OpenItems}}
	g.certificates(seed)
	g.structure(seed)
	g.quorum(seed)
	g.timeAdmission(seed)
	g.encoding(seed)
	g.resources(seed)
	g.rsmt(seed)
	g.m.Deferred = []Deferred{
		{"Time/history", "change actualStart to EarliestActivation", "needs the transition-v4 history projection and layout-3 registry"},
		{"Time/history", "omitted or reordered intermediate epoch", "needs the transition-v4 history projection and layout-3 registry"},
		{"Time/history", "forged activationCommitID", "needs the transition-v4 history projection and layout-3 registry"},
		{"State/path parity", "builder, follower, replay, eth_call, two nodes, reorg", "needs the Rust/EVM execution paths and the layout-3 registry"},
		{"Gas/resources", "warm/cold/cache-enabled charge parity", "needs an EVM host with registry state reads"},
	}
	for i := range g.m.Vectors {
		g.m.Vectors[i].Provisional = provisional[g.m.Vectors[i].ID]
	}
	return g.m
}

// provisional maps a vector to the open item its expectation depends on.
var provisional = map[string]string{
	"view.key":          "O1",
	"quorum.sig.r-zero": "O2", "quorum.sig.s-zero": "O2", "quorum.sig.r-n": "O2", "quorum.sig.high-s": "O2",
	"quorum.sig.short": "O2", "quorum.sig.v2": "O2", "quorum.sig.v255": "O2",
	"cert.shared.order": "O3", "cert.shared.order-shard": "O3", "cert.shared.duplicate": "O3", "view.order": "O3",
	"quorum.dup-node-id": "O3", "quorum.dup-key": "O3",
	"view.shape": "O4", "enc.cbor.depth-16": "O4",
	"seal.sigs-null": "O5", "seal.sigs-empty": "O5",
	"cert.shared.mixed-subsets.false": "O6", "cert.shared.sigcount-3-4.false": "O6", "cert.shared.sigcount-4-3.false": "O6",
	"view.empty": "O7", "view.kind": "O7", "quorum.weight": "O7",
	"cert.neg.epoch": "O8", "time.seal-epoch.after-origin": "O8",
}

type gen struct{ m *Manifest }

// shape is what the gas formula needs of a well-formed call.
type shape struct{ members, sigs, claims, steps int }

func (s shape) gas(reqLen int) uint64 {
	return 60000 + 16*uint64(reqLen) + 1000*uint64(s.members) + 6000*uint64(s.sigs) + 2000*uint64(s.claims) + 250*uint64(s.steps)
}

func shapeOf(v viewSpec, ucs ...ucSpec) shape {
	s := shape{members: len(v.members), sigs: len(ucs[0].seal.sigs), claims: len(ucs)}
	for _, u := range ucs {
		s.steps += len(u.shardSibs) + len(u.steps)
	}
	return s
}

// ok adds a vector whose request is well formed; want is "" for true or the
// sentinel naming why the relation is false.
func (g *gen) ok(id, fam, op, desc string, req []byte, pre PreState, sh shape, want string, seal *sealSpec, inter map[string]string) {
	valid := want == ""
	v := Vector{ID: id, Family: fam, Op: op, Description: desc, PreState: &pre, Request: hx(req), Intermediate: inter,
		Expected: Expected{Status: "ok", Valid: &valid, Sentinel: want, Output: hx(outputWords(valid)), Gas: sh.gas(len(req))}}
	if seal != nil {
		d := sha256.Sum256(seal.sigBytes())
		v.SealSigBytes, v.SealDigest = hx(seal.sigBytes()), hx(d[:])
	}
	g.m.Vectors = append(g.m.Vectors, v)
}

// bad adds a malformed request: a precompile error naming the sentinel.
func (g *gen) bad(id, fam, op, desc string, req []byte, pre *PreState, want string) {
	g.m.Vectors = append(g.m.Vectors, Vector{ID: id, Family: fam, Op: op, Description: desc, PreState: pre, Request: hx(req),
		Expected: Expected{Status: "error", Sentinel: want}})
}

func inter(cs *certSet, u ucSpec) map[string]string {
	sr := shardLeaf(u.ir, u.tr, u.conf)
	return map[string]string{
		"shardLeaf": hex32(sr), "shardTreeRoot": hex32(cs.shardRoot[u.part]), "unicityTreeRoot": hex32(cs.treeRoot),
		"irDigest": hex32(sha256.Sum256(u.ir.cbor())),
	}
}

const (
	opUC     = "UC_V1"
	opShared = "SHARED_SEAL_V1"
	opMember = "RSMT_MEMBER_V1"
)

func flip(b []byte, i int) []byte { c := append([]byte{}, b...); c[i] ^= 0x01; return c }

func flip32(h [32]byte) [32]byte { h[0] ^= 0x01; return h }

func (g *gen) certificates(seed string) {
	const fam = "Native certificates"
	f := newFixture(seed, 4)
	pre := f.pre()
	q := f.vals[:3] // threshold floor(8/3)+1 = 3
	cs := f.build("a", f.round, q, false)
	u := cs.get(1, "")
	one := func(u ucSpec) []byte { return newRequest(f.view.cbor(), claimOf(u)).wire() }

	seal := u.seal
	g.ok("cert.single.ok", fam, opUC, "single shard, one seal, quorum 3 of 4", one(u), pre, shapeOf(f.view, u), "", &seal, inter(cs, u))

	var all []ucSpec
	for _, k := range [][2]interface{}{{uint32(1), ""}, {uint32(2), "0"}, {uint32(2), "1"}, {uint32(3), ""}} {
		all = append(all, cs.get(k[0].(uint32), k[1].(string)))
	}
	claims := func(us []ucSpec) []claimSpec {
		var c []claimSpec
		for _, x := range us {
			c = append(c, claimOf(x))
		}
		return c
	}
	g.ok("cert.shared.ok", fam, opShared, "four claims over three partitions and two shards, one common seal", newRequest(f.view.cbor(), claims(all)...).wire(), pre, shapeOf(f.view, all...), "", &seal, inter(cs, all[1]))
	g.ok("cert.shared.single.ok", fam, opShared, "shared call with one claim", one(u), pre, shapeOf(f.view, u), "", &seal, nil)
	g.ok("cert.uc.shard.ok", fam, opUC, "two-shard partition, shard 1", one(all[2]), pre, shapeOf(f.view, all[2]), "", &seal, inter(cs, all[2]))

	// repeated IR: the same IR certified again at a later root round.
	rep := f.build("a", f.round+3, q, false).get(1, "")
	g.ok("cert.repeat-ir.ok", fam, opUC, "repeat UC: identical input record under a later seal", one(rep), pre, shapeOf(f.view, rep), "", &rep.seal, nil)

	// distinct valid quorum subsets of the same statement.
	subA := f.build("a", f.round, f.vals[:3], false).get(1, "")
	subB := f.build("a", f.round, f.vals[1:], false).get(1, "")
	g.ok("cert.subset-a.ok", fam, opUC, "quorum subset {0,1,2}", one(subA), pre, shapeOf(f.view, subA), "", &subA.seal, nil)
	g.ok("cert.subset-b.ok", fam, opUC, "quorum subset {1,2,3}", one(subB), pre, shapeOf(f.view, subB), "", &subB.seal, nil)
	g.ok("cert.shared.mixed-subsets.false", fam, opShared, "shared call whose seals carry different quorum subsets",
		newRequest(f.view.cbor(), claimOf(subA), claimOf(cs.get(2, "0")), claimOf(f.build("a", f.round, f.vals[1:], false).get(3, ""))).wire(), pre,
		shapeOf(f.view, subA, cs.get(2, "0"), cs.get(3, "")), "ErrSealMismatch", nil, nil)

	// unequal signature counts across the seals: the call is false either way, and the vectors pin the provisional
	// gas count (S is the first claim's signature-map size, O6) in both orders.
	full4 := f.build("a", f.round, f.vals, false)
	few, many := claimOf(subA), claimOf(full4.get(3, ""))
	g.ok("cert.shared.sigcount-3-4.false", fam, opShared, "seals with 3 then 4 signatures: S is the first claim's 3",
		newRequest(f.view.cbor(), few, many).wire(), pre, shapeOf(f.view, subA, full4.get(3, "")), "ErrSealMismatch", nil, nil)
	g.ok("cert.shared.sigcount-4-3.false", fam, opShared, "seals with 4 then 3 signatures: S is the first claim's 4",
		newRequest(f.view.cbor(), claimOf(full4.get(1, "")), claimOf(f.build("a", f.round, f.vals[:3], false).get(3, ""))).wire(), pre,
		shapeOf(f.view, full4.get(1, ""), f.build("a", f.round, f.vals[:3], false).get(3, "")), "ErrSealMismatch", nil, nil)

	// single perturbations.
	reseal := func(mod func(*sealSpec)) ucSpec {
		x := u
		mod(&x.seal)
		x.seal.signWith(q, false)
		return x
	}
	bad := func(id, desc, want string, x ucSpec, c claimSpec) {
		g.ok(id, fam, opUC, desc, newRequest(f.view.cbor(), c).wire(), pre, shapeOf(f.view, x), want, nil, nil)
	}
	x := reseal(func(s *sealSpec) { s.network = 4 })
	bad("cert.neg.network", "seal network changed and re-signed", "ErrNetwork", x, claimOf(x))
	c := claimOf(u)
	c.part = 2
	bad("cert.neg.partition", "claim partition differs from the certificate", "ErrPartition", u, c)
	c = claimOf(cs.get(2, "0"))
	c.shardWire = shardBits("1")
	bad("cert.neg.shard-bit", "claim shard bit flipped", "ErrShard", cs.get(2, "0"), c)
	c = claimOf(u)
	c.conf = flip32(c.conf)
	bad("cert.neg.config", "claim shard configuration hash flipped", "ErrShardConf", u, c)
	x = u
	x.tr = flip32(x.tr)
	c = claimOf(u)
	c.uc = x.cbor()
	bad("cert.neg.trhash", "TRHash flipped inside the certificate", "ErrTreeRoot", x, c)
	x = u
	x.ir.state = flip(x.ir.state, 0)
	bad("cert.neg.ir-state", "IR state hash flipped inside the certificate", "ErrTreeRoot", x, claimOf(x))
	c = claimOf(u)
	c.stateRoot = flip32(c.stateRoot)
	bad("cert.neg.expected-state", "expectedStateRoot flipped", "ErrStateRoot", u, c)
	c = claimOf(u)
	c.irHash = flip32(c.irHash)
	bad("cert.neg.expected-ir", "expectedIRHash flipped", "ErrIRHash", u, c)
	x = u
	x.seal.root = flip32(x.seal.root)
	bad("cert.neg.root", "seal tree root flipped (unsigned)", "ErrTreeRoot", x, claimOf(x))
	x = reseal(func(s *sealSpec) { s.epoch = 6 })
	bad("cert.neg.epoch", "seal epoch changed and re-signed", "ErrSealEpoch", x, claimOf(x))
	x = u
	x.seal.timestamp++
	bad("cert.neg.signed-byte", "one signed seal byte changed after signing", "ErrSigInvalid", x, claimOf(x))
	x = u
	x.seal.sigs = append([]entry{}, u.seal.sigs...)
	other := makeValidator(seed, "intruder-key")
	x.seal.sigs[0] = entry{u.seal.sigs[0].key, other.sign(u.seal.sigBytes(), false)}
	bad("cert.neg.signer-key", "a signature made by a key other than the named member's", "ErrSigInvalid", x, claimOf(x))
	rawReq, rawUC := rawConcatRequest(f, cs, q)
	g.ok("cert.neg.raw-concat-fold", fam, opUC, "shard fold computed as raw SHA256(left||right) instead of CBOR operands", rawReq, pre, shapeOf(f.view, rawUC), "ErrTreeRoot", nil, nil)
}

// rawConcatRequest builds a UC for shard 2/0 whose unicity tree was built from
// a shard root folded with raw concatenation.
func rawConcatRequest(f *fixture, cs *certSet, q []validator) ([]byte, ucSpec) {
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
	return newRequest(f.view.cbor(), claimOf(u)).wire(), u
}
