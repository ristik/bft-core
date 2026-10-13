package b1gen

import (
	"fmt"
	"sort"
)

// fixture is one explicit scenario: validators, a registry authority for one epoch, a
// sharded partition set and its unicity tree, all derived from the seed.
type fixture struct {
	seed      string
	network   uint16
	epoch     uint64
	origin    uint64
	clock     uint64 // O
	round     uint64 // seal root round of the default certificate set
	vals      []validator
	body      [32]byte
	authority authoritySpec
	scheme    map[uint32][]string // nil: the default scheme
	states    map[string][]byte   // input record state hash by ucKey, overriding the derived one
}

// scheme maps partition to its shard scheme.
var scheme = map[uint32][]string{1: {""}, 2: {"0", "1"}, 3: {""}, 4: {""}, 5: {""}, 6: {""}, 7: {""}}

func newFixture(seed string, nVals int) *fixture {
	f := &fixture{seed: seed, network: 3, epoch: 7, origin: 7, clock: 1000, round: 990}
	for i := 0; i < nVals; i++ {
		f.vals = append(f.vals, makeValidator(seed, fmt.Sprintf("node%02d", i)))
	}
	f.body = newDRBG(seed, "body").hash()
	f.authority = authorityOf(f.network, f.epoch, 2, f.body, f.vals)
	return f
}

// pre is the default registry: a fresh genesis whose genesis epoch is the fixture's epoch (7), open from round 900, usable, O
// 1000.
func (f *fixture) pre() PreState { return f.preForAuthority(f.authority) }

func (f *fixture) preForAuthority(v authoritySpec) PreState {
	p := f.registryBase()
	p.GenesisEpoch, p.ImportedTip, p.Origin = f.epoch, f.epoch, f.origin
	p.Epochs = []EpochWords{f.epochWords(v, f.epoch, 900, 0, true)}
	return p
}

// registryBase is the common words of a ready registry, without entries.
func (f *fixture) registryBase() PreState {
	d := newDRBG(f.seed, "registry")
	gc, ph := d.hash(), d.hash()
	return PreState{Network: f.network, Phase: 2, GenesisCommitment: hex32(gc), PinnedGenesisCommitment: hex32(gc), ProfileHash: hex32(ph), PinnedProfileHash: hex32(ph),
		OriginReady: true, ClockRound: f.clock}
}

// epochWords is the entry of epoch e for an authority: the genesis kind for the genesis epoch, a handoff otherwise.
func (f *fixture) epochWords(v authoritySpec, e, start, end uint64, genesis bool) EpochWords {
	d := newDRBG(f.seed, fmt.Sprintf("entry/%d", e))
	w := EpochWords{Epoch: e, BodyKind: 2, BodyID: hex32(v.bodyID), ActivationCommitID: hex32(d.hash()), Start: start, End: end, HasEnd: end != 0,
		SigningScheme: 1, SigningConfigHash: hex32(d.hash())}
	if genesis {
		w.BodyKind, w.ActivationCommitID = 1, hex32([32]byte{})
	}
	for _, m := range v.members {
		w.Members = append(w.Members, MemberWords{NodeID: m.id, Key: hx(m.pub), Weight: m.weight})
	}
	return w
}

// certSet is the unsigned-then-signed certificates of every (partition, shard).
type certSet struct {
	ucs       map[string]*ucSpec
	treeRoot  [32]byte
	shardRoot map[uint32][32]byte
}

func ucKey(part uint32, shard string) string { return fmt.Sprintf("%d/%s", part, shard) }

// build constructs the trees for an IR variant and signs one common seal at
// the given root round with the given signers.
func (f *fixture) build(variant string, round uint64, signers []validator, withV bool) *certSet {
	cs := &certSet{ucs: map[string]*ucSpec{}, shardRoot: map[uint32][32]byte{}}
	sch := f.scheme
	if sch == nil {
		sch = scheme
	}
	parts := make([]uint32, 0, len(sch))
	for p := range sch {
		parts = append(parts, p)
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i] < parts[j] })

	var leaves []imtLeaf
	trees := map[uint32]shardTree{}
	for _, p := range parts {
		st := shardTree{leaves: map[string][32]byte{}}
		for _, sh := range sch[p] {
			r := newDRBG(f.seed, fmt.Sprintf("ir/%s/%d/%s", variant, p, sh))
			ir := irSpec{
				round: 5, epoch: 1, prev: r.bytes32(), state: r.bytes32(), summary: r.bytes32()[:8],
				timestamp: genesisTime + 1000, block: r.bytes32(), fees: 12, et: r.bytes32(),
			}
			if s, ok := f.states[ucKey(p, sh)]; ok {
				ir.state = s
			}
			u := &ucSpec{part: p, shard: sh, ir: ir}
			copy(u.tr[:], r.bytes32())
			copy(u.conf[:], r.bytes32())
			cs.ucs[ucKey(p, sh)] = u
			st.leaves[sh] = shardLeaf(ir, u.tr, u.conf)
		}
		trees[p] = st
		sr := st.root()
		cs.shardRoot[p] = sr
		var l imtLeaf
		l.key = [4]byte{byte(p >> 24), byte(p >> 16), byte(p >> 8), byte(p)}
		l.data = sum(cBytes(sr[:]))
		leaves = append(leaves, l)
	}
	root := imtBuild(leaves)
	cs.treeRoot = root.hash

	seal := sealSpec{network: f.network, round: round, epoch: f.epoch, timestamp: genesisTime + 5000 + round,
		prev: newDRBG(f.seed, "prev/"+variant).hash(), root: root.hash}
	seal.signWith(signers, withV)
	for _, p := range parts {
		var key [4]byte
		key = [4]byte{byte(p >> 24), byte(p >> 16), byte(p >> 8), byte(p)}
		for _, sh := range sch[p] {
			u := cs.ucs[ucKey(p, sh)]
			u.shardSibs = trees[p].siblings(sh)
			u.steps = root.path(key)
			u.seal = seal
		}
	}
	return cs
}

func (c *certSet) get(part uint32, shard string) ucSpec { return *c.ucs[ucKey(part, shard)] }
