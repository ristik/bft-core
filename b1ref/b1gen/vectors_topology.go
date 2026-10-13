package b1gen

import "fmt"

// topology: one aggregation partition at several shard depths, and a historical prefix change whose parent and child shards meet in
// one batch (contract section 6; vectors plan family E). Each proof is checked against its own certified shard path.
func (g *gen) topology(seed string) {
	const fam = "Topology"
	h := NewHistory(seed, 0)
	pre := h.Pre()
	shards := func(depth int) []string {
		out := []string{""}
		for d := 0; d < depth; d++ {
			var next []string
			for _, s := range out {
				next = append(next, s+"0", s+"1")
			}
			out = next
		}
		return out
	}
	at := func(s Seal, sch map[uint32][]string, shard string) claimSpec {
		hh := *h
		f := *h.f
		f.scheme = sch
		hh.f = &f
		return claimOf(hh.uc(s, 9, shard))
	}
	for _, depth := range []int{2, 3, 5} {
		sch := map[uint32][]string{1: {""}, 9: shards(depth)}
		all := shards(depth)
		s := hseal(8, 9000+uint64(depth), "topo")
		picks := []claimSpec{at(s, sch, all[0]), at(s, sch, all[len(all)/2+1]), at(s, sch, all[len(all)-1])}
		g.ok(fmt.Sprintf("topo.depth-%d.ok", depth), fam, fmt.Sprintf("%d shards (depth %d) of one aggregation partition, three of them under one seal", len(all), depth),
			req(picks...), pre, "", nil, nil)
	}
	before := map[uint32][]string{1: {""}, 9: shards(1)}
	after := map[uint32][]string{1: {""}, 9: shards(2)}
	old := at(hseal(2, 2500, "split"), before, "0")
	young := at(hseal(6, 6500, "split"), after, "01")
	g.ok("topo.prefix-change.ok", fam, "shard 0 before a split (epoch 2) and its child 01 after it (epoch 6) in one batch", req(old, young), pre, "", nil, nil)
	wrong := young
	wrong.shardWire = shardBits("0")
	g.ok("topo.prefix-change.parent-claimed", fam, "the child's certificate claimed as the parent shard", req(old, wrong), pre, "ErrShard", nil, nil)
}
