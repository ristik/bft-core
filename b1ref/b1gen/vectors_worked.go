package b1gen

import "fmt"

// worked: the contract's worked budget cases (section 5), gas.worked.a{1,4,8,16}.n{4,16}.{shared,distinct_epoch}, as signed,
// canonical batches with their actual byte lengths: one aggregation partition (1) of sixteen shards at depth four, one Unicity-tree
// step per anchor (a second partition, 2, makes the tree), every member of an N-member committee signing each distinct seal.
// Shared: E = S = 1, Q = N. Distinct: E = S = A, Q = N*A. K = A, P = 5*A. The registry holds sixteen consecutive epochs of the same
// committee, so the distinct cases draw one epoch per anchor.
func (g *gen) worked(seed string) {
	const fam = "Gas/resources"
	shards := []string{}
	for i := 0; i < 16; i++ {
		shards = append(shards, fmt.Sprintf("%04b", i))
	}
	for _, n := range []int{4, 16} {
		base := newFixture(fmt.Sprintf("%s/worked-n%d", seed, n), n)
		base.scheme = map[uint32][]string{1: shards, 2: {""}}
		p := base.registryBase()
		p.GenesisEpoch, p.ImportedTip, p.Origin, p.ClockRound = 0, 15, 15, 20_000
		for e := uint64(0); e < 16; e++ {
			end := uint64(0)
			if e < 15 {
				end = 1000 * (e + 2)
			}
			p.Epochs = append(p.Epochs, base.epochWords(base.authority, e, 1000*(e+1), end, e == 0))
		}
		at := func(e uint64, shard string) claimSpec {
			f := *base
			f.epoch = e
			return claimOf(f.build("worked", 1000*(e+1)+500, f.vals, false).get(1, shard))
		}
		for _, a := range []int{1, 4, 8, 16} {
			var shared, distinct []claimSpec
			for i := 0; i < a; i++ {
				shared = append(shared, at(15, shards[i]))
				distinct = append(distinct, at(uint64(i), shards[i]))
			}
			g.ok(fmt.Sprintf("gas.worked.a%d.n%d.shared", a, n), fam, fmt.Sprintf("worked budget case: %d anchors, %d signers, one shared seal", a, n), req(shared...), p, "", nil, nil)
			g.ok(fmt.Sprintf("gas.worked.a%d.n%d.distinct_epoch", a, n), fam, fmt.Sprintf("worked budget case: %d anchors, %d signers, one seal per epoch", a, n), req(distinct...), p, "", nil, nil)
		}
	}
}
