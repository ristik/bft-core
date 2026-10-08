package continuity

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// This file is a reference model of the ranking and bounded greedy election of design v5 section 5, written independently of the
// Solidity port and judged by the production continuity rule (Check). It is test code: the root never recomputes an election, it only
// verifies the continuity of the committee the election chose. The vectors it writes are what unicity-pos-contracts' Selection library
// reproduces case by case.
//
//	SELECTION_WRITE_VECTORS=testdata/selection-vectors.json go test ./continuity -run TestSelectionVectors

const selectionVectorsPath = "testdata/selection-vectors.json"

// Reasons an election finds no candidate.
const (
	reasonNone = iota
	reasonInvalidProfile
	reasonCardinality
	reasonMembershipChurn
	reasonWeightChurn
)

type selConfig struct {
	NMin    uint64 `json:"nMin"`
	NTarget uint64 `json:"nTarget"`
	NMax    uint64 `json:"nMax"`
	MaxM    uint64 `json:"maxM"`
	DistNum uint64 `json:"distNum"`
	DistDen uint64 `json:"distDen"`
}

type selCase struct {
	Name     string    `json:"name"`
	Old      []vMember `json:"old"`
	Eligible []vMember `json:"eligible"`
	Config   selConfig `json:"config"`
	Reason   uint8     `json:"reason"`
	Chosen   []uint64  `json:"chosen"`
}

// better is the strict rank order: descending weight, then ascending identity.
func better(a, b vMember) bool {
	if a.Weight != b.Weight {
		return a.Weight > b.Weight
	}
	return a.ID < b.ID
}

func churnReason(failed error) uint8 {
	switch {
	case errors.Is(failed, ErrMembership) || errors.Is(failed, ErrTurnover):
		return reasonMembershipChurn
	default:
		return reasonWeightChurn
	}
}

// elect is the model: it returns the chosen identities ascending, or a reason.
func elect(c selCase) ([]uint64, uint8) {
	cfg := c.Config
	if cfg.NMin < 1 || cfg.NTarget < cfg.NMin || cfg.NMax < cfg.NTarget || cfg.NMax > 32 || cfg.DistDen == 0 {
		return nil, reasonInvalidProfile
	}
	policy := Policy{MaxM: cfg.MaxM, MaxDistNum: cfg.DistNum, MaxDistDen: cfg.DistDen}
	old := map[uint64]bool{}
	for _, m := range c.Old {
		old[m.ID] = true
	}
	ranked := append([]vMember(nil), c.Eligible...)
	sort.Slice(ranked, func(i, j int) bool { return better(ranked[i], ranked[j]) })
	if uint64(len(ranked)) < cfg.NMin {
		return nil, reasonCardinality
	}
	// the seed: the best eligible incumbents up to the target, then the best outsiders up to it
	in := map[uint64]bool{}
	for _, m := range ranked {
		if old[m.ID] && uint64(len(in)) < cfg.NTarget {
			in[m.ID] = true
		}
	}
	for _, m := range ranked {
		if !old[m.ID] && uint64(len(in)) < cfg.NTarget {
			in[m.ID] = true
		}
	}
	committee := func(sel map[uint64]bool) []Member {
		var ms []vMember
		for _, m := range c.Eligible {
			if sel[m.ID] {
				ms = append(ms, m)
			}
		}
		sort.Slice(ms, func(i, j int) bool { return ms[i].ID < ms[j].ID })
		return toMembers(ms)
	}
	oldMembers := toMembers(c.Old)
	if _, err := Check(oldMembers, committee(in), policy); err != nil {
		return nil, churnReason(err)
	}
	// each remaining outsider, once, in rank order
	for _, x := range ranked {
		if old[x.ID] || in[x.ID] {
			continue
		}
		var lowest *vMember
		for i := range ranked {
			m := ranked[i]
			if old[m.ID] && in[m.ID] && (lowest == nil || better(*lowest, m)) {
				lowest = &ranked[i]
			}
		}
		if lowest == nil || !better(x, *lowest) {
			continue
		}
		trial := map[uint64]bool{x.ID: true}
		for id := range in {
			if id != lowest.ID {
				trial[id] = true
			}
		}
		if _, err := Check(oldMembers, committee(trial), policy); err == nil {
			in = trial
		}
	}
	var out []uint64
	for id := range in {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, reasonNone
}

func sel(id, binding, weight uint64) vMember {
	return vMember{ID: id, Binding: binding, Weight: weight}
}

func uniform(from, to, weight uint64) []vMember {
	var out []vMember
	for i := from; i <= to; i++ {
		out = append(out, sel(i, i, weight))
	}
	return out
}

func selectionCases() []selCase {
	dev := selConfig{NMin: 4, NTarget: 10, NMax: 32, MaxM: 4, DistNum: 1, DistDen: 4}
	var out []selCase
	add := func(name string, old, eligible []vMember, cfg selConfig) {
		// the snapshot lists its identities ascending by StakingID
		eligible = append([]vMember(nil), eligible...)
		sortMembers(eligible)
		out = append(out, selCase{Name: name, Old: old, Eligible: eligible, Config: cfg})
	}
	ten := uniform(1, 10, 5)
	add("an unchanged committee is re-elected", ten, ten, dev)
	// an outsider with more weight replaces the weakest incumbent
	richer := append(append([]vMember{}, uniform(1, 9, 5)...), sel(10, 10, 4), sel(11, 11, 9))
	add("a richer outsider replaces the weakest incumbent", ten, richer, dev)
	// two richer outsiders: the budget lets only so much change
	two := append(append([]vMember{}, uniform(1, 8, 5)...), sel(9, 9, 3), sel(10, 10, 3), sel(11, 11, 9), sel(12, 12, 9))
	add("two richer outsiders against the churn budget", ten, two, dev)
	loose := dev
	loose.MaxM, loose.DistNum, loose.DistDen = 100, 1, 1
	add("two richer outsiders under a wide budget", ten, two, loose)
	// equal weight: the smaller id wins the tie; the outsider 0 outranks incumbent 10 only by id
	tie := append(uniform(1, 9, 5), sel(10, 10, 5), sel(11, 11, 5))
	add("equal weights: the larger incumbent id keeps its seat over a larger outsider id", ten, tie, dev)
	tieSmall := append([]vMember{sel(0, 100, 5)}, uniform(1, 10, 5)...)
	add("equal weights: an outsider with a smaller id outranks the largest incumbent id", ten, tieSmall, dev)
	// forced exits: incumbents not eligible
	exits := uniform(1, 8, 5)
	add("two incumbents are no longer eligible", ten, exits, dev)
	add("three incumbents are no longer eligible, filled by outsiders", ten, append(uniform(1, 7, 5), uniform(11, 13, 5)...), dev)
	// cardinality
	add("fewer eligible identities than the minimum", ten, uniform(1, 3, 5), dev)
	add("exactly the minimum", uniform(1, 4, 5), uniform(1, 4, 5), dev)
	// shrink: more eligible incumbents than the target
	shrinkCfg := dev
	shrinkCfg.NTarget = 8
	shrinkCfg.MaxM, shrinkCfg.DistNum, shrinkCfg.DistDen = 100, 1, 1
	add("target below the incumbent count trims the lowest ranks", ten, ten, shrinkCfg)
	// rebinding of a shared identity
	rebind := append([]vMember{sel(1, 77, 5)}, uniform(2, 10, 5)...)
	add("one shared identity rebinds", ten, rebind, dev)
	rebindAll := make([]vMember, 0, 10)
	for i := uint64(1); i <= 10; i++ {
		rebindAll = append(rebindAll, sel(i, 900+i, 5))
	}
	add("every binding replaced", ten, rebindAll, dev)
	// weights shift
	shift := uniform(1, 10, 5)
	shift[0].Weight, shift[9].Weight = 1, 9
	add("weights shift", ten, shift, dev)
	// a seed that fails: all outsiders richer than all incumbents
	flood := uniform(11, 20, 50)
	flood = append(flood, uniform(1, 10, 5)...)
	add("richer outsiders swamp the seed", ten, flood, dev)
	// invalid profiles
	bad := dev
	bad.NMin = 0
	add("minimum of zero", ten, ten, bad)
	bad = dev
	bad.NTarget = 3
	add("target below the minimum", ten, ten, bad)
	bad = dev
	bad.NMax = 33
	add("maximum above the ceiling", ten, ten, bad)
	bad = dev
	bad.DistDen = 0
	add("no distance denominator", ten, ten, bad)
	bad = dev
	bad.NMax = 8
	add("target above the maximum", ten, ten, bad)
	// a chain of trials: outsiders ranked just above incumbents, one after another
	chain := uniform(1, 10, 5)
	chain[0].Weight, chain[1].Weight, chain[2].Weight = 4, 4, 4
	chainElig := append(append([]vMember{}, chain...), sel(11, 11, 6), sel(12, 12, 6), sel(13, 13, 6))
	add("several outsiders contend for the weakest seats", chain, chainElig, loose)

	rng := rand.New(rand.NewSource(8585))
	for n := 0; n < 500; n++ {
		size := 6 + rng.Intn(9)
		perm := rng.Perm(30)
		var o []vMember
		for _, p := range perm[:size] {
			o = append(o, sel(uint64(p+1), uint64(p+1), uint64(1+rng.Intn(20))))
		}
		sortMembers(o)
		// the eligible snapshot: most incumbents survive, some leave, outsiders appear, weights and bindings drift
		var e []vMember
		for _, m := range o {
			if rng.Intn(14) == 0 {
				continue
			}
			if rng.Intn(4) == 0 {
				m.Weight = uint64(1 + rng.Intn(20))
			}
			if rng.Intn(30) == 0 {
				m.Binding += 1000
			}
			e = append(e, m)
		}
		for k := rng.Intn(5); k > 0; k-- {
			id := uint64(1 + rng.Intn(60))
			e = append(e, sel(id, id, uint64(1+rng.Intn(25))))
		}
		e = dedupe(e)
		sortMembers(e)
		cfg := selConfig{NMin: uint64(1 + rng.Intn(4)), NTarget: uint64(size - 1 + rng.Intn(4)), NMax: 32, MaxM: uint64(2 + rng.Intn(8)),
			DistNum: uint64(1 + rng.Intn(2)), DistDen: uint64(2 + rng.Intn(3))}
		out = append(out, selCase{Name: fmt.Sprintf("random %d", n), Old: o, Eligible: e, Config: cfg})
	}
	return out
}

func TestSelectionVectors(t *testing.T) {
	var all []selCase
	for _, c := range selectionCases() {
		if c.Old == nil {
			c.Old = []vMember{}
		}
		if c.Eligible == nil {
			c.Eligible = []vMember{}
		}
		chosen, reason := elect(c)
		c.Reason = reason
		c.Chosen = chosen
		if c.Chosen == nil {
			c.Chosen = []uint64{}
		}
		all = append(all, c)
	}
	raw, err := json.MarshalIndent(map[string]any{"description": "bounded greedy election: Go reference model results for the Solidity port", "cases": all}, "", " ")
	require.NoError(t, err)
	raw = append(raw, '\n')
	if out := os.Getenv("SELECTION_WRITE_VECTORS"); out != "" {
		require.NoError(t, os.WriteFile(out, raw, 0o644))
	}
	committed, err := os.ReadFile(selectionVectorsPath)
	require.NoError(t, err, "run with SELECTION_WRITE_VECTORS=%s", selectionVectorsPath)
	require.JSONEq(t, string(committed), string(raw))

	// the cases reach every outcome
	reasons := map[uint8]int{}
	changed := 0
	for _, c := range all {
		reasons[c.Reason]++
		if c.Reason == reasonNone {
			same := len(c.Chosen) == len(c.Old)
			for i := range c.Chosen {
				if !same || c.Chosen[i] != c.Old[i].ID {
					same = false
				}
			}
			if !same {
				changed++
			}
		}
	}
	for _, r := range []uint8{reasonNone, reasonInvalidProfile, reasonCardinality, reasonMembershipChurn, reasonWeightChurn} {
		require.Positive(t, reasons[r], "reason %d", r)
	}
	require.Greater(t, reasons[reasonNone], 150)
	require.Greater(t, changed, 60, "elections that change the committee are exercised")
	t.Logf("selection vectors: %d cases, outcomes %v, %d change the committee", len(all), reasons, changed)
}
