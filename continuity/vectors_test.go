package continuity

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// The vectors are the contract between this reference and unicity-pos-contracts' Continuity library: the same committees, the same
// policy, and the measured quantities and failed predicates both must report. The Go package owns them; the contracts repository keeps
// a copy under test/p85/fixtures/continuity-vectors.json and checks its Solidity port against every case.
//
//	CONTINUITY_WRITE_VECTORS=continuity/testdata/continuity-vectors.json go test ./continuity -run TestVectors
const vectorsPath = "testdata/continuity-vectors.json"

type vMember struct {
	ID      uint64 `json:"id"`
	Binding uint64 `json:"binding"` // a label: equal labels are the same binding tuple
	Weight  uint64 `json:"weight"`
}

type vCase struct {
	Name   string    `json:"name"`
	Old    []vMember `json:"old"`
	New    []vMember `json:"new"`
	MaxM   uint64    `json:"maxM"`
	DistN  uint64    `json:"distNum"`
	DistD  uint64    `json:"distDen"`
	Result vResult   `json:"result"`
	// Invalid names the committee that cannot be judged ("predecessor" or "successor", empty otherwise), in which case the result is zero.
	// Every field is always present: the Solidity test decodes the whole file with one parseJson.
	Invalid string `json:"invalid"`
}

type vResult struct {
	Replaced     uint64 `json:"replaced"`
	Removed      uint64 `json:"removed"`
	Added        uint64 `json:"added"`
	M            uint64 `json:"m"`
	UnchangedOld uint64 `json:"unchangedOld"`
	UnchangedNew uint64 `json:"unchangedNew"`
	TotalOld     uint64 `json:"totalOld"`
	TotalNew     uint64 `json:"totalNew"`
	DistanceNum  string `json:"distanceNumerator"`
	// Failed are the predicates that fail: bit 0 membership, bit 1 turnover, bit 2 weight distance, bit 3 overlap.
	Failed uint8 `json:"failed"`
}

func toMembers(ms []vMember) []Member {
	out := make([]Member, 0, len(ms))
	for _, m := range ms {
		var id StakingID
		for i := 0; i < 8; i++ {
			id[31-i] = byte(m.ID >> (8 * i))
		}
		out = append(out, Member{ID: id, RootNodeID: fmt.Sprintf("r%d", m.Binding), RootKey: []byte{1, byte(m.Binding), byte(m.Binding >> 8)},
			EVMNodeID: fmt.Sprintf("e%d", m.Binding), EVMKey: []byte{2, byte(m.Binding), byte(m.Binding >> 8)}, Weight: m.Weight})
	}
	return out
}

func evaluate(c vCase) vCase {
	if c.Old == nil {
		c.Old = []vMember{}
	}
	if c.New == nil {
		c.New = []vMember{}
	}
	o, s := toMembers(c.Old), toMembers(c.New)
	r, err := Check(o, s, Policy{MaxM: c.MaxM, MaxDistNum: c.DistN, MaxDistDen: c.DistD})
	switch {
	case errors.Is(err, ErrCommittee):
		if _, _, ierr := index(o); ierr != nil {
			c.Invalid = "predecessor"
		} else {
			c.Invalid = "successor"
		}
	default:
		var failed uint8
		for bit, target := range []error{ErrMembership, ErrTurnover, ErrWeightDistance, ErrOverlap} {
			if errors.Is(err, target) {
				failed |= 1 << bit
			}
		}
		c.Result = vResult{Replaced: r.Replaced, Removed: r.Removed, Added: r.Added, M: r.M, UnchangedOld: r.UnchangedOld, UnchangedNew: r.UnchangedNew,
			TotalOld: r.TotalOld, TotalNew: r.TotalNew, DistanceNum: r.DistanceNumerator.String(), Failed: failed}
	}
	return c
}

func equal(n int, w uint64, binding func(i int) uint64) []vMember {
	out := make([]vMember, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, vMember{ID: uint64(i), Binding: binding(i), Weight: w})
	}
	return out
}

func same(i int) uint64 { return uint64(i) }

func cases() []vCase {
	def := func(name string, o, s []vMember) vCase {
		return vCase{Name: name, Old: o, New: s, MaxM: 4, DistN: 1, DistD: 4}
	}
	var out []vCase
	// no change
	out = append(out, def("identical committees of ten", equal(10, 5, same), equal(10, 5, same)))
	// one equal-weight replacement of ten: M=2, strict 3*1<10, D=0.1+0.1... passes at the default 1/4, overlap 9/10
	swap := equal(10, 5, same)
	swap[9] = vMember{ID: 11, Binding: 11, Weight: 5}
	out = append(out, def("one identity swapped of ten", equal(10, 5, same), swap))
	// two swaps of ten: M=4, change fraction 2/10, D = 4*0.1 = 0.4 > 1/4
	two := equal(10, 5, same)
	two[8], two[9] = vMember{ID: 11, Binding: 11, Weight: 5}, vMember{ID: 12, Binding: 12, Weight: 5}
	out = append(out, def("two identities swapped of ten (distance exceeds the default)", equal(10, 5, same), two))
	wide := def("two identities swapped of ten under a wider distance", equal(10, 5, same), two)
	wide.DistN, wide.DistD = 1, 2
	out = append(out, wide)
	// strict boundary: three of nine is exactly one third
	nine := equal(9, 1, same)
	third := equal(9, 1, same)
	for i := 6; i < 9; i++ {
		third[i] = vMember{ID: uint64(100 + i), Binding: uint64(100 + i), Weight: 1}
	}
	loose := def("three of nine replaced: exactly one third", nine, third)
	loose.MaxM, loose.DistN, loose.DistD = 100, 1, 1
	out = append(out, loose)
	two9 := equal(9, 1, same)
	for i := 7; i < 9; i++ {
		two9[i] = vMember{ID: uint64(100 + i), Binding: uint64(100 + i), Weight: 1}
	}
	below := def("two of nine replaced: below one third", nine, two9)
	below.MaxM, below.DistN, below.DistD = 100, 1, 1
	out = append(out, below)
	// binding replacement of a shared identity counts once on each side
	rebind := equal(10, 5, same)
	rebind[0].Binding = 77
	out = append(out, def("one shared identity rebound", equal(10, 5, same), rebind))
	rebindAll := equal(10, 5, same)
	for i := range rebindAll {
		rebindAll[i].Binding = uint64(500 + i)
	}
	out = append(out, def("every binding replaced", equal(10, 5, same), rebindAll))
	// shrink and grow
	out = append(out, def("shrink from ten to nine", equal(10, 5, same), equal(9, 5, same)))
	out = append(out, def("grow from nine to ten", equal(9, 5, same), equal(10, 5, same)))
	// weight changes only
	reweigh := equal(10, 5, same)
	reweigh[0].Weight, reweigh[1].Weight = 9, 1
	out = append(out, def("weights shift between two members", equal(10, 5, same), reweigh))
	// overlap boundary: unchanged weight exactly two thirds of the new committee fails, just above passes
	heavy := []vMember{{1, 1, 4}, {2, 2, 1}, {3, 3, 1}}
	out = append(out, def("one heavy member replaced", heavy, []vMember{{1, 1, 4}, {2, 2, 1}, {4, 4, 1}}))
	exact := []vMember{{1, 1, 2}, {2, 2, 2}, {3, 3, 2}}
	out = append(out, def("unchanged weight exactly two thirds", exact, []vMember{{1, 1, 2}, {2, 2, 2}, {4, 4, 2}}))
	// the boundary on each side alone: old exactly two thirds with the new committee well above, and the mirror
	loose2 := func(name string, o, s []vMember) vCase {
		c := def(name, o, s)
		c.MaxM, c.DistN, c.DistD = 100, 1, 1
		return c
	}
	out = append(out, loose2("unchanged weight exactly two thirds of the old committee only",
		[]vMember{{1, 1, 2}, {2, 2, 2}, {3, 3, 2}}, []vMember{{1, 1, 2}, {2, 2, 2}, {4, 4, 1}}))
	out = append(out, loose2("unchanged weight exactly two thirds of the new committee only",
		[]vMember{{1, 1, 2}, {2, 2, 2}, {3, 3, 1}}, []vMember{{1, 1, 2}, {2, 2, 2}, {4, 4, 2}}))
	// invalid committees
	out = append(out, def("empty predecessor", nil, equal(3, 1, same)))
	out = append(out, def("empty successor", equal(3, 1, same), nil))
	out = append(out, def("zero weight in the successor", equal(3, 1, same), []vMember{{1, 1, 1}, {2, 2, 0}, {3, 3, 1}}))
	out = append(out, def("zero weight in the predecessor", []vMember{{1, 1, 0}, {2, 2, 1}}, equal(3, 1, same)))
	out = append(out, def("duplicate identity in the successor", equal(3, 1, same), []vMember{{1, 1, 1}, {2, 2, 1}, {2, 2, 1}}))
	// large weights: products exceed 64 bits
	big := []vMember{{1, 1, 1 << 62}, {2, 2, 1 << 62}, {3, 3, 1 << 62}, {4, 4, 1 << 62}}
	bigNew := []vMember{{1, 1, 1 << 62}, {2, 2, 1 << 62}, {3, 3, 1 << 62}, {5, 5, 1 << 62}}
	wideBig := def("weights near 2^62", big, bigNew)
	wideBig.MaxM, wideBig.DistN, wideBig.DistD = 100, 1, 1
	out = append(out, wideBig)
	// a zero-denominator policy is not a case; M budget of zero
	zero := def("membership budget of zero with a swap", equal(10, 5, same), swap)
	zero.MaxM = 0
	out = append(out, zero)

	// randomized: committees of up to 24 over a pool of 40 identities with weights up to 40 and a few binding changes
	rng := rand.New(rand.NewSource(85))
	for n := 0; n < 400; n++ {
		draw := func() []vMember {
			size := 1 + rng.Intn(24)
			picked := rng.Perm(40)[:size]
			ms := make([]vMember, 0, size)
			for _, p := range picked {
				ms = append(ms, vMember{ID: uint64(p + 1), Binding: uint64(p + 1), Weight: uint64(1 + rng.Intn(40))})
			}
			sortMembers(ms)
			return ms
		}
		o := draw()
		s := draw()
		// keep most of the old committee so the predicates are not all trivially failing
		if rng.Intn(3) != 0 && len(o) > 2 {
			s = append([]vMember(nil), o...)
			for k := rng.Intn(4); k > 0 && len(s) > 1; k-- {
				switch rng.Intn(4) {
				case 0:
					s = s[: len(s)-1 : len(s)-1]
				case 1:
					s = append(s, vMember{ID: uint64(100 + rng.Intn(50)), Binding: uint64(100 + rng.Intn(50)), Weight: uint64(1 + rng.Intn(40))})
				case 2:
					s[rng.Intn(len(s))].Binding += 1000
				default:
					s[rng.Intn(len(s))].Weight = uint64(1 + rng.Intn(40))
				}
			}
			s = dedupe(s)
			sortMembers(s)
		}
		c := vCase{Name: fmt.Sprintf("random %d", n), Old: o, New: s, MaxM: uint64(rng.Intn(7)), DistN: uint64(rng.Intn(3)), DistD: uint64(1 + rng.Intn(6))}
		out = append(out, c)
	}
	return out
}

func sortMembers(ms []vMember) {
	for i := 1; i < len(ms); i++ {
		for j := i; j > 0 && ms[j-1].ID > ms[j].ID; j-- {
			ms[j-1], ms[j] = ms[j], ms[j-1]
		}
	}
}

func dedupe(ms []vMember) []vMember {
	seen := map[uint64]bool{}
	out := ms[:0:0]
	for _, m := range ms {
		if !seen[m.ID] {
			seen[m.ID] = true
			out = append(out, m)
		}
	}
	return out
}

func TestVectors(t *testing.T) {
	var all []vCase
	for _, c := range cases() {
		all = append(all, evaluate(c))
	}
	raw, err := json.MarshalIndent(map[string]any{"description": "committee continuity: Go reference results for the Solidity port", "cases": all}, "", " ")
	require.NoError(t, err)
	raw = append(raw, '\n')
	if out := os.Getenv("CONTINUITY_WRITE_VECTORS"); out != "" {
		require.NoError(t, os.WriteFile(out, raw, 0o644))
	}
	committed, err := os.ReadFile(vectorsPath)
	require.NoError(t, err, "run with CONTINUITY_WRITE_VECTORS=%s to create it", vectorsPath)
	require.JSONEq(t, string(committed), string(raw), "the committed vectors are the reference's current output")

	// the cases cover every outcome the port must reproduce
	var invalid, passing int
	failed := map[uint8]int{}
	for _, c := range all {
		switch {
		case c.Invalid != "":
			invalid++
		case c.Result.Failed == 0:
			passing++
		default:
			failed[c.Result.Failed]++
		}
	}
	require.Positive(t, invalid)
	require.Positive(t, passing)
	for bit := uint8(0); bit < 4; bit++ {
		seen := false
		for mask, n := range failed {
			if mask&(1<<bit) != 0 && n > 0 {
				seen = true
			}
		}
		require.True(t, seen, "predicate bit %d fails somewhere", bit)
	}
}
