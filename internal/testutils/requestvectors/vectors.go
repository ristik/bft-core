// Package requestvectors holds the weighted and unit request-counting vectors of Q2 (briefs/q2-design-v2.md section 5,
// fixtures 1, 2 and 4) and an independent oracle, so the request buffer and proof verification are run through the same
// cases. The oracle shares no code with the production tally: it enumerates completions instead of applying M+U < Q.
package requestvectors

import "slices"

// Status is what a set of received requests proves.
type Status int

const (
	// Possible: no group has a quorum and one still can reach it.
	Possible Status = iota
	// Achieved: one group has weight of at least Q.
	Achieved
	// Impossible: no completion of the missing signers gives any group Q.
	Impossible
)

func (s Status) String() string { return [...]string{"possible", "achieved", "impossible"}[s] }

// Vote is one signer's request, in a group identified by name (requests of one group have equal IR and sizes).
type Vote struct{ Signer, Group string }

// Vector is a committee and the requests that may arrive from it.
type Vector struct {
	Name    string
	Weights map[string]uint64
	Votes   []Vote
}

// Total is W, the weight of every member.
func (v Vector) Total() (w uint64) {
	for _, x := range v.Weights {
		w += x
	}
	return w
}

// Threshold is floor(W/2)+1.
func (v Vector) Threshold() uint64 { return v.Total()/2 + 1 }

// Oracle is the status of the received votes, by brute force: the missing signers (every subset of them) join each
// group, existing or new, and quorum is possible if any such completion gives a group weight of Q or more.
func (v Vector) Oracle(received []Vote) Status {
	q := v.Threshold()
	got := map[string]uint64{}
	seen := map[string]bool{}
	for _, r := range received {
		got[r.Group] += v.Weights[r.Signer]
		seen[r.Signer] = true
	}
	for _, w := range got {
		if w >= q {
			return Achieved
		}
	}
	var missing []string
	for id := range v.Weights {
		if !seen[id] {
			missing = append(missing, id)
		}
	}
	slices.Sort(missing)
	groups := []string{"\x00new"} // a group nobody voted for yet
	for g := range got {
		groups = append(groups, g)
	}
	for _, g := range groups {
		for mask := 0; mask < 1<<len(missing); mask++ {
			sum := got[g]
			for i, id := range missing {
				if mask&(1<<i) != 0 {
					sum += v.Weights[id]
				}
			}
			if sum >= q {
				return Possible
			}
		}
	}
	return Impossible
}

// Winner is the group holding a quorum in the received votes, or "".
func (v Vector) Winner(received []Vote) string {
	got := map[string]uint64{}
	for _, r := range received {
		got[r.Group] += v.Weights[r.Signer]
	}
	for g, w := range got {
		if w >= v.Threshold() {
			return g
		}
	}
	return ""
}

func unit(ids ...string) map[string]uint64 {
	m := map[string]uint64{}
	for _, id := range ids {
		m[id] = 1
	}
	return m
}

// Vectors are the fixtures. All committees use signer ids "a".."g".
func Vectors() []Vector {
	skew := map[string]uint64{"a": 6, "b": 1, "c": 1, "d": 1}             // fixture 1: W=9 Q=5
	boundary := map[string]uint64{"a": 3, "b": 2, "c": 1, "d": 2, "e": 2} // fixture 2: W=10 Q=6
	vs := []Vector{
		{"skew: the heavy signer alone certifies", skew, []Vote{{"a", "X"}, {"b", "Y"}, {"c", "Y"}, {"d", "Z"}}},
		{"skew: three light identities cannot", skew, []Vote{{"b", "X"}, {"c", "X"}, {"d", "X"}}},
		{"skew: light identities without the heavy one are not impossible", skew, []Vote{{"b", "X"}, {"c", "Y"}, {"d", "Z"}}},
		{"skew: heavy and light disagree", skew, []Vote{{"a", "X"}, {"b", "Y"}, {"c", "Y"}, {"d", "Y"}}},
		{"boundary: strict, X3 Y2+1 Z2", boundary, []Vote{{"a", "X"}, {"b", "Y"}, {"c", "Y"}, {"d", "Z"}}},
		{"boundary: equality, X3 Y2+2 Z1 is still possible", boundary, []Vote{{"a", "X"}, {"b", "Y"}, {"d", "Y"}, {"c", "Z"}}},
		{"boundary: the last weight-2 signer completes Y", boundary, []Vote{{"a", "X"}, {"b", "Y"}, {"d", "Y"}, {"c", "Z"}, {"e", "Y"}}},
		{"boundary: all five apart", boundary, []Vote{{"a", "X"}, {"b", "Y"}, {"c", "Z"}, {"d", "W"}, {"e", "V"}}},
		{"aggregator: four unit keys need three", unit("a", "b", "c", "d"), []Vote{{"a", "X"}, {"b", "X"}, {"c", "X"}, {"d", "Y"}}},
		{"aggregator: one key never certifies", unit("a", "b", "c", "d"), []Vote{{"a", "X"}, {"b", "Y"}, {"c", "Z"}}},
	}
	// fixture 4: all-one sets of every size, with the splits that matter
	for n := 1; n <= 6; n++ {
		ids := []string{"a", "b", "c", "d", "e", "f"}[:n]
		same, split, apart := []Vote{}, []Vote{}, []Vote{}
		for i, id := range ids {
			same = append(same, Vote{id, "X"})
			g := "X"
			if i%2 == 1 {
				g = "Y"
			}
			split = append(split, Vote{id, g})
			apart = append(apart, Vote{id, string(rune('A' + i))})
		}
		for _, c := range []struct {
			name  string
			votes []Vote
		}{{"same", same}, {"split", split}, {"apart", apart}} {
			vs = append(vs, Vector{"unit n=" + string(rune('0'+n)) + " " + c.name, unit(ids...), c.votes})
		}
	}
	return vs
}
