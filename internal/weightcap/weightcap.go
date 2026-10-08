// Package weightcap holds the one profile constant that bounds a committee's committed weight.
//
// The weighted leader selector (root-wrr-v1) is periodic with period W/gcd(weights), so a bounded total committed weight W bounds its
// whole schedule to a table of at most B entries (design: briefs/leader-lookup.md). B is therefore a single profile constant, enforced
// at every admission point before a weight is committed, in Go, ureth and the contracts alike. It is not a per-role or per-format
// knob: a committed context with a larger total would halt the root at activation or restart, so it is refused before it commits.
package weightcap

// B is the largest total committed (assigned) weight of a root or coupled EVM committee: 65,536. A member's weight is bounded by B too
// (it cannot exceed the total).
const B uint64 = 1 << 16

// MaxMembers is the largest committee the selector supports (the Q4 envelope). The coupled root/EVM format keeps its own, smaller limit
// of 64 members; this one is the selector's own bound and is not a reason to widen that format.
const MaxMembers = 100
