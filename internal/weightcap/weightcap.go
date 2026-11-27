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

// MaxMembers is the largest committee the selector supports: 256 (owner §49), the native resource ceiling of the trust base entry. The
// table of winner indices is a uint8, which holds the indices 0..255 exactly; more members would need another representation. The weight
// bound B is unchanged, so the table stays at most B = 65,536 bytes and its construction at most MaxMembers*B comparisons (benchmarked in
// rootchain/consensus/leader at 128 and 256 members, unit weights and the worst total). This bound is the selector's own: the B1 registry's
// 16 members is a separate admission guard of a B1-enabled deployment.
const MaxMembers = 256
