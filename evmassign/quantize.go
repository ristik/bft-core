package evmassign

import (
	"errors"
	"math"
)

// The weight quantization rule (briefs/leader-lookup.md as amended by leader-lookup-review.md, F2): the committed voting, leader, reward and
// threshold weight q of a committee is derived from the raw bonded weights x so that the committed total never exceeds the profile cap B.
//
//	X = sum(x); if X <= B: q = x; else s = ceil(X / (B - n)), q_i = max(1, floor(x_i / s)).
//
// Σq <= X/s + n <= B and 1 <= q_i <= x_i. The election (unicity-pos-contracts Quantize.sol), the root's projection and derivation checks (here)
// and ureth (quant.rs) all evaluate this one pure function; test/p85/fixtures/quant-vectors.json is the shared vector set.
//
// Security premise: BFT safety assumes the Byzantine committed q-weight is below one third, not the raw stake. For any member subset S,
// |q(S)/Q - x(S)/X| < 2n/Q, where Q = Σq; with Q > (B+1)/2 - n (about 32,700 at n = 64) the shift is under 0.4%.

var (
	// ErrQuantize reports raw weights the rule is not defined for: no members, a zero weight, n >= B, or a raw total beyond uint64.
	ErrQuantize = errors.New("evmassign: weights cannot be quantized")
)

// Quantize returns q = quant(x, n, b) for b the profile cap B, and the divisor s the rule used (1 when X <= b).
func Quantize(x []uint64, b uint64) (q []uint64, s uint64, err error) {
	n := uint64(len(x))
	if n == 0 || n >= b {
		return nil, 0, ErrQuantize
	}
	var total uint64
	for _, v := range x {
		if v == 0 || total > math.MaxUint64-v {
			return nil, 0, ErrQuantize
		}
		total += v
	}
	q = make([]uint64, len(x))
	if total <= b {
		copy(q, x)
		return q, 1, nil
	}
	room := b - n
	s = total / room
	if total%room != 0 {
		s++
	}
	for i, v := range x {
		q[i] = max(1, v/s)
	}
	return q, s, nil
}
