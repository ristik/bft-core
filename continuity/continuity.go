// Package continuity is the binding-aware committee continuity rule of #85 (docs/design/pos-architecture.md section 5): the
// membership budget M, the strict turnover boundary, the normalized weight distance D and the unchanged-binding weight overlap, between
// two consecutive committees. The same Check judges O to J and J to K, each with its own predecessor and successor records.
//
// Committees are sets of staking identities. A shared identity whose binding tuple (root node id and key, EVM node id and key) differs
// in any field is a replacement, counted once in r however many of its fields changed. All comparisons are exact integer arithmetic;
// nothing here uses a float.
package continuity

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
)

// StakingID is the fixed-width unsigned identity of a validator entity.
type StakingID [32]byte

// Member is one committee entry: the identity, its binding tuple and its committed weight. The payee is deliberately absent: a
// payee change alone is not a signing-binding replacement.
type Member struct {
	ID         StakingID
	RootNodeID string
	RootKey    []byte
	EVMNodeID  string
	EVMKey     []byte
	Weight     uint64
}

// Policy is the governed part of the rule. The strict one-third turnover and two-thirds overlap bounds are not parameters.
type Policy struct {
	// MaxM bounds M = removed + added.
	MaxM uint64
	// MaxDistNum/MaxDistDen bound D = sum |w_i/W - v_i/V| as an exact rational.
	MaxDistNum, MaxDistDen uint64
}

var (
	// ErrCommittee reports a committee that cannot be judged: empty, a duplicate identity or a zero weight.
	ErrCommittee = errors.New("continuity: invalid committee")
	// ErrPolicy reports an unusable policy (zero denominator).
	ErrPolicy = errors.New("continuity: invalid policy")
	// ErrMembership reports M above the membership budget.
	ErrMembership = errors.New("continuity: membership budget exceeded")
	// ErrTurnover reports 3*max(removed, added) >= min(|O|, |S|): at or past one third of either committee changed.
	ErrTurnover = errors.New("continuity: strict turnover boundary violated")
	// ErrWeightDistance reports a normalized weight distance above the policy.
	ErrWeightDistance = errors.New("continuity: weight distance exceeded")
	// ErrOverlap reports unchanged-binding weight that is not strictly more than two thirds of both committees.
	ErrOverlap = errors.New("continuity: unchanged-binding overlap is not above two thirds of both committees")
)

// Result is the measured transition, returned even when a predicate fails so a caller can report it.
type Result struct {
	// Replaced is r: shared identities with any changed binding field.
	Replaced uint64
	Removed  uint64
	Added    uint64
	// M is Removed + Added.
	M uint64
	// UnchangedOld and UnchangedNew are the weights the unchanged-binding identities carry in O and in S.
	UnchangedOld, UnchangedNew uint64
	// TotalOld and TotalNew are V and W.
	TotalOld, TotalNew uint64
	// DistanceNumerator over TotalOld*TotalNew is D: sum |w_i*V - v_i*W|.
	DistanceNumerator *big.Int
}

func index(c []Member) (map[StakingID]Member, uint64, error) {
	if len(c) == 0 {
		return nil, 0, fmt.Errorf("%w: empty", ErrCommittee)
	}
	out := make(map[StakingID]Member, len(c))
	var total uint64
	for _, m := range c {
		if m.Weight == 0 {
			return nil, 0, fmt.Errorf("%w: %x has zero weight", ErrCommittee, m.ID[:4])
		}
		if _, dup := out[m.ID]; dup {
			return nil, 0, fmt.Errorf("%w: duplicate identity %x", ErrCommittee, m.ID[:4])
		}
		if total+m.Weight < total {
			return nil, 0, fmt.Errorf("%w: weight overflow", ErrCommittee)
		}
		total += m.Weight
		out[m.ID] = m
	}
	return out, total, nil
}

func sameBinding(a, b Member) bool {
	return a.RootNodeID == b.RootNodeID && a.EVMNodeID == b.EVMNodeID && bytes.Equal(a.RootKey, b.RootKey) && bytes.Equal(a.EVMKey, b.EVMKey)
}

// Measure computes the transition quantities between the last committed committee o and the trial successor s.
func Measure(o, s []Member) (Result, error) {
	var r Result
	oi, ov, err := index(o)
	if err != nil {
		return r, fmt.Errorf("predecessor: %w", err)
	}
	si, sw, err := index(s)
	if err != nil {
		return r, fmt.Errorf("successor: %w", err)
	}
	r.TotalOld, r.TotalNew = ov, sw
	dist := new(big.Int)
	var onlyOld, onlyNew uint64
	for id, om := range oi {
		sm, shared := si[id]
		if !shared {
			onlyOld++
			dist.Add(dist, absDiff(0, om.Weight, sw, ov))
			continue
		}
		if sameBinding(om, sm) {
			r.UnchangedOld += om.Weight
			r.UnchangedNew += sm.Weight
		} else {
			r.Replaced++
		}
		dist.Add(dist, absDiff(sm.Weight, om.Weight, sw, ov))
	}
	for id, sm := range si {
		if _, shared := oi[id]; !shared {
			onlyNew++
			dist.Add(dist, absDiff(sm.Weight, 0, sw, ov))
		}
	}
	r.Removed, r.Added = onlyOld+r.Replaced, onlyNew+r.Replaced
	r.M = r.Removed + r.Added
	r.DistanceNumerator = dist
	return r, nil
}

// absDiff is |w*V - v*W| with w the successor weight, v the predecessor weight, W the successor total and V the predecessor total.
func absDiff(w, v, bigW, bigV uint64) *big.Int {
	a := new(big.Int).Mul(new(big.Int).SetUint64(w), new(big.Int).SetUint64(bigV))
	b := new(big.Int).Mul(new(big.Int).SetUint64(v), new(big.Int).SetUint64(bigW))
	return a.Sub(a, b).Abs(a)
}

// Check applies every predicate to the boundary o -> s and returns the measured Result with a joined error naming each predicate
// that failed (errors.Is selects them independently). o must be the last committed committee of that boundary, never a trial-local
// one, and may include retiring or excluded members.
func Check(o, s []Member, p Policy) (Result, error) {
	if p.MaxDistDen == 0 {
		return Result{}, ErrPolicy
	}
	r, err := Measure(o, s)
	if err != nil {
		return r, err
	}
	var errs []error
	if r.M > p.MaxM {
		errs = append(errs, fmt.Errorf("%w: M=%d > %d", ErrMembership, r.M, p.MaxM))
	}
	minSize := uint64(min(len(o), len(s)))
	if 3*max(r.Removed, r.Added) >= minSize {
		errs = append(errs, fmt.Errorf("%w: removed=%d added=%d of min(|O|,|S|)=%d", ErrTurnover, r.Removed, r.Added, minSize))
	}
	// D <= num/den  <=>  numerator*den <= num*V*W
	lhs := new(big.Int).Mul(r.DistanceNumerator, new(big.Int).SetUint64(p.MaxDistDen))
	rhs := new(big.Int).Mul(new(big.Int).SetUint64(p.MaxDistNum), new(big.Int).Mul(new(big.Int).SetUint64(r.TotalOld), new(big.Int).SetUint64(r.TotalNew)))
	if lhs.Cmp(rhs) > 0 {
		errs = append(errs, fmt.Errorf("%w: sum |w*V-v*W|=%s over V*W", ErrWeightDistance, r.DistanceNumerator))
	}
	// strictly more than two thirds of both committees: 3*unchanged > 2*total (checked in big arithmetic: totals reach 2^48)
	if !aboveTwoThirds(r.UnchangedOld, r.TotalOld) || !aboveTwoThirds(r.UnchangedNew, r.TotalNew) {
		errs = append(errs, fmt.Errorf("%w: unchanged %d of %d (old), %d of %d (new)", ErrOverlap, r.UnchangedOld, r.TotalOld, r.UnchangedNew, r.TotalNew))
	}
	return r, errors.Join(errs...)
}

func aboveTwoThirds(part, total uint64) bool {
	l := new(big.Int).Mul(big.NewInt(3), new(big.Int).SetUint64(part))
	r := new(big.Int).Mul(big.NewInt(2), new(big.Int).SetUint64(total))
	return l.Cmp(r) > 0
}
