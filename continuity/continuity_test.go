package continuity

import (
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

var dev = Policy{MaxM: 4, MaxDistNum: 1, MaxDistDen: 4}

func id(i int) StakingID { var s StakingID; s[31], s[30] = byte(i), byte(i>>8); return s }

func member(i int, w uint64) Member {
	return Member{ID: id(i), RootNodeID: fmt.Sprintf("r%d", i), RootKey: []byte{1, byte(i)}, EVMNodeID: fmt.Sprintf("e%d", i), EVMKey: []byte{2, byte(i)}, Weight: w}
}

func committee(n int, w uint64) []Member {
	out := make([]Member, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, member(i, w))
	}
	return out
}

func clone(c []Member) []Member { return append([]Member(nil), c...) }

// variants of replacing the binding of one shared identity: root only, EVM only, both.
var variants = map[string]func(m *Member){
	"root only": func(m *Member) { m.RootKey = []byte{9, 9} },
	"evm only":  func(m *Member) { m.EVMNodeID += "x" },
	"both":      func(m *Member) { m.RootNodeID += "x"; m.EVMKey = []byte{9, 8} },
}

func TestSameIdentityBindingReplacementCountsOnce(t *testing.T) {
	for name, change := range variants {
		t.Run(name, func(t *testing.T) {
			o := committee(10, 100)
			s := clone(o)
			change(&s[0])
			r, err := Check(o, s, dev)
			require.NoError(t, err)
			require.Equal(t, [4]uint64{1, 1, 1, 2}, [4]uint64{r.Replaced, r.Removed, r.Added, r.M})
			require.Zero(t, r.DistanceNumerator.Sign(), "D=0")
			require.Equal(t, uint64(900), r.UnchangedOld) // overlap 9/10
		})
	}
}

func TestThreeReplacementsExceedMembershipBudgetOnly(t *testing.T) {
	o := committee(10, 1)
	s := clone(o)
	for i := 0; i < 3; i++ {
		variants["both"](&s[i])
	}
	r, err := Check(o, s, dev)
	require.Equal(t, uint64(6), r.M)
	require.ErrorIs(t, err, ErrMembership)
	require.NotErrorIs(t, err, ErrTurnover, "9 < 10 holds")
	require.NotErrorIs(t, err, ErrOverlap, "7/10 > 2/3")
	require.NotErrorIs(t, err, ErrWeightDistance)
}

func TestHeavyUnchangedLightChangedFailsStrictBoundary(t *testing.T) {
	for name, change := range variants {
		t.Run(name, func(t *testing.T) {
			var o []Member
			for i := 1; i <= 6; i++ {
				o = append(o, member(i, 100))
			}
			for i := 7; i <= 10; i++ {
				o = append(o, member(i, 1))
			}
			s := clone(o)
			for i := 6; i < 10; i++ {
				change(&s[i])
			}
			r, err := Check(o, s, dev)
			require.Equal(t, [4]uint64{4, 4, 4, 8}, [4]uint64{r.Replaced, r.Removed, r.Added, r.M})
			require.Zero(t, r.DistanceNumerator.Sign())
			require.Equal(t, uint64(600), r.UnchangedOld)
			require.ErrorIs(t, err, ErrTurnover, "3*4=12 !< 10")
			require.ErrorIs(t, err, ErrMembership, "M=8")
			require.NotErrorIs(t, err, ErrOverlap, "600/604 > 2/3")
		})
	}
}

func TestExactOneThirdAndTwoThirdsBoundariesReject(t *testing.T) {
	// 9 members, 3 replaced: 3*3 = 9 !< 9 rejects at exactly one third even though M=6 would pass a larger budget.
	wide := Policy{MaxM: 100, MaxDistNum: 1, MaxDistDen: 1}
	o := committee(9, 1)
	s := clone(o)
	for i := 0; i < 3; i++ {
		variants["root only"](&s[i])
	}
	_, err := Check(o, s, wide)
	require.ErrorIs(t, err, ErrTurnover)
	require.NotErrorIs(t, err, ErrMembership)
	require.NotErrorIs(t, err, ErrWeightDistance)
	// two replaced of nine (2*2 < 9) is inside the boundary
	s = clone(o)
	for i := 0; i < 2; i++ {
		variants["root only"](&s[i])
	}
	_, err = Check(o, s, wide)
	require.NoError(t, err)
}

func TestOverlapExactlyTwoThirdsRejected(t *testing.T) {
	wide := Policy{MaxM: 100, MaxDistNum: 1, MaxDistDen: 1}
	o := committee(9, 1)
	s := clone(o)
	for i := 0; i < 3; i++ {
		variants["root only"](&s[i])
	}
	r, err := Check(o, s, wide)
	require.Equal(t, uint64(6), r.UnchangedOld)
	require.ErrorIs(t, err, ErrOverlap)
}

func TestOverlapJustAboveTwoThirdsWithWeights(t *testing.T) {
	wide := Policy{MaxM: 100, MaxDistNum: 1, MaxDistDen: 1}
	// 7 members: weights 3,3,3,3,3,1,1 -> total 17, unchanged (first five) 15 > 34/3
	o := []Member{member(1, 3), member(2, 3), member(3, 3), member(4, 3), member(5, 3), member(6, 1), member(7, 1)}
	s := clone(o)
	variants["both"](&s[5])
	variants["both"](&s[6])
	r, err := Check(o, s, wide)
	require.NoError(t, err)
	require.Equal(t, uint64(15), r.UnchangedOld)
}

func TestOverlapBothSidesWeightMatter(t *testing.T) {
	wide := Policy{MaxM: 100, MaxDistNum: 1, MaxDistDen: 1}
	// unchanged identities carry 9/10 of O's weight but, after a weight rise of the newcomers, only 1/2 of S's weight
	o := []Member{member(1, 3), member(2, 3), member(3, 3), member(4, 1)}
	s := []Member{member(1, 3), member(2, 3), member(3, 3), member(5, 50)}
	_, err := Check(o, s, wide)
	require.ErrorIs(t, err, ErrOverlap)
}

func TestWeightDistanceIsExactAndSeparate(t *testing.T) {
	// same bindings, only weights move: D is the only predicate that can fail.
	o := []Member{member(1, 1), member(2, 1), member(3, 1), member(4, 1)}
	pol := Policy{MaxM: 4, MaxDistNum: 1, MaxDistDen: 4}
	s := []Member{member(1, 2), member(2, 1), member(3, 1), member(4, 1)} // w=(2/5,1/5,1/5,1/5) v=1/4 each: D=3/20+3*(1/20)=6/20
	r, err := Check(o, s, pol)
	require.ErrorIs(t, err, ErrWeightDistance)
	require.NotErrorIs(t, err, ErrMembership)
	require.NotErrorIs(t, err, ErrTurnover)
	require.NotErrorIs(t, err, ErrOverlap)
	require.Equal(t, "6", r.DistanceNumerator.String()) // sum |w*V-v*W| = |2*4-1*5|+3*|1*4-1*5| = 3+3
	// exact boundary D = 1/4 passes: weights (2,1,1,1) -> (3,1,1,1)... find equality instead with rational model
	exact := Policy{MaxM: 4, MaxDistNum: 6, MaxDistDen: 20}
	_, err = Check(o, s, exact)
	require.NoError(t, err, "D=6/20 equal to the bound is allowed")
	below := Policy{MaxM: 4, MaxDistNum: 5999, MaxDistDen: 20000}
	_, err = Check(o, s, below)
	require.ErrorIs(t, err, ErrWeightDistance)
}

func TestForcedExitsShrinkageAndWeightChangesConsumeBudgets(t *testing.T) {
	o := committee(10, 1)
	s := o[:9] // one forced exit: removed=1 added=0
	r, err := Check(o, s, Policy{MaxM: 1, MaxDistNum: 1, MaxDistDen: 4})
	require.NoError(t, err)
	require.Equal(t, [2]uint64{1, 0}, [2]uint64{r.Removed, r.Added})
	_, err = Check(o, s, Policy{MaxM: 0, MaxDistNum: 1, MaxDistDen: 4})
	require.ErrorIs(t, err, ErrMembership)
}

func TestPayeeChangeIsNotAReplacement(t *testing.T) {
	// Member carries no payee: identical bindings with a different payee are, by construction, unchanged.
	o := committee(10, 1)
	r, err := Check(o, clone(o), Policy{MaxM: 0, MaxDistNum: 0, MaxDistDen: 1})
	require.NoError(t, err)
	require.Zero(t, r.M)
}

func TestInvalidCommitteesAndPolicy(t *testing.T) {
	good := committee(4, 1)
	dup := append(clone(good), good[0])
	zero := clone(good)
	zero[0].Weight = 0
	for name, c := range map[string][]Member{"empty": nil, "duplicate": dup, "zero weight": zero} {
		_, err := Check(c, good, dev)
		require.ErrorIs(t, err, ErrCommittee, name+" predecessor")
		_, err = Check(good, c, dev)
		require.ErrorIs(t, err, ErrCommittee, name+" successor")
	}
	_, err := Check(good, good, Policy{MaxM: 4})
	require.ErrorIs(t, err, ErrPolicy)
	over := []Member{member(1, ^uint64(0)), member(2, 1)}
	_, err = Check(over, good, dev)
	require.ErrorIs(t, err, ErrCommittee)
}

func TestSuccessorMeasuredAgainstSameOldCommitteeForExcludedMembers(t *testing.T) {
	// The predecessor keeps its excluded/retiring members: dropping two of ten consumes the budget however the cause is named.
	o := committee(10, 1)
	s := o[2:]
	r, err := Check(o, s, Policy{MaxM: 4, MaxDistNum: 1, MaxDistDen: 2})
	require.NoError(t, err)
	require.Equal(t, uint64(2), r.Removed)
}

// independent model: big.Rat over the union, no shared helpers with Check
func modelOK(o, s []Member, p Policy) map[error]bool {
	oi, si := map[StakingID]Member{}, map[StakingID]Member{}
	V, W := new(big.Rat), new(big.Rat)
	for _, m := range o {
		oi[m.ID] = m
		V.Add(V, new(big.Rat).SetUint64(m.Weight))
	}
	for _, m := range s {
		si[m.ID] = m
		W.Add(W, new(big.Rat).SetUint64(m.Weight))
	}
	union := map[StakingID]bool{}
	for k := range oi {
		union[k] = true
	}
	for k := range si {
		union[k] = true
	}
	D := new(big.Rat)
	uo, us := new(big.Rat), new(big.Rat)
	rep, onlyO, onlyS := 0, 0, 0
	for k := range union {
		a, inO := oi[k]
		b, inS := si[k]
		x, y := new(big.Rat), new(big.Rat)
		if inS {
			x.Quo(new(big.Rat).SetUint64(b.Weight), W)
		}
		if inO {
			y.Quo(new(big.Rat).SetUint64(a.Weight), V)
		}
		D.Add(D, new(big.Rat).Abs(new(big.Rat).Sub(x, y)))
		switch {
		case inO && inS && sameBinding(a, b):
			uo.Add(uo, new(big.Rat).SetUint64(a.Weight))
			us.Add(us, new(big.Rat).SetUint64(b.Weight))
		case inO && inS:
			rep++
		case inO:
			onlyO++
		default:
			onlyS++
		}
	}
	removed, added := onlyO+rep, onlyS+rep
	third := new(big.Rat).SetFrac64(2, 3)
	return map[error]bool{
		ErrMembership:     uint64(removed+added) <= p.MaxM,
		ErrTurnover:       3*max(removed, added) < min(len(o), len(s)),
		ErrWeightDistance: D.Cmp(new(big.Rat).SetFrac64(int64(p.MaxDistNum), int64(p.MaxDistDen))) <= 0,
		ErrOverlap:        uo.Cmp(new(big.Rat).Mul(third, V)) > 0 && us.Cmp(new(big.Rat).Mul(third, W)) > 0,
	}
}

func TestMatchesIndependentRationalModel(t *testing.T) {
	rng := rand.New(rand.NewSource(85))
	for n := 0; n < 3000; n++ {
		size := 3 + rng.Intn(10)
		var o []Member
		for i := 1; i <= size; i++ {
			o = append(o, member(i, uint64(1+rng.Intn(5))))
		}
		var s []Member
		for _, m := range o {
			switch rng.Intn(8) {
			case 0: // drop
			case 1:
				m.Weight = uint64(1 + rng.Intn(5))
				s = append(s, m)
			case 2:
				variants["root only"](&m)
				s = append(s, m)
			default:
				s = append(s, m)
			}
		}
		for i := 0; i < rng.Intn(3); i++ {
			s = append(s, member(100+i, uint64(1+rng.Intn(5))))
		}
		if len(s) == 0 {
			continue
		}
		p := Policy{MaxM: uint64(rng.Intn(6)), MaxDistNum: uint64(rng.Intn(4)), MaxDistDen: uint64(1 + rng.Intn(8))}
		_, err := Check(o, s, p)
		for sentinel, pass := range modelOK(o, s, p) {
			require.Equal(t, !pass, errors.Is(err, sentinel), "case %d sentinel %v", n, sentinel)
		}
	}
}
