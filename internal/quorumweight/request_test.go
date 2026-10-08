package quorumweight

import (
	"crypto"
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmassign"
)

func TestMajorityThreshold(t *testing.T) {
	for _, tc := range []struct{ w, q uint64 }{{1, 1}, {2, 2}, {3, 2}, {4, 3}, {5, 3}, {9, 5}, {10, 6}, {1 << 48, 1<<47 + 1}, {math.MaxUint64, math.MaxUint64/2 + 1}} {
		q, err := MajorityThreshold(tc.w)
		require.NoError(t, err, tc.w)
		require.Equal(t, tc.q, q, "W=%d", tc.w)
	}
	_, err := MajorityThreshold(0)
	require.ErrorIs(t, err, ErrZeroWeight)
}

func TestQuorumImpossibleErrors(t *testing.T) {
	_, err := QuorumImpossible(0, 0, 0)
	require.ErrorIs(t, err, ErrZeroWeight)
	for _, tc := range []struct{ w, r, m uint64 }{{10, 11, 3}, {10, 3, 4}} {
		imp, err := QuorumImpossible(tc.w, tc.r, tc.m)
		require.ErrorIs(t, err, ErrInconsistentTally, tc)
		require.False(t, imp, "an inconsistent tally is an error, never impossibility")
	}
}

// Fixture 2 of briefs/q2-design.md: weights (3,2,1,2,2), W=10, Q=6.
func TestQuorumImpossibleBoundary(t *testing.T) {
	const w = 10
	for _, tc := range []struct {
		name       string
		r, m       uint64
		impossible bool
	}{
		{"empty", 0, 0, false},
		{"X3 + Y2+1", 6, 3, false},                       // M+U = 3+4 = 7
		{"X3 + Y2+1 + Z2", 8, 3, true},                   // 3+2 = 5 < 6
		{"X3 + Y2+2", 7, 4, false},                       // 4+3 = 7
		{"X3 + Y2+2 + Z1", 8, 4, false},                  // 4+2 = 6 == Q: still possible
		{"X3 + Y2+2 + Z1 + last2 joins Y", 10, 6, false}, // reached, M+U=6
	} {
		got, err := QuorumImpossible(w, tc.r, tc.m)
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.impossible, got, tc.name)
	}
}

// Every arrival order of the (3,2,1,2,2) fixture agrees with a brute-force "can any completion reach Q" oracle, and M+U
// never increases as more votes arrive.
func TestQuorumImpossibleAgreesWithOracleForEveryOrder(t *testing.T) {
	weights := []uint64{3, 2, 1, 2, 2}
	const total, q = 10, 6
	// group assignment per voter, voters that never arrive stay out
	for mask := 0; mask < 1<<len(weights); mask++ {
		for groups := 0; groups < 3*3*3*3*3; groups++ {
			g := make([]int, len(weights))
			for i, x := 0, groups; i < len(g); i, x = i+1, x/3 {
				g[i] = x % 3
			}
			assertSubset(t, weights, mask, g, total, q)
		}
	}
}

func assertSubset(t *testing.T, weights []uint64, mask int, group []int, total, q uint64) {
	var r uint64
	sum := map[int]uint64{}
	for i, w := range weights {
		if mask&(1<<i) != 0 {
			r += w
			sum[group[i]] += w
		}
	}
	var m uint64
	for _, s := range sum {
		m = max(m, s)
	}
	// oracle: some assignment of the absent voters lets one group reach q
	possible := m >= q
	for g := 0; g < 3 && !possible; g++ {
		extra := sum[g]
		for i, w := range weights {
			if mask&(1<<i) == 0 {
				extra += w
			}
		}
		possible = extra >= q
	}
	// a brand new group can only gain absent weight, covered by the loop over g (sum[g] may be 0)
	got, err := QuorumImpossible(total, r, m)
	require.NoError(t, err)
	require.Equal(t, !possible, got, "mask=%b groups=%v", mask, group)
}

// M+U cannot increase when a vote arrives, whichever group it joins.
func TestQuorumImpossibleMonotone(t *testing.T) {
	const total = 10
	for r := uint64(0); r < total; r++ {
		for m := uint64(0); m <= r; m++ {
			for x := uint64(1); r+x <= total; x++ {
				for _, m2 := range []uint64{m, m + x} { // joins a lighter group, or the heaviest
					if m2 > r+x {
						continue
					}
					before, after := m+total-r, m2+total-(r+x)
					require.LessOrEqual(t, after, before)
				}
			}
		}
	}
}

func TestQuorumImpossibleOverflow(t *testing.T) {
	// M + (W-R) can not overflow when M <= R <= W, but the guard must hold even so
	imp, err := QuorumImpossible(math.MaxUint64, 0, 0)
	require.NoError(t, err)
	require.False(t, imp)
	imp, err = QuorumImpossible(math.MaxUint64, math.MaxUint64, math.MaxUint64)
	require.NoError(t, err)
	require.False(t, imp)
}

type member struct {
	id     string
	weight uint64
}

func nodeInfos(t *testing.T, ms ...member) []*types.NodeInfo {
	out := make([]*types.NodeInfo, len(ms))
	for i, m := range ms {
		out[i] = &types.NodeInfo{NodeID: m.id, SigKey: key(t, byte(i+1)), Stake: m.weight}
	}
	return out
}

func key(t *testing.T, seed byte) []byte {
	signer, err := abcrypto.NewInMemorySecp256K1SignerFromKey(append(make([]byte, 31), seed))
	require.NoError(t, err)
	v, err := signer.Verifier()
	require.NoError(t, err)
	b, err := v.MarshalPublicKey()
	require.NoError(t, err)
	return b
}

func pdr(typeID types.PartitionTypeID, vals []*types.NodeInfo) *types.PartitionDescriptionRecord {
	return &types.PartitionDescriptionRecord{
		Version: 1, NetworkID: 5, PartitionID: 1, PartitionTypeID: typeID, UnitIDLen: 256, TypeIDLen: 32,
		T2Timeout: 2500_000_000, Epoch: 1, Validators: vals,
	}
}

func confHash(t *testing.T, p *types.PartitionDescriptionRecord) []byte {
	h, err := p.Hash(crypto.SHA256)
	require.NoError(t, err)
	return h
}

func TestUnitRequestContextThresholds(t *testing.T) {
	for n, q := range map[int]uint64{1: 1, 2: 2, 3: 2, 4: 3, 5: 3, 6: 4, 7: 4} {
		ms := make([]member, n)
		for i := range ms {
			ms[i] = member{fmt.Sprint("n", i), 1}
		}
		p := pdr(1, nodeInfos(t, ms...))
		c, err := NewUnitRequestContext(p, crypto.SHA256, confHash(t, p))
		require.NoError(t, err)
		require.Equal(t, PolicyUnit, c.Policy())
		require.Equal(t, n, c.MemberCount())
		require.EqualValues(t, n, c.TotalWeight())
		require.Equal(t, q, c.Threshold(), "N=%d", n)
		require.Equal(t, n == 1, c.QuorumReached(1))
		w, err := c.SignerWeight("n0")
		require.NoError(t, err)
		require.EqualValues(t, 1, w)
		_, err = c.SignerWeight("stranger")
		require.ErrorIs(t, err, ErrUnknownSigner)
	}
}

func TestUnitRequestContextRefusals(t *testing.T) {
	vals := nodeInfos(t, member{"a", 1}, member{"b", 1})
	p := pdr(1, vals)
	h := confHash(t, p)

	t.Run("non-unit stake is refused, not normalised", func(t *testing.T) {
		bad := pdr(1, nodeInfos(t, member{"a", 1}, member{"b", 2}))
		_, err := NewUnitRequestContext(bad, crypto.SHA256, confHash(t, bad))
		require.ErrorIs(t, err, ErrWeightCap)
	})
	t.Run("zero stake", func(t *testing.T) {
		bad := pdr(1, nodeInfos(t, member{"a", 1}, member{"b", 0}))
		_, err := NewUnitRequestContext(bad, crypto.SHA256, confHash(t, bad))
		require.ErrorIs(t, err, ErrWeightCap) // the unit policy refuses it before any weight is read
	})
	t.Run("hash mismatch", func(t *testing.T) {
		other := pdr(1, vals)
		other.T2Timeout++
		_, err := NewUnitRequestContext(other, crypto.SHA256, h)
		require.ErrorIs(t, err, ErrRequestContext)
		_, err = NewUnitRequestContext(p, crypto.SHA256, nil)
		require.ErrorIs(t, err, ErrRequestContext)
		_, err = NewUnitRequestContext(nil, crypto.SHA256, h)
		require.ErrorIs(t, err, ErrRequestContext)
	})
	t.Run("empty set", func(t *testing.T) {
		e := pdr(1, nil)
		_, err := NewUnitRequestContext(e, crypto.SHA256, confHash(t, e))
		require.ErrorIs(t, err, ErrZeroWeight)
	})
	t.Run("duplicate identity", func(t *testing.T) {
		d := pdr(1, nodeInfos(t, member{"a", 1}, member{"a", 1}))
		_, err := NewUnitRequestContext(d, crypto.SHA256, confHash(t, d))
		require.ErrorIs(t, err, ErrDuplicateSigner)
	})
	t.Run("duplicate key", func(t *testing.T) {
		d := pdr(1, nodeInfos(t, member{"a", 1}, member{"b", 1}))
		d.Validators[1].SigKey = d.Validators[0].SigKey
		_, err := NewUnitRequestContext(d, crypto.SHA256, confHash(t, d))
		require.ErrorIs(t, err, ErrDuplicateKey)
	})
	t.Run("nil member and empty identity", func(t *testing.T) {
		d := pdr(1, []*types.NodeInfo{nil})
		_, err := NewUnitRequestContext(d, crypto.SHA256, confHash(t, d))
		require.ErrorIs(t, err, ErrUnknownSigner)
		d = pdr(1, nodeInfos(t, member{"", 1}))
		_, err = NewUnitRequestContext(d, crypto.SHA256, confHash(t, d))
		require.ErrorIs(t, err, ErrUnknownSigner)
	})
}

// coupled builds an EVM PDR whose root side mirrors the weights.
func coupled(t *testing.T, ws ...uint64) (*types.PartitionDescriptionRecord, *Coupling) {
	evm := make([]*types.NodeInfo, len(ws))
	root := make([]evmassign.RootMember, len(ws))
	bind := make([]evmassign.Binding, len(ws))
	for i, w := range ws {
		evm[i] = &types.NodeInfo{NodeID: fmt.Sprintf("e%02d", i), SigKey: key(t, byte(i+1)), Stake: w}
		root[i] = evmassign.RootMember{NodeID: fmt.Sprintf("r%02d", i), Key: key(t, byte(i+101)), Weight: w}
		bind[i] = evmassign.Binding{RootNodeID: root[i].NodeID, EVMNodeID: evm[i].NodeID}
	}
	return pdr(evmassign.EVMPartitionTypeID, evm), &Coupling{RootEpoch: 7, RootBodyID: []byte("body-7"), Root: root, Bindings: bind}
}

func TestWeightedRequestContextSkew(t *testing.T) {
	// fixture 1: (6,1,1,1), W=9, Q=5; the root threshold would be 7
	p, c := coupled(t, 6, 1, 1, 1)
	ctx, err := NewWeightedRequestContext(p, crypto.SHA256, confHash(t, p), c)
	require.NoError(t, err)
	require.Equal(t, PolicyWeighted(), ctx.Policy())
	require.EqualValues(t, 9, ctx.TotalWeight())
	require.EqualValues(t, 5, ctx.Threshold())
	rootQ, err := Threshold(ctx.TotalWeight())
	require.NoError(t, err)
	require.EqualValues(t, 7, rootQ)
	require.True(t, ctx.QuorumReached(6))
	require.False(t, ctx.QuorumReached(3), "three light identities cannot certify")
	imp, err := ctx.QuorumImpossible(3, 3)
	require.NoError(t, err)
	require.False(t, imp, "omitting the heavy signer cannot prove impossibility: M=3, U=6")
	require.EqualValues(t, 7, ctx.RootEpoch())
	require.Equal(t, []byte("body-7"), ctx.RootBodyID())
	require.NotEqual(t, ctx.Identity(), func() string {
		p2, c2 := coupled(t, 1, 6, 1, 1)
		c2.RootBodyID = []byte("body-8")
		x, err := NewWeightedRequestContext(p2, crypto.SHA256, confHash(t, p2), c2)
		require.NoError(t, err)
		return x.Identity()
	}())
}

func PolicyWeighted() RequestPolicy { return PolicyEVMWeighted }

func TestWeightedRequestContextUnitEquivalence(t *testing.T) {
	// all-one EVM sets reproduce the unit/count outcomes
	for n := 1; n <= 7; n++ {
		ws := make([]uint64, n)
		for i := range ws {
			ws[i] = 1
		}
		p, c := coupled(t, ws...)
		w, err := NewWeightedRequestContext(p, crypto.SHA256, confHash(t, p), c)
		require.NoError(t, err)
		u, err := NewUnitRequestContext(p, crypto.SHA256, confHash(t, p))
		require.NoError(t, err)
		require.Equal(t, u.TotalWeight(), w.TotalWeight())
		require.Equal(t, u.Threshold(), w.Threshold())
		for r := uint64(0); r <= uint64(n); r++ {
			for m := uint64(0); m <= r; m++ {
				a, errA := u.QuorumImpossible(r, m)
				b, errB := w.QuorumImpossible(r, m)
				require.NoError(t, errA)
				require.NoError(t, errB)
				require.Equal(t, a, b)
				require.Equal(t, u.QuorumReached(m), w.QuorumReached(m))
			}
		}
	}
}

func TestWeightedRequestContextRefusals(t *testing.T) {
	t.Run("no coupling evidence", func(t *testing.T) {
		p, c := coupled(t, 1, 1)
		_, err := NewWeightedRequestContext(p, crypto.SHA256, confHash(t, p), nil)
		require.ErrorIs(t, err, ErrCouplingRequired)
		c.RootBodyID = nil
		_, err = NewWeightedRequestContext(p, crypto.SHA256, confHash(t, p), c)
		require.ErrorIs(t, err, ErrCouplingRequired)
	})
	t.Run("aggregator type cannot be weighted", func(t *testing.T) {
		p, c := coupled(t, 2, 1)
		p.PartitionTypeID = 1
		_, err := NewWeightedRequestContext(p, crypto.SHA256, confHash(t, p), c)
		require.ErrorIs(t, err, ErrRequestContext)
	})
	t.Run("hash mismatch", func(t *testing.T) {
		p, c := coupled(t, 2, 1)
		h := confHash(t, p)
		p.Epoch++
		_, err := NewWeightedRequestContext(p, crypto.SHA256, h, c)
		require.ErrorIs(t, err, ErrRequestContext)
	})
	t.Run("mirror mismatch", func(t *testing.T) {
		p, c := coupled(t, 6, 1, 1, 1)
		c.Root[0].Weight = 1
		_, err := NewWeightedRequestContext(p, crypto.SHA256, confHash(t, p), c)
		require.ErrorIs(t, err, evmassign.ErrCoupling)
	})
	t.Run("binding to a stranger", func(t *testing.T) {
		p, c := coupled(t, 2, 1)
		c.Bindings[0].EVMNodeID = "nobody"
		_, err := NewWeightedRequestContext(p, crypto.SHA256, confHash(t, p), c)
		require.ErrorIs(t, err, evmassign.ErrCoupling)
	})
	t.Run("zero weight", func(t *testing.T) {
		p, c := coupled(t, 0, 1)
		_, err := NewWeightedRequestContext(p, crypto.SHA256, confHash(t, p), c)
		require.ErrorIs(t, err, ErrZeroWeight)
	})
	t.Run("member cap", func(t *testing.T) {
		p, c := coupled(t, MaxMemberWeight-1, 1)
		x, err := NewWeightedRequestContext(p, crypto.SHA256, confHash(t, p), c)
		require.NoError(t, err)
		require.EqualValues(t, MaxMemberWeight, x.TotalWeight(), "a total of exactly B is admitted")
		p, c = coupled(t, MaxMemberWeight, 1)
		_, err = NewWeightedRequestContext(p, crypto.SHA256, confHash(t, p), c)
		require.ErrorIs(t, err, ErrWeightCap, "W = B+1 is refused")
		p, c = coupled(t, MaxMemberWeight+1, 1)
		_, err = NewWeightedRequestContext(p, crypto.SHA256, confHash(t, p), c)
		require.ErrorIs(t, err, ErrWeightCap)
	})
	t.Run("largest admissible total", func(t *testing.T) {
		ws := make([]uint64, evmassign.MaxValidators)
		for i := range ws {
			ws[i] = MaxTotalWeight / evmassign.MaxValidators
		}
		p, c := coupled(t, ws...)
		x, err := NewWeightedRequestContext(p, crypto.SHA256, confHash(t, p), c)
		require.NoError(t, err)
		require.EqualValues(t, evmassign.MaxValidators*(MaxTotalWeight/evmassign.MaxValidators), x.TotalWeight())
		require.LessOrEqual(t, x.TotalWeight(), MaxTotalWeight)
	})
	t.Run("member count cap", func(t *testing.T) {
		ws := make([]uint64, evmassign.MaxValidators+1)
		for i := range ws {
			ws[i] = 1
		}
		p, c := coupled(t, ws...)
		_, err := NewWeightedRequestContext(p, crypto.SHA256, confHash(t, p), c)
		require.ErrorIs(t, err, ErrWeightCap)
	})
	t.Run("duplicate identity and key", func(t *testing.T) {
		p, c := coupled(t, 1, 1, 1)
		p.Validators[1].NodeID = p.Validators[0].NodeID
		_, err := NewWeightedRequestContext(p, crypto.SHA256, confHash(t, p), c)
		require.ErrorIs(t, err, ErrDuplicateSigner)
		require.ErrorIs(t, err, evmassign.ErrCoupling, "a repeated identity is also not a bijection")
		p, c = coupled(t, 1, 1, 1)
		p.Validators[1].SigKey = p.Validators[0].SigKey
		_, err = NewWeightedRequestContext(p, crypto.SHA256, confHash(t, p), c)
		require.ErrorIs(t, err, ErrDuplicateKey)
	})
}

// MaxValidators (64) members of at most 2^40 weigh at most 2^46, so through NewWeightedRequestContext the 2^48 total cap
// can not be hit; it is kept as an independent guard and exercised here below the member-count check.
func TestTotalWeightCapIsAnIndependentGuard(t *testing.T) {
	n := int(MaxTotalWeight/MaxMemberWeight) + 1 // 257 members of 2^40 weigh more than 2^48
	vals := make([]*types.NodeInfo, n)
	for i := range vals {
		vals[i] = &types.NodeInfo{NodeID: fmt.Sprintf("e%03d", i), Stake: MaxMemberWeight}
	}
	for i := range vals {
		s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(append(make([]byte, 29), byte(i>>8), byte(i), 1))
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		vals[i].SigKey, err = v.MarshalPublicKey()
		require.NoError(t, err)
	}
	c := &RequestContext{policy: PolicyEVMWeighted}
	_, err := c.finish(pdr(evmassign.EVMPartitionTypeID, vals), func(v *types.NodeInfo) uint64 { return v.Stake }, 1, []byte("b"))
	require.ErrorIs(t, err, ErrWeightCap)
	// exactly at the cap is fine
	c = &RequestContext{policy: PolicyEVMWeighted}
	_, err = c.finish(pdr(evmassign.EVMPartitionTypeID, vals[:n-1]), func(v *types.NodeInfo) uint64 { return v.Stake }, 1, []byte("b"))
	require.NoError(t, err)
	require.EqualValues(t, MaxTotalWeight, c.total)
}

func TestContextAccessorsReturnCopies(t *testing.T) {
	p, c := coupled(t, 3, 2)
	ctx, err := NewWeightedRequestContext(p, crypto.SHA256, confHash(t, p), c)
	require.NoError(t, err)
	ctx.ConfHash()[0] ^= 0xff
	ctx.RootBodyID()[0] ^= 0xff
	ctx.NodeIDs()[0] = "x"
	require.Equal(t, confHash(t, p), ctx.ConfHash())
	require.Equal(t, []byte("body-7"), ctx.RootBodyID())
	require.Equal(t, []string{"e00", "e01"}, ctx.NodeIDs())
	c.RootBodyID[0] ^= 0xff // the caller's slice is not aliased
	require.Equal(t, []byte("body-7"), ctx.RootBodyID())
}

// Constructor inputs are copied: mutating the configuration or the coupling evidence after construction cannot change an
// established context (weights, members, threshold, identity).
func TestContextIsImmuneToConstructorInputMutation(t *testing.T) {
	p, c := coupled(t, 6, 1, 1, 1)
	ctx, err := NewWeightedRequestContext(p, crypto.SHA256, confHash(t, p), c)
	require.NoError(t, err)
	identity := ctx.Identity()

	p.Validators[0].Stake = 1
	p.Validators[0].NodeID = "mutated"
	p.Validators = p.Validators[:1]
	c.Root[0].Weight = 99
	c.Bindings[0].EVMNodeID = "mutated"

	require.Equal(t, identity, ctx.Identity())
	require.EqualValues(t, 9, ctx.TotalWeight())
	require.EqualValues(t, 5, ctx.Threshold())
	require.Equal(t, 4, ctx.MemberCount())
	w, err := ctx.SignerWeight("e00")
	require.NoError(t, err)
	require.EqualValues(t, 6, w)
	_, err = ctx.SignerWeight("mutated")
	require.ErrorIs(t, err, ErrUnknownSigner)
}

// NodeInfo.SigVerifier caches a verifier on the caller's NodeInfo; a context must verify with the key it was built from,
// not with a verifier cached for an earlier key.
func TestContextVerifierIgnoresCallerVerifierCache(t *testing.T) {
	signerA, err := abcrypto.NewInMemorySecp256K1SignerFromKey(append(make([]byte, 31), 1))
	require.NoError(t, err)
	signerB, err := abcrypto.NewInMemorySecp256K1SignerFromKey(append(make([]byte, 31), 2))
	require.NoError(t, err)
	p := pdr(1, nodeInfos(t, member{"a", 1}))
	_, err = p.Validators[0].SigVerifier() // caches the verifier of key A on the NodeInfo
	require.NoError(t, err)
	p.Validators[0].SigKey = key(t, 2) // key B afterwards

	ctx, err := NewUnitRequestContext(p, crypto.SHA256, confHash(t, p))
	require.NoError(t, err)
	ver, err := ctx.Verifier("a")
	require.NoError(t, err)
	data := []byte("request")
	sigB, err := signerB.SignBytes(data)
	require.NoError(t, err)
	sigA, err := signerA.SignBytes(data)
	require.NoError(t, err)
	require.NoError(t, ver.VerifyBytes(sigB, data))
	require.ErrorIs(t, ver.VerifyBytes(sigA, data), abcrypto.ErrVerificationFailed)
}

// A nil weighted member is refused by error before the coupling check dereferences it.
func TestWeightedNilMemberIsRefused(t *testing.T) {
	p, c := coupled(t, 1, 1)
	p.Validators[0] = nil
	ctx, err := NewWeightedRequestContext(p, crypto.SHA256, confHash(t, p), c)
	require.ErrorIs(t, err, ErrUnknownSigner)
	require.Nil(t, ctx)
	p, c = coupled(t, 1, 1)
	p.Validators[1].NodeID = ""
	_, err = NewWeightedRequestContext(p, crypto.SHA256, confHash(t, p), c)
	require.ErrorIs(t, err, ErrUnknownSigner)
}

// The shard is part of the identity, and as a string copied at construction it cannot change afterwards (ShardID's bits
// are unexported and have no mutator, so no caller input aliasing exists to test beyond this).
func TestIdentityBindsTheShard(t *testing.T) {
	left, right := types.ShardID{}.Split()
	var ids []string
	for _, sh := range []types.ShardID{{}, left, right} {
		p := pdr(1, nodeInfos(t, member{"a", 1}))
		p.ShardID = sh
		ctx, err := NewUnitRequestContext(p, crypto.SHA256, confHash(t, p))
		require.NoError(t, err)
		require.NotContains(t, ids, ctx.Identity())
		ids = append(ids, ctx.Identity())
	}
}
