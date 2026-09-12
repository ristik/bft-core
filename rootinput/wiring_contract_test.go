package rootinput

/*
#10 wiring-contract negatives, for docs/design/f2c-root-input-wiring-contract.md §10.

Each case is decidable against the tree as it stands, before any call site is wired, and each one
establishes a premise the wiring unit would otherwise have to take on faith. Three of them are
negatives in an unusual sense: they demonstrate that Derive CANNOT catch a particular substitution,
because the substituted value arrives as a pinned input it is required to trust. Those are the cases
that decide where the wiring unit has to be careful, so they are pinned here rather than argued.

Nothing here activates anything. No production call site changes and v0 still governs every block.
*/

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// v0PrevRandao and v0BeaconRoot restate what engineapi/params.go computes today, so this file can
// compare the two derivations without importing an unexported helper or changing production code.
// D1 §4 describes exactly this: one-byte prefixes over raw concatenation, keyed by (u, n).
func v0Domain(prefix byte, sealHash []byte, shardRound uint64) [32]byte {
	buf := make([]byte, 0, 1+len(sealHash)+8)
	buf = append(buf, prefix)
	buf = append(buf, sealHash...)
	var be [8]byte
	binary.BigEndian.PutUint64(be[:], shardRound)
	return sha256.Sum256(append(buf, be[:]...))
}

// 1. A mixed v0/v1 deployment is a consensus split, not a cosmetic difference.
func TestWiring_V0AndV1DisagreeForTheSameRound(t *testing.T) {
	f := newFixture(t)
	uc, tr := f.successful(t)
	res, err := Derive(context.Background(), f.context(), uc, tr)
	require.NoError(t, err)

	const shardRound = 5
	sealHash := uc.UnicitySeal.Hash
	rootRound := uc.UnicitySeal.RootChainRoundNumber

	// The v0 derivation this branch runs, against the v1 derivation D1 §4 specifies.
	v0Randao := v0Domain(0x01, sealHash, shardRound)
	v0Beacon := v0Domain(0x02, sealHash, shardRound)
	v1Randao := evmroot.DerivePrevRandao(rootRound, shardRound)
	v1Beacon := evmroot.DeriveBeaconRoot(rootRound, shardRound)

	require.NotEqual(t, v0Randao[:], v1Randao[:], "prevRandao must differ, or 'v1 replaces v0 wholesale' would be untrue")
	require.NotEqual(t, v0Beacon[:], v1Beacon[:], "parentBeaconBlockRoot must differ for the same reason")

	// And the keys really are different quantities, not the same number arrived at twice: v0 keys on
	// the seal hash, v1 on the root round.
	require.NotEqual(t, rootRound, shardRound, "the fixture must not make (u,n) and (r,n) coincide")
	require.NotEmpty(t, res.Encoded, "v1 additionally commits the whole input, which v0 has no field for")
}

// 2. The parameters an executor sees today cannot authenticate anything, and widening them with the
// root round would not change that.
func TestWiring_TodaysRoundParamsCannotAuthenticate(t *testing.T) {
	f := newFixture(t)
	uc, tr := f.successful(t)

	// What produceBlock hands an executor for a genuine round: four scalars, a seal hash, a leader
	// name and a parent reference. The certificate does not travel with it.
	genuine := shardnode.RoundParams{
		Round: 5, Epoch: 0, Timestamp: uc.UnicitySeal.Timestamp,
		SealHash: shardnode.Hash(uc.UnicitySeal.Hash), Leader: tr.Leader,
		Parent: shardnode.BlockRef{Hash: shardnode.Hash(f.parent)},
	}

	// The same structure, fully populated, authorized by nothing at all.
	fabricated := shardnode.RoundParams{
		Round: 5, Epoch: 0, Timestamp: uc.UnicitySeal.Timestamp,
		SealHash: shardnode.Hash(bytes.Repeat([]byte{0x77}, 32)), Leader: tr.Leader,
		Parent: shardnode.BlockRef{Hash: shardnode.Hash(f.parent)},
	}

	// Both are well formed, and every field an executor can read is of the same kind in both. A seal
	// hash is a value, not a certificate: it carries no quorum, no inclusion path and no trust base,
	// so no executor holding one can tell these apart.
	require.Len(t, genuine.SealHash, 32)
	require.Len(t, fabricated.SealHash, 32)
	require.Equal(t, genuine.Round, fabricated.Round)
	require.Equal(t, genuine.Parent, fabricated.Parent)
	require.NotEqual(t, genuine.SealHash, fabricated.SealHash,
		"they differ, but only in a value neither of them lets anyone check")

	// Adding the root round does not help: the v1 derivations are total functions of two integers,
	// so an invented root round produces output as well formed as a certified one.
	const invented = uint64(999)
	real := evmroot.DerivePrevRandao(uc.UnicitySeal.RootChainRoundNumber, 5)
	fake := evmroot.DerivePrevRandao(invented, 5)
	require.Len(t, real, 32)
	require.Len(t, fake, 32)
	require.NotEqual(t, real, fake,
		"a fabricated root round derives cleanly, so authentication cannot live in the derivation")

	// Which is the contract: the parameters must carry the authenticated authorization itself, so
	// the executor checks a certificate rather than trusting a summary of one.
	res, err := Derive(context.Background(), f.context(), uc, tr)
	require.NoError(t, err)
	require.NotNil(t, res.Certificate, "Derive returns the authenticated certificate, which is what must travel")
	require.NotNil(t, res.Technical)
}

// 3. Derive cannot tell a certified parent from an executor head, because the parent is pinned.
func TestWiring_ExecutorHeadIsAcceptedAsTheCertifiedParent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	uc, tr := f.successful(t)

	certifiedParent := f.parent
	// What a node would hold after a quiet tail: the executor has moved on, so its head is not the
	// last state-changing certified block.
	executorHead := bytes.Repeat([]byte{0x5e}, 32)
	require.NotEqual(t, certifiedParent, executorHead)

	good := f.context()
	good.ParentHash = certifiedParent
	wrong := f.context()
	wrong.ParentHash = executorHead

	resGood, err := Derive(ctx, good, uc, tr)
	require.NoError(t, err)
	resWrong, err := Derive(ctx, wrong, uc, tr)
	require.NoError(t, err, "the wrong parent is ACCEPTED: it is a pinned input, not a claim Derive can check")

	require.NotEqual(t, resGood.Commitment, resWrong.Commitment,
		"and it silently changes the commitment, so the wiring unit owns this sourcing rule")
}

// 4. The committed cursor cannot be replaced by the highest observed root round.
func TestWiring_ObservedMaximumIsNotTheCommittedCursor(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// An authorization from root round 50, and a node whose committed cursor has already advanced
	// past it: the binding is stale and must be refused.
	uc, tr := f.successful(t)
	committed := f.context()
	committed.LastAppliedRootRound = 60
	_, err := Derive(ctx, committed, uc, tr)
	require.ErrorIs(t, err, ErrNotPinned, "against the committed cursor the stale binding is refused")

	// The same certificate, with the cursor taken from what this node happens to have observed.
	observed := f.context()
	observed.LastAppliedRootRound = 40
	_, err = Derive(ctx, observed, uc, tr)
	require.NoError(t, err, "substituting an observed value makes the refusal disappear, and Derive cannot tell")
}

// 5. extraData is checkable on a payload, and absent from the attributes that would produce one.
func TestWiring_ExtraDataIsCheckableButNotProvisionable(t *testing.T) {
	f := newFixture(t)
	uc, tr := f.successful(t)
	res, err := Derive(context.Background(), f.context(), uc, tr)
	require.NoError(t, err)

	// The import-side check, as a pure comparison: a payload carrying the commitment passes, one
	// carrying anything else does not.
	payload := engineapi.ExecutionPayloadV3{ExtraData: res.Commitment[:]}
	require.True(t, bytes.Equal(payload.ExtraData, res.Commitment[:]))

	other := engineapi.ExecutionPayloadV3{ExtraData: bytes.Repeat([]byte{0x00}, 32)}
	require.False(t, bytes.Equal(other.ExtraData, res.Commitment[:]), "a mismatching commitment is detectable")

	// A payload built through the stock attributes carries NOTHING to compare: PayloadAttributesV3
	// has no extraData field, so a builder using the standard Engine API cannot ask for the
	// commitment to be written. Enforcing the check without the execution-side provision mechanism
	// therefore halts the builder rather than protecting it (§5 of the contract).
	empty := engineapi.ExecutionPayloadV3{}
	require.Empty(t, empty.ExtraData)
	require.False(t, bytes.Equal(empty.ExtraData, res.Commitment[:]))

	// If a later Engine API revision adds the field, this assertion is what should fail, so the
	// contract's central dependency is re-examined rather than silently satisfied.
	var names []string
	rt := reflect.TypeOf(engineapi.PayloadAttributesV3{})
	for i := 0; i < rt.NumField(); i++ {
		names = append(names, rt.Field(i).Name)
	}
	require.NotContains(t, names, "ExtraData",
		"PayloadAttributesV3 must still have no extraData field, or §5's dependency has changed")
}

// 6. Each refusal still arrives as itself, so a call site cannot collapse them.
func TestWiring_RefusalsStayDistinct(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	uc, tr := f.successful(t)

	for _, tc := range []struct {
		name string
		want error
		ctxf func(Context) Context
	}{
		{"wrong configuration", ErrUnauthenticated, func(c Context) Context {
			c.ShardConfHash = bytes.Repeat([]byte{0x11}, 32)
			return c
		}},
		{"wrong network", ErrWrongContext, func(c Context) Context { c.NetworkID = testNetworkID + 1; return c }},
		{"unpinned round", ErrNotPinned, func(c Context) Context { c.Round = 9; return c }},
		{"stale cursor", ErrNotPinned, func(c Context) Context { c.LastAppliedRootRound = 60; return c }},
		{"incomplete context", ErrContextIncomplete, func(c Context) Context { c.ParentHash = nil; return c }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Derive(ctx, tc.ctxf(f.context()), uc, tr)
			require.ErrorIs(t, err, tc.want)
		})
	}

	// The premise: unmodified, the same inputs derive.
	_, err := Derive(ctx, f.context(), uc, tr)
	require.NoError(t, err)
}
