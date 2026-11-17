package vrschema

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Hand-written expectations for the boundaries the VT-16 reviews named; none is computed by the generator.

func TestCandidateListsAreArraysAndNullIsRefused(t *testing.T) {
	c := CandidateV6{Version: 6, Kind: evmassign.KindPrimary, Predecessor: wb("p"), SourceRef: wb("r")}
	enc, err := c.Encode()
	require.NoError(t, err)
	var g []any
	require.NoError(t, types.Cbor.Unmarshal(enc, &g))
	f := g[1].([]any)
	for _, i := range []int{5, 9, 11, 12, 17} { // RootMembers, PoPs, Bindings, Identities, RegistryChanges
		require.Equal(t, []any{}, f[i], "field %d", i)
	}
	require.Nil(t, f[15]) // Changes is null
	null, err := types.Cbor.Marshal([]any{candidateDomain, c})
	require.NoError(t, err)
	require.NotEqual(t, enc, null)
	_, err = DecodeCandidateV6(null)
	require.ErrorIs(t, err, ErrCanonical)
}

func TestInvalidateReasonZeroIsANoOpEverywhere(t *testing.T) {
	m := NewVRModel(fxModule)
	r := w("r")
	changed, err := m.Invalidate(r, fxModule, 0) // unknown id
	require.NoError(t, err)
	require.False(t, changed)
	require.NoError(t, m.Reserve(r, fxModule, false, nil, 0, MinEpochGap))
	changed, err = m.Invalidate(r, fxModule, 0)
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, OutReserved, m.Outputs[r].State)
	_, err = m.Invalidate(r, fxOther, 0)
	require.ErrorIs(t, err, ErrNotSource)
}

func TestPDRPartitionBytes(t *testing.T) {
	p, err := PDRPartition([]byte{0xd9, 0x98, 0x60, 0x83, 0x01, 0x03, 0x1a, 0x00, 0x01, 0x11, 0x70})
	require.NoError(t, err)
	require.Equal(t, uint32(70000), p)
	for _, bad := range [][]byte{{0x83, 1, 3, 9}, {0xd9, 0x98, 0x61, 0x83, 1, 3, 9}, {0xd9, 0x98, 0x60, 0x82, 1, 3}, {0xd9, 0x98, 0x60, 0x83, 1, 3, 0x19, 0, 9},
		{0xd9, 0x98, 0x60, 0x83, 1, 3, 0x1b, 0, 0, 0, 1, 0, 0, 0, 0}} {
		_, err := PDRPartition(bad)
		require.ErrorIs(t, err, ErrScope, "%x", bad)
	}
}

func TestProofPredicateIgnoresTheBuild(t *testing.T) {
	require.NoError(t, ProofConfigValid(map[string]string{"proof_type": "aggregator_zk_v1"})) // needs an FFI build to verify, still valid
	require.ErrorIs(t, ProofConfigValid(map[string]string{"proof_type": "risc0"}), ErrProofType)
	require.ErrorIs(t, ProofConfigValid(map[string]string{"proof_type": "sp1", "vkey_path": "/k", "chain_id": "-1"}), ErrProofChainID)
}

func TestRootNeverRestartsAtZero(t *testing.T) {
	rm := NewRootModel(1)
	rm.Control = ControlState{Kind: CtlAborted, Attempt: ^uint64(0)}
	require.ErrorIs(t, rm.Prepare(w("R"), 1), ErrHandoffApproval)
	require.Equal(t, ^uint64(0), rm.Control.Attempt)
	rm.Control = ControlState{Kind: CtlPrepared, Attempt: 7, OrderedRound: ^uint64(0) - 20}
	require.False(t, rm.Quiet(^uint64(0)-10))
	require.False(t, rm.Quiet(^uint64(0)))
}

func TestScopedSingletonsDefer(t *testing.T) {
	s1 := mustChange(KindScheduleActivation, RuleID("r"), w("1"), uint64(20), uint64(0), "")
	s2 := mustChange(KindScheduleActivation, RuleID("r"), w("2"), uint64(30), uint64(0), "")
	a, _ := ChangeScope(KindScheduleActivation, s1)
	b, _ := ChangeScope(KindScheduleActivation, s2)
	require.Equal(t, a, b)
	bound, deferred := SelectBinding([]BindCandidate{{ID: 1, Kind: KindScheduleActivation, Scope: a}, {ID: 2, Kind: KindScheduleActivation, Scope: b}})
	require.Equal(t, []uint64{1}, bound)
	require.Equal(t, []uint64{2}, deferred)
	require.Error(t, CheckRegistryChanges([]RegistryChange{{ID: 1, Kind: 9, Payload: s1}, {ID: 2, Kind: 9, Payload: s2}}))
}

// sol round 2: embedded encodings are judged before the scope, in both orders.
func TestMalformedEmbeddingsClaimNoScope(t *testing.T) {
	agg := fxPDR(7, 3, 2, 0, 3)
	in := FoldInput{Network: fxRootNetwork, SuccessorRootEpoch: 6, PartitionCeiling: PartitionCeiling,
		Installed: map[ShardKey]*types.PartitionDescriptionRecord{{7, string(agg.ShardID.Bytes())}: agg}}
	good := fxPDR(7, 3, 3, 0, 3)
	good.Validators = agg.Validators
	good.T2Timeout += 500_000_000
	valid := RegistryChange{Kind: 8, Payload: mustChange(KindUpdatePartition, uint64(7), agg.ShardID.Bytes(), pdrHash(agg), mustCBOR(good))}
	bad := RegistryChange{Kind: 8, Payload: mustChange(KindUpdatePartition, uint64(7), agg.ShardID.Bytes(), pdrHash(agg), []byte{0x80})}
	addPDR := fxPDR(9, 3, 0, 20, 2)
	addOK := func(id uint64) RegistryChange {
		return RegistryChange{Kind: 7, Payload: mustChange(KindAddPartition, mustCBOR(addPDR), fxChangePoPs(id, addPDR, 20))}
	}
	addBad := RegistryChange{Kind: 7, Payload: mustChange(KindAddPartition, mustCBOR(addPDR), []byte{0x83, 1, 2, 3})}
	for _, c := range []struct {
		a, b RegistryChange
		want []uint8
	}{
		{bad, valid, []uint8{VerdictMalformed, VerdictAccepted}},
		{valid, bad, []uint8{VerdictAccepted, VerdictMalformed}},
		{addBad, addOK(3), []uint8{VerdictMalformed, VerdictAccepted}},
		{addOK(2), addBad, []uint8{VerdictAccepted, VerdictMalformed}},
	} {
		c.a.ID, c.b.ID = 2, 3
		got, err := FoldVerdicts(in, []RegistryChange{c.a, c.b})
		require.NoError(t, err)
		require.Equal(t, c.want, got)
	}
}

// astra round 2: a null change-PoP list is Malformed; an empty array with validators required is BadPoP; chain_id is canonical decimal.
func TestNullPoPsAndChainIDGrammar(t *testing.T) {
	in := FoldInput{Network: fxRootNetwork, SuccessorRootEpoch: 6, PartitionCeiling: PartitionCeiling}
	pdr := mustCBOR(fxPDR(9, 3, 0, 20, 2))
	got, err := FoldVerdicts(in, []RegistryChange{{ID: 2, Kind: 7, Payload: mustChange(KindAddPartition, pdr, []byte{0xf6})}})
	require.NoError(t, err)
	require.Equal(t, []uint8{VerdictMalformed}, got)
	got, err = FoldVerdicts(in, []RegistryChange{{ID: 2, Kind: 7, Payload: mustChange(KindAddPartition, pdr, []byte{0x80})}})
	require.NoError(t, err)
	require.Equal(t, []uint8{VerdictBadPoP}, got)
	for _, ok := range []string{"0", "3", "31337", "18446744073709551615"} {
		require.NoError(t, ProofConfigValid(map[string]string{"proof_type": "light_client", "chain_id": ok}), ok)
	}
	for _, bad := range []string{"00", "03", "00018446744073709551615", "+3", "-3", " 3", "3 ", "3_000", "0x3", "18446744073709551616", ""} {
		require.ErrorIs(t, ProofConfigValid(map[string]string{"proof_type": "light_client", "chain_id": bad}), ErrProofChainID, bad)
	}
}
