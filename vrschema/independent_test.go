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
