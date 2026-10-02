package engineapi

// F2c §10's import-path negatives (cases 5, 6, 7 and 8) and the companion-shape refusals the W3
// correction fixes into the contract. Everything here drives Adapter.Verify through the mock Engine
// API, so each case is decided by the production path rather than by a helper that restates it.
//
// The negatives are constructed so they can actually fail: case 7 in particular would pass a
// re-selecting implementation only by coincidence, so the test also computes what re-selection would
// have derived and shows it differs.

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// companionHarness is a follower-side fixture: a derivation fixture, a mock engine that counts which
// newPayload method arrives, and an adapter configured to authenticate.
type companionHarness struct {
	f       *derivationFixture
	adapter *Adapter
	engine  *mockReth
	close   func()

	sealCalls int
	v3Calls   int
}

func newCompanionHarness(t *testing.T, cursor SealRegistryCursor) *companionHarness {
	t.Helper()
	return newCompanionHarnessWithVerifier(t, func(f *derivationFixture) *VerifierContext {
		return f.verifier(cursor)
	})
}

func newCompanionHarnessWithVerifier(t *testing.T, verifier func(*derivationFixture) *VerifierContext) *companionHarness {
	t.Helper()
	f := newDerivationFixture(t)
	h := &companionHarness{f: f}

	engine := newMockReth(t, Secret{})
	engine.on("engine_newPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		h.sealCalls++
		return PayloadStatusV1{Status: PayloadStatusValid}, nil
	})
	engine.on("engine_newPayloadV3", func(json.RawMessage) (any, *rpcError) {
		h.v3Calls++
		return PayloadStatusV1{Status: PayloadStatusValid}, nil
	})

	eth := newMockReth(t, Secret{})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Timestamp: 100}, nil
	})

	h.engine = engine
	h.adapter, h.close = newTestAdapterWithVerifier(t, engine, eth, verifier(f))
	return h
}

// paramsFor is the RoundParams both the leader and this follower hold for a round. The follower's own
// authorizing certificate is deliberately part of it, so a re-selecting implementation has something
// wrong to select.
func paramsFor(parent shardnode.BlockRef, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) shardnode.RoundParams {
	return shardnode.RoundParams{
		Round: 5, Timestamp: 1000, SealHash: shardnode.Hash(fixedHashBytes(0x99)), Leader: tr.Leader,
		Parent:                     parent,
		AuthorizingCertificate:     uc,
		AuthorizingTechnicalRecord: tr,
	}
}

// companionEnvelope builds the payload and companion a block for params would carry: the v1
// attributes every validator derives from the authenticated input, the commitment, and the two
// witnesses Seal would fill. Callers tamper with the returned envelope and then encode it, so a
// tamper is applied to the bytes the follower actually reads.
func companionEnvelope(t *testing.T, f *derivationFixture, params shardnode.RoundParams, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) (ProposalEnvelope, rootinput.Result) {
	t.Helper()
	derived := f.derive(t, params.Round, params.Parent.Hash, uc, tr)
	attrs := DeriveAttributes(derived.Input, ParentHeader{Timestamp: 100})
	companion := f.sealCompanion(t, derived)
	parentHash, err := toData32(params.Parent.Hash)
	require.NoError(t, err)

	envelope := ProposalEnvelope{
		ExecutionPayload: ExecutionPayloadV3{
			ParentHash:   parentHash,
			Timestamp:    attrs.Timestamp,
			PrevRandao:   attrs.PrevRandao,
			FeeRecipient: attrs.SuggestedFeeRecipient,
			ExtraData:    derived.Commitment[:],
			Withdrawals:  []WithdrawalV1{},
			Transactions: []data{{0xaa}},
		},
		ExpectedBlobVersionedHashes: []data32{},
		SealCompanion:               &companion,
	}
	return envelope, derived
}

func blockFromEnvelope(t *testing.T, envelope ProposalEnvelope) shardnode.Block {
	t.Helper()
	raw, err := json.Marshal(envelope)
	require.NoError(t, err)
	return shardnode.Block{Raw: raw}
}

// 6. Refusals stay distinct across the companion boundary: each rootinput class still arrives at the
// call site as itself (F2c §10 negative 6 / §8). Each case reaches Adapter.Verify with otherwise-valid
// bytes and differs only in one field, so the class it reports is the field's — ErrUnauthenticated
// and ErrWrongContext arrive distinguishably, and neither is collapsed into a generic
// failure. Cases requiring a verified v2 parent are exercised by adapter_v2_continuation_test.go.
func TestAdapter_Verify_RefusalClassesStayDistinctAcrossTheCompanionBoundary(t *testing.T) {
	cases := []struct {
		name     string
		verifier func(*derivationFixture) *VerifierContext
		tamper   func(*testing.T, *derivationFixture, *ProposalEnvelope)
		want     error
		notWant  error
	}{
		{
			name: "substituted certificate for another configuration",
			tamper: func(t *testing.T, f *derivationFixture, env *ProposalEnvelope) {
				// Authentic, signed by the same quorum, and for a different configuration. A
				// follower that trusted the proposer's choice would accept it.
				other := &types.PartitionDescriptionRecord{Version: 1, NetworkID: fixtureNetworkID, PartitionID: fixturePartitionID, T2Timeout: 4_000_000_000}
				otherUC, otherTR := f.certWithPDR(t, other, 4, 5, 50, 3)
				w, err := encodeSealCompanionWitnesses(otherUC, otherTR)
				require.NoError(t, err)
				env.SealCompanion.Witnesses = w
			},
			want:    rootinput.ErrUnauthenticated,
			notWant: rootinput.ErrWrongContext,
		},
		{
			name: "unauthenticated certificate below quorum",
			tamper: func(t *testing.T, f *derivationFixture, env *ProposalEnvelope) {
				subUC, subTR := f.certWithPDR(t, f.pdr, 4, 5, 50, 1)
				w, err := encodeSealCompanionWitnesses(subUC, subTR)
				require.NoError(t, err)
				env.SealCompanion.Witnesses = w
			},
			want:    rootinput.ErrUnauthenticated,
			notWant: rootinput.ErrNotPinned,
		},
		{
			name: "certificate for another network",
			verifier: func(f *derivationFixture) *VerifierContext {
				v := f.verifier(CursorNotActivated())
				v.NetworkID = fixtureNetworkID + 1
				return v
			},
			want:    rootinput.ErrWrongContext,
			notWant: rootinput.ErrUnauthenticated,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			makeVerifier := tc.verifier
			if makeVerifier == nil {
				makeVerifier = func(f *derivationFixture) *VerifierContext { return f.verifier(CursorNotActivated()) }
			}
			h := newCompanionHarnessWithVerifier(t, makeVerifier)
			defer h.close()

			uc, tr := h.f.cert(t, 4, 5, 50)
			parent := shardnode.BlockRef{Number: 4, Hash: shardnode.Hash(fixedHashBytes(0x01))}
			params := paramsFor(parent, uc, tr)
			envelope, _ := companionEnvelope(t, h.f, params, uc, tr)
			if tc.tamper != nil {
				tc.tamper(t, h.f, &envelope)
			}

			status, err := h.adapter.Verify(context.Background(), blockFromEnvelope(t, envelope), params)
			require.ErrorIs(t, err, tc.want, "the refusal must arrive as its own class")
			require.False(t, errors.Is(err, tc.notWant), "and must not be collapsed into another class")
			require.Equal(t, shardnode.StatusInvalid, status)
			require.Zero(t, h.sealCalls, "a refused companion must never reach reth")
		})
	}
}

// 8. Evidence yes, verdict no. A substituted or unauthenticated companion certificate is refused
// rather than accepted on the proposer's word, and no type on the path carries a field by which a
// caller could instead assert that something was already verified.
func TestAdapter_Verify_RefusesCompanionEvidenceItCannotAuthenticate(t *testing.T) {
	t.Run("an authentic certificate for another configuration is not this node's authority", func(t *testing.T) {
		h := newCompanionHarness(t, CursorNotActivated())
		defer h.close()

		uc, tr := h.f.cert(t, 4, 5, 50)
		parent := shardnode.BlockRef{Number: 4, Hash: shardnode.Hash(fixedHashBytes(0x01))}
		params := paramsFor(parent, uc, tr)
		envelope, _ := companionEnvelope(t, h.f, params, uc, tr)

		other := &types.PartitionDescriptionRecord{Version: 1, NetworkID: fixtureNetworkID, PartitionID: fixturePartitionID, T2Timeout: 4_000_000_000}
		otherUC, otherTR := h.f.certWithPDR(t, other, 4, 5, 50, 3)
		w, err := encodeSealCompanionWitnesses(otherUC, otherTR)
		require.NoError(t, err)
		envelope.SealCompanion.Witnesses = w

		status, err := h.adapter.Verify(context.Background(), blockFromEnvelope(t, envelope), params)
		require.ErrorIs(t, err, rootinput.ErrUnauthenticated)
		require.Equal(t, shardnode.StatusInvalid, status)
		require.Zero(t, h.sealCalls)
	})

	t.Run("no field lets a caller assert something was already verified", func(t *testing.T) {
		for _, typ := range []reflect.Type{
			reflect.TypeOf(shardnode.RoundParams{}),
			reflect.TypeOf(SealCompanion{}),
			reflect.TypeOf(ProposalEnvelope{}),
			reflect.TypeOf(rootinput.Context{}),
		} {
			for i := 0; i < typ.NumField(); i++ {
				name := typ.Field(i).Name
				for _, banned := range []string{"Verified", "Authenticated", "Trusted", "Checked", "Valid"} {
					require.NotContains(t, name, banned,
						"%s.%s looks like a caller-supplied verdict; the companion must be re-verified instead", typ, name)
				}
			}
		}
	})
}

// A block with no companion is refused, and the refusal does not fall through to the stock
// engine_newPayloadV3 path: a payload disseminated without one cannot be authenticated by anyone, so
// silently executing it would skip the boundary this unit installs.
func TestAdapter_Verify_MissingCompanionIsRefusedWithoutFallingBackToNewPayloadV3(t *testing.T) {
	h := newCompanionHarness(t, CursorNotActivated())
	defer h.close()

	uc, tr := h.f.cert(t, 4, 5, 50)
	parent := shardnode.BlockRef{Number: 4, Hash: shardnode.Hash(fixedHashBytes(0x01))}
	params := paramsFor(parent, uc, tr)
	envelope, _ := companionEnvelope(t, h.f, params, uc, tr)
	envelope.SealCompanion = nil

	status, err := h.adapter.Verify(context.Background(), blockFromEnvelope(t, envelope), params)
	require.ErrorIs(t, err, ErrCompanionMissing)
	require.Equal(t, shardnode.StatusInvalid, status)
	require.Zero(t, h.sealCalls)
	require.Zero(t, h.v3Calls, "a missing companion is a refusal, never a fallback to engine_newPayloadV3")
}

// A companion whose witness list is empty is refused with a message that says exactly that; any
// length other than the fixed two is refused the same way (a third entry must be a deliberate
// decision, not an accident).
func TestAdapter_Verify_RefusesAWrongWitnessCountAndSaysSo(t *testing.T) {
	cases := []struct {
		name      string
		witnesses func(t *testing.T, f *derivationFixture, env *ProposalEnvelope) []data
		wantCount string
	}{
		{
			name:      "empty list",
			witnesses: func(*testing.T, *derivationFixture, *ProposalEnvelope) []data { return []data{} },
			wantCount: "0 witnesses",
		},
		{
			name: "one entry",
			witnesses: func(_ *testing.T, _ *derivationFixture, env *ProposalEnvelope) []data {
				return env.SealCompanion.Witnesses[:1]
			},
			wantCount: "1 witnesses",
		},
		{
			name: "three entries",
			witnesses: func(_ *testing.T, _ *derivationFixture, env *ProposalEnvelope) []data {
				return append(append([]data{}, env.SealCompanion.Witnesses...), env.SealCompanion.Witnesses[0])
			},
			wantCount: "3 witnesses",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newCompanionHarness(t, CursorNotActivated())
			defer h.close()

			uc, tr := h.f.cert(t, 4, 5, 50)
			parent := shardnode.BlockRef{Number: 4, Hash: shardnode.Hash(fixedHashBytes(0x01))}
			params := paramsFor(parent, uc, tr)
			envelope, _ := companionEnvelope(t, h.f, params, uc, tr)
			envelope.SealCompanion.Witnesses = tc.witnesses(t, h.f, &envelope)

			status, err := h.adapter.Verify(context.Background(), blockFromEnvelope(t, envelope), params)
			require.ErrorIs(t, err, ErrCompanionWitnesses)
			require.Contains(t, err.Error(), tc.wantCount, "the message must say how many witnesses arrived")
			require.Contains(t, err.Error(), "exactly 2")
			require.Equal(t, shardnode.StatusInvalid, status)
			require.Zero(t, h.sealCalls)
		})
	}
}

// Without a derivation context there is nothing to authenticate the companion against, so Verify
// refuses rather than deriving against an invented trust base. (The doctor's adapter has no
// verifier; it does not call Verify.)
func TestAdapter_Verify_RefusesWithoutAVerifierContext(t *testing.T) {
	engine := newMockReth(t, Secret{})
	eth := newMockReth(t, Secret{})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Timestamp: 100}, nil
	})
	a, closeFn := newTestAdapter(t, engine, eth)
	defer closeFn()

	parent := shardnode.BlockRef{Number: 0, Hash: shardnode.Hash(fixedHashBytes(0x01))}
	params := shardnode.RoundParams{Round: 5, Timestamp: 1000, SealHash: shardnode.Hash(fixedHashBytes(0x99)), Parent: parent}
	parentHash, err := toData32(parent.Hash)
	require.NoError(t, err)

	// The payload need not match anything: since W4 the verifier-context refusal runs before any field
	// comparison, because without a configured context there is nothing to derive expected fields
	// from. A non-empty raw block with a 32-byte parent is all it takes to reach the refusal.
	envelope := ProposalEnvelope{
		ExecutionPayload: ExecutionPayloadV3{
			ParentHash: parentHash, Withdrawals: []WithdrawalV1{}, Transactions: []data{{0xaa}},
		},
	}
	status, err := a.Verify(context.Background(), blockFromEnvelope(t, envelope), params)
	require.ErrorContains(t, err, "no verifier context")
	require.Equal(t, shardnode.StatusInvalid, status)
}
