package engineapi

// F2c §10's import-path negatives (cases 5, 6, 7 and 8) and the companion-shape refusals the W3
// correction fixes into the contract. Everything here drives Adapter.Verify through the mock Engine
// API, so each case is decided by the production path rather than by a helper that restates it.
//
// The negatives are constructed so they can actually fail: case 7 in particular would pass a
// re-selecting implementation only by coincidence, so the test also computes what re-selection would
// have derived and shows it differs.

import (
	"bytes"
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

// companionEnvelope builds the payload and companion a block for params would carry: the v0
// attributes every validator derives, the v1 commitment, and the two witnesses Seal would fill.
// Callers tamper with the returned envelope and then encode it, so a tamper is applied to the bytes
// the follower actually reads.
func companionEnvelope(t *testing.T, f *derivationFixture, params shardnode.RoundParams, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) (ProposalEnvelope, rootinput.Result) {
	t.Helper()
	attrs, err := DeriveAttributes(params, ParentHeader{Timestamp: 100})
	require.NoError(t, err)
	derived := f.derive(t, params.Round, params.Parent.Hash, uc, tr)
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

// 5. A payload whose extraData does not match the recomputed commitment is rejected, and the
// rejection is local: reth is never asked to execute it.
func TestAdapter_Verify_RejectsExtraDataThatDoesNotMatchTheRecomputedCommitment(t *testing.T) {
	h := newCompanionHarness(t, CursorNotActivated())
	defer h.close()

	uc, tr := h.f.cert(t, 4, 5, 50)
	parent := shardnode.BlockRef{Number: 4, Hash: shardnode.Hash(fixedHashBytes(0x01))}
	params := paramsFor(parent, uc, tr)
	envelope, derived := companionEnvelope(t, h.f, params, uc, tr)

	// The header claims a commitment other than the one this node derives. It is a well-formed
	// 32-byte value, so nothing about its shape gives it away.
	envelope.ExecutionPayload.ExtraData = bytes.Repeat([]byte{0x00}, 32)
	require.NotEqual(t, derived.Commitment[:], envelope.ExecutionPayload.ExtraData)

	status, err := h.adapter.Verify(context.Background(), blockFromEnvelope(t, envelope), params)
	require.ErrorIs(t, err, ErrCompanionCommitment, "the mismatch must be reported as itself")
	require.Equal(t, shardnode.StatusInvalid, status)
	require.Zero(t, h.sealCalls, "a wrong commitment must be refused before reth sees the payload")
}

// 6. Refusals stay distinct across the companion boundary: each rootinput class still arrives at the
// call site as itself (F2c §10 negative 6 / §8). Each case reaches Adapter.Verify with otherwise-valid
// bytes and differs only in one field, so the class it reports is the field's — ErrUnauthenticated,
// ErrWrongContext and ErrNotPinned all arrive distinguishably, and none is collapsed into a generic
// failure. There is deliberately no case expecting a VerifyCompanionWitnesses reason: that call is
// reached only with evidence this node has already derived and authenticated, so it cannot produce
// one, and the cursor refusal belongs to Derive as a rootinput class.
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
		{
			name: "bound certificate behind the committed cursor",
			verifier: func(f *derivationFixture) *VerifierContext {
				return f.verifier(CommittedCursor(60)) // the bound certificate is at root round 50
			},
			want:    rootinput.ErrNotPinned,
			notWant: ErrCompanionUnauthenticated,
		},
		{
			name: "companion rootInput is not the canonical derivation",
			tamper: func(t *testing.T, f *derivationFixture, env *ProposalEnvelope) {
				env.SealCompanion.RootInput = bytes.Repeat([]byte{0x7e}, len(env.SealCompanion.RootInput))
			},
			want:    ErrCompanionBinding,
			notWant: ErrCompanionCommitment,
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

// 7. Asymmetric delivery agrees. Node B holds a later valid repeat the proposer did not bind; node A
// holds only the bound certificate. Both validate the binding, so both accept and derive the same
// commitment. The test also derives from B's own certificate and shows the commitment differs, which
// is what re-selecting would have produced — so the test is capable of failing.
func TestAdapter_Verify_AsymmetricDeliveryAgreesOnTheBlockBoundCertificate(t *testing.T) {
	ctx := context.Background()
	h := newCompanionHarness(t, CursorNotActivated())
	defer h.close()

	bound, boundTR := h.f.cert(t, 4, 5, 50)
	repeat, repeatTR := h.f.cert(t, 4, 5, 60) // same input record and technical record, later root round
	require.NotEqual(t, bound.UnicitySeal.RootChainRoundNumber, repeat.UnicitySeal.RootChainRoundNumber)

	parent := shardnode.BlockRef{Number: 4, Hash: shardnode.Hash(fixedHashBytes(0x01))}
	// The block the leader disseminated is bound to `bound`, whichever certificate each follower
	// happens to hold.
	leaderParams := paramsFor(parent, bound, boundTR)
	envelope, derived := companionEnvelope(t, h.f, leaderParams, bound, boundTR)
	block := blockFromEnvelope(t, envelope)

	nodeAParams := paramsFor(parent, bound, boundTR)
	nodeBParams := paramsFor(parent, repeat, repeatTR) // node B's own view

	statusA, err := h.adapter.Verify(ctx, block, nodeAParams)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, statusA)

	statusB, err := h.adapter.Verify(ctx, block, nodeBParams)
	require.NoError(t, err, "node B accepts the same block even though its own inbox holds the repeat")
	require.Equal(t, shardnode.StatusValid, statusB)
	require.Equal(t, 2, h.sealCalls, "both nodes reached newPayloadWithSealV1")

	// Capability to fail: had node B re-selected from its own view, it would have derived these
	// bytes, which are not the ones the block commits to.
	rePicked := h.f.derive(t, nodeBParams.Round, nodeBParams.Parent.Hash, repeat, repeatTR)
	require.False(t, bytes.Equal(rePicked.Encoded, envelope.SealCompanion.RootInput),
		"re-selecting from node B's own certificate would derive different bytes for this block")
	require.NotEqual(t, rePicked.Commitment, derived.Commitment, "and a different commitment")
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

	parent := shardnode.BlockRef{Number: 4, Hash: shardnode.Hash(fixedHashBytes(0x01))}
	params := shardnode.RoundParams{Round: 5, Timestamp: 1000, SealHash: shardnode.Hash(fixedHashBytes(0x99)), Parent: parent}
	attrs, err := DeriveAttributes(params, ParentHeader{Timestamp: 100})
	require.NoError(t, err)
	parentHash, err := toData32(parent.Hash)
	require.NoError(t, err)

	envelope := ProposalEnvelope{
		ExecutionPayload: ExecutionPayloadV3{
			ParentHash: parentHash, Timestamp: attrs.Timestamp, PrevRandao: attrs.PrevRandao,
			FeeRecipient: attrs.SuggestedFeeRecipient, Withdrawals: []WithdrawalV1{}, Transactions: []data{{0xaa}},
		},
	}
	status, err := a.Verify(context.Background(), blockFromEnvelope(t, envelope), params)
	require.ErrorContains(t, err, "no verifier context")
	require.Equal(t, shardnode.StatusInvalid, status)
}
