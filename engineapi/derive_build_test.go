package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// capturedSealBuild records what Adapter.Build sent to engine_forkchoiceUpdatedWithSealV1.
type capturedSealBuild struct {
	state ForkchoiceStateV1
	attrs UnicityPayloadAttributes
	input SealBuildInput
	calls int
}

// sealHarness wires an adapter over a derivation fixture and a mock engine that records the seal
// forkchoice parameters. It computes what rootinput.Derive independently produces for the same
// inputs, so the assertions compare against the derivation rather than against a literal.
type sealHarness struct {
	adapter *Adapter
	close   func()
	params  shardnode.RoundParams
	capture *capturedSealBuild
	want    rootinput.Result
}

func newSealHarness(t *testing.T, cursor SealRegistryCursor, payload ExecutionPayloadV3, companion SealCompanion) *sealHarness {
	t.Helper()
	f := newDerivationFixture(t)
	uc, tr := f.cert(t, 4, 5, 50)

	parentHash := fixedHash(0x01)
	params := shardnode.RoundParams{
		Round: 5, Timestamp: 1000, SealHash: shardnode.Hash(fixedHashBytes(0x99)), Leader: tr.Leader,
		Parent:                     shardnode.BlockRef{Number: 4, Hash: shardnode.Hash(parentHash[:]), StateRoot: shardnode.Hash(fixedHashBytes(0x03))},
		AuthorizingCertificate:     uc,
		AuthorizingTechnicalRecord: tr,
	}

	applied, err := cursor.appliedRootRound()
	require.NoError(t, err)
	want, err := rootinput.Derive(context.Background(), rootinput.Context{
		NetworkID: fixtureNetworkID, PartitionID: fixturePartitionID, ShardID: types.ShardID{},
		ShardConfHash: f.confHash, TrustBases: fixtureTrustBases{tb: f.tb},
		Round: 5, ParentHash: params.Parent.Hash, LastAppliedRootRound: applied,
	}, uc, tr)
	require.NoError(t, err)

	capture := &capturedSealBuild{}
	var payloadID data = []byte{1, 2, 3, 4, 5, 6, 7, 8}

	engine := newMockReth(t, Secret{})
	engine.on("engine_forkchoiceUpdatedWithSealV1", func(p json.RawMessage) (any, *rpcError) {
		var raw []json.RawMessage
		require.NoError(t, json.Unmarshal(p, &raw))
		require.Len(t, raw, 3)
		capture.calls++
		require.NoError(t, json.Unmarshal(raw[0], &capture.state))
		require.NoError(t, json.Unmarshal(raw[1], &capture.attrs))
		require.NoError(t, json.Unmarshal(raw[2], &capture.input))
		return ForkchoiceUpdatedResponse{
			PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid},
			PayloadID:     &payloadID,
		}, nil
	})
	engine.on("engine_getPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		return GetPayloadWithSealV1Response{ExecutionPayload: payload, SealCompanion: companion}, nil
	})

	eth := newMockReth(t, Secret{})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: 4, Hash: parentHash, Timestamp: 999}, nil
	})

	adapter, closeFn := newTestAdapterWithVerifier(t, engine, eth, f.verifier(cursor))
	return &sealHarness{adapter: adapter, close: closeFn, params: params, capture: capture, want: want}
}

func TestAdapter_BuildDerivesTheRootInputAndSendsTheSealSibling(t *testing.T) {
	h := newSealHarness(t, CursorNotActivated(), samplePayload(), *sampleCompanion())
	defer h.close()

	id, err := h.adapter.Build(context.Background(), h.params)
	require.NoError(t, err)
	require.NotEmpty(t, id)
	require.Equal(t, 1, h.capture.calls)

	require.Equal(t, h.want.Encoded, []byte(h.capture.input.RootInput),
		"rootInput must be exactly rootinput.Derive's canonical CBOR")
	require.Equal(t, data32(h.want.Commitment), h.capture.attrs.Commitment,
		"the commitment must be exactly rootinput.Derive's extraData")
	require.Empty(t, h.capture.input.Transitions, "transitions are empty, not an unauthenticated stand-in")

	// The standard V3 attributes are still v0-derived; only extraData is v1 in this unit. That
	// mixed state is the deliberate intermediate F2c §3 orders, and this pins it so a later
	// "cleanup" that switched the derivation early would fail here.
	v0, err := DeriveAttributes(h.params, ParentHeader{Timestamp: 999})
	require.NoError(t, err)
	require.Equal(t, v0.PrevRandao, h.capture.attrs.PrevRandao)
	require.Equal(t, v0.Timestamp, h.capture.attrs.Timestamp)
	require.Equal(t, v0.SuggestedFeeRecipient, h.capture.attrs.SuggestedFeeRecipient)
}

func TestAdapter_SealCarriesTheCompanionInTheEnvelope(t *testing.T) {
	// ureth returns witnesses empty; Seal must fill them with the bound authorization, exactly two
	// entries, in the canonical encoding. The rootInput and provenance ureth returned are preserved.
	companion := SealCompanion{RootInput: data{0x01, 0x02, 0x03}, Witnesses: []data{}, Provenance: "build"}
	h := newSealHarness(t, CursorNotActivated(), samplePayload(), companion)
	defer h.close()

	id, err := h.adapter.Build(context.Background(), h.params)
	require.NoError(t, err)
	block, err := h.adapter.Seal(context.Background(), id)
	require.NoError(t, err)
	require.NotEmpty(t, block.Raw, "a non-quiet block carries a proposal envelope")

	envelope, err := DecodeBlock(block)
	require.NoError(t, err)
	require.NotNil(t, envelope.SealCompanion, "the companion the far side returned must be in the envelope")
	require.Equal(t, companion.RootInput, envelope.SealCompanion.RootInput)
	require.Equal(t, companion.Provenance, envelope.SealCompanion.Provenance)

	wantWitnesses, err := encodeSealCompanionWitnesses(h.want.Certificate, h.want.Technical)
	require.NoError(t, err)
	require.Equal(t, wantWitnesses, envelope.SealCompanion.Witnesses,
		"Seal fills exactly [bound certificate, bound technical record]")
	require.Len(t, envelope.SealCompanion.Witnesses, SealCompanionWitnessCount)

	// The filled witnesses are the actual authorization, not labels: decode them and require the
	// certificate and record back.
	uc, tr, err := decodeSealCompanionWitnesses(envelope.SealCompanion.Witnesses)
	require.NoError(t, err)
	require.Equal(t, h.want.Certificate, uc)
	require.Equal(t, h.want.Technical, tr)
}

func TestBlockSizeIsUnchangedByTheCompanion(t *testing.T) {
	payload := samplePayload()
	without, err := EncodeBlock(payload)
	require.NoError(t, err)
	with, err := EncodeBlockWithSealCompanion(payload, sampleCompanion())
	require.NoError(t, err)

	require.Equal(t, without.BlockSize, with.BlockSize,
		"the companion is envelope-only and must not enter BlockSize")
	require.Greater(t, len(with.Raw), len(without.Raw), "but it must be in the envelope")
}

func TestSealRegistryCursorZeroValueIsRefusedNotTreatedAsCursorZero(t *testing.T) {
	// A bare 0 cursor deletes evmroot.ValidateBoundCertificate's stale-cursor refusal, so the zero
	// value must never resolve to a usable cursor.
	if _, err := (SealRegistryCursor{}).appliedRootRound(); err == nil {
		t.Fatal("the zero SealRegistryCursor must not resolve to a usable cursor")
	}

	// And through the adapter: the zero cursor refuses Build before any derivation or RPC. The
	// engine URL is unreachable, so reaching the transport would produce a different error.
	f := newDerivationFixture(t)
	uc, tr := f.cert(t, 4, 5, 50)
	a := NewAdapter(Config{EngineURL: "http://127.0.0.1:1", EthURL: "http://127.0.0.1:1", Secret: Secret{}, Verifier: f.verifier(SealRegistryCursor{})}, nil)

	_, err := a.Build(context.Background(), shardnode.RoundParams{
		Round: 5, Parent: shardnode.BlockRef{Hash: f.parent},
		AuthorizingCertificate: uc, AuthorizingTechnicalRecord: tr,
	})
	require.ErrorContains(t, err, "cursor was never constructed")
}

func TestCommittedCursorRefusesACertificateBehindIt(t *testing.T) {
	f := newDerivationFixture(t)
	uc, tr := f.cert(t, 4, 5, 50) // root round 50
	a := NewAdapter(Config{EngineURL: "http://127.0.0.1:1", EthURL: "http://127.0.0.1:1", Secret: Secret{}, Verifier: f.verifier(CommittedCursor(60))}, nil)

	_, err := a.Build(context.Background(), shardnode.RoundParams{
		Round: 5, Parent: shardnode.BlockRef{Hash: f.parent},
		AuthorizingCertificate: uc, AuthorizingTechnicalRecord: tr,
	})
	require.ErrorIs(t, err, rootinput.ErrNotPinned,
		"a certificate whose root round is behind the committed cursor must be refused")
}

func TestAdapter_BuildKeepsRootInputRefusalClassesDistinct(t *testing.T) {
	cases := []struct {
		name     string
		verifier func(*derivationFixture) *VerifierContext
		mutate   func(*shardnode.RoundParams)
		want     error
		notWant  error
	}{
		{
			name: "wrong network",
			verifier: func(f *derivationFixture) *VerifierContext {
				v := f.verifier(CursorNotActivated())
				v.NetworkID = fixtureNetworkID + 1
				return v
			},
			want:    rootinput.ErrWrongContext,
			notWant: rootinput.ErrNotPinned,
		},
		{
			name:     "certificate behind the committed cursor",
			verifier: func(f *derivationFixture) *VerifierContext { return f.verifier(CommittedCursor(60)) },
			want:     rootinput.ErrNotPinned,
			notWant:  rootinput.ErrWrongContext,
		},
		{
			name:     "missing authorizing certificate",
			verifier: func(f *derivationFixture) *VerifierContext { return f.verifier(CursorNotActivated()) },
			mutate:   func(p *shardnode.RoundParams) { p.AuthorizingCertificate = nil },
			want:     rootinput.ErrContextIncomplete,
			notWant:  rootinput.ErrNotPinned,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newDerivationFixture(t)
			uc, tr := f.cert(t, 4, 5, 50)
			params := shardnode.RoundParams{
				Round: 5, Parent: shardnode.BlockRef{Hash: f.parent},
				AuthorizingCertificate: uc, AuthorizingTechnicalRecord: tr,
			}
			if tc.mutate != nil {
				tc.mutate(&params)
			}
			a := NewAdapter(Config{EngineURL: "http://127.0.0.1:1", EthURL: "http://127.0.0.1:1", Secret: Secret{}, Verifier: tc.verifier(f)}, nil)

			_, err := a.Build(context.Background(), params)
			require.ErrorIs(t, err, tc.want, "the refusal must arrive as its own class")
			require.False(t, errors.Is(err, tc.notWant), "and must not be collapsed into another class")
		})
	}
}

func TestAdapter_LogsTheUnactivatedCursorAtStartupAndOnlyThen(t *testing.T) {
	f := newDerivationFixture(t)

	var unactivated bytes.Buffer
	_ = NewAdapter(Config{EngineURL: "http://127.0.0.1:1", EthURL: "http://127.0.0.1:1", Secret: Secret{}, Verifier: f.verifier(CursorNotActivated())},
		slog.New(slog.NewTextHandler(&unactivated, nil)))
	require.Equal(t, 1, strings.Count(unactivated.String(), "cursor rule is NOT activated"),
		"the unactivated cursor is reported exactly once, at construction")

	// An activated cursor is not a warning.
	var committed bytes.Buffer
	_ = NewAdapter(Config{EngineURL: "http://127.0.0.1:1", EthURL: "http://127.0.0.1:1", Secret: Secret{}, Verifier: f.verifier(CommittedCursor(50))},
		slog.New(slog.NewTextHandler(&committed, nil)))
	require.Empty(t, committed.String(), "an activated cursor logs nothing")

	// An adapter with no derivation context (the doctor's) does not log a cursor decision at all.
	var doctor bytes.Buffer
	_ = NewAdapter(Config{EngineURL: "http://127.0.0.1:1", EthURL: "http://127.0.0.1:1", Secret: Secret{}},
		slog.New(slog.NewTextHandler(&doctor, nil)))
	require.Empty(t, doctor.String(), "no verifier context, nothing to say about a cursor")
}

// TestPayloadAttributesHaveNoExtraDataAndTheCommitmentIsCheckable is the rootinput
// wiring-contract §5/§10-5 case, relocated here because it asserts on this package's types and
// engineapi now imports rootinput (which would make importing engineapi from a rootinput test a
// cycle).
func TestPayloadAttributesHaveNoExtraDataAndTheCommitmentIsCheckable(t *testing.T) {
	f := newDerivationFixture(t)
	uc, tr := f.cert(t, 4, 5, 50)
	res, err := rootinput.Derive(context.Background(), rootinput.Context{
		NetworkID: fixtureNetworkID, PartitionID: fixturePartitionID, ShardID: types.ShardID{},
		ShardConfHash: f.confHash, TrustBases: fixtureTrustBases{tb: f.tb},
		Round: 5, ParentHash: f.parent, LastAppliedRootRound: 0,
	}, uc, tr)
	require.NoError(t, err)

	// The import-side check, as a pure comparison: a payload carrying the commitment passes, one
	// carrying anything else does not.
	payload := ExecutionPayloadV3{ExtraData: res.Commitment[:]}
	require.True(t, bytes.Equal(payload.ExtraData, res.Commitment[:]))

	other := ExecutionPayloadV3{ExtraData: bytes.Repeat([]byte{0x00}, 32)}
	require.False(t, bytes.Equal(other.ExtraData, res.Commitment[:]), "a mismatching commitment is detectable")

	// A payload built through the stock attributes carries NOTHING to compare: PayloadAttributesV3
	// has no extraData field, so a builder using the standard Engine API cannot ask for the
	// commitment to be written. Enforcing the check without the provision mechanism would halt the
	// builder rather than protect it, which is why the build path routes through the seal sibling.
	empty := ExecutionPayloadV3{}
	require.Empty(t, empty.ExtraData)
	require.False(t, bytes.Equal(empty.ExtraData, res.Commitment[:]))

	// If a later Engine API revision adds the field, this assertion is what should fail.
	var names []string
	rt := reflect.TypeOf(PayloadAttributesV3{})
	for i := 0; i < rt.NumField(); i++ {
		names = append(names, rt.Field(i).Name)
	}
	require.NotContains(t, names, "ExtraData",
		"PayloadAttributesV3 must still have no extraData field, or §5's dependency has changed")
}

// TestAdapter_RequireSealCapabilitiesTurnsTheStartupCheckOn pins that the adapter exposes the
// requirement the node's executor wiring turns on: a stock client must fail startup once the build
// path uses the seal siblings.
func TestAdapter_RequireSealCapabilitiesTurnsTheStartupCheckOn(t *testing.T) {
	engine := newMockReth(t, Secret{})
	engine.on("engine_exchangeCapabilities", func(json.RawMessage) (any, *rpcError) {
		return requiredCapabilities, nil // a stock client, no seal siblings
	})
	a, closeFn := newTestAdapter(t, engine, newMockReth(t, Secret{}))
	defer closeFn()

	require.NoError(t, a.CheckCapabilities(context.Background()), "not required until the executor opts in")

	a.RequireSealCapabilities()
	err := a.CheckCapabilities(context.Background())
	require.Error(t, err)
	for _, m := range sealCapabilities {
		require.Contains(t, err.Error(), m, "every absent seal sibling is named")
	}
}
