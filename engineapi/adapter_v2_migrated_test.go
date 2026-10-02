package engineapi

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registrywitness"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The tests in this file carry the properties of the v1 adapter tests that were skipped with
// "U5d: v1 adapter fixture awaits migration to the RPC parent witness". Each one says which v1 test
// it replaces; docs/pos/m2-engine-acceptance-coverage.md has the full disposition table.

// postGenesis is a certified parent B1 with its authenticated registry witness served over RPC, the
// verifier context of the bootstrap fixture, and a way to certify the same shard statement at another
// root round. Only the root round of the authorizing certificate varies between cases.
type postGenesis struct {
	t        *testing.T
	verifier *VerifierContext
	chain    *certifiedchain.Chain
	parent   certifiedchain.Block
	tr       *certification.TechnicalRecord
	signerID string
	source   *ParentWitnessSource
}

func newPostGenesis(t *testing.T) *postGenesis {
	t.Helper()
	verifier, _, _ := bootstrapAdapterFixture(t)
	c := certifiedchain.New(t, 3, 3)
	require.Equal(t, verifier.GenesisOrigin.BlockHash(), c.Blocks[0].Hash)
	v, err := c.Signer.Verifier()
	require.NoError(t, err)
	pk, err := v.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(t, err)
	parent := c.Blocks[1]
	_, tr := c.Certificate(1)
	srv, _ := sourceServer(t, parent.Hash, parent.Evidence, nil)
	t.Cleanup(srv.Close)
	source, err := NewParentWitnessSource(context.Background(), ParentWitnessPins{
		NetworkID: verifier.NetworkID, PartitionID: verifier.PartitionID, ShardID: verifier.ShardID,
		FullShardConfHash: verifier.GenesisOrigin.FullShardConfHash(), Registry: verifier.GenesisOrigin.ProofContext(),
	}, registrywitness.NewHTTPCaller(srv.URL, time.Second), DefaultParentWitnessBudget())
	require.NoError(t, err)
	t.Cleanup(source.Close)
	return &postGenesis{t: t, verifier: verifier, chain: c, parent: parent, tr: tr, signerID: id.String(), source: source}
}

// certifyAt is the parent's own shard statement certified by the root at rootRound.
func (g *postGenesis) certifyAt(rootRound uint64) *types.UnicityCertificate {
	g.t.Helper()
	uc := g.chain.Certify(g.chain.Signer, g.chain.InputRecord(1), g.tr, rootRound)
	uc.UnicitySeal.NetworkID = g.verifier.NetworkID
	uc.UnicitySeal.Signatures = nil
	require.NoError(g.t, uc.UnicitySeal.Sign(g.signerID, g.chain.Signer))
	return uc
}

func (g *postGenesis) params(uc *types.UnicityCertificate) shardnode.RoundParams {
	return shardnode.RoundParams{
		Round:                  g.tr.Round,
		Parent:                 shardnode.BlockRef{Number: g.parent.Number, Hash: g.parent.Hash.Bytes(), StateRoot: g.parent.StateRoot.Bytes()},
		AuthorizingCertificate: uc, AuthorizingTechnicalRecord: g.tr,
	}
}

// follower returns an adapter over mock engine and eth surfaces. sealCalls counts the blocks that
// reach newPayloadWithSealV1; buildCalls counts the builds that reach forkchoiceUpdatedWithSealV1.
func (g *postGenesis) follower() (a *Adapter, sealCalls, buildCalls *int) {
	g.t.Helper()
	engine, eth := newMockReth(g.t, Secret{}), newMockReth(g.t, Secret{})
	sealCalls, buildCalls = new(int), new(int)
	payloadID := data{1, 2, 3, 4, 5, 6, 7, 8}
	engine.on("engine_newPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		*sealCalls++
		return PayloadStatusV1{Status: PayloadStatusValid}, nil
	})
	engine.on("engine_forkchoiceUpdatedWithSealV1", func(json.RawMessage) (any, *rpcError) {
		*buildCalls++
		return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}, PayloadID: &payloadID}, nil
	})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: quantity(g.parent.Number), Hash: data32(g.parent.Hash), Timestamp: 0}, nil
	})
	a, closeFn := newTestAdapterWithVerifier(g.t, engine, eth, g.verifier)
	g.t.Cleanup(closeFn)
	a.parentWitness = g.source
	return a, sealCalls, buildCalls
}

// block is what an honest leader disseminates for a round authorized by bound: the canonical root
// input, its commitment in extraData, the derived attributes, and the bound certificate and record as
// the companion witnesses. witnessed, when it differs from bound, replaces only the witnesses.
func (g *postGenesis) block(a *Adapter, bound, witnessed *types.UnicityCertificate) shardnode.Block {
	g.t.Helper()
	params := g.params(bound)
	derived, err := a.deriveV2(context.Background(), params, bound, g.tr)
	require.NoError(g.t, err)
	attrs := DeriveAttributesV2(derived.Input, ParentHeader{}, a.feeCollector)
	payload := samplePayload()
	payload.ParentHash = data32(g.parent.Hash)
	payload.BlockNumber = quantity(g.parent.Number + 1)
	payload.Timestamp, payload.PrevRandao, payload.FeeRecipient, payload.Withdrawals = attrs.Timestamp, attrs.PrevRandao, attrs.SuggestedFeeRecipient, attrs.Withdrawals
	payload.ExtraData = derived.Commitment[:]
	witnesses, err := encodeSealCompanionWitnesses(witnessed, g.tr)
	require.NoError(g.t, err)
	b, err := EncodeBlockWithSealCompanion(payload, &SealCompanion{RootInput: derived.Encoded, Witnesses: witnesses, Provenance: "build"})
	require.NoError(g.t, err)
	return b
}

// Replaces TestAdapter_Verify_AsymmetricDeliveryAgreesOnTheBlockBoundCertificate and
// TestAdapter_Verify_ObservedMaximumRootRoundRefusesAGoodBlock. Node B holds a later valid repeat the
// proposer did not bind; node A holds only the bound certificate. A follower authenticates the
// block-bound witnesses, not its own inbox, so both accept and both derive the same bytes. The test can
// fail: re-selecting from node B's inbox derives different bytes.
func TestAdapterV2AsymmetricDeliveryAgreesOnTheBlockBoundCertificate(t *testing.T) {
	g := newPostGenesis(t)
	bound := g.certifyAt(5)
	repeat := g.certifyAt(7) // same input record and technical record, later root round
	require.NotEqual(t, bound.UnicitySeal.RootChainRoundNumber, repeat.UnicitySeal.RootChainRoundNumber)
	a, sealCalls, _ := g.follower()
	block := g.block(a, bound, bound)

	statusA, err := a.Verify(context.Background(), block, g.params(bound))
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, statusA)
	statusB, err := a.Verify(context.Background(), block, g.params(repeat))
	require.NoError(t, err, "node B accepts the block even though its own inbox holds the later repeat")
	require.Equal(t, shardnode.StatusValid, statusB)
	require.Equal(t, 2, *sealCalls, "both nodes reached newPayloadWithSealV1")

	envelope, err := DecodeBlock(block)
	require.NoError(t, err)
	rePicked, err := a.deriveV2(context.Background(), g.params(repeat), repeat, g.tr)
	require.NoError(t, err, "a later certificate for the same statement is itself valid")
	require.NotEqual(t, envelope.SealCompanion.RootInput, rePicked.Encoded,
		"re-selecting from node B's own certificate would derive different bytes for this block")
	require.NotEqual(t, envelope.ExecutionPayload.ExtraData, rePicked.Commitment[:], "and a different commitment")
}

// Replaces TestAdapter_Verify_ArbitraryLowCursorRemovesARefusal, TestCommittedCursorRefusesACertificateBehindIt
// and the "certificate behind the committed cursor" case of TestAdapter_BuildKeepsRootInputRefusalClassesDistinct.
// The v1 cursor was node configuration, so a low one could remove the refusal; in v2 it is the
// authenticated LastAppliedRootRound of the parent snapshot, which no node can lower. Only the root
// round of the authorizing certificate varies: behind the cursor is refused as ErrNotPinned by Build and
// by Verify, at the cursor and after it are accepted.
func TestAdapterV2RefusesACertificateBehindTheParentCursor(t *testing.T) {
	g := newPostGenesis(t)
	for _, tc := range []struct {
		name      string
		rootRound uint64
		want      error
	}{
		{"behind the cursor", 4, rootinput.ErrNotPinned},
		{"at the cursor", 5, nil},
		{"after the cursor", 7, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, sealCalls, buildCalls := g.follower()
			accepted := g.certifyAt(5)
			uc := g.certifyAt(tc.rootRound)
			// Build authorizes with uc itself.
			_, err := a.Build(context.Background(), g.params(uc))
			// Verify reads the block-bound witnesses. An accepted certificate has an honest block of its
			// own; for a refused one the payload and commitment are the accepted ones, so only the
			// witnessed certificate differs.
			var block shardnode.Block
			if tc.want == nil {
				block = g.block(a, uc, uc)
			} else {
				block = g.block(a, accepted, uc)
			}
			status, verr := a.Verify(context.Background(), block, g.params(accepted))
			if tc.want == nil {
				require.NoError(t, err)
				require.Equal(t, 1, *buildCalls)
				require.NoError(t, verr)
				require.Equal(t, shardnode.StatusValid, status)
				return
			}
			require.ErrorIs(t, err, tc.want)
			require.Zero(t, *buildCalls, "a refused build never reaches the execution client")
			require.ErrorIs(t, verr, tc.want)
			require.Equal(t, shardnode.StatusInvalid, status)
			require.Zero(t, *sealCalls, "a refused block never reaches the execution client")
		})
	}
}

// Replaces TestAdapter_BuildKeepsRootInputRefusalClassesDistinct (the cursor case moved to
// TestAdapterV2RefusesACertificateBehindTheParentCursor, the unauthenticated case is
// TestAdapterV2BuildAndVerifyAuthenticateBeforeDeriving). Each case changes one thing and the refusal
// arrives as its own rootinput class, not collapsed into another. The engine URL is unreachable, so a case
// that got past derivation would fail with a transport error instead.
func TestAdapterV2BuildKeepsRootInputRefusalClassesDistinct(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*VerifierContext, *shardnode.RoundParams)
		want    error
		notWant error
	}{
		{"wrong network", func(v *VerifierContext, _ *shardnode.RoundParams) { v.NetworkID++ }, rootinput.ErrWrongContext, rootinput.ErrContextIncomplete},
		{"missing authorizing certificate", func(_ *VerifierContext, p *shardnode.RoundParams) { p.AuthorizingCertificate = nil }, rootinput.ErrContextIncomplete, rootinput.ErrWrongContext},
		{"missing technical record", func(_ *VerifierContext, p *shardnode.RoundParams) { p.AuthorizingTechnicalRecord = nil }, rootinput.ErrContextIncomplete, rootinput.ErrWrongContext},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier, params, _ := bootstrapAdapterFixture(t)
			v := *verifier
			tc.mutate(&v, &params)
			a := NewAdapter(Config{EngineURL: "http://127.0.0.1:1", EthURL: "http://127.0.0.1:1", Verifier: &v}, nil)
			_, err := a.Build(context.Background(), params)
			require.ErrorIs(t, err, tc.want, "the refusal must arrive as its own class")
			require.NotErrorIs(t, err, tc.notWant, "and must not be collapsed into another class")
		})
	}
}

// Replaces TestAdapter_SealCarriesTheCompanionInTheEnvelope. ureth returns the witnesses empty (the
// execution client holds no trust base), so Seal must fill exactly [bound certificate, bound technical
// record], preserve the root input and provenance it returned, and never pass the far side's witnesses
// through. The mock returns a bogus witness to make that last part falsifiable.
func TestAdapterV2SealFillsTheWitnessesFromTheBoundAuthorization(t *testing.T) {
	verifier, params, want := bootstrapAdapterFixture(t)
	engine, eth := newMockReth(t, Secret{}), newMockReth(t, Secret{})
	payloadID := data{1, 2, 3, 4, 5, 6, 7, 8}
	engine.on("engine_forkchoiceUpdatedWithSealV1", func(json.RawMessage) (any, *rpcError) {
		return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}, PayloadID: &payloadID}, nil
	})
	engine.on("engine_getPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		payload := samplePayload()
		payload.ParentHash = data32(verifier.GenesisOrigin.BlockHash())
		return GetPayloadWithSealV1Response{
			ExecutionPayload: payload,
			SealCompanion:    SealCompanion{RootInput: want.Encoded, Witnesses: []data{{0xff}}, Provenance: "build"},
		}, nil
	})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: 0, Hash: data32(verifier.GenesisOrigin.BlockHash()), Timestamp: 0}, nil
	})
	a, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
	defer closeFn()
	id, err := a.Build(context.Background(), params)
	require.NoError(t, err)
	block, err := a.Seal(context.Background(), id)
	require.NoError(t, err)
	require.NotEmpty(t, block.Raw)

	envelope, err := DecodeBlock(block)
	require.NoError(t, err)
	require.NotNil(t, envelope.SealCompanion)
	require.Equal(t, want.Encoded, []byte(envelope.SealCompanion.RootInput), "the root input ureth returned is preserved")
	require.Equal(t, "build", envelope.SealCompanion.Provenance)
	wantWitnesses, err := encodeSealCompanionWitnesses(params.AuthorizingCertificate, params.AuthorizingTechnicalRecord)
	require.NoError(t, err)
	require.Equal(t, wantWitnesses, envelope.SealCompanion.Witnesses, "Seal fills exactly [bound certificate, bound technical record]")
	require.Len(t, envelope.SealCompanion.Witnesses, SealCompanionWitnessCount)
	uc, tr, err := decodeSealCompanionWitnesses(envelope.SealCompanion.Witnesses)
	require.NoError(t, err)
	require.Equal(t, params.AuthorizingCertificate, uc, "the witnesses are the actual authorization, not labels")
	require.Equal(t, params.AuthorizingTechnicalRecord, tr)
}

// Replaces the Verify half of TestAdapter_Seal_QuietRound_EchoesParentWithNilHash. Seal no longer
// echoes a quiet block (even an empty transaction list is a real payload, see Seal), but Verify still
// has a branch for a block with no envelope, and it must stay narrow: it accepts only a block that is
// exactly its parent, without calling the execution client, and past genesis only after the parent
// witness authenticates the round. Each case changes one thing.
func TestAdapterV2VerifyQuietBlockIsExactlyTheParent(t *testing.T) {
	verifier, params, _ := bootstrapAdapterFixture(t)
	parent := params.Parent
	for _, tc := range []struct {
		name       string
		block      shardnode.Block
		parentNum  uint64
		wantStatus shardnode.Status
		wantErr    error
	}{
		{"genesis parent, exact echo", shardnode.Block{Number: 0, StateRoot: parent.StateRoot}, 0, shardnode.StatusValid, nil},
		{"genesis parent, different state root", shardnode.Block{Number: 0, StateRoot: fixedHashBytes(0xee)}, 0, shardnode.StatusInvalid, nil},
		{"genesis parent, different number", shardnode.Block{Number: 1, StateRoot: parent.StateRoot}, 0, shardnode.StatusInvalid, nil},
		{"post-genesis parent without its witness", shardnode.Block{Number: 1, StateRoot: parent.StateRoot}, 1, shardnode.StatusSyncing, ErrParentWitnessUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// No engine handler is registered: a call to newPayload would fail the test.
			a, closeFn := newTestAdapterWithVerifier(t, newMockReth(t, Secret{}), newMockReth(t, Secret{}), verifier)
			defer closeFn()
			p := params
			p.Parent.Number = tc.parentNum
			status, err := a.Verify(context.Background(), tc.block, p)
			require.Equal(t, tc.wantStatus, status)
			if tc.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.wantErr)
			}
		})
	}
}
