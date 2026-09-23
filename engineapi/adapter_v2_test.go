package engineapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

func bootstrapAdapterFixture(t *testing.T) (*VerifierContext, shardnode.RoundParams, rootinput.ResultV2) {
	t.Helper()
	c := certifiedchain.New(t, 3, 0)
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(c.Genesis.GenesisJSON(), &doc))
	var alloc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc["alloc"], &alloc))
	for k := range alloc {
		if strings.EqualFold(strings.TrimPrefix(k, "0x"), strings.TrimPrefix(registryproof.RegistryAddress.Hex(), "0x")) {
			delete(alloc, k)
		}
	}
	doc["alloc"], _ = json.Marshal(alloc)
	source, err := json.Marshal(doc)
	require.NoError(t, err)
	art, err := registrygenesis.PinnedArtifact()
	require.NoError(t, err)
	prepared, err := registrygenesis.PrepareGenesisJSON(certifiedchain.Config(3), c.Pins, art, source, registrygenesis.GenesisJSONLimits{})
	require.NoError(t, err)
	origin := prepared.Origin()
	snapshot, err := registryproof.Verify(origin.ProofContext(), origin.BlockHash(), origin.Evidence())
	require.NoError(t, err)
	tr := certifiedchain.Technical(0)
	tr.Round = 1
	uc := c.Certify(c.Signer, &types.InputRecord{Version: 1}, tr, 4)
	uc.UnicitySeal.NetworkID = 3
	uc.UnicitySeal.Signatures = nil
	v, err := c.Signer.Verifier()
	require.NoError(t, err)
	pk, err := v.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(t, err)
	require.NoError(t, uc.UnicitySeal.Sign(id.String(), c.Signer))
	verifier := &VerifierContext{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, ShardConfHash: origin.FullShardConfHash().Bytes(), RootEpoch: 1, TrustBases: fixtureTrustBases{tb: c.TrustBase}, Cursor: CursorNotActivated(), GenesisOrigin: origin, BootstrapSnapshot: snapshot}
	params := shardnode.RoundParams{Round: 1, Parent: shardnode.BlockRef{Number: 0, Hash: origin.BlockHash().Bytes(), StateRoot: origin.StateRoot().Bytes()}, AuthorizingCertificate: uc, AuthorizingTechnicalRecord: tr}
	observation, err := rootinput.AuthenticateObservationV2(context.Background(), rootinput.ObservationContextV2{NetworkID: verifier.NetworkID, PartitionID: verifier.PartitionID, ShardID: verifier.ShardID, ShardConfHash: verifier.ShardConfHash, RootEpoch: verifier.RootEpoch, TrustBases: verifier.TrustBases}, uc, tr)
	require.NoError(t, err)
	want, err := rootinput.DeriveV2(rootinput.ContextV2{Genesis: origin, Parent: snapshot, Round: params.Round, ParentHash: params.Parent.Hash}, observation)
	require.NoError(t, err)
	return verifier, params, want
}

func TestAdapterV2BootstrapBuildSendsCanonicalInput(t *testing.T) {
	verifier, params, want := bootstrapAdapterFixture(t)
	engine := newMockReth(t, Secret{})
	eth := newMockReth(t, Secret{})
	var captured SealBuildInput
	var attrs UnicityPayloadAttributes
	payloadID := data{1, 2, 3, 4, 5, 6, 7, 8}
	engine.on("engine_forkchoiceUpdatedWithSealV1", func(raw json.RawMessage) (any, *rpcError) {
		var args []json.RawMessage
		require.NoError(t, json.Unmarshal(raw, &args))
		require.Len(t, args, 3)
		require.NoError(t, json.Unmarshal(args[1], &attrs))
		require.NoError(t, json.Unmarshal(args[2], &captured))
		return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}, PayloadID: &payloadID}, nil
	})
	engine.on("engine_getPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		payload := samplePayload()
		payload.ParentHash = data32(verifier.GenesisOrigin.BlockHash())
		payload.BlockNumber = 1
		payload.Timestamp = attrs.Timestamp
		payload.PrevRandao = attrs.PrevRandao
		payload.FeeRecipient = attrs.SuggestedFeeRecipient
		payload.ExtraData = want.Commitment[:]
		payload.Withdrawals = attrs.Withdrawals
		return GetPayloadWithSealV1Response{ExecutionPayload: payload, SealCompanion: SealCompanion{RootInput: want.Encoded, Provenance: "build"}}, nil
	})
	engine.on("engine_newPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		return PayloadStatusV1{Status: PayloadStatusValid}, nil
	})
	engine.on("engine_forkchoiceUpdatedV3", func(json.RawMessage) (any, *rpcError) {
		return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}}, nil
	})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: 0, Hash: data32(verifier.GenesisOrigin.BlockHash()), Timestamp: 0}, nil
	})
	a, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
	defer closeFn()
	id, err := a.Build(context.Background(), params)
	require.NoError(t, err)
	require.Equal(t, want.Input.Encode(), []byte(captured.RootInput))
	require.Equal(t, want.Encoded, []byte(captured.RootInput))
	require.Equal(t, data32(want.Commitment), attrs.Commitment)
	require.Equal(t, DeriveAttributesV2(want.Input, ParentHeader{}), attrs.PayloadAttributesV3)
	firstAttrs, firstInput := attrs, captured
	changed := params
	changed.Timestamp = params.Timestamp + 42
	changed.SealHash = fixedHashBytes(0x99)
	_, err = a.Build(context.Background(), changed)
	require.NoError(t, err)
	require.Equal(t, firstAttrs, attrs, "fabricable round scalars cannot change v2 execution attributes")
	require.Equal(t, firstInput, captured, "fabricable round scalars cannot change canonical root input")
	block, err := a.Seal(context.Background(), id)
	require.NoError(t, err)
	require.NotEmpty(t, block.Raw)
	status, err := a.Verify(context.Background(), block, params)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, status)
	status, err = a.Commit(context.Background(), block.Hash)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, status)
}

func TestAdapterV2PostGenesisFailsClosed(t *testing.T) {
	verifier, params, _ := bootstrapAdapterFixture(t)
	params.Parent.Number = 1
	a := NewAdapter(Config{Verifier: verifier}, nil)
	_, err := a.Build(context.Background(), params)
	require.ErrorIs(t, err, ErrParentWitnessUnavailable)
}

func TestAdapterV2BootstrapVerifyBoundCompanion(t *testing.T) {
	verifier, params, want := bootstrapAdapterFixture(t)
	engine := newMockReth(t, Secret{})
	eth := newMockReth(t, Secret{})
	sealCalls := 0
	engine.on("engine_newPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		sealCalls++
		return PayloadStatusV1{Status: PayloadStatusValid}, nil
	})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: 0, Hash: data32(verifier.GenesisOrigin.BlockHash()), Timestamp: 0}, nil
	})
	a, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
	defer closeFn()
	attrs := DeriveAttributesV2(want.Input, ParentHeader{})
	payload := samplePayload()
	payload.ParentHash = data32(verifier.GenesisOrigin.BlockHash())
	payload.BlockNumber = 1
	payload.Timestamp = attrs.Timestamp
	payload.PrevRandao = attrs.PrevRandao
	payload.FeeRecipient = attrs.SuggestedFeeRecipient
	payload.ExtraData = want.Commitment[:]
	payload.Withdrawals = attrs.Withdrawals
	witnesses, err := encodeSealCompanionWitnesses(params.AuthorizingCertificate, params.AuthorizingTechnicalRecord)
	require.NoError(t, err)
	companion := &SealCompanion{RootInput: want.Input.Encode(), Witnesses: witnesses, Provenance: "build"}
	block, err := EncodeBlockWithSealCompanion(payload, companion)
	require.NoError(t, err)
	status, err := a.Verify(context.Background(), block, params)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, status)
	require.Equal(t, 1, sealCalls)

	companion.RootInput[0] ^= 1
	bad, err := EncodeBlockWithSealCompanion(payload, companion)
	require.NoError(t, err)
	status, err = a.Verify(context.Background(), bad, params)
	require.ErrorIs(t, err, ErrCompanionBinding)
	require.Equal(t, shardnode.StatusInvalid, status)
	require.Equal(t, 1, sealCalls)

	missing, err := EncodeBlockWithSealCompanion(payload, nil)
	require.NoError(t, err)
	status, err = a.Verify(context.Background(), missing, params)
	require.ErrorIs(t, err, ErrCompanionMissing)
	require.Equal(t, shardnode.StatusInvalid, status)
	require.Equal(t, 1, sealCalls)

	companion.RootInput = want.Encoded
	companion.Witnesses = nil
	wrongWitnesses, err := EncodeBlockWithSealCompanion(payload, companion)
	require.NoError(t, err)
	status, err = a.Verify(context.Background(), wrongWitnesses, params)
	require.ErrorIs(t, err, ErrCompanionWitnesses)
	require.Equal(t, shardnode.StatusInvalid, status)
	require.Equal(t, 1, sealCalls)

	params.Parent.Number = 1
	status, err = a.Verify(context.Background(), block, params)
	require.ErrorIs(t, err, ErrParentWitnessUnavailable)
	require.Equal(t, shardnode.StatusInvalid, status)
	require.Equal(t, 1, sealCalls)
}
