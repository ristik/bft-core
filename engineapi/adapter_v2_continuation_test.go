package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/registrywitness"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
)

func TestAdapterV2ContinuesThroughCertifiedParents(t *testing.T) {
	verifier, _, _ := bootstrapAdapterFixture(t)
	c := certifiedchain.New(t, 3, 3)
	require.Equal(t, verifier.GenesisOrigin.BlockHash(), c.Blocks[0].Hash)
	for parentIndex := 1; parentIndex <= 2; parentIndex++ {
		t.Run(string(rune('0'+parentIndex)), func(t *testing.T) {
			parent := c.Blocks[parentIndex]
			uc, tr := c.Certificate(parentIndex)
			uc.UnicitySeal.NetworkID = verifier.NetworkID
			uc.UnicitySeal.Signatures = nil
			v, err := c.Signer.Verifier()
			require.NoError(t, err)
			pk, err := v.MarshalPublicKey()
			require.NoError(t, err)
			id, err := network.NodeIDFromPublicKeyBytes(pk)
			require.NoError(t, err)
			require.NoError(t, uc.UnicitySeal.Sign(id.String(), c.Signer))
			params := shardnode.RoundParams{Round: tr.Round, Parent: shardnode.BlockRef{Number: parent.Number, Hash: parent.Hash.Bytes(), StateRoot: parent.StateRoot.Bytes()}, AuthorizingCertificate: uc, AuthorizingTechnicalRecord: tr}
			observation, err := rootinput.AuthenticateObservationV2(context.Background(), rootinput.ObservationContextV2{NetworkID: verifier.NetworkID, PartitionID: verifier.PartitionID, ShardID: verifier.ShardID, ShardConfHash: verifier.ShardConfHash, RootEpoch: verifier.RootEpoch, TrustBases: verifier.TrustBases}, uc, tr)
			require.NoError(t, err)
			snapshot, err := registryproof.Verify(verifier.GenesisOrigin.ProofContext(), parent.Hash, parent.Evidence)
			require.NoError(t, err)
			want, err := rootinput.DeriveV2(rootinput.ContextV2{Genesis: verifier.GenesisOrigin, Parent: snapshot, Round: params.Round, ParentHash: params.Parent.Hash}, observation)
			require.NoError(t, err)
			if parentIndex == 2 {
				alternativeRPC, _ := sourceServer(t, parent.Hash, parent.Evidence, func(method string, value any) any {
					if method == "eth_getProof" {
						proof := value.(registryproof.GetProofResult)
						for i, j := 0, len(proof.StorageProof)-1; i < j; i, j = i+1, j-1 {
							proof.StorageProof[i], proof.StorageProof[j] = proof.StorageProof[j], proof.StorageProof[i]
						}
						return proof
					}
					return value
				})
				defer alternativeRPC.Close()
				alternative, err := NewParentWitnessSource(context.Background(), ParentWitnessPins{NetworkID: verifier.NetworkID, PartitionID: verifier.PartitionID, ShardID: verifier.ShardID, FullShardConfHash: verifier.GenesisOrigin.FullShardConfHash(), Registry: verifier.GenesisOrigin.ProofContext()}, registrywitness.NewHTTPCaller(alternativeRPC.URL, time.Second), DefaultParentWitnessBudget())
				require.NoError(t, err)
				defer alternative.Close()
				alternativeSnapshot, err := alternative.Acquire(context.Background(), params.Parent)
				require.NoError(t, err)
				alternativeResult, err := rootinput.DeriveV2(rootinput.ContextV2{Genesis: verifier.GenesisOrigin, Parent: alternativeSnapshot, Round: params.Round, ParentHash: params.Parent.Hash}, observation)
				require.NoError(t, err)
				require.Equal(t, want.Encoded, alternativeResult.Encoded, "proof response ordering is not consensus data")
			}
			s, calls := sourceServer(t, parent.Hash, parent.Evidence, nil)
			defer s.Close()
			source, err := NewParentWitnessSource(context.Background(), ParentWitnessPins{NetworkID: verifier.NetworkID, PartitionID: verifier.PartitionID, ShardID: verifier.ShardID, FullShardConfHash: verifier.GenesisOrigin.FullShardConfHash(), Registry: verifier.GenesisOrigin.ProofContext()}, registrywitness.NewHTTPCaller(s.URL, time.Second), DefaultParentWitnessBudget())
			require.NoError(t, err)
			defer source.Close()
			engine := newMockReth(t, Secret{})
			eth := newMockReth(t, Secret{})
			payloadID := data{1, 2, 3, 4, 5, 6, 7, 8}
			var gotInput SealBuildInput
			var attrs UnicityPayloadAttributes
			sealCalls := 0
			buildCalls := 0
			engine.on("engine_forkchoiceUpdatedWithSealV1", func(raw json.RawMessage) (any, *rpcError) {
				buildCalls++
				var args []json.RawMessage
				require.NoError(t, json.Unmarshal(raw, &args))
				require.NoError(t, json.Unmarshal(args[1], &attrs))
				require.NoError(t, json.Unmarshal(args[2], &gotInput))
				return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}, PayloadID: &payloadID}, nil
			})
			engine.on("engine_newPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
				sealCalls++
				return PayloadStatusV1{Status: PayloadStatusValid}, nil
			})
			eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
				return blockHeaderJSON{Number: quantity(parent.Number), Hash: data32(parent.Hash), Timestamp: 0}, nil
			})
			a, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
			defer closeFn()
			a.parentWitness = source
			proofCtx := shardnode.WithProofEvidence(context.Background())
			_, err = a.Build(proofCtx, params)
			require.NoError(t, err)
			builtProof := shardnode.CurrentProofEvidence(proofCtx)
			require.Len(t, builtProof.SnapshotID, 64)
			require.False(t, builtProof.VerifiedAt.IsZero())
			require.Equal(t, want.Encoded, []byte(gotInput.RootInput))
			payload := samplePayload()
			payload.ParentHash = data32(parent.Hash)
			payload.BlockNumber = quantity(parent.Number + 1)
			payload.Timestamp = attrs.Timestamp
			payload.PrevRandao = attrs.PrevRandao
			payload.FeeRecipient = attrs.SuggestedFeeRecipient
			payload.ExtraData = want.Commitment[:]
			payload.Withdrawals = attrs.Withdrawals
			witnesses, err := encodeSealCompanionWitnesses(uc, tr)
			require.NoError(t, err)
			block, err := EncodeBlockWithSealCompanion(payload, &SealCompanion{RootInput: want.Encoded, Witnesses: witnesses})
			require.NoError(t, err)
			status, err := a.Verify(proofCtx, block, params)
			require.NoError(t, err)
			require.Equal(t, shardnode.StatusValid, status)
			require.Equal(t, builtProof, shardnode.CurrentProofEvidence(proofCtx), "Build and Verify used the same verified proof")
			differentInbox := params
			differentInbox.AuthorizingCertificate = nil
			differentInbox.AuthorizingTechnicalRecord = nil
			status, err = a.Verify(context.Background(), block, differentInbox)
			require.NoError(t, err, "follower authenticates the block-bound witnesses, not its own inbox")
			require.Equal(t, shardnode.StatusValid, status)
			require.EqualValues(t, 2, calls.Load(), "Build and Verify reuse one verified parent snapshot")
			require.Equal(t, 2, sealCalls)
			bad := params
			bad.Parent.StateRoot = bytes.Repeat([]byte{0xee}, 32)
			status, err = a.Verify(context.Background(), block, bad)
			require.Equal(t, shardnode.StatusSyncing, status)
			require.ErrorIs(t, err, ErrParentWitnessMismatch)
			require.Equal(t, 2, sealCalls)
			payload.ExtraData = bytes.Repeat([]byte{0x72}, 32)
			badCommitment, err := EncodeBlockWithSealCompanion(payload, &SealCompanion{RootInput: want.Encoded, Witnesses: witnesses})
			require.NoError(t, err)
			status, err = a.Verify(context.Background(), badCommitment, params)
			require.Equal(t, shardnode.StatusInvalid, status)
			require.ErrorIs(t, err, ErrCompanionCommitment)
			require.Equal(t, 2, sealCalls)
			payload.ExtraData = want.Commitment[:]
			payload.Timestamp++
			badAttributes, err := EncodeBlockWithSealCompanion(payload, &SealCompanion{RootInput: want.Encoded, Witnesses: witnesses})
			require.NoError(t, err)
			status, err = a.Verify(context.Background(), badAttributes, params)
			require.NoError(t, err)
			require.Equal(t, shardnode.StatusInvalid, status)
			require.Equal(t, 2, sealCalls)
			payload.Timestamp--
			if parentIndex == 1 {
				repeat := c.Certify(c.Signer, c.InputRecord(1), tr, 7)
				repeat.UnicitySeal.NetworkID = verifier.NetworkID
				repeat.UnicitySeal.Signatures = nil
				require.NoError(t, repeat.UnicitySeal.Sign(id.String(), c.Signer))
				repeatParams := params
				repeatParams.AuthorizingCertificate = repeat
				repeated, err := a.deriveV2(context.Background(), repeatParams, repeat, tr)
				require.NoError(t, err, "a later root certificate for the same B1 authorizes the repeated round")
				require.NotEqual(t, want.Encoded, repeated.Encoded)
			}
			savedSignatures := uc.UnicitySeal.Signatures
			uc.UnicitySeal.Signatures = nil
			badWitnesses, err := encodeSealCompanionWitnesses(uc, tr)
			require.NoError(t, err)
			badBlock, err := EncodeBlockWithSealCompanion(payload, &SealCompanion{RootInput: want.Encoded, Witnesses: badWitnesses})
			require.NoError(t, err)
			before := calls.Load()
			status, err = a.Verify(context.Background(), badBlock, params)
			require.Equal(t, shardnode.StatusInvalid, status)
			require.Error(t, err)
			require.Equal(t, before, calls.Load(), "invalid UC must be refused before proof RPC")
			require.Equal(t, 2, sealCalls)
			uc.UnicitySeal.Signatures = savedSignatures
			unavailableRPC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"parent proof unavailable"}}`))
			}))
			defer unavailableRPC.Close()
			unavailable, err := NewParentWitnessSource(context.Background(), ParentWitnessPins{NetworkID: verifier.NetworkID, PartitionID: verifier.PartitionID, ShardID: verifier.ShardID, FullShardConfHash: verifier.GenesisOrigin.FullShardConfHash(), Registry: verifier.GenesisOrigin.ProofContext()}, registrywitness.NewHTTPCaller(unavailableRPC.URL, time.Second), DefaultParentWitnessBudget())
			require.NoError(t, err)
			defer unavailable.Close()
			a.parentWitness = unavailable
			status, err = a.Verify(context.Background(), block, params)
			require.Equal(t, shardnode.StatusSyncing, status)
			require.ErrorIs(t, err, ErrParentWitnessUnavailable)
			var transient interface{ TransientVerify() bool }
			require.ErrorAs(t, err, &transient)
			require.True(t, transient.TransientVerify())
			require.Equal(t, 2, sealCalls)
			_, err = a.Build(context.Background(), params)
			require.ErrorIs(t, err, ErrParentWitnessUnavailable)
			require.Equal(t, 1, buildCalls)
		})
	}
}

func TestAdapterV2IdlePostGenesisParentAdvancesBlock(t *testing.T) {
	verifier, _, _ := bootstrapAdapterFixture(t)
	c := certifiedchain.New(t, 3, 1)
	parent := c.Blocks[1]
	uc, tr := c.Certificate(1)
	uc.UnicitySeal.NetworkID = verifier.NetworkID
	uc.UnicitySeal.Signatures = nil
	v, err := c.Signer.Verifier()
	require.NoError(t, err)
	pk, err := v.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(t, err)
	require.NoError(t, uc.UnicitySeal.Sign(id.String(), c.Signer))
	params := shardnode.RoundParams{Round: tr.Round, Parent: shardnode.BlockRef{Number: parent.Number, Hash: parent.Hash.Bytes(), StateRoot: parent.StateRoot.Bytes()}, AuthorizingCertificate: uc, AuthorizingTechnicalRecord: tr}
	s, calls := sourceServer(t, parent.Hash, parent.Evidence, nil)
	defer s.Close()
	source, err := NewParentWitnessSource(context.Background(), ParentWitnessPins{NetworkID: verifier.NetworkID, PartitionID: verifier.PartitionID, ShardID: verifier.ShardID, FullShardConfHash: verifier.GenesisOrigin.FullShardConfHash(), Registry: verifier.GenesisOrigin.ProofContext()}, registrywitness.NewHTTPCaller(s.URL, time.Second), DefaultParentWitnessBudget())
	require.NoError(t, err)
	defer source.Close()
	engine := newMockReth(t, Secret{})
	eth := newMockReth(t, Secret{})
	payloadID := data{8, 7, 6, 5, 4, 3, 2, 1}
	var attrs UnicityPayloadAttributes
	var input SealBuildInput
	engine.on("engine_forkchoiceUpdatedWithSealV1", func(raw json.RawMessage) (any, *rpcError) {
		var args []json.RawMessage
		require.NoError(t, json.Unmarshal(raw, &args))
		require.NoError(t, json.Unmarshal(args[1], &attrs))
		require.NoError(t, json.Unmarshal(args[2], &input))
		return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}, PayloadID: &payloadID}, nil
	})
	engine.on("engine_getPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		payload := samplePayload()
		payload.ParentHash = data32(parent.Hash)
		payload.BlockNumber = quantity(parent.Number + 1)
		payload.Timestamp = attrs.Timestamp
		payload.PrevRandao = attrs.PrevRandao
		payload.FeeRecipient = attrs.SuggestedFeeRecipient
		payload.ExtraData = attrs.Commitment[:]
		payload.Withdrawals = attrs.Withdrawals
		payload.Transactions = []data{}
		return GetPayloadWithSealV1Response{ExecutionPayload: payload, SealCompanion: SealCompanion{RootInput: input.RootInput, Provenance: "build"}}, nil
	})
	engine.on("engine_newPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		return PayloadStatusV1{Status: PayloadStatusValid}, nil
	})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: quantity(parent.Number), Hash: data32(parent.Hash), Timestamp: 0}, nil
	})
	a, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
	defer closeFn()
	a.parentWitness = source
	buildID, err := a.Build(context.Background(), params)
	require.NoError(t, err)
	block, err := a.Seal(context.Background(), buildID)
	require.NoError(t, err)
	require.NotEmpty(t, block.Hash)
	require.NotEmpty(t, block.Raw)
	require.Equal(t, parent.Number+1, block.Number)
	envelope, err := DecodeBlock(block)
	require.NoError(t, err)
	require.Empty(t, envelope.ExecutionPayload.Transactions)
	require.Equal(t, []byte(attrs.Commitment[:]), []byte(envelope.ExecutionPayload.ExtraData))
	status, err := a.Verify(context.Background(), block, params)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, status)
	require.EqualValues(t, 2, calls.Load(), "quiet Verify reuses the Build parent snapshot")
}
