package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// The expected root input is assembled field by field from the fixture's signed certificate, record
// and configured genesis, without rootinput.DeriveV2, and encoded with evmroot's vector-tested
// encoder. The adapter's shipped bytes must equal it.
func TestAdapterV2ShipsIndependentlyAssembledRootInput(t *testing.T) {
	verifier, params, _ := bootstrapAdapterFixture(t)
	uc, tr := params.AuthorizingCertificate, params.AuthorizingTechnicalRecord
	ir := uc.InputRecord
	independent := evmroot.RootInputV2{
		Version: 2, NetworkID: 3, PartitionID: 8, ShardID: []byte{0x80}, Round: 1, // shard id: empty bit-string, terminator bit only
		CertifiedEpoch: 0, AuthorizedEpoch: 0,
		ParentHash: verifier.GenesisOrigin.BlockHash().Bytes(),
		Origin: evmroot.RootOriginV2{
			NetworkID: 3, RootRound: uc.UnicitySeal.RootChainRoundNumber, RootEpoch: uc.UnicitySeal.Epoch,
			ReferenceTime: uc.UnicitySeal.Timestamp, UnicityTreeRoot: uc.UnicitySeal.Hash, InputVersion: uint64(ir.Version),
			IR:     evmroot.ShardInputRecord{Round: ir.RoundNumber, Epoch: ir.Epoch, PreviousHash: ir.PreviousHash, Hash: ir.Hash, Timestamp: ir.Timestamp, BlockHash: ir.BlockHash},
			TRHash: uc.TRHash, ShardConfHash: uc.ShardConfHash,
		},
		TE: evmroot.TechnicalRecord{Round: tr.Round, Epoch: tr.Epoch, Leader: tr.Leader, StatHash: tr.StatHash, FeeHash: tr.FeeHash},
	}
	require.NoError(t, independent.Validate())
	wantBytes, wantCommit := independent.Encode(), independent.ExtraData()

	engine, eth := newMockReth(t, Secret{}), newMockReth(t, Secret{})
	var captured SealBuildInput
	var attrs UnicityPayloadAttributes
	pid := data{1, 2, 3, 4, 5, 6, 7, 8}
	engine.on("engine_forkchoiceUpdatedWithSealV1", func(raw json.RawMessage) (any, *rpcError) {
		var args []json.RawMessage
		require.NoError(t, json.Unmarshal(raw, &args))
		require.NoError(t, json.Unmarshal(args[1], &attrs))
		require.NoError(t, json.Unmarshal(args[2], &captured))
		return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}, PayloadID: &pid}, nil
	})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: 0, Hash: data32(verifier.GenesisOrigin.BlockHash()), Timestamp: 0}, nil
	})
	a, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
	defer closeFn()
	_, err := a.Build(context.Background(), params)
	require.NoError(t, err)
	require.True(t, bytes.Equal(wantBytes, captured.RootInput))
	require.Equal(t, data32(wantCommit), attrs.Commitment)
}

func TestAdapterV2FollowerChecksFeeCollectorAndCommitment(t *testing.T) {
	verifier, params, want := bootstrapAdapterFixture(t)
	engine, eth := newMockReth(t, Secret{}), newMockReth(t, Secret{})
	calls := 0
	engine.on("engine_newPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		calls++
		return PayloadStatusV1{Status: PayloadStatusValid}, nil
	})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: 0, Hash: data32(verifier.GenesisOrigin.BlockHash()), Timestamp: 0}, nil
	})
	a, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
	defer closeFn()
	a.feeCollector = [20]byte{19: 0xad}
	mk := func(fee [20]byte, extra []byte) shardnode.Block {
		attrs := DeriveAttributesV2(want.Input, ParentHeader{}, fee)
		p := samplePayload()
		p.ParentHash = data32(verifier.GenesisOrigin.BlockHash())
		p.BlockNumber = 1
		p.Timestamp, p.PrevRandao, p.FeeRecipient, p.Withdrawals = attrs.Timestamp, attrs.PrevRandao, attrs.SuggestedFeeRecipient, attrs.Withdrawals
		p.ExtraData = extra
		w, err := encodeSealCompanionWitnesses(params.AuthorizingCertificate, params.AuthorizingTechnicalRecord)
		require.NoError(t, err)
		b, err := EncodeBlockWithSealCompanion(p, &SealCompanion{RootInput: want.Encoded, Witnesses: w, Provenance: "build"})
		require.NoError(t, err)
		return b
	}
	st, err := a.Verify(context.Background(), mk([20]byte{}, want.Commitment[:]), params)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusInvalid, st, "zero recipient refused when collector is configured")
	require.Equal(t, 0, calls)

	bad := append([]byte{}, want.Commitment[:]...)
	bad[0] ^= 1
	st, err = a.Verify(context.Background(), mk(a.feeCollector, bad), params)
	require.ErrorIs(t, err, ErrCompanionCommitment)
	require.Equal(t, shardnode.StatusInvalid, st)
	require.Equal(t, 0, calls)

	st, err = a.Verify(context.Background(), mk(a.feeCollector, want.Commitment[:]), params)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, st)
	require.Equal(t, 1, calls)
}

func TestAdapterV2BuildAndVerifyAuthenticateBeforeDeriving(t *testing.T) {
	verifier, params, want := bootstrapAdapterFixture(t)
	tampered := params
	uc := *params.AuthorizingCertificate
	seal := *uc.UnicitySeal
	seal.Signatures = nil
	uc.UnicitySeal = &seal
	tampered.AuthorizingCertificate = &uc

	a := NewAdapter(Config{EngineURL: "http://127.0.0.1:1", EthURL: "http://127.0.0.1:1", Verifier: verifier}, nil)
	_, err := a.Build(context.Background(), tampered)
	require.ErrorIs(t, err, rootinput.ErrUnauthenticated)

	engine, eth := newMockReth(t, Secret{}), newMockReth(t, Secret{})
	calls := 0
	engine.on("engine_newPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		calls++
		return PayloadStatusV1{Status: PayloadStatusValid}, nil
	})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: 0, Hash: data32(verifier.GenesisOrigin.BlockHash()), Timestamp: 0}, nil
	})
	b, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
	defer closeFn()
	attrs := DeriveAttributesV2(want.Input, ParentHeader{}, b.feeCollector)
	p := samplePayload()
	p.ParentHash = data32(verifier.GenesisOrigin.BlockHash())
	p.BlockNumber = 1
	p.Timestamp, p.PrevRandao, p.FeeRecipient, p.Withdrawals, p.ExtraData = attrs.Timestamp, attrs.PrevRandao, attrs.SuggestedFeeRecipient, attrs.Withdrawals, want.Commitment[:]
	w, err := encodeSealCompanionWitnesses(&uc, params.AuthorizingTechnicalRecord)
	require.NoError(t, err)
	blk, err := EncodeBlockWithSealCompanion(p, &SealCompanion{RootInput: want.Encoded, Witnesses: w, Provenance: "build"})
	require.NoError(t, err)
	st, err := b.Verify(context.Background(), blk, params)
	require.ErrorIs(t, err, rootinput.ErrUnauthenticated)
	require.Equal(t, shardnode.StatusInvalid, st)
	require.Equal(t, 0, calls)
}

// Before D1 idle execution is enabled, a zero-transaction genesis build is a
// quiet certificate. Its round hash must use the state root, never alias the
// execution client's pre-existing genesis block hash.
func TestAdapterV2GenesisQuietRoundDoesNotAliasGenesisHash(t *testing.T) {
	verifier, params, _ := bootstrapAdapterFixture(t)
	engine, eth := newMockReth(t, Secret{}), newMockReth(t, Secret{})
	payloadID := data{1, 2, 3, 4, 5, 6, 7, 8}
	engine.on("engine_forkchoiceUpdatedWithSealV1", func(json.RawMessage) (any, *rpcError) {
		return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}, PayloadID: &payloadID}, nil
	})
	engine.on("engine_getPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		return GetPayloadWithSealV1Response{ExecutionPayload: ExecutionPayloadV3{
			ParentHash: data32(verifier.GenesisOrigin.BlockHash()), Transactions: []data{},
		}}, nil
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
	require.Empty(t, block.Hash)
	require.Empty(t, block.Raw)
	roundHash := shardnode.Hash(shardnode.BlockHashOrFallback(block, false))
	require.Equal(t, params.Parent.StateRoot, roundHash)
	require.NotEqual(t, params.Parent.Hash, roundHash)
}
