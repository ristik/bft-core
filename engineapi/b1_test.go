package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1paired"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/b1fixture"
	"github.com/unicitynetwork/bft-core/shardnode"
)

func TestB1BuildSealsTheLocallyDerivedUpdate(t *testing.T) {
	f := b1fixture.New(t, 0)
	v := &VerifierContext{B1: f.Pair, NetworkID: 5, PartitionID: 8, ShardConfHash: f.Origin.FullShardConfHash().Bytes(), RootEpoch: 1, TrustBases: f.Runtime.Trust(nil), GenesisOrigin: f.Origin, BootstrapSnapshot: f.Parent}
	p := shardnode.RoundParams{Round: 1, Parent: shardnode.BlockRef{Hash: f.Parent.ParentHash().Bytes(), StateRoot: f.Parent.StateRoot().Bytes()}, AuthorizingCertificate: f.UC, AuthorizingTechnicalRecord: f.TR}
	engine, eth := newMockReth(t, Secret{}), newMockReth(t, Secret{})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: 0, Hash: data32(f.Parent.ParentHash())}, nil
	})
	var captured SealBuildInput
	var attrs UnicityPayloadAttributes
	id := data{1, 2, 3, 4, 5, 6, 7, 8}
	engine.on("engine_forkchoiceUpdatedWithSealV1", func(raw json.RawMessage) (any, *rpcError) {
		var args []json.RawMessage
		require.NoError(t, json.Unmarshal(raw, &args))
		require.NoError(t, json.Unmarshal(args[1], &attrs))
		require.NoError(t, json.Unmarshal(args[2], &captured))
		return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}, PayloadID: &id}, nil
	})
	bad := false
	badGas := false
	badInput := false
	badCommitment := false
	engine.on("engine_getPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		payload := samplePayload()
		payload.ParentHash = data32(f.Parent.ParentHash())
		payload.BlockNumber = 1
		payload.Timestamp = attrs.Timestamp
		payload.PrevRandao = attrs.PrevRandao
		payload.FeeRecipient = attrs.SuggestedFeeRecipient
		payload.ExtraData = attrs.Commitment[:]
		payload.GasLimit = quantity(f.Pair.Profile.MaxGas)
		if badCommitment {
			payload.ExtraData = bytes.Repeat([]byte{9}, 32)
		}
		if badGas {
			payload.GasLimit--
		}
		payload.LogsBloom = make(data, 256)
		payload.Transactions = []data{}
		payload.Withdrawals = []WithdrawalV1{}
		payload.BlobGasUsed = 0
		payload.ExcessBlobGas = 0
		beacon := common.Hash(evmroot.DeriveBeaconRoot(5, 1))
		withdrawals := gethtypes.DeriveSha(gethtypes.Withdrawals{}, trie.NewStackTrie(nil))
		zero := uint64(0)
		header := &gethtypes.Header{ParentHash: common.Hash(payload.ParentHash), UncleHash: gethtypes.EmptyUncleHash, Coinbase: common.Address(payload.FeeRecipient), Root: common.Hash(payload.StateRoot), TxHash: gethtypes.EmptyTxsHash, ReceiptHash: common.Hash(payload.ReceiptsRoot), Bloom: gethtypes.BytesToBloom(payload.LogsBloom), Difficulty: new(big.Int), Number: big.NewInt(1), GasLimit: uint64(payload.GasLimit), GasUsed: uint64(payload.GasUsed), Time: uint64(payload.Timestamp), Extra: payload.ExtraData, MixDigest: common.Hash(payload.PrevRandao), BaseFee: new(big.Int).SetUint64(uint64(payload.BaseFeePerGas)), WithdrawalsHash: &withdrawals, BlobGasUsed: &zero, ExcessBlobGas: &zero, ParentBeaconRoot: &beacon}
		payload.BlockHash = data32(header.Hash())
		update := bytes.Clone(captured.B1Update)
		if bad {
			update[len(update)-1] ^= 1
		}
		input := bytes.Clone(captured.RootInput)
		if badInput {
			input[len(input)-1] ^= 1
		}
		return GetPayloadWithSealV1Response{ExecutionPayload: payload, SealCompanion: SealCompanion{RootInput: input, B1Update: update, Provenance: "build"}}, nil
	})
	var imported int
	engine.on("engine_newPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		imported++
		return PayloadStatusV1{Status: PayloadStatusValid}, nil
	})
	a, closeFn := newTestAdapterWithVerifier(t, engine, eth, v)
	defer closeFn()
	want, err := a.deriveV2(context.Background(), p, f.UC, f.TR)
	require.NoError(t, err)
	require.Len(t, want.Input.B1UpdateHash, 32)
	require.NotEmpty(t, want.B1Update)
	require.Equal(t, byte(0x8c), want.Encoded[0], "fresh root input has exactly twelve fields")
	build, err := a.Build(context.Background(), p)
	require.NoError(t, err)
	require.Equal(t, want.B1Update, []byte(captured.B1Update))
	require.Equal(t, want.Encoded, []byte(captured.RootInput))
	block, err := a.Seal(context.Background(), build)
	require.NoError(t, err)
	envelope, err := DecodeBlock(block)
	require.NoError(t, err)
	require.Equal(t, want.B1Update, []byte(envelope.SealCompanion.B1Update))
	_, _, _, archived, err := ArchiveParts(block, 5, 1)
	require.NoError(t, err)
	var durable SealCompanion
	require.NoError(t, json.Unmarshal(archived, &durable))
	require.Equal(t, captured.B1Update, durable.B1Update)
	require.NoError(t, a.CheckBlockBinding(context.Background(), block, p))
	for _, replay := range []bool{false, true} {
		verifyCtx := context.Background()
		if replay {
			verifyCtx = a.HistoricalContext(verifyCtx)
		}
		status, err := a.Verify(verifyCtx, block, p)
		require.NoError(t, err)
		require.Equal(t, shardnode.StatusValid, status)
	}
	require.Equal(t, 2, imported)
	for _, mutation := range []string{"update", "input", "header", "gas"} {
		t.Run(mutation, func(t *testing.T) {
			comp := *envelope.SealCompanion
			comp.B1Update = bytes.Clone(comp.B1Update)
			comp.RootInput = bytes.Clone(comp.RootInput)
			payload := envelope.ExecutionPayload
			wantErr := ErrCompanionBinding
			switch mutation {
			case "update":
				comp.B1Update[len(comp.B1Update)-1] ^= 1
			case "input":
				comp.RootInput[len(comp.RootInput)-1] ^= 1
			case "header":
				payload.ExtraData = bytes.Repeat([]byte{9}, 32)
				wantErr = ErrCompanionCommitment
			case "gas":
				payload.GasLimit--
				wantErr = b1paired.ErrAdmission
			}
			forged, err := EncodeBlockWithSealCompanion(payload, &comp)
			require.NoError(t, err)
			_, err = a.Verify(context.Background(), forged, p)
			require.ErrorIs(t, err, wantErr)
			bindingErr := ErrCompanionBinding
			if mutation == "gas" {
				bindingErr = b1paired.ErrAdmission
			}
			err = a.CheckBlockBinding(context.Background(), forged, p)
			require.ErrorIs(t, err, bindingErr)
			require.Equal(t, 2, imported)
		})
	}
	bad = true
	build, err = a.Build(context.Background(), p)
	require.NoError(t, err)
	_, err = a.Seal(context.Background(), build)
	require.ErrorIs(t, err, ErrCompanionBinding)
	_, err = a.Verify(context.Background(), shardnode.Block{}, p)
	require.ErrorIs(t, err, ErrCompanionMissing)
	bad = false
	badGas = true
	build, err = a.Build(context.Background(), p)
	require.NoError(t, err)
	_, err = a.Seal(context.Background(), build)
	require.ErrorIs(t, err, ErrCompanionBinding)
	badGas = false
	for _, mutation := range []string{"input", "commitment"} {
		badInput = mutation == "input"
		badCommitment = mutation == "commitment"
		build, err = a.Build(context.Background(), p)
		require.NoError(t, err)
		_, err = a.Seal(context.Background(), build)
		require.ErrorIs(t, err, ErrCompanionBinding)
	}
	badInput, badCommitment = false, false
	v.B1 = nil
	_, err = a.deriveV2(context.Background(), p, f.UC, f.TR)
	require.ErrorIs(t, err, b1paired.ErrAdmission)
	v.B1 = f.Pair
	// Existing rootinput admission remains mandatory alongside B1 projection.
	p.Parent.Hash = bytes.Repeat([]byte{9}, 32)
	_, err = a.deriveV2(context.Background(), p, f.UC, f.TR)
	require.ErrorIs(t, err, ErrParentWitnessMismatch)
}

func TestB1ActualCompanionReservation(t *testing.T) {
	f := b1fixture.NewWithReservation(t, 0, 1)
	v := &VerifierContext{B1: f.Pair, NetworkID: 5, PartitionID: 8, ShardConfHash: f.Origin.FullShardConfHash().Bytes(), RootEpoch: 1, TrustBases: f.Runtime.Trust(nil), GenesisOrigin: f.Origin, BootstrapSnapshot: f.Parent}
	p := shardnode.RoundParams{Round: 1, Parent: shardnode.BlockRef{Hash: f.Parent.ParentHash().Bytes(), StateRoot: f.Parent.StateRoot().Bytes()}, AuthorizingCertificate: f.UC, AuthorizingTechnicalRecord: f.TR}
	a := NewAdapter(Config{Verifier: v}, nil)
	_, err := a.deriveV2(context.Background(), p, f.UC, f.TR)
	require.ErrorIs(t, err, b1paired.ErrAdmission)
}
