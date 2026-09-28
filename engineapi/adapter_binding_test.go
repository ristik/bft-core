package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/shardnode"
)

func TestCheckBlockBindingRecomputesRawHeaderBeforeRetention(t *testing.T) {
	verifier, params, want := bootstrapAdapterFixture(t)
	engine := newMockReth(t, Secret{})
	eth := newMockReth(t, Secret{})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: 0, Hash: data32(verifier.GenesisOrigin.BlockHash()), Timestamp: 0}, nil
	})
	a, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
	defer closeFn()
	attrs := DeriveAttributesV2(want.Input, ParentHeader{}, a.feeCollector)
	payload := samplePayload()
	payload.ParentHash = data32(verifier.GenesisOrigin.BlockHash())
	payload.BlockNumber = 1
	payload.Timestamp = attrs.Timestamp
	payload.PrevRandao = attrs.PrevRandao
	payload.FeeRecipient = attrs.SuggestedFeeRecipient
	payload.ExtraData = want.Commitment[:]
	payload.Withdrawals = attrs.Withdrawals
	payload.LogsBloom = make(data, 256)
	payload.Transactions = []data{}
	withdrawals := make([]*gethtypes.Withdrawal, 0, len(payload.Withdrawals))
	for _, w := range payload.Withdrawals {
		withdrawals = append(withdrawals, &gethtypes.Withdrawal{Index: uint64(w.Index), Validator: uint64(w.ValidatorIndex), Address: common.Address(w.Address), Amount: uint64(w.Amount)})
	}
	withdrawalsRoot := gethtypes.DeriveSha(gethtypes.Withdrawals(withdrawals), trie.NewStackTrie(nil))
	blobGas, excessBlobGas := uint64(payload.BlobGasUsed), uint64(payload.ExcessBlobGas)
	beaconRoot := common.Hash(attrs.ParentBeaconBlockRoot)
	header := &gethtypes.Header{ParentHash: common.Hash(payload.ParentHash), UncleHash: gethtypes.EmptyUncleHash, Coinbase: common.Address(payload.FeeRecipient), Root: common.Hash(payload.StateRoot), TxHash: gethtypes.DeriveSha(gethtypes.Transactions{}, trie.NewStackTrie(nil)), ReceiptHash: common.Hash(payload.ReceiptsRoot), Bloom: gethtypes.BytesToBloom(payload.LogsBloom), Difficulty: new(big.Int), Number: big.NewInt(1), GasLimit: uint64(payload.GasLimit), GasUsed: uint64(payload.GasUsed), Time: uint64(payload.Timestamp), Extra: payload.ExtraData, MixDigest: common.Hash(payload.PrevRandao), BaseFee: new(big.Int).SetUint64(uint64(payload.BaseFeePerGas)), WithdrawalsHash: &withdrawalsRoot, BlobGasUsed: &blobGas, ExcessBlobGas: &excessBlobGas, ParentBeaconRoot: &beaconRoot}
	payload.BlockHash = data32(header.Hash())
	witnesses, err := encodeSealCompanionWitnesses(params.AuthorizingCertificate, params.AuthorizingTechnicalRecord)
	require.NoError(t, err)
	block, err := EncodeBlockWithSealCompanion(payload, &SealCompanion{RootInput: want.Encoded, Witnesses: witnesses, Provenance: "build"})
	require.NoError(t, err)
	require.NoError(t, a.CheckBlockBinding(context.Background(), block, params))
	archivedHeader, archivedBody, archivedInput, archivedCompanion, err := ArchiveParts(block, params.AuthorizingCertificate.GetRootRoundNumber(), params.Round)
	require.NoError(t, err)
	var decodedHeader gethtypes.Header
	require.NoError(t, rlp.DecodeBytes(archivedHeader, &decodedHeader))
	require.Equal(t, header.Hash(), decodedHeader.Hash())
	require.NotEmpty(t, archivedBody)
	require.True(t, bytes.Equal(want.Encoded, archivedInput))
	require.Contains(t, string(archivedCompanion), "rootInput")
	var archivedHash [32]byte
	copy(archivedHash[:], block.Hash)
	archiveQuery := archive.Request{BlockHash: archivedHash}
	archiveRecord := &archive.Record{Header: archivedHeader, Body: archivedBody, CanonicalRootInput: archivedInput, Companion: archivedCompanion}
	rebuilt, err := BlockFromArchive(archiveQuery, archiveRecord, params.AuthorizingCertificate.GetRootRoundNumber(), params.Round)
	require.NoError(t, err)
	require.Equal(t, block.Raw, rebuilt.Raw)
	badArchive := *archiveRecord
	badArchive.CanonicalRootInput = []byte{0xff}
	_, err = BlockFromArchive(archiveQuery, &badArchive, params.AuthorizingCertificate.GetRootRoundNumber(), params.Round)
	require.Error(t, err)
	archiveQuery.BlockHash[0] ^= 1
	_, err = BlockFromArchive(archiveQuery, archiveRecord, params.AuthorizingCertificate.GetRootRoundNumber(), params.Round)
	require.Error(t, err)
	zeroBase := decodedHeader
	zeroBase.BaseFee = big.NewInt(0)
	badArchive.CanonicalRootInput = archivedInput
	badArchive.Header, err = rlp.EncodeToBytes(&zeroBase)
	require.NoError(t, err)
	archiveQuery.BlockHash = [32]byte(zeroBase.Hash())
	_, err = BlockFromArchive(archiveQuery, &badArchive, params.AuthorizingCertificate.GetRootRoundNumber(), params.Round)
	require.Error(t, err, "the paired profile's positive base-fee floor forbids zero")
	payload.GasUsed++ // The claimed block hash and parent linkage remain unchanged.
	forged, err := EncodeBlockWithSealCompanion(payload, &SealCompanion{RootInput: want.Encoded, Witnesses: witnesses, Provenance: "build"})
	require.NoError(t, err)
	require.Equal(t, block.Hash, forged.Hash)
	require.Equal(t, block.ParentHash, forged.ParentHash)
	require.ErrorContains(t, a.CheckBlockBinding(context.Background(), forged, params), "computed header hash")
	_, _, _, _, err = ArchiveParts(forged, params.AuthorizingCertificate.GetRootRoundNumber(), params.Round)
	require.Error(t, err)
	var binder interface {
		CheckBlockBinding(context.Context, shardnode.Block, shardnode.RoundParams) error
	} = a
	require.NotNil(t, binder)
}
