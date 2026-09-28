package engineapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// BlockFromArchive reconstructs the exact paired Engine payload from a
// certified archive record. ArchiveParts must reproduce every supplied byte;
// this prevents a plausible header from concealing a different payload body.
func BlockFromArchive(q archive.Request, rec *archive.Record, originalRootRound, authorizedRound uint64) (shardnode.Block, error) {
	if rec == nil {
		return shardnode.Block{}, archive.ErrInvalid
	}
	var header gethtypes.Header
	var body gethtypes.Body
	var companion SealCompanion
	if rlp.DecodeBytes(rec.Header, &header) != nil || rlp.DecodeBytes(rec.Body, &body) != nil || json.Unmarshal(rec.Companion, &companion) != nil ||
		header.Number == nil || header.BaseFee == nil || header.BaseFee.Sign() <= 0 || !header.BaseFee.IsUint64() || len(body.Uncles) != 0 || len(body.Withdrawals) != 0 {
		return shardnode.Block{}, archive.ErrInvalid
	}
	if header.Hash() != common.Hash(q.BlockHash) {
		return shardnode.Block{}, archive.ErrInvalid
	}
	txs := make([]data, len(body.Transactions))
	for i, tx := range body.Transactions {
		raw, err := tx.MarshalBinary()
		if err != nil {
			return shardnode.Block{}, err
		}
		txs[i] = raw
	}
	payload := ExecutionPayloadV3{
		ParentHash: data32(header.ParentHash), FeeRecipient: data20(header.Coinbase), StateRoot: data32(header.Root),
		ReceiptsRoot: data32(header.ReceiptHash), LogsBloom: header.Bloom.Bytes(), PrevRandao: data32(header.MixDigest),
		BlockNumber: quantity(header.Number.Uint64()), GasLimit: quantity(header.GasLimit), GasUsed: quantity(header.GasUsed),
		Timestamp: quantity(header.Time), ExtraData: bytes.Clone(header.Extra), BaseFeePerGas: quantity(header.BaseFee.Uint64()),
		BlockHash: data32(q.BlockHash), Transactions: txs, Withdrawals: []WithdrawalV1{},
	}
	block, err := EncodeBlockWithSealCompanion(payload, &companion)
	if err != nil {
		return shardnode.Block{}, err
	}
	h, b, root, seal, err := ArchiveParts(block, originalRootRound, authorizedRound)
	if err != nil || !bytes.Equal(h, rec.Header) || !bytes.Equal(b, rec.Body) || !bytes.Equal(root, rec.CanonicalRootInput) || !bytes.Equal(seal, rec.Companion) {
		return shardnode.Block{}, archive.ErrInvalid
	}
	return block, nil
}

// ArchiveParts returns exact execution bytes from a journal envelope. The
// independently authenticated authorizing root round selects the beacon root;
// ExecutableDataToBlock verifies the resulting header hash against the payload.
// Callers still authenticate both certificate roles and the root input.
func ArchiveParts(block shardnode.Block, rootRound, round uint64) (header, body, rootInput, companion []byte, err error) {
	envelope, err := DecodeBlock(block)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, block.Raw) || envelope.SealCompanion == nil || len(envelope.SealCompanion.RootInput) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("engineapi: archive envelope is missing or noncanonical")
	}
	if len(envelope.ExpectedBlobVersionedHashes) != 0 {
		return nil, nil, nil, nil, fmt.Errorf("engineapi: archive envelope has blob hashes")
	}
	payload := envelope.ExecutionPayload
	if len(payload.LogsBloom) != 256 || len(payload.ExtraData) > 32 || len(payload.Withdrawals) != 0 || payload.BlobGasUsed != 0 || payload.ExcessBlobGas != 0 {
		return nil, nil, nil, nil, fmt.Errorf("engineapi: archive payload violates the fixed profile")
	}
	txs := make(gethtypes.Transactions, len(payload.Transactions))
	for i, raw := range payload.Transactions {
		var tx gethtypes.Transaction
		if err := tx.UnmarshalBinary(raw); err != nil || len(tx.BlobHashes()) != 0 {
			return nil, nil, nil, nil, fmt.Errorf("engineapi: archive transaction %d invalid: %v", i, err)
		}
		txs[i] = &tx
	}
	beacon := common.Hash(evmroot.DeriveBeaconRoot(rootRound, round))
	withdrawalsRoot := gethtypes.DeriveSha(gethtypes.Withdrawals{}, trie.NewStackTrie(nil))
	zero := uint64(0)
	h := &gethtypes.Header{
		ParentHash: common.Hash(payload.ParentHash), UncleHash: gethtypes.EmptyUncleHash,
		Coinbase: common.Address(payload.FeeRecipient), Root: common.Hash(payload.StateRoot),
		TxHash: gethtypes.DeriveSha(txs, trie.NewStackTrie(nil)), ReceiptHash: common.Hash(payload.ReceiptsRoot),
		Bloom: gethtypes.BytesToBloom(payload.LogsBloom), Difficulty: new(big.Int),
		Number: new(big.Int).SetUint64(uint64(payload.BlockNumber)), GasLimit: uint64(payload.GasLimit),
		GasUsed: uint64(payload.GasUsed), Time: uint64(payload.Timestamp), Extra: payload.ExtraData,
		MixDigest: common.Hash(payload.PrevRandao), BaseFee: new(big.Int).SetUint64(uint64(payload.BaseFeePerGas)),
		WithdrawalsHash: &withdrawalsRoot, BlobGasUsed: &zero, ExcessBlobGas: &zero, ParentBeaconRoot: &beacon,
	}
	if h.Hash() != common.Hash(payload.BlockHash) || block.Number != uint64(payload.BlockNumber) || !bytes.Equal(block.Hash, payload.BlockHash[:]) || !bytes.Equal(block.ParentHash, payload.ParentHash[:]) || !bytes.Equal(block.StateRoot, payload.StateRoot[:]) {
		return nil, nil, nil, nil, fmt.Errorf("engineapi: archive payload does not reconstruct the certified block")
	}
	header, err = rlp.EncodeToBytes(h)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	body, err = rlp.EncodeToBytes(&gethtypes.Body{Transactions: txs, Withdrawals: []*gethtypes.Withdrawal{}})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	companion, err = json.Marshal(envelope.SealCompanion)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return header, body, bytes.Clone(envelope.SealCompanion.RootInput), companion, nil
}
