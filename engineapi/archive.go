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
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/shardnode"
)

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
