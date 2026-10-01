package mintproof

import (
	"bytes"
	stdcrypto "crypto"
	"fmt"
	"math"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/unicitynetwork/bft-go-base/types"
)

type ExpectedClaim struct {
	Network         types.NetworkID
	Partition       types.PartitionID
	Shard           []byte
	ShardConf       [32]byte
	BlockHash       [32]byte
	BlockNumber     uint64
	TransactionHash *common.Hash
	MatchLog        func(*gethtypes.Log) bool
	// Pin is the immutable deployment expectation (the genesis configuration) a PDR-carrying bundle is
	// checked against. It is required for version 2 bundles. For them ShardConf is only an optional exact
	// historical-configuration pin that narrows acceptance; zero means any assignment of the deployment.
	Pin GenesisPin
}

// Verify authenticates the subject UC with the caller's epoch trust base,
// then verifies the EVM header and the inclusion or complete-block absence
// evidence without network, filesystem, or historical-database access.
func Verify(bundle []byte, trustBase types.RootTrustBase, expected ExpectedClaim, limits Limits) error {
	version, err := bundleVersion(bundle)
	if err != nil {
		return err
	}
	var b MintReasonBundleV1
	var v2 *MintReasonBundleV2
	switch version {
	case 1:
		// Legacy bundles are valid under their explicit original configuration pin only.
		if b, err = DecodeBundle(bundle, limits); err != nil {
			return err
		}
	case BundleVersion2:
		decoded, err := DecodeBundleV2(bundle, limits)
		if err != nil {
			return err
		}
		b, v2 = decoded.MintReasonBundleV1, &decoded
	default:
		return fmt.Errorf("%w: bundle schema version %d", ErrInvalid, version)
	}
	if trustBase == nil || trustBase.GetNetworkID() != b.Context.Network || trustBase.GetEpoch() == 0 || expected.Network != b.Context.Network || expected.Partition != b.Context.Partition || !bytes.Equal(expected.Shard, b.Context.Shard) || len(b.Context.Shard) == 0 {
		return ErrInvalid
	}
	if v2 == nil && expected.ShardConf != b.Context.ShardConf {
		return ErrInvalid
	}
	if expected.BlockHash == ([32]byte{}) {
		return ErrInvalid
	}
	var shard types.ShardID
	if err := shard.UnmarshalText([]byte("0x" + common.Bytes2Hex(b.Context.Shard))); err != nil || !bytes.Equal(shard.Bytes(), b.Context.Shard) {
		return ErrInvalid
	}
	var uc types.UnicityCertificate
	if err := types.Cbor.Unmarshal(b.SubjectUC, &uc); err != nil {
		return fmt.Errorf("%w: subject UC: %v", ErrInvalid, err)
	}
	canonicalUC, err := types.Cbor.Marshal(&uc)
	if err != nil || !bytes.Equal(canonicalUC, b.SubjectUC) || uc.InputRecord == nil || uc.UnicitySeal == nil || uc.GetRootEpoch() != trustBase.GetEpoch() || uc.UnicitySeal.NetworkID != b.Context.Network {
		return ErrInvalid
	}
	if err := uc.Verify(trustBase, stdcrypto.SHA256, b.Context.Partition, shard, b.Context.ShardConf[:]); err != nil {
		return fmt.Errorf("%w: subject UC: %v", ErrInvalid, err)
	}
	if v2 != nil {
		// The UC's root-epoch trust base is the caller's; the PDR is the assignment its configuration
		// hash commits to. Root epoch and shard epoch are independent: an EVM-only rotation advances the
		// root epoch with identical root keys, and the caller supplies that epoch's trust base.
		if _, err := verifyConfigPDR(*v2, &uc, expected); err != nil {
			return err
		}
	}
	if len(uc.InputRecord.BlockHash) != 32 || len(uc.InputRecord.Hash) != 32 {
		return ErrInvalid
	}
	var header gethtypes.Header
	if err := rlp.DecodeBytes(b.HeaderRLP, &header); err != nil || header.Number == nil || !header.Number.IsUint64() {
		return ErrInvalid
	}
	canonicalHeader, err := rlp.EncodeToBytes(&header)
	if err != nil || !bytes.Equal(canonicalHeader, b.HeaderRLP) {
		return ErrInvalid
	}
	if !bytes.Equal(gethcrypto.Keccak256(b.HeaderRLP), uc.InputRecord.BlockHash) || !bytes.Equal(header.Root[:], uc.InputRecord.Hash) || !bytes.Equal(header.Hash().Bytes(), expected.BlockHash[:]) || header.Number.Uint64() != expected.BlockNumber {
		return ErrInvalid
	}
	if expected.BlockNumber > math.MaxInt64 || header.UncleHash != gethtypes.EmptyUncleHash || header.Difficulty == nil || header.Difficulty.Sign() != 0 ||
		header.BaseFee == nil || header.BaseFee.Sign() <= 0 || !header.BaseFee.IsUint64() || header.WithdrawalsHash == nil || *header.WithdrawalsHash != gethtypes.EmptyWithdrawalsHash ||
		header.BlobGasUsed == nil || *header.BlobGasUsed != 0 || header.ExcessBlobGas == nil || *header.ExcessBlobGas != 0 || header.ParentBeaconRoot == nil || len(header.Extra) > 32 {
		return ErrInvalid
	}
	work := len(bundle) + countNodes(b)
	if work > limits.MaxWork {
		return ErrTooLarge
	}
	if b.Evidence.Absence {
		return verifyAbsence(b, header, expected, limits)
	}
	return verifyInclusion(b, header, expected, limits)
}

func verifyInclusion(b MintReasonBundleV1, header gethtypes.Header, expected ExpectedClaim, limits Limits) error {
	if expected.MatchLog == nil {
		return ErrInvalid
	}
	if b.Evidence.TxIndex > math.MaxUint64-1 {
		return ErrInvalid
	}
	key, _ := rlp.EncodeToBytes(b.Evidence.TxIndex)
	value, err := verifyProof(header.TxHash, key, b.Evidence.TxProof, limits)
	if err != nil || !bytes.Equal(value, b.Evidence.TxEnvelope) {
		return ErrInvalid
	}
	var tx gethtypes.Transaction
	if tx.UnmarshalBinary(b.Evidence.TxEnvelope) != nil || len(tx.BlobHashes()) != 0 {
		return ErrInvalid
	}
	if expected.TransactionHash != nil && tx.Hash() != *expected.TransactionHash {
		return ErrInvalid
	}
	value, err = verifyProof(header.ReceiptHash, key, b.Evidence.ReceiptProof, limits)
	if err != nil || !bytes.Equal(value, b.Evidence.Receipt) {
		return ErrInvalid
	}
	var receipt gethtypes.Receipt
	if receipt.UnmarshalBinary(b.Evidence.Receipt) != nil || receipt.Type != tx.Type() || receipt.Status != gethtypes.ReceiptStatusSuccessful {
		return ErrInvalid
	}
	if b.Evidence.LogIndex >= uint64(len(receipt.Logs)) {
		return ErrInvalid
	}
	log := receipt.Logs[b.Evidence.LogIndex]
	if log == nil || !expected.MatchLog(log) {
		return ErrInvalid
	}
	return nil
}

func verifyAbsence(b MintReasonBundleV1, header gethtypes.Header, expected ExpectedClaim, limits Limits) error {
	if expected.MatchLog == nil {
		return ErrInvalid
	}
	if len(b.Evidence.AllReceipts) > limits.MaxNodes {
		return ErrTooLarge
	}
	receipts := make(gethtypes.Receipts, len(b.Evidence.AllReceipts))
	for i, envelope := range b.Evidence.AllReceipts {
		var receipt gethtypes.Receipt
		if receipt.UnmarshalBinary(envelope) != nil {
			return ErrInvalid
		}
		canonical, err := receipt.MarshalBinary()
		if err != nil || !bytes.Equal(canonical, envelope) {
			return ErrInvalid
		}
		receipts[i] = &receipt
		for _, log := range receipt.Logs {
			if log != nil && expected.MatchLog(log) {
				return ErrInvalid
			}
		}
	}
	if gethtypes.DeriveSha(receipts, trie.NewStackTrie(nil)) != header.ReceiptHash || gethtypes.CreateBloom(receipts) != header.Bloom {
		return ErrInvalid
	}
	return nil
}

func verifyProof(root common.Hash, key []byte, nodes [][]byte, limits Limits) ([]byte, error) {
	if len(nodes) == 0 || len(nodes) > limits.MaxNodes {
		return nil, ErrTooLarge
	}
	db := rawdb.NewMemoryDatabase()
	for _, node := range nodes {
		if len(node) == 0 || len(node) > limits.MaxBytes {
			return nil, ErrTooLarge
		}
		hash := gethcrypto.Keccak256(node)
		if err := db.Put(hash, node); err != nil {
			return nil, err
		}
	}
	return trie.VerifyProof(root, key, db)
}
