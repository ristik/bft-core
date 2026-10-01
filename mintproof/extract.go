package mintproof

import (
	"bytes"
	"crypto"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/archivewiring"
	"github.com/unicitynetwork/bft-go-base/types"
)

type ExtractRequest struct {
	Archive           archive.Request
	Absence           bool
	TxIndex, LogIndex uint64
	// ConfigPDR, when set, makes ExtractV2 write a PDR-carrying bundle. It is the full configuration the
	// record's resulting UC commits to; the archive namespace itself stays anchored to the immutable
	// deployment identity.
	ConfigPDR *types.PartitionDescriptionRecord
}

// ExtractV2 is Extract for a deployment whose EVM assignment has changed: the bundle carries the full
// PDR of the record's own resulting UC. The archive keeps that original resulting evidence for a block
// certified before an assignment; extraction never substitutes a later recertification or assignment.
func ExtractV2(store *archive.Store, request ExtractRequest) (MintReasonBundleV2, error) {
	if request.ConfigPDR == nil {
		return MintReasonBundleV2{}, fmt.Errorf("%w: no configuration PDR for the record's certificate", ErrUnavailable)
	}
	v1, err := Extract(store, request)
	if err != nil {
		return MintReasonBundleV2{}, err
	}
	var uc types.UnicityCertificate
	if err := types.Cbor.Unmarshal(v1.SubjectUC, &uc); err != nil {
		return MintReasonBundleV2{}, ErrInvalid
	}
	hash, err := request.ConfigPDR.Hash(crypto.SHA256)
	if err != nil || !bytes.Equal(hash, uc.ShardConfHash) {
		return MintReasonBundleV2{}, fmt.Errorf("%w: the supplied PDR is not the configuration of the record's certificate", ErrInvalid)
	}
	raw, err := types.Cbor.Marshal(request.ConfigPDR)
	if err != nil {
		return MintReasonBundleV2{}, err
	}
	v1.Context.ShardConf = [32]byte(hash)
	return MintReasonBundleV2{MintReasonBundleV1: v1, ConfigPDR: raw}, nil
}

// Extract reads only the immutable receipt-complete archive namespace. It
// never contacts the execution client or a historical database.
func Extract(store *archive.Store, request ExtractRequest) (MintReasonBundleV1, error) {
	if store == nil {
		return MintReasonBundleV1{}, ErrUnavailable
	}
	rec, err := store.GetReceiptComplete(request.Archive)
	if err != nil {
		return MintReasonBundleV1{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if archivewiring.ValidateReceiptCommitments(rec) != nil {
		return MintReasonBundleV1{}, ErrInvalid
	}
	envelopes, err := archivewiring.DecodeReceiptList(rec)
	if err != nil {
		return MintReasonBundleV1{}, err
	}
	var header gethtypes.Header
	var body gethtypes.Body
	if rlp.DecodeBytes(rec.Header, &header) != nil || rlp.DecodeBytes(rec.Body, &body) != nil || len(envelopes) != len(body.Transactions) || header.Hash() != common.Hash(request.Archive.BlockHash) {
		return MintReasonBundleV1{}, ErrInvalid
	}
	b := MintReasonBundleV1{Context: Context{Network: request.Archive.Context.NetworkID, Partition: request.Archive.Context.PartitionID, Shard: request.Archive.Context.ShardID.Bytes(), ShardConf: request.Archive.Context.FullShardConfHash}, SubjectUC: bytes.Clone(rec.ResultingUC), HeaderRLP: bytes.Clone(rec.Header)}
	if request.Absence {
		b.Evidence = Evidence{Absence: true, AllReceipts: clone2d(envelopes)}
		return b, nil
	}
	if request.TxIndex >= uint64(len(body.Transactions)) || request.TxIndex >= uint64(len(envelopes)) {
		return MintReasonBundleV1{}, ErrInvalid
	}
	tx := body.Transactions[request.TxIndex]
	txRaw, err := tx.MarshalBinary()
	if err != nil {
		return MintReasonBundleV1{}, err
	}
	txProof, err := buildProof(txValues(body.Transactions), request.TxIndex)
	if err != nil {
		return MintReasonBundleV1{}, err
	}
	receiptProof, err := buildProof(envelopes, request.TxIndex)
	if err != nil {
		return MintReasonBundleV1{}, err
	}
	b.Evidence = Evidence{TxIndex: request.TxIndex, TxEnvelope: txRaw, TxProof: txProof, Receipt: bytes.Clone(envelopes[request.TxIndex]), ReceiptProof: receiptProof, LogIndex: request.LogIndex}
	return b, nil
}

func txValues(txs gethtypes.Transactions) [][]byte {
	values := make([][]byte, len(txs))
	for i, tx := range txs {
		values[i], _ = tx.MarshalBinary()
	}
	return values
}
func clone2d(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = bytes.Clone(in[i])
	}
	return out
}

func buildProof(values [][]byte, index uint64) ([][]byte, error) {
	db := triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil)
	t := trie.NewEmpty(db)
	for i, value := range values {
		key, err := rlp.EncodeToBytes(uint64(i))
		if err != nil {
			return nil, err
		}
		if err = t.Update(key, value); err != nil {
			return nil, err
		}
	}
	key, err := rlp.EncodeToBytes(index)
	if err != nil {
		return nil, err
	}
	proof := rawdb.NewMemoryDatabase()
	if err := t.Prove(key, proof); err != nil {
		return nil, err
	}
	iterator := proof.NewIterator(nil, nil)
	defer iterator.Release()
	var nodes [][]byte
	for iterator.Next() {
		nodes = append(nodes, bytes.Clone(iterator.Value()))
	}
	if iterator.Error() != nil || len(nodes) == 0 {
		return nil, ErrInvalid
	}
	return nodes, nil
}
