package archivewiring

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/unicitynetwork/bft-core/archive"
)

// WithReceiptList adds a validated ordered list of typed/legacy consensus
// receipt envelopes to an archive v2 record.
func WithReceiptList(rec *archive.Record, envelopes [][]byte) (*archive.Record, error) {
	if rec == nil {
		return nil, archive.ErrInvalid
	}
	var header gethtypes.Header
	var body gethtypes.Body
	if rlp.DecodeBytes(rec.Header, &header) != nil || rlp.DecodeBytes(rec.Body, &body) != nil || header.Number == nil || len(envelopes) != len(body.Transactions) {
		return nil, archive.ErrInvalid
	}
	if header.TxHash != gethtypes.DeriveSha(gethtypes.Transactions(body.Transactions), trie.NewStackTrie(nil)) {
		return nil, archive.ErrInvalid
	}
	receipts := make(gethtypes.Receipts, len(envelopes))
	for i, envelope := range envelopes {
		var receipt gethtypes.Receipt
		if len(envelope) == 0 || receipt.UnmarshalBinary(envelope) != nil || receipt.Type != body.Transactions[i].Type() {
			return nil, fmt.Errorf("archive receipt %d is invalid or has the wrong type", i)
		}
		canonical, err := receipt.MarshalBinary()
		if err != nil || !bytes.Equal(canonical, envelope) {
			return nil, archive.ErrInvalid
		}
		receipts[i] = &receipt
	}
	if gethtypes.DeriveSha(receipts, trie.NewStackTrie(nil)) != common.Hash(header.ReceiptHash) || gethtypes.CreateBloom(receipts) != header.Bloom {
		return nil, fmt.Errorf("archive receipt root does not match certified header")
	}
	list, err := rlp.EncodeToBytes(envelopes)
	if err != nil {
		return nil, err
	}
	cp := *rec
	cp.Extensions = make(map[string][]byte, len(rec.Extensions)+1)
	for k, v := range rec.Extensions {
		cp.Extensions[k] = bytes.Clone(v)
	}
	cp.Extensions[archive.ReceiptListKey] = list
	return &cp, nil
}

// ValidateReceiptCommitments checks the complete consensus receipt list,
// transaction count/types and both execution roots against the archived
// canonical header and body.
func ValidateReceiptCommitments(rec *archive.Record) error {
	if rec == nil {
		return archive.ErrInvalid
	}
	var header gethtypes.Header
	var body gethtypes.Body
	if rlp.DecodeBytes(rec.Header, &header) != nil || rlp.DecodeBytes(rec.Body, &body) != nil || header.Number == nil {
		return archive.ErrInvalid
	}
	envelopes, err := DecodeReceiptList(rec)
	if err != nil || len(envelopes) != len(body.Transactions) {
		return archive.ErrInvalid
	}
	receipts := make(gethtypes.Receipts, len(envelopes))
	for i, envelope := range envelopes {
		var receipt gethtypes.Receipt
		if receipt.UnmarshalBinary(envelope) != nil || receipt.Type != body.Transactions[i].Type() {
			return archive.ErrInvalid
		}
		canonical, err := receipt.MarshalBinary()
		if err != nil || !bytes.Equal(canonical, envelope) {
			return archive.ErrInvalid
		}
		receipts[i] = &receipt
	}
	if header.TxHash != gethtypes.DeriveSha(gethtypes.Transactions(body.Transactions), trie.NewStackTrie(nil)) || header.ReceiptHash != gethtypes.DeriveSha(receipts, trie.NewStackTrie(nil)) || header.Bloom != gethtypes.CreateBloom(receipts) {
		return archive.ErrInvalid
	}
	return nil
}

// DecodeReceiptList decodes the v2 archive's bounded RLP envelope list.
func DecodeReceiptList(rec *archive.Record) ([][]byte, error) {
	if !archive.HasReceiptList(rec) {
		return nil, archive.ErrUnavailable
	}
	var envelopes [][]byte
	if err := rlp.DecodeBytes(rec.Extensions[archive.ReceiptListKey], &envelopes); err != nil {
		return nil, archive.ErrInvalid
	}
	canonical, err := rlp.EncodeToBytes(envelopes)
	if err != nil || !bytes.Equal(canonical, rec.Extensions[archive.ReceiptListKey]) {
		return nil, archive.ErrInvalid
	}
	return envelopes, nil
}

// SameArchiveCore compares the journal-certified v1 fields while allowing the
// independently root-checked receipt list to occupy the v2 namespace.
func SameArchiveCore(q archive.Request, a, b *archive.Record) bool {
	strip := func(in *archive.Record) *archive.Record {
		if in == nil {
			return nil
		}
		cp := *in
		cp.Extensions = make(map[string][]byte, len(in.Extensions))
		for k, v := range in.Extensions {
			if k != archive.ReceiptListKey {
				cp.Extensions[k] = v
			}
		}
		return &cp
	}
	x, errX := archive.ManifestDigest(q, strip(a))
	y, errY := archive.ManifestDigest(q, strip(b))
	return errX == nil && errY == nil && x == y
}
