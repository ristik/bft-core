package main

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/unicitynetwork/bft-core/archive"
)

func TestEqualCertifiedBlockChecksRootsAndAllCompanionBytes(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*storedBlock)
	}{
		{"block root", func(b *storedBlock) { b.header.Root[0] ^= 1 }},
		{"receipt root", func(b *storedBlock) { b.header.ReceiptHash[0] ^= 1 }},
		{"header bytes", func(b *storedBlock) { b.record.Header[0] ^= 1 }},
		{"body bytes", func(b *storedBlock) { b.record.Body[0] ^= 1 }},
		{"canonical input", func(b *storedBlock) { b.record.CanonicalRootInput[0] ^= 1 }},
		{"authorizing UC", func(b *storedBlock) { b.record.OriginalUC[0] ^= 1 }},
		{"authorizing TR", func(b *storedBlock) { b.record.OriginalTR[0] ^= 1 }},
		{"resulting UC", func(b *storedBlock) { b.record.ResultingUC[0] ^= 1 }},
		{"resulting TR", func(b *storedBlock) { b.record.ResultingTR[0] ^= 1 }},
		{"seal companion", func(b *storedBlock) { b.record.Companion[0] ^= 1 }},
		{"receipt list", func(b *storedBlock) { b.record.Extensions[archive.ReceiptListKey][0] ^= 1 }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			a, b := equalPair()
			tc.mutate(b)
			if err := equalCertifiedBlock(7, a, b); err == nil {
				t.Fatalf("equalCertifiedBlock accepted mutated %s", tc.name)
			}
		})
	}
}

func equalPair() (*storedBlock, *storedBlock) {
	header := gethtypes.Header{Number: big.NewInt(7), Root: common.HexToHash("0x11"), ReceiptHash: common.HexToHash("0x22")}
	left := &storedBlock{header: header, record: &archive.Record{
		Header: []byte{1}, Body: []byte{2}, CanonicalRootInput: []byte{3}, OriginalUC: []byte{4}, OriginalTR: []byte{5},
		ResultingUC: []byte{6}, ResultingTR: []byte{7}, Companion: []byte{8},
		Extensions: map[string][]byte{archive.ReceiptListKey: []byte{9}},
	}}
	right := &storedBlock{header: header, record: &archive.Record{
		Header: []byte{1}, Body: []byte{2}, CanonicalRootInput: []byte{3}, OriginalUC: []byte{4}, OriginalTR: []byte{5},
		ResultingUC: []byte{6}, ResultingTR: []byte{7}, Companion: []byte{8},
		Extensions: map[string][]byte{archive.ReceiptListKey: []byte{9}},
	}}
	return left, right
}
