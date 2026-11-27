package main

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/archive/archivetest"
)

// requestForBlock finds a receipt-complete record in either archive layout (bft-core#1049), and only in the receipt-complete namespace.
func TestRequestForBlockReadsBothLayouts(t *testing.T) {
	dir := t.TempDir()
	store, err := archive.Open(dir)
	require.NoError(t, err)
	ctx := archive.Context{NetworkID: 1, PartitionID: 2, ExecutionIdentity: []byte("config")}
	ctx.FullShardConfHash[0], ctx.RegistryAddress[0], ctx.RegistryCodeHash[0], ctx.GenesisCommitment[0], ctx.EVMGenesisHash[0] = 1, 2, 3, 4, 5
	record := func(i byte, receipts bool) (archive.Request, *archive.Record) {
		header := []byte{0xc1, 0x80, i}
		r := &archive.Record{Header: header, Body: []byte{0xc0}, CanonicalRootInput: []byte{1}, OriginalUC: []byte{2}, OriginalTR: []byte{3}, ResultingUC: []byte{4},
			ResultingTR: []byte{5}, Companion: []byte{6}, Extensions: map[string][]byte{}}
		if receipts {
			r.Extensions[archive.ReceiptListKey] = []byte{0xc0}
		}
		return archive.Request{Context: ctx, BlockHash: [32]byte(crypto.Keccak256(header))}, r
	}
	packedQ, packedRec := record(1, true)
	require.NoError(t, store.Put(packedQ, packedRec))
	legacyQ, legacyRec := record(2, true)
	_, err = archivetest.WriteDirectoryLayout(dir, legacyQ, legacyRec, false)
	require.NoError(t, err)
	v1Q, v1Rec := record(3, false)
	require.NoError(t, store.Put(v1Q, v1Rec))
	for _, q := range []archive.Request{packedQ, legacyQ} {
		got, err := requestForBlock(dir, common.Hash(q.BlockHash))
		require.NoError(t, err)
		require.Equal(t, q.BlockHash, got.BlockHash)
	}
	_, err = requestForBlock(dir, common.Hash(v1Q.BlockHash))
	require.ErrorContains(t, err, "found 0", "a v1 record is not a receipt-complete source")
}

// #1059 review: a record held in both layouts (a migration interrupted between publishing the packed copy and removing the directory, or a
// tool on a live archive) is one record, not two.
func TestRequestForBlockCountsARecordHeldInBothLayoutsOnce(t *testing.T) {
	dir := t.TempDir()
	ctx := archive.Context{NetworkID: 1, PartitionID: 2, ExecutionIdentity: []byte("config")}
	ctx.FullShardConfHash[0], ctx.RegistryAddress[0], ctx.RegistryCodeHash[0], ctx.GenesisCommitment[0], ctx.EVMGenesisHash[0] = 1, 2, 3, 4, 5
	header := []byte{0xc1, 0x80, 9}
	rec := &archive.Record{Header: header, Body: []byte{0xc0}, CanonicalRootInput: []byte{1}, OriginalUC: []byte{2}, OriginalTR: []byte{3}, ResultingUC: []byte{4},
		ResultingTR: []byte{5}, Companion: []byte{6}, Extensions: map[string][]byte{archive.ReceiptListKey: {0xc0}}}
	q := archive.Request{Context: ctx, BlockHash: [32]byte(crypto.Keccak256(header))}
	_, err := archivetest.WriteDirectoryLayout(dir, q, rec, false)
	require.NoError(t, err)
	store, err := archive.Open(dir)
	require.NoError(t, err)
	store.Fault = func(point string) error {
		if point == "migrate-before-remove" {
			return errors.New("interrupted")
		}
		return nil
	}
	_, err = store.MigrateLegacy(archive.MaxPutBatch)
	require.Error(t, err, "the migration stops with both copies in place")
	got, err := requestForBlock(dir, common.Hash(q.BlockHash))
	require.NoError(t, err)
	require.Equal(t, q.BlockHash, got.BlockHash)
}
