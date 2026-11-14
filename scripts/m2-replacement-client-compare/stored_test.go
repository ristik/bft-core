package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/archive/archivetest"
)

// A directory-layout record listed, then migrated and removed before it is read (a live archive, bft-core#1049): its packed copy is read.
func TestStoredRequestFollowsARecordMigratedAfterTheListing(t *testing.T) {
	dir := t.TempDir()
	ctx := archive.Context{NetworkID: 1, PartitionID: 2, ExecutionIdentity: []byte("config")}
	ctx.FullShardConfHash[0], ctx.RegistryAddress[0], ctx.RegistryCodeHash[0], ctx.GenesisCommitment[0], ctx.EVMGenesisHash[0] = 1, 2, 3, 4, 5
	header := []byte{0xc1, 0x80, 7}
	rec := &archive.Record{Header: header, Body: []byte{0xc0}, CanonicalRootInput: []byte{1}, OriginalUC: []byte{2}, OriginalTR: []byte{3}, ResultingUC: []byte{4},
		ResultingTR: []byte{5}, Companion: []byte{6}, Extensions: map[string][]byte{archive.ReceiptListKey: {0xc0}}}
	q := archive.Request{Context: ctx, BlockHash: [32]byte(crypto.Keccak256(header))}
	name, err := archivetest.WriteDirectoryLayout(dir, q, rec, false)
	require.NoError(t, err)
	var listed []string
	require.NoError(t, archive.StoredNames(dir, 16, func(n []string) error { listed = append(listed, n...); return nil }))
	require.Equal(t, []string{name}, listed)
	store, err := archive.Open(dir)
	require.NoError(t, err)
	res, err := store.MigrateLegacy(archive.MaxPutBatch)
	require.NoError(t, err)
	require.Equal(t, 1, res.Migrated)
	_, err = os.Stat(filepath.Join(dir, name))
	require.True(t, os.IsNotExist(err), "the directory is gone")
	got, err := storedRequest(dir, listed[0])
	require.NoError(t, err)
	require.Equal(t, q.BlockHash, got.BlockHash)
}
