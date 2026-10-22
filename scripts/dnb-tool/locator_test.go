package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-go-base/types"
)

func testContext(epoch uint64) archive.Context {
	return archive.Context{NetworkID: 3, PartitionID: 8, ShardEpoch: epoch, RootEpoch: 1, FullShardConfHash: [32]byte{1}, RegistryAddress: [20]byte{2},
		RegistryCodeHash: [32]byte{3}, GenesisCommitment: [32]byte{4}, EVMGenesisHash: [32]byte{5}, ExecutionIdentity: []byte{6}}
}

func blockHash(i int) [32]byte {
	var h [32]byte
	binary.BigEndian.PutUint64(h[24:], uint64(i)+1)
	return h
}

// writeRecord writes the start of a v2 record directory (its manifest's Request header), where archive.Store would put it.
func writeRecord(t testing.TB, dir string, q archive.Request) {
	b, err := archive.EncodeRequest(q)
	require.NoError(t, err)
	sum := sha256.Sum256(b)
	d := filepath.Join(dir, "v2-"+hex.EncodeToString(sum[:]))
	require.NoError(t, os.MkdirAll(d, 0o755))
	m := append([]byte("ARCHIVE2"), binary.BigEndian.AppendUint32(nil, uint32(len(b)))...)
	require.NoError(t, os.WriteFile(filepath.Join(d, "manifest"), append(m, b...), 0o644))
}

// fakeArchive answers GetReceiptComplete for the requests it holds and counts the calls.
type fakeArchive struct {
	records map[string]*archive.Record
	gets    int
}

func (f *fakeArchive) GetReceiptComplete(q archive.Request) (*archive.Record, error) {
	f.gets++
	b, err := archive.EncodeRequest(q)
	if err != nil {
		return nil, err
	}
	if r, ok := f.records[string(b)]; ok {
		return r, nil
	}
	return nil, archive.ErrUnavailable
}

func (f *fakeArchive) hold(t testing.TB, dir string, q archive.Request, r *archive.Record) {
	b, err := archive.EncodeRequest(q)
	require.NoError(t, err)
	f.records[string(b)] = r
	writeRecord(t, dir, q)
}

// archiveOf builds an archive of n records over two Contexts (epochs 0 and 1).
func archiveOf(t testing.TB, n int) (string, *fakeArchive) {
	dir, f := t.TempDir(), &fakeArchive{records: map[string]*archive.Record{}}
	for i := range n {
		f.hold(t, dir, archive.Request{Context: testContext(uint64(i % 2)), BlockHash: blockHash(i)}, &archive.Record{})
	}
	return dir, f
}

// countingLocator counts manifest reads and directory listings (a listing is O(archive) too, if a cheap one).
func countingLocator(t testing.TB, dir string, f *fakeArchive) (*archiveLocator, *int, *time.Time) {
	reads, at := 0, time.Unix(1000, 0)
	l := &archiveLocator{dir: dir, store: f, rescanEvery: 10 * time.Second, now: func() time.Time { return at },
		listDir:      func(d string) ([]string, error) { reads += 1_000_000; return listNames(d) },
		readManifest: func(p string) ([]byte, error) { reads++; return os.ReadFile(p) },
		contexts:     map[string]archive.Context{}, seen: map[uint64]struct{}{}}
	require.NoError(t, l.rescan(context.Background()))
	return l, &reads, &at
}

func TestArchiveLocator_ALookupCostsTheSameForTenAndTenThousandRecords(t *testing.T) {
	for _, n := range []int{10, 10_000} {
		dir, f := archiveOf(t, n)
		l, reads, _ := countingLocator(t, dir, f)
		require.Equal(t, 1_000_000+n, *reads, "the start lists the archive once and reads every manifest once")
		require.Len(t, l.contexts, 2)
		*reads, f.gets = 0, 0
		for i := range 20 { // hits
			_, _, err := l.locate(context.Background(), blockHash(i*(n/20)))
			require.NoError(t, err, "n=%d i=%d", n, i)
		}
		for i := range 20 { // misses: random hashes, within the rescan interval
			_, _, err := l.locate(context.Background(), blockHash(n+1000+i))
			require.ErrorIs(t, err, errNotFound)
		}
		require.Zero(t, *reads, "n=%d: no lookup lists the archive or reads a manifest", n)
		require.LessOrEqual(t, f.gets, 40*2*2, "n=%d: at most two reads per Context per lookup (a miss looks twice)", n)
	}
}

func TestArchiveLocator_LearnsANewContextOnAThrottledRescan(t *testing.T) {
	dir, f := archiveOf(t, 10)
	l, reads, at := countingLocator(t, dir, f)
	q := archive.Request{Context: testContext(7), BlockHash: blockHash(500)} // a new epoch's first record
	f.hold(t, dir, q, &archive.Record{})
	*reads = 0
	_, _, err := l.locate(context.Background(), q.BlockHash)
	require.ErrorIs(t, err, errNotFound, "within the interval a miss does not rescan")
	require.Zero(t, *reads)
	*at = at.Add(11 * time.Second)
	_, _, err = l.locate(context.Background(), q.BlockHash)
	require.NoError(t, err, "past the interval the miss rescans and finds the new Context")
	require.Equal(t, 1_000_000+1, *reads, "the rescan lists once and reads only the directory not seen before")
	*at = at.Add(11 * time.Second)
	_, _, err = l.locate(context.Background(), blockHash(9999))
	require.ErrorIs(t, err, errNotFound)
	require.Equal(t, 2*1_000_000+1, *reads, "nothing new: a rescan lists but reads no manifest")
}

func TestArchiveLocator_ARescanHonoursCancellation(t *testing.T) {
	dir, f := archiveOf(t, 600)
	l := &archiveLocator{dir: dir, store: f, rescanEvery: time.Second, now: time.Now, listDir: listNames, readManifest: os.ReadFile,
		contexts: map[string]archive.Context{}, seen: map[uint64]struct{}{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, l.rescan(ctx), context.Canceled)
	require.Less(t, len(l.seen), 600, "a cancelled scan stops")
}

// corruptArchive holds every record, all corrupt.
type corruptArchive struct{ fakeArchive }

func (c *corruptArchive) GetReceiptComplete(archive.Request) (*archive.Record, error) {
	return nil, archive.ErrCorrupt
}

func TestArchiveLocator_ACorruptRecordIsAnErrorNotAMissAndRescansNothing(t *testing.T) {
	dir, f := archiveOf(t, 10)
	l, reads, at := countingLocator(t, dir, f)
	l.store = &corruptArchive{}
	*reads = 0
	*at = at.Add(time.Minute) // a rescan would be due
	_, _, err := l.locate(context.Background(), blockHash(3))
	require.ErrorIs(t, err, archive.ErrCorrupt)
	require.NotErrorIs(t, err, errNotFound, "a corrupt record is a server-side fault (502), not a missing block (404)")
	require.Zero(t, *reads, "an error that is not a miss does not rescan")
}

func TestArchiveLocator_AnUnreadableArchiveIsNotNotFound(t *testing.T) {
	_, err := newArchiveLocator(context.Background(), filepath.Join(t.TempDir(), "missing"), &fakeArchive{}, time.Second)
	require.Error(t, err)
	require.NotErrorIs(t, err, errNotFound)
}

// TestLockProofSource_MapsNoLockAndARefusalToNotFound drives build with a real header and certificate in a fake archive and a fake JSON-RPC client.
func TestLockProofSource_MapsNoLockAndARefusalToNotFound(t *testing.T) {
	pdr := []byte("pdr")
	pdrHash := sha256.Sum256(pdr)
	header, err := rlp.EncodeToBytes(&gethtypes.Header{Number: big.NewInt(26), Difficulty: big.NewInt(0)})
	require.NoError(t, err)
	var hdr gethtypes.Header
	require.NoError(t, rlp.DecodeBytes(header, &hdr))
	uc, err := types.Cbor.Marshal(&types.UnicityCertificate{ShardConfHash: pdrHash[:]})
	require.NoError(t, err)
	dir, f := t.TempDir(), &fakeArchive{records: map[string]*archive.Record{}}
	f.hold(t, dir, archive.Request{Context: testContext(0), BlockHash: hdr.Hash()}, &archive.Record{Header: header, ResultingUC: uc})

	answer := ""
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(answer)) }))
	defer rpc.Close()
	l, _, _ := countingLocator(t, dir, f)
	vault := common.HexToAddress("0xe5d2db50c8d119078fa4d75e04bf93995793a06a")
	s := &lockProofSource{archive: l, ethURL: rpc.URL, vault: vault, pdr: pdr, pdrHash: pdrHash}
	proof := func(value string) string {
		return fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"address":"%s","accountProof":["0x01"],"storageProof":[{"value":"%s","proof":["0x02"]}]}}`, vault.Hex(), value)
	}

	answer = proof("0x1")
	_, err = s.build(context.Background(), hdr.Hash(), 1)
	require.NoError(t, err, "a lock")
	answer = proof("0x0")
	_, err = s.build(context.Background(), hdr.Hash(), 2)
	require.ErrorIs(t, err, errNotFound, "no lock with that nonce")
	answer = `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"distance to target block exceeds maximum proof window"}}`
	_, err = s.build(context.Background(), hdr.Hash(), 1)
	require.ErrorIs(t, err, errNotFound, "past the proof window")
	_, err = s.build(context.Background(), blockHash(77), 1)
	require.ErrorIs(t, err, errNotFound, "a block the archive does not hold")
	rpc.Close()
	answer = proof("0x1")
	_, err = s.build(context.Background(), hdr.Hash(), 1)
	require.Error(t, err)
	require.NotErrorIs(t, err, errNotFound, "an unreachable client is not not-found")
}
