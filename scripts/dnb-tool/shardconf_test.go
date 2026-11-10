package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-go-base/types"
)

// confSetOf is a set holding exactly pdrs, with no directory.
func confSetOf(pdrs map[[32]byte][]byte) *confSet {
	s := &confSet{rescanEvery: confRescanEvery, now: time.Now, maxEntries: maxConfDirEntries, maxScan: maxConfScanBytes, maxRetained: maxConfRetained,
		pdrs: map[[32]byte][]byte{}, loaded: map[string]struct{}{}}
	for h, p := range pdrs {
		if err := s.add(h, p); err != nil {
			panic(err)
		}
	}
	return s
}

// confJSON is a distinct full shard configuration per epoch, and the hash of its CBOR encoding (what a UC's ShardConfHash names).
func confJSON(t testing.TB, epoch uint64) ([]byte, [32]byte) {
	raw, err := json.Marshal(&types.PartitionDescriptionRecord{Version: 1, NetworkID: 3, PartitionID: 8, PartitionTypeID: 8, Epoch: epoch, EpochStart: epoch * 100,
		T2Timeout: 2500 * time.Millisecond, ShardID: types.ShardID{}})
	require.NoError(t, err)
	pdr, err := encodeConf(raw)
	require.NoError(t, err)
	return raw, sha256.Sum256(pdr)
}

// publish writes a configuration the way the handoff does: a temporary name in the same directory, then a rename.
func publish(t testing.TB, dir string, epoch uint64) [32]byte {
	raw, h := confJSON(t, epoch)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	tmp := filepath.Join(dir, fmt.Sprintf(".shard-conf-%d.json.tmp", epoch))
	require.NoError(t, os.WriteFile(tmp, raw, 0o644))
	require.NoError(t, os.Rename(tmp, filepath.Join(dir, fmt.Sprintf("shard-conf-%d.json", epoch))))
	return h
}

// testSet is a set with the genesis configuration given explicitly and DIR as its directory, its clock injected and advanced past the
// throttle of the start scan.
func testSet(t testing.TB, dir string) (*confSet, [32]byte, *time.Time) {
	raw, h0 := confJSON(t, 0)
	explicit := filepath.Join(t.TempDir(), "full-shard-conf.json")
	require.NoError(t, os.WriteFile(explicit, raw, 0o600))
	s, err := newConfSet([]string{explicit}, dir)
	require.NoError(t, err)
	clock := time.Now().Add(time.Hour)
	s.now = func() time.Time { return clock }
	return s, h0, &clock
}

func scansOf(s *confSet) int {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	return s.scans
}

func TestConfSet_FindsAConfigurationPublishedAfterStartWithoutARestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "handoff")
	h1 := publish(t, dir, 1)
	s, h0, _ := testSet(t, dir)
	require.Equal(t, 2, s.size(), "the explicit genesis configuration and the one already in the directory")
	h2 := publish(t, dir, 2) // the next handoff, after the endpoint started
	got, err := s.lookup(context.Background(), h2[:])
	require.NoError(t, err, "found by a rescan, with no new source")
	require.Equal(t, h2, sha256.Sum256(got))
	for _, h := range [][32]byte{h0, h1} {
		got, err := s.lookup(context.Background(), h[:])
		require.NoError(t, err, "the historical configurations are still served")
		require.Equal(t, h, sha256.Sum256(got))
	}
	// a restart reconstructs all of them from disk
	r, _, _ := testSet(t, dir)
	require.Equal(t, 3, r.size())
	for _, h := range [][32]byte{h0, h1, h2} {
		_, ok := r.get(h)
		require.True(t, ok)
	}
}

func TestConfSet_AnAbsentDirectoryIsEmptyAndDiscoveredOnceCreated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "handoff") // not created: before the first handoff
	s, _, clock := testSet(t, dir)
	require.Equal(t, 1, s.size())
	_, h2 := confJSON(t, 2)
	_, err := s.lookup(context.Background(), h2[:])
	require.ErrorIs(t, err, errNotFound, "an absent directory is not a failure")
	publish(t, dir, 2)
	*clock = clock.Add(confRescanEvery)
	_, err = s.lookup(context.Background(), h2[:])
	require.NoError(t, err)
}

func TestConfSet_AMissIsThrottledAndAnUnknownHashStaysRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "handoff")
	s, _, clock := testSet(t, dir)
	start := scansOf(s)
	unknown := sha256.Sum256([]byte("a configuration nobody published"))
	_, err := s.lookup(context.Background(), unknown[:])
	require.ErrorIs(t, err, errNotFound)
	require.Equal(t, start+1, scansOf(s), "one rescan for the miss")
	for range 5 {
		_, err = s.lookup(context.Background(), unknown[:])
		require.ErrorIs(t, err, errNotFound)
	}
	require.Equal(t, start+1, scansOf(s), "no rescan within the throttle")
	*clock = clock.Add(confRescanEvery)
	_, err = s.lookup(context.Background(), unknown[:])
	require.ErrorIs(t, err, errNotFound, "still refused after another scan: never served under another configuration")
	require.Equal(t, start+2, scansOf(s))
}

func TestConfSet_AFailedScanIsAnErrorSharedAndThrottledNotAMiss(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "handoff")
	s, _, clock := testSet(t, dir)
	require.NoError(t, os.WriteFile(dir, []byte("not a directory"), 0o600)) // opens, but cannot be listed
	start := scansOf(s)
	_, h2 := confJSON(t, 2)
	_, err := s.lookup(context.Background(), h2[:])
	require.Error(t, err)
	require.NotErrorIs(t, err, errNotFound, "an unreadable directory is not 'not yet'")
	_, err2 := s.lookup(context.Background(), h2[:])
	require.Error(t, err2)
	require.NotErrorIs(t, err2, errNotFound, "the throttled call returns the failed scan's error")
	require.Equal(t, start+1, scansOf(s), "a failing directory is not scanned per request")
	require.NoError(t, os.Remove(dir))
	publish(t, dir, 2)
	*clock = clock.Add(confRescanEvery)
	_, err = s.lookup(context.Background(), h2[:])
	require.NoError(t, err, "found once the directory is readable again")

	_, err = newConfSet(nil, filepath.Join(base, "missing", "..", "x"))
	require.NoError(t, err, "a directory alone is enough at start")
	require.NoError(t, os.WriteFile(filepath.Join(base, "file"), nil, 0o600))
	_, err = newConfSet(nil, filepath.Join(base, "file"))
	require.Error(t, err, "a directory that cannot be read is a startup failure")
}

func TestConfSet_ConcurrentMissesShareOneScanAndWaitersGetItsResult(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "handoff")
	s, h0, _ := testSet(t, dir)
	h2 := publish(t, dir, 2)
	release := make(chan struct{})
	s.hook = func() { <-release }
	start := scansOf(s)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.lookup(context.Background(), h2[:]); errs <- err }()
	}
	require.Eventually(t, func() bool { return scansOf(s) == start+1 }, 5*time.Second, time.Millisecond)
	// a hit is served while the scan is held open
	hit := make(chan error, 1)
	go func() { _, err := s.lookup(context.Background(), h0[:]); hit <- err }()
	select {
	case err := <-hit:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("a hit waited for the scan")
	}
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err, "every waiter gets the shared scan's result")
	}
	require.Equal(t, start+1, scansOf(s), "one scan for all of them")

	// the scan's error is shared too
	release = make(chan struct{})
	s.hook = func() { <-release }
	require.NoError(t, os.RemoveAll(dir))
	require.NoError(t, os.WriteFile(dir, nil, 0o600))
	s.scanMu.Lock()
	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	s.scanMu.Unlock()
	_, h3 := confJSON(t, 3)
	failedErrs := make(chan error, 4)
	for range 4 {
		go func() { _, err := s.lookup(context.Background(), h3[:]); failedErrs <- err }()
	}
	require.Eventually(t, func() bool { return scansOf(s) == start+2 }, 5*time.Second, time.Millisecond)
	close(release)
	for range 4 {
		err := <-failedErrs
		require.Error(t, err)
		require.NotErrorIs(t, err, errNotFound, "every waiter gets the shared scan's error")
	}
	require.Equal(t, start+2, scansOf(s), "one scan for all of them")
}

func TestConfSet_AWaiterCanCancel(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "handoff")
	s, _, _ := testSet(t, dir)
	release := make(chan struct{})
	defer close(release)
	s.hook = func() { <-release }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	_, h2 := confJSON(t, 2)
	go func() { _, err := s.lookup(ctx, h2[:]); done <- err }()
	require.Eventually(t, func() bool { return scansOf(s) > 1 }, 5*time.Second, time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, errNotFound, "a cancelled lookup is not 'not yet'")
	case <-time.After(5 * time.Second):
		t.Fatal("the cancelled waiter kept waiting")
	}
}

func TestConfSet_ARetriesAFileThatDidNotDecodeAndKeysByTheComputedHash(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "handoff")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	s, _, clock := testSet(t, dir)
	raw, h3 := confJSON(t, 3)
	path := filepath.Join(dir, "shard-conf-3.json")
	require.NoError(t, os.WriteFile(path, raw[:len(raw)/2], 0o644)) // a truncated file (a non-atomic writer)
	_, err := s.lookup(context.Background(), h3[:])
	require.ErrorIs(t, err, errNotFound)
	require.NoError(t, os.WriteFile(path, raw, 0o644))
	*clock = clock.Add(confRescanEvery)
	_, err = s.lookup(context.Background(), h3[:])
	require.NoError(t, err, "the complete file is loaded on the next scan")

	// a file named for epoch 5 holding epoch 7's configuration: served for 7's hash only
	raw7, h7 := confJSON(t, 7)
	_, h5 := confJSON(t, 5)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "shard-conf-5.json"), raw7, 0o644))
	*clock = clock.Add(confRescanEvery)
	_, err = s.lookup(context.Background(), h5[:])
	require.ErrorIs(t, err, errNotFound, "never served under the hash its name suggests")
	got, err := s.lookup(context.Background(), h7[:])
	require.NoError(t, err)
	require.Equal(t, h7, sha256.Sum256(got))
}

func TestConfSet_IgnoresSymlinksOversizedFilesAndOtherNames(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "handoff")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	s, _, clock := testSet(t, dir)
	raw8, h8 := confJSON(t, 8)
	outside := filepath.Join(t.TempDir(), "elsewhere.json")
	require.NoError(t, os.WriteFile(outside, raw8, 0o644))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "shard-conf-8.json")))
	raw9, h9 := confJSON(t, 9)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "shard-conf-9.json.tmp"), raw9, 0o644))
	raw10, h10 := confJSON(t, 10)
	big := append(append([]byte{}, raw10...), bytes.Repeat([]byte(" "), maxConfFileBytes)...) // valid JSON: only the size check refuses it
	require.NoError(t, os.WriteFile(filepath.Join(dir, "shard-conf-10.json"), big, 0o644))
	*clock = clock.Add(confRescanEvery)
	for name, h := range map[string][32]byte{"a symlink": h8, "a temporary name": h9, "a file over the per-file limit": h10} {
		_, err := s.lookup(context.Background(), h[:])
		require.ErrorIs(t, err, errNotFound, name)
	}
	require.Equal(t, 1, s.size())
}

func TestConfSet_ResourceBoundsAreErrorsAndKeepTheHits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit func(*confSet)
	}{
		{"entries examined", func(s *confSet) { s.maxEntries = 3 }},
		{"bytes read by one scan", func(s *confSet) { s.maxScan = 1 }},
		{"bytes retained", func(s *confSet) { s.maxRetained = s.retained + 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "handoff")
			s, h0, clock := testSet(t, dir)
			for e := uint64(1); e <= 4; e++ {
				publish(t, dir, e)
			}
			tc.limit(s)
			*clock = clock.Add(confRescanEvery)
			_, unpublished := confJSON(t, 99)
			_, err := s.lookup(context.Background(), unpublished[:])
			require.ErrorIs(t, err, errConfLimit)
			require.NotErrorIs(t, err, errNotFound, "a resource bound is not 'not yet'")
			_, err = s.lookup(context.Background(), h0[:])
			require.NoError(t, err, "existing hits are kept")
		})
	}
}

func TestLockProofSource_AnUnknownConfigurationIsNotFoundAndANewOneIsServed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "handoff")
	s, _, clock := testSet(t, dir)
	_, h2 := confJSON(t, 2)
	header, err := rlp.EncodeToBytes(&gethtypes.Header{Number: big.NewInt(31), Difficulty: big.NewInt(0)})
	require.NoError(t, err)
	var hdr gethtypes.Header
	require.NoError(t, rlp.DecodeBytes(header, &hdr))
	uc, err := types.Cbor.Marshal(&types.UnicityCertificate{ShardConfHash: h2[:]})
	require.NoError(t, err)
	adir, f := t.TempDir(), &fakeArchive{records: map[string]*archive.Record{}}
	f.hold(t, adir, archive.Request{Context: testContext(0), BlockHash: hdr.Hash()}, &archive.Record{Header: header, ResultingUC: uc})
	vault := common.HexToAddress("0xe5d2db50c8d119078fa4d75e04bf93995793a06a")
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"address":"%s","accountProof":["0x01"],"storageProof":[{"value":"0x1","proof":["0x02"]}]}}`, vault.Hex())
	}))
	defer rpc.Close()
	l, _, _ := countingLocator(t, adir, f)
	src := &lockProofSource{archive: l, ethURL: rpc.URL, vault: vault, confs: s}
	_, err = src.build(context.Background(), hdr.Hash(), 1)
	require.True(t, errors.Is(err, errNotFound), "a block under a configuration not held yet is 404, not 502: %v", err)
	publish(t, dir, 2)
	*clock = clock.Add(confRescanEvery)
	lp, err := src.build(context.Background(), hdr.Hash(), 1)
	require.NoError(t, err, "served once the handoff published the configuration, with the same source")
	pdr, _ := s.get(h2)
	require.True(t, bytes.Contains(lp, pdr))
}
