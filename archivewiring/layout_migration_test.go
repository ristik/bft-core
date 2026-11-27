package archivewiring

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/archive/archivetest"
)

// The node's background migration moves an archive an earlier binary wrote to the packed layout, a step at a time, the records readable
// throughout; it picks up a directory-layout record placed later (a joiner's seed), and stops with its context.
func TestLayoutMigrationMovesAnEarlierArchiveAndPicksUpLaterSeeds(t *testing.T) {
	dir := t.TempDir()
	base, rec := transportFixture()
	record := func(i int) (archive.Request, *archive.Record) {
		r := *rec
		r.Header = append(bytes.Clone(rec.Header), byte(i), byte(i>>8))
		q := base
		copy(q.BlockHash[:], crypto.Keccak256(r.Header))
		return q, &r
	}
	const n = 2*archive.MaxPutBatch + 3
	for i := 0; i < n; i++ {
		q, r := record(i)
		_, err := archivetest.WriteDirectoryLayout(dir, q, r, false)
		require.NoError(t, err)
	}
	store, err := archive.Open(dir)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- (&LayoutMigration{Archive: store, Pause: time.Millisecond, Recheck: 20 * time.Millisecond}).Run(ctx)
	}()
	legacyLeft := func() int {
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		left := 0
		for _, e := range entries {
			if e.IsDir() && (len(e.Name()) == 64 || strings.HasPrefix(e.Name(), "v2-")) {
				left++
			}
		}
		return left
	}
	for i := 0; i < n; i++ {
		q, r := record(i)
		got, err := store.Get(q)
		require.NoError(t, err, "record %d during the migration", i)
		require.Equal(t, r.Header, got.Header)
	}
	require.Eventually(t, func() bool { return legacyLeft() == 0 }, 10*time.Second, 5*time.Millisecond)
	q, r := record(n)
	_, err = archivetest.WriteDirectoryLayout(dir, q, r, false)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return legacyLeft() == 0 }, 10*time.Second, 5*time.Millisecond, "a later seed is migrated on the recheck")
	for i := 0; i <= n; i++ {
		q, _ := record(i)
		_, err := store.Get(q)
		require.NoError(t, err, "record %d after the migration", i)
	}
	cancel()
	require.True(t, errors.Is(<-done, context.Canceled))
}
