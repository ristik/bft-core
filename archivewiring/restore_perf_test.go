package archivewiring

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// TestRestoreFetchProfile times a restore of a synthetic N-block archive from two in-process replicas over real libp2p streams, and the
// parts of one record's work separately. RESTORE_PROFILE_BLOCKS selects N (unset: skipped).
func TestRestoreFetchProfile(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("RESTORE_PROFILE_BLOCKS"))
	if n == 0 {
		t.Skip("set RESTORE_PROFILE_BLOCKS")
	}
	restore, executor, sender, ids, qs, recs := newTwoReplicaRestore(t, n)

	// the parts, each over every record
	part := func(name string, fn func(i int)) {
		start := time.Now()
		for i := range qs {
			fn(i)
		}
		t.Logf("  %-34s %8.2f ms per record", name, float64(time.Since(start).Microseconds())/1000/float64(len(qs)))
	}
	part("fetch (one stream per record)", func(i int) {
		_, err := Fetch(context.Background(), sender, ids[0], qs[i], DefaultLimits())
		require.NoError(t, err)
	})
	part("checkRecord (certificates)", func(i int) {
		_, _, err := restore.checkRecord(qs[i], recs[i])
		require.NoError(t, err)
	})
	scratch, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	part("local archive Put", func(i int) { require.NoError(t, scratch.Put(qs[i], recs[i])) })
	batched, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	start := time.Now()
	for i := 0; i < len(qs); i += restorePutBatch {
		end := min(i+restorePutBatch, len(qs))
		require.NoError(t, batched.PutBatch(qs[i:end], recs[i:end]))
	}
	t.Logf("  %-34s %8.2f ms per record", "local archive PutBatch", float64(time.Since(start).Microseconds())/1000/float64(len(qs)))
	part("local archive Get", func(i int) {
		_, err := scratch.Get(qs[i])
		require.NoError(t, err)
	})

	restore.Log = slog.New(slog.NewTextHandler(testWriter{t}, nil))
	start = time.Now()
	require.NoError(t, restore.Restore(context.Background()))
	total := time.Since(start)
	require.EqualValues(t, n, executor.head.Number)
	t.Logf("restore of %d blocks: %s, %.2f ms per block", n, total, float64(total.Microseconds())/1000/float64(n))
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(b []byte) (int, error) { w.t.Log(string(b)); return len(b), nil }

// newTwoReplicaRestore is a restore of a synthetic n-block archive that two in-process replicas serve over real libp2p streams.
func newTwoReplicaRestore(t *testing.T, n int) (*ArchiveRestore, *restoreExecutorFixture, *network.Peer, [2]peer.ID, []archive.Request, []*archive.Record) {
	t.Helper()
	f := newWiringFixtureWithLimits(t, n, configuredprogress.JournalLimits{Candidates: n + 16, Observations: 2*n + 32, Bytes: 128 << 20})
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	var ids [2]peer.ID
	var qs []archive.Request
	var recs []*archive.Record
	for i := range ids {
		replica := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
		sender.Network().Peerstore().AddAddrs(replica.ID(), replica.MultiAddresses(), peerstore.PermanentAddrTTL)
		remote, err := archive.Open(t.TempDir())
		require.NoError(t, err)
		for _, entry := range f.entries {
			q, rec, err := FromJournal(context.Background(), f.context, f.subject, nil, entry)
			require.NoError(t, err)
			require.NoError(t, remote.Put(q, rec))
			if i == 0 {
				qs, recs = append(qs, q), append(recs, rec)
			}
		}
		server, err := NewServer(remote, f.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{sender.ID()}, DefaultLimits())
		require.NoError(t, err)
		server.Register(context.Background(), replica)
		ids[i] = replica.ID()
	}
	journal, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/restored.db", configuredprogress.Settings{Retain: 16})
	require.NoError(t, err)
	_, _, err = journal.Initialize(context.Background(), f.context)
	require.NoError(t, err)
	limits := configuredprogress.JournalLimits{Candidates: 3, Observations: 4, Bytes: 16 << 20}
	require.NoError(t, journal.EnableJournal(context.Background(), f.context, limits))
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	last := f.entries[0]
	for _, entry := range f.entries {
		if entry.Candidate.Number > last.Candidate.Number {
			last = entry
		}
	}
	genesis := shardnode.BlockRef{Number: 0, Hash: f.context.Origin.BlockHash().Bytes(), StateRoot: f.context.Origin.StateRoot().Bytes()}
	executor := newRestoreExecutorFixture(genesis)
	restore := &ArchiveRestore{Journal: journal, Context: f.context, JournalLimits: limits, Archive: local,
		Subject: f.subject, Replicas: ids, Host: sender, Limits: DefaultLimits(), Adapter: executor,
		Genesis: genesis, TipUC: last.ResultingUC, TipTR: last.ResultingTR}

	return restore, executor, sender, ids, qs, recs
}

// The restore retains its authenticated records in batches. A chain longer than one batch, and not a multiple of it, is restored
// whole: every record is in the local store before the replay reads it back, and the progress log names the phases.
func TestArchiveRestoreRetainsInBatchesAndReportsItsPhases(t *testing.T) {
	n := restorePutBatch + 5
	restore, executor, _, _, qs, _ := newTwoReplicaRestore(t, n)
	var lines []string
	restore.Log = slog.New(slog.NewTextHandler(lineWriter{&lines}, nil))
	require.NoError(t, restore.Restore(context.Background()))
	require.EqualValues(t, n, executor.head.Number)
	require.True(t, sameBlockRef(executor.head, executor.finalized))
	for i, q := range qs {
		_, err := restore.Archive.Get(q)
		require.NoError(t, err, "record %d of %d is not in the local store", i, n)
	}
	require.Len(t, lines, 1, "one line between the phases (the periodic lines need a restore longer than %s): %v", restoreProgressEvery, lines)
	require.Contains(t, lines[0], "archive records fetched and retained; replaying")
	require.Contains(t, lines[0], "blocks="+strconv.Itoa(n))
	require.Contains(t, lines[0], "fetchAndVerify=")
	require.Contains(t, lines[0], "retain=")
}

func TestRestoreProgressIsRateLimited(t *testing.T) {
	var lines []string
	log := slog.New(slog.NewTextHandler(lineWriter{&lines}, nil))
	p := restoreProgress{started: time.Now()}
	p.note(log, "phase", 1, 10, 9)
	require.Empty(t, lines, "nothing before the first interval has passed")
	p.started = time.Now().Add(-restoreProgressEvery - time.Second)
	p.note(log, "phase", 5, 10, 5)
	p.note(log, "phase", 6, 10, 4)
	require.Len(t, lines, 1, "one line per interval")
	require.Contains(t, lines[0], "done=5 of=10 height=5")
	p.note(nil, "phase", 7, 10, 3) // no logger: nothing happens
}

type lineWriter struct{ lines *[]string }

func (w lineWriter) Write(b []byte) (int, error) {
	*w.lines = append(*w.lines, string(b))
	return len(b), nil
}

// A batch the local store fails to retain stops the restore: it returns ErrRestore and the execution client is never driven. The
// failing batch is the first one (the tip's side), so a restore that ignored the failure would go on, retain the rest, and replay
// from height 1.
func TestArchiveRestoreStopsWhenABatchIsNotRetained(t *testing.T) {
	n := restorePutBatch + 5
	restore, executor, _, _, qs, _ := newTwoReplicaRestore(t, n)
	failure := errors.New("injected store failure")
	var once sync.Once
	restore.Archive.Fault = func(point string) (err error) {
		if point == "before-publish" {
			once.Do(func() { err = failure })
		}
		return err
	}
	err := restore.Restore(context.Background())
	require.ErrorIs(t, err, ErrRestore)
	require.ErrorContains(t, err, failure.Error(), "the store's failure is what the restore reports")
	require.Len(t, executor.blocks, 1, "no block was given to the execution client to verify")
	require.EqualValues(t, 0, executor.head.Number, "and its head is still genesis")
	require.True(t, sameBlockRef(executor.head, executor.finalized))
	stored := 0
	for _, q := range qs {
		if _, err := restore.Archive.Get(q); err == nil {
			stored++
		}
	}
	require.Zero(t, stored, "the restore stopped at the failed batch: nothing of it, and no later batch, was retained")
}
