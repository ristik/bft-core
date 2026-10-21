package configuredprogress

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

type recordedLog struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (h *recordedLog) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordedLog) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recs = append(h.recs, r)
	return nil
}
func (h *recordedLog) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordedLog) WithGroup(string) slog.Handler      { return h }

func (h *recordedLog) find(msg string) []map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []map[string]any
	for _, r := range h.recs {
		if r.Message != msg {
			continue
		}
		m := map[string]any{"level": r.Level}
		r.Attrs(func(a slog.Attr) bool { m[a.Key] = a.Value.Any(); return true })
		out = append(out, m)
	}
	return out
}

func openTimedDB(t *testing.T) (*timedDB, *recordedLog) {
	t.Helper()
	db, err := bolt.Open(filepath.Join(t.TempDir(), "t.db"), 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	d := &timedDB{DB: db}
	rec := &recordedLog{}
	d.log.Store(slog.New(rec))
	return d, rec
}

func holdWriteLock(d *timedDB, hold time.Duration, entered chan<- struct{}) {
	_ = d.Update(func(tx *bolt.Tx) error {
		close(entered)
		time.Sleep(hold)
		return nil
	})
}

func askForWriteLock(d *timedDB) error {
	return d.Update(func(tx *bolt.Tx) error { return nil })
}

// bft-core#728 trace: a writer that waits for the write lock logs how long it waited and which transaction held it.
func TestTimedDBLogsWriteLockWaitAndHolder(t *testing.T) {
	d, rec := openTimedDB(t)
	d.slow = time.Millisecond
	entered := make(chan struct{})
	go holdWriteLock(d, 200*time.Millisecond, entered)
	<-entered
	require.NoError(t, askForWriteLock(d))

	logs := rec.find("configuredprogress: slow write transaction")
	var waiter map[string]any
	for _, l := range logs {
		if strings.Contains(l["site"].(string), "askForWriteLock") {
			waiter = l
		}
	}
	require.NotNil(t, waiter, "the waiting writer was logged: %v", logs)
	require.Equal(t, slog.LevelDebug, waiter["level"])
	require.GreaterOrEqual(t, waiter["lockWait"].(time.Duration), 100*time.Millisecond)
	require.Contains(t, waiter["holderWhenAsked"], "holdWriteLock")
	require.Contains(t, waiter, "body")
	require.Contains(t, waiter, "commit")
}

func TestTimedDBDoesNotLogFastTransactionsOrWithoutALogger(t *testing.T) {
	d, rec := openTimedDB(t)
	d.slow = time.Hour // nothing is slow enough to log; a first commit on a cold file can take 100 ms
	require.NoError(t, askForWriteLock(d))
	require.NoError(t, d.View(func(*bolt.Tx) error { return nil }))
	require.Empty(t, rec.find("configuredprogress: slow write transaction"))
	require.Empty(t, rec.find("configuredprogress: slow read transaction"))

	d.slow = time.Millisecond
	d.log.Store(nil)
	entered := make(chan struct{})
	go holdWriteLock(d, 80*time.Millisecond, entered)
	<-entered
	require.NoError(t, askForWriteLock(d)) // slow, but there is no logger: no panic, nothing logged
}

func TestTimedDBKeepsTransactionSemantics(t *testing.T) {
	d, _ := openTimedDB(t)
	require.NoError(t, d.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("b"))
		require.NoError(t, err)
		return b.Put([]byte("k"), []byte("v"))
	}))
	var got []byte
	require.NoError(t, d.View(func(tx *bolt.Tx) error { got = append(got, tx.Bucket([]byte("b")).Get([]byte("k"))...); return nil }))
	require.Equal(t, []byte("v"), got)
	require.ErrorIs(t, d.Update(func(*bolt.Tx) error { return context.Canceled }), context.Canceled, "a body error is returned and rolls back")
}

// bft-core#728 trace: a journal load reports how big the journal it just read was, so load time can be plotted against size.
func TestJournalLoadLogsItsSize(t *testing.T) {
	f := newFixture(t, 2)
	s, _ := openJournal(t, f, testJournalLimits)
	defer s.Close()
	bootstrap := f.bootstrap(1, 4)
	admitJournal(t, s, f, bootstrap)
	require.NoError(t, s.PutJournalCandidate(context.Background(), f.ctx, testJournalLimits, candidateB1(f, bootstrap)))
	rec := &recordedLog{}
	s.SetLogger(slog.New(rec))
	s.db.slow = time.Nanosecond // every load counts as slow here
	image, err := s.LoadJournal(context.Background(), f.ctx, testJournalLimits)
	require.NoError(t, err)

	logs := rec.find("configuredprogress: journal load")
	require.NotEmpty(t, logs)
	last := logs[len(logs)-1]
	require.NotEmpty(t, image.Candidates)
	require.Equal(t, int64(len(image.Candidates)), last["candidates"])
	require.Equal(t, int64(len(image.Observations)), last["observations"])
	require.Equal(t, uint64(image.Bytes), last["bytes"])
	require.Positive(t, last["took"].(time.Duration))
}
