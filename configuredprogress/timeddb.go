package configuredprogress

import (
	"context"
	"log/slog"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"
)

// slowDBOp is the duration from which a database transaction is logged (bft-core#728 diagnosis).
const slowDBOp = 50 * time.Millisecond

type dbHolder struct {
	site  string
	since time.Time
}

// timedDB is the store's bolt database with timing of its transactions, for the #728 trace: how long a writer waited for the single write lock, how long it held it
// in the transaction body and in the commit (the fsync), and which transaction held the lock when it asked. It changes nothing a transaction does. Debug level, and only
// for transactions of slowDBOp or more.
type timedDB struct {
	*bolt.DB
	log    atomic.Pointer[slog.Logger]
	holder atomic.Pointer[dbHolder] // the write transaction currently in its body or commit
	slow   time.Duration            // log from this duration; zero means slowDBOp
}

func (t *timedDB) threshold() time.Duration {
	if t.slow > 0 {
		return t.slow
	}
	return slowDBOp
}

// site names the store method that opened the transaction (the caller of Update or View).
func site() string {
	pc, _, _, ok := runtime.Caller(2)
	if !ok {
		return "?"
	}
	name := runtime.FuncForPC(pc).Name()
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	return name
}

func (t *timedDB) Update(fn func(tx *bolt.Tx) error) error {
	where, asked := site(), time.Now()
	prior := t.holder.Load()
	var entered, bodyDone time.Time
	var me *dbHolder
	err := t.DB.Update(func(tx *bolt.Tx) error {
		entered = time.Now()
		me = &dbHolder{site: where, since: entered}
		t.holder.Store(me)
		defer func() { bodyDone = time.Now() }()
		return fn(tx)
	})
	done := time.Now()
	if me != nil {
		t.holder.CompareAndSwap(me, nil)
	}
	if l := t.log.Load(); l != nil && done.Sub(asked) >= t.threshold() {
		attrs := []slog.Attr{slog.String("site", where), slog.Duration("total", done.Sub(asked))}
		if !entered.IsZero() {
			attrs = append(attrs, slog.Duration("lockWait", entered.Sub(asked)), slog.Duration("body", bodyDone.Sub(entered)), slog.Duration("commit", done.Sub(bodyDone)))
		}
		if prior != nil {
			attrs = append(attrs, slog.String("holderWhenAsked", prior.site), slog.Duration("heldForWhenAsked", asked.Sub(prior.since)))
		}
		if err != nil {
			attrs = append(attrs, slog.String("err", err.Error()))
		}
		l.LogAttrs(context.Background(), slog.LevelDebug, "configuredprogress: slow write transaction", attrs...)
	}
	return err
}

func (t *timedDB) View(fn func(tx *bolt.Tx) error) error {
	where, asked := site(), time.Now()
	writer := t.holder.Load()
	err := t.DB.View(fn)
	if l := t.log.Load(); l != nil && time.Since(asked) >= t.threshold() {
		attrs := []slog.Attr{slog.String("site", where), slog.Duration("total", time.Since(asked))}
		if writer != nil {
			attrs = append(attrs, slog.String("writerWhenAsked", writer.site), slog.Duration("writerHeldForWhenAsked", asked.Sub(writer.since)))
		}
		l.LogAttrs(context.Background(), slog.LevelDebug, "configuredprogress: slow read transaction", attrs...)
	}
	return err
}
