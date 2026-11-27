package archivewiring

import (
	"context"
	"log/slog"
	"time"

	"github.com/unicitynetwork/bft-core/archive"
)

// LayoutMigration moves a node's archive records from the directory layout to the packed layout (bft-core#1049) in the background, in steps of
// at most archive.MaxPutBatch records with a pause between them so the node's own archive traffic keeps the disk. Every record stays readable
// throughout (archive.Store.MigrateLegacy). Once nothing is left it looks again every Recheck: a joiner's archive seed can place records of the
// directory layout into a running node's archive.
type LayoutMigration struct {
	Archive *archive.Store
	Log     *slog.Logger
	Pause   time.Duration // between steps; 0: 100 ms
	Recheck time.Duration // after a complete migration; 0: 10 minutes
	Retry   time.Duration // after a failed step; 0: 30 s
}

func (m *LayoutMigration) Run(ctx context.Context) error {
	pause, recheck, retry := or(m.Pause, 100*time.Millisecond), or(m.Recheck, 10*time.Minute), or(m.Retry, 30*time.Second)
	log := m.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	var migrated, skipped int
	started := time.Time{}
	for {
		res, err := m.Archive.MigrateLegacy(archive.MaxPutBatch)
		migrated += res.Migrated
		skipped += res.Skipped
		if res.Migrated > 0 && started.IsZero() {
			started = time.Now()
			log.InfoContext(ctx, "archive: moving records to the packed layout (bft-core#1049); they stay readable throughout")
		}
		wait := pause
		switch {
		case err != nil:
			log.WarnContext(ctx, "archive layout migration step failed; retrying", "err", err, "migrated", migrated)
			wait = retry
		case res.Done:
			if !started.IsZero() || skipped > 0 {
				log.InfoContext(ctx, "archive layout migration complete", "migrated", migrated, "leftAsIs", skipped, "took", time.Since(started).Round(time.Second))
			}
			migrated, skipped, started = 0, 0, time.Time{}
			wait = recheck
		case migrated%1024 < res.Migrated:
			log.InfoContext(ctx, "archive layout migration progress", "migrated", migrated)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

func or(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}
