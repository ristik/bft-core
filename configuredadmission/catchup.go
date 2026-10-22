package configuredadmission

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ArchiveCatchUp is the archive side of a catch-up longer than one recovery (bft-core#769, briefs/769-rejoin-design.md). Production wires
// archivewiring.CatchUp: an ArchivePlan walked back through the archive replicas, and the frontier worker's Advance. Its errors are
// availability conditions to the coordinator: a page's data is judged by admitFetched, as any fetched suffix is.
type ArchiveCatchUp interface {
	// Walk continues the plan from after, or starts one from after up to top when there is none (top is used only then), until it
	// joins after or until passes. walked is how many blocks the plan holds.
	Walk(ctx context.Context, after shardnode.BlockRef, top []byte, until time.Time) (joined bool, walked int, err error)
	// Live reports whether a plan for after is in progress (walking from after, or joined and holding after): its top is fixed then.
	Live(after shardnode.BlockRef) bool
	// Page returns up to max verified entries of the joined plan above from, oldest first, and how many planned blocks lie above from.
	Page(ctx context.Context, from shardnode.BlockRef, max int) (entries []shardnode.JournalFetchEntry, above int, err error)
	// Drop forgets the plan; the next call starts another.
	Drop()
	// AdvanceFrontier covers and prunes up to max blocks above the frontier, under the frontier's unchanged rules.
	AdvanceFrontier(ctx context.Context, max int) error
}

// catchUpPageSize is how many blocks one call admits: a quarter of the journal's candidate limit leaves room for the certificates
// that arrive meanwhile, and one page is never more than one recovery.
func (r *ExecutionRecovery) catchUpPageSize() int {
	return max(1, min(64, r.walkLimit()/4, r.limits().Blocks))
}

// catchUpPage advances a long catch-up by one page (#769): it finds the top of the gap (the oldest parent of the peers' journal tail,
// else the target this coordinator saw last, else the target), walks the archive back to the retained anchor within a third of the
// call's time, then admits the next page through admitFetched and finalizes it. When the journal has no room for a page, the call
// first advances the frontier (the worker's passes do so too) and waits while it cannot. A call that made progress still returns ErrRecoveryUnavailable naming the height, unless its page reached
// the target: the next authenticated certificate continues it.
func (r *ExecutionRecovery) catchUpPage(ctx context.Context, after shardnode.BlockRef, target []byte, expected *types.UnicityCertificate) (err error) {
	started := time.Now()
	defer func() {
		// Out of time: what this call admitted is durable journal state and the next call resumes from it.
		if err != nil && !errors.Is(err, ErrRecoveryUnavailable) && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)) {
			err = fmt.Errorf("%w: archive catch-up call ran out of time after %s: %w", ErrRecoveryUnavailable, time.Since(started).Round(time.Millisecond), err)
		}
	}()
	catchUp := r.ArchiveCatchUp
	page := r.catchUpPageSize()
	var top []byte
	fromPeer := false
	if !catchUp.Live(after) {
		top, fromPeer = r.catchUpTop(ctx, after, target, expected)
	}
	if len(target) == 32 && !bytes.Equal(target, r.catchUpSeen) {
		defer func() { r.catchUpPrev, r.catchUpSeen = r.catchUpSeen, bytes.Clone(target) }()
	}
	// a third of the call walks; the rest admits, finalizes and advances the frontier
	until := started.Add(r.limits().Deadline / 3)
	if deadline, ok := ctx.Deadline(); ok {
		until = started.Add(time.Until(deadline) / 3)
	}
	joined, walked, err := catchUp.Walk(ctx, after, top, until)
	if err != nil {
		if fromPeer && walked == 0 {
			// rev2 B2: a peer's tail is only its claim. A top the archive does not have is skipped for a while, so that one faulty
			// peer first in the provider order cannot hold the catch-up on its fabricated tail.
			r.catchUpRefuseTop(top)
		}
		return r.catchUpWaiting(ctx, target, "walking the archive", err)
	}
	if !joined {
		r.catchUpProgress(ctx, "archive catch-up: walking back", after.Number, walked, started)
		return fmt.Errorf("%w: catching up from the archive: %d blocks walked back towards height %d", ErrRecoveryUnavailable, walked, after.Number)
	}
	frontierWait, err := r.catchUpRoomFor(ctx, page, target, true)
	if err != nil {
		return err
	}
	entries, above, err := catchUp.Page(ctx, after, page)
	if err != nil || len(entries) == 0 {
		catchUp.Drop()
		return r.catchUpWaiting(ctx, target, "reading the planned page", errors.Join(err, errors.New("empty page")))
	}
	entries = withinBytes(entries, r.limits().Bytes)
	last := entries[len(entries)-1].Block
	if err := r.admitFetched(ctx, after, last.Hash, entries, true, "archive_catchup"); err != nil {
		catchUp.Drop()
		return err
	}
	c, err := r.load(ctx)
	if err != nil {
		return err
	}
	if _, err := r.recoverChain(ctx, c, false); err != nil {
		return err
	}
	// The frontier covers this page later: the worker's passes, or the next call when it finds no room.
	left := above - len(entries)
	if left == 0 {
		catchUp.Drop()
	}
	r.catchUpProgress(ctx, "archive catch-up: page admitted", last.Number, left, started, slog.Duration("frontierWait", frontierWait))
	if bytes.Equal(last.Hash, target) {
		return nil
	}
	return fmt.Errorf("%w: catching up from the archive: at height %d, %d planned blocks above", ErrRecoveryUnavailable, last.Number, left)
}

// catchUpTop is the block the archive walk starts from (rev2 R1): the newest blocks are in the peers' hot journals and not archived yet,
// so a peer's journal tail (a zero ancestor) names the parent of its oldest retained entry, which two replicas hold. A peer's tail is
// unauthenticated: a top whose walk failed at its first record is skipped for a while (catchUpRefuseTop), and the next provider's is
// taken. Without one, a certified target from an earlier call (archived by now, most likely), else the target. fromPeer reports
// whether the top came from a peer's tail.
func (r *ExecutionRecovery) catchUpTop(ctx context.Context, after shardnode.BlockRef, target []byte, expected *types.UnicityCertificate) (top []byte, fromPeer bool) {
	req := shardnode.JournalFetchRequest{TargetHash: target, AfterHash: make([]byte, 32)}
	if len(target) == 0 && expected != nil {
		req.HeldRound = expected.GetRoundNumber()
		req.HeldIdentity, _ = expected.InputRecord.Bytes()
	}
	limits := r.TransportLimits
	if limits.MaxBlocks == 0 {
		limits = shardnode.DefaultJournalTransportLimits()
	}
	for index, provider := range r.providerList() {
		if index >= 4 || ctx.Err() != nil {
			break
		}
		var entries []shardnode.JournalFetchEntry
		var err error
		if r.fetch != nil {
			entries, err = r.fetch(ctx, provider, req)
		} else if r.Host != nil {
			entries, err = shardnode.RequestJournalEntries(ctx, r.Host, provider, req, limits)
		} else {
			break
		}
		if err != nil || len(entries) == 0 || len(target) == 32 && !bytes.Equal(entries[len(entries)-1].Block.Hash, target) {
			continue
		}
		linked := true
		for i := 1; i < len(entries); i++ {
			linked = linked && bytes.Equal(entries[i].Block.ParentHash, entries[i-1].Block.Hash) && entries[i].Block.Number == entries[i-1].Block.Number+1
		}
		oldest := entries[0].Block
		// Only a locator: the walk verifies every record it reaches from here and admission verifies the tail again later.
		if linked && len(oldest.ParentHash) == 32 && oldest.Number > after.Number+1 && !r.catchUpRefused(oldest.ParentHash) {
			return bytes.Clone(oldest.ParentHash), true
		}
	}
	// Certified targets of earlier calls: the one before this target, else the one before that.
	for _, earlier := range [][]byte{r.catchUpSeen, r.catchUpPrev} {
		if len(earlier) == 32 && !bytes.Equal(earlier, target) && !bytes.Equal(earlier, after.Hash) {
			return bytes.Clone(earlier), false
		}
	}
	return target, false
}

// catchUpRefusedFor is how long a peer-supplied top whose walk failed at its first record is skipped.
const catchUpRefusedFor = time.Minute

func (r *ExecutionRecovery) catchUpRefuseTop(top []byte) {
	if r.catchUpRefusedTops == nil || len(r.catchUpRefusedTops) >= 64 {
		r.catchUpRefusedTops = make(map[string]time.Time) // bounded: a fresh map forgets older refusals
	}
	r.catchUpRefusedTops[string(top)] = time.Now()
}

func (r *ExecutionRecovery) catchUpRefused(top []byte) bool {
	at, ok := r.catchUpRefusedTops[string(top)]
	return ok && time.Since(at) < catchUpRefusedFor
}

// withinBytes cuts a page at the recovery's byte budget, keeping at least one entry: admitFetched refuses a longer suffix with the
// terminal ErrRecoveryBudget (rev2 B1), and one entry is at most configuredprogress.MaxCandidateBytes, under any valid budget.
func withinBytes(entries []shardnode.JournalFetchEntry, budget int64) []shardnode.JournalFetchEntry {
	var total int64
	for i, e := range entries {
		total += int64(len(e.Block.Raw))
		if total > budget && i > 0 {
			return entries[:i]
		}
	}
	return entries
}

// catchUpRoomFor makes room in the journal for n more blocks before a catch-up admits them (an archive page, or the last stretch from
// a peer or the archive): admitting more than the journal holds would stop at its bounds, and that stop is terminal. Without room it
// advances the frontier, which frees the journal only for blocks two replicas hold verified copies of; the frontier's errors (replica
// copies, local finality, a concurrent pass) are never a recovery class (rev2 R2), and the call waits. Without a catch-up wired, or
// for a backfill (advance false), nothing changes.
func (r *ExecutionRecovery) catchUpRoomFor(ctx context.Context, n int, target []byte, advance bool) (time.Duration, error) {
	if r.ArchiveCatchUp == nil || !advance {
		return 0, nil
	}
	if room, err := r.catchUpRoom(ctx, n); err != nil || room {
		return 0, err
	}
	started := time.Now()
	advanceErr := r.ArchiveCatchUp.AdvanceFrontier(ctx, n)
	wait := time.Since(started) // includes waiting for a worker pass that holds the frontier
	if advanceErr != nil {
		return wait, r.catchUpWaiting(ctx, target, "waiting for archive copies", advanceErr)
	}
	if room, err := r.catchUpRoom(ctx, n); err != nil {
		return wait, err
	} else if !room {
		return wait, r.catchUpWaiting(ctx, target, "waiting for archive copies", fmt.Errorf("the journal has no room for %d more blocks", n))
	}
	return wait, nil
}

// catchUpRoom reports whether the journal can take n more candidates and certificates.
func (r *ExecutionRecovery) catchUpRoom(ctx context.Context, n int) (bool, error) {
	image, err := r.Store.LoadJournal(ctx, r.Context, r.JournalLimits)
	if err != nil {
		return false, fmt.Errorf("%w: verifying journal: %w", ErrRecoveryUnavailable, err)
	}
	return len(image.Candidates)+n <= r.walkLimit() && (r.JournalLimits.Observations <= 0 || len(image.Observations)+n <= r.JournalLimits.Observations), nil
}

// catchUpWaiting is an availability stop of the catch-up: never a terminal or data class, logged once a minute per target (they repeat
// on every certificate).
func (r *ExecutionRecovery) catchUpWaiting(ctx context.Context, target []byte, what string, cause error) error {
	if r.Log != nil && (!bytes.Equal(r.catchUpWarned, target) || time.Since(r.catchUpWarnedAt) >= time.Minute) {
		r.catchUpWarned, r.catchUpWarnedAt = bytes.Clone(target), time.Now()
		r.Log.WarnContext(ctx, "archive catch-up waiting", slog.String("step", what), slog.String("target", fmt.Sprintf("%x", target)), slog.String("cause", cause.Error()))
	}
	return fmt.Errorf("%w: archive catch-up %s: %v", ErrRecoveryUnavailable, what, cause)
}

func (r *ExecutionRecovery) catchUpProgress(ctx context.Context, msg string, height uint64, left int, started time.Time, extra ...slog.Attr) {
	if r.Log != nil {
		attrs := append([]slog.Attr{slog.Uint64("height", height), slog.Int("blocks", left), slog.Duration("took", time.Since(started))}, extra...)
		r.Log.LogAttrs(ctx, slog.LevelInfo, msg, attrs...)
	}
}
