package configuredadmission

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/unicitynetwork/bft-core/shardnode"
)

// errBehindBase marks an execution client whose finalized block lies below the journal's retained base: the client lost what it had not
// saved (a SIGKILL of the execution client), while the frontier pruned the journal up to a block the archive holds. Neither is a conflict:
// the blocks in between are certified history in the archive, and recovery replays them (replayPrefix, bft-core#843).
var errBehindBase = errors.New("execution recovery: executor finalized block is below the retained base")

// replayPrefix brings an execution client whose finalized block f lies below the base of the journal chain c up to that base, from the
// archive: the certified blocks above f are fetched (the surviving finalized block is the join point, so a finalized block that the certified
// chain does not contain is proven by the walk and is a conflict), verified exactly as a fetched suffix is (verifyFetched: historical
// certificates, block binding, the client's Verify) and applied parent first. Nothing is written to the journal, whose floors and
// protections stay as they are; readiness stays off because the caller returns an error until the base is reached.
//
// Finality only advances: after each page the page's last block, certified and below the base, is committed, so a call that runs out of
// blocks, bytes or time leaves a client from which the next call resumes (ErrRecoveryUnavailable, never the terminal budget class).
func (r *ExecutionRecovery) replayPrefix(ctx context.Context, c recoveryChain, head, f shardnode.BlockRef) error {
	if r.FetchArchive == nil && r.ArchiveCatchUp == nil {
		return fmt.Errorf("%w: execution is at %d/%x, below the retained base %d/%x, and no archive is configured to replay the pruned history (a restored snapshot needs a compatible execution snapshot)", ErrRecoveryUnavailable, f.Number, f.Hash, c.base.Number, c.base.Hash)
	}
	started := time.Now()
	if r.Log != nil {
		r.Log.InfoContext(ctx, "recovery: execution is below the retained base, replaying archived history",
			slog.Uint64("head", head.Number), slog.String("headHash", fmt.Sprintf("%x", head.Hash)), slog.Uint64("finalized", f.Number), slog.String("finalizedHash", fmt.Sprintf("%x", f.Hash)),
			slog.Uint64("base", c.base.Number), slog.String("baseHash", fmt.Sprintf("%x", c.base.Hash)), slog.Uint64("target", c.anchor.Number), slog.String("targetHash", fmt.Sprintf("%x", c.anchor.Hash)))
	}
	l := r.limits()
	blocks, used := 0, int64(0)
	cur := f
	for cur.Number < c.base.Number {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%w: replaying archived history to height %d: %w", ErrRecoveryUnavailable, c.base.Number, err)
		}
		entries, source, err := r.prefixEntries(ctx, cur, c, started)
		if err != nil {
			return err
		}
		fin, last := cur, cur
		stop := ""
		for _, e := range entries {
			if err := ctx.Err(); err != nil {
				stop = err.Error()
				break
			}
			if blocks >= l.Blocks {
				stop = fmt.Sprintf("%d blocks replayed in one call", blocks)
				break
			}
			if err := checkEntryBounds(e); err != nil {
				return err
			}
			if used+int64(len(e.Block.Raw)) > l.Bytes && blocks > 0 {
				stop = fmt.Sprintf("%d bytes replayed in one call", used)
				break
			}
			b, _, err := r.verifyFetched(ctx, last, e)
			if err != nil {
				return err
			}
			next := shardnode.BlockRef{Number: b.Number, Hash: b.Hash, StateRoot: b.StateRoot}
			if _, err := r.move(ctx, next, fin, false); err != nil {
				return err
			}
			last = next
			blocks++
			used += int64(len(b.Raw))
		}
		if last.Number > cur.Number {
			// certified and covered by the archive, below the base: finality advances to the page's end and never retreats
			if err := r.commit(ctx, last); err != nil {
				return err
			}
			cur = last
		}
		if stop != "" {
			return fmt.Errorf("%w: replaying archived history from %s: at height %d of %d (%s)", ErrRecoveryUnavailable, source, cur.Number, c.base.Number, stop)
		}
		if last.Number == f.Number && len(entries) == 0 {
			return fmt.Errorf("%w: the archive returned no history above %d/%x", ErrRecoveryUnavailable, cur.Number, cur.Hash)
		}
	}
	if !equalRef(cur, c.base) {
		return fmt.Errorf("%w: archived history ends at %d/%x, the retained base is %d/%x", ErrRecoveryConflict, cur.Number, cur.Hash, c.base.Number, c.base.Hash)
	}
	if r.ArchiveCatchUp != nil {
		r.ArchiveCatchUp.Drop()
	}
	if r.Log != nil {
		r.Log.InfoContext(ctx, "recovery: archived history replayed", slog.Uint64("finalized", cur.Number), slog.Int("blocks", blocks), slog.Duration("took", time.Since(started)))
	}
	return nil
}

// prefixEntries returns the next verified stretch of certified history above cur towards the base: the whole stretch from the archive when
// one recovery can take it, else a page of the long catch-up's plan (#769). Its errors keep their class: missing history is
// ErrRecoveryUnavailable, a verified chain that does not contain cur is ErrRecoveryConflict.
func (r *ExecutionRecovery) prefixEntries(ctx context.Context, cur shardnode.BlockRef, c recoveryChain, started time.Time) ([]shardnode.JournalFetchEntry, string, error) {
	if r.FetchArchive != nil {
		entries, err := r.FetchArchive(ctx, cur, c.base.Hash)
		if err == nil {
			return entries, "the archive", nil
		}
		if r.ArchiveCatchUp == nil || !errors.Is(err, ErrRecoveryUnavailable) || errors.Is(err, shardnode.ErrCertifiedChainForksAnchor) {
			return nil, "", r.prefixError(cur, c.base, err)
		}
	}
	catchUp := r.ArchiveCatchUp
	if catchUp == nil {
		return nil, "", fmt.Errorf("%w: no archive source", ErrRecoveryUnavailable)
	}
	until := started.Add(r.limits().Deadline / 3)
	if deadline, ok := ctx.Deadline(); ok {
		until = started.Add(time.Until(deadline) / 3)
	}
	joined, walked, err := catchUp.Walk(ctx, cur, c.base.Hash, until)
	if err != nil {
		return nil, "", r.prefixError(cur, c.base, err)
	}
	if !joined {
		return nil, "", fmt.Errorf("%w: walking the archive back from the retained base %d/%x towards %d/%x: %d blocks walked", ErrRecoveryUnavailable, c.base.Number, c.base.Hash, cur.Number, cur.Hash, walked)
	}
	entries, _, err := catchUp.Page(ctx, cur, r.catchUpPageSize())
	if err != nil || len(entries) == 0 {
		catchUp.Drop()
		return nil, "", r.prefixError(cur, c.base, errors.Join(err, errors.New("empty page")))
	}
	return withinBytes(entries, r.limits().Bytes), "the archive catch-up plan", nil
}

// prefixError classifies an archive failure while replaying the prefix: the walk of a verified chain that passes the surviving finalized
// block's height without containing it proves a conflict; everything else is history that is not available (yet), kept with its cause.
func (r *ExecutionRecovery) prefixError(cur, base shardnode.BlockRef, err error) error {
	switch {
	case errors.Is(err, shardnode.ErrCertifiedChainForksAnchor):
		return fmt.Errorf("%w: the executor's finalized %d/%x is not on the certified chain to the retained base %d/%x: %w", ErrRecoveryConflict, cur.Number, cur.Hash, base.Number, base.Hash, err)
	case errors.Is(err, ErrRecoveryConflict):
		return err
	}
	return fmt.Errorf("%w: archived history above %d/%x towards the retained base %d/%x: %w", ErrRecoveryUnavailable, cur.Number, cur.Hash, base.Number, base.Hash, err)
}
