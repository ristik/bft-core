package archivewiring

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// MaxPlanBlocks bounds the gap one ArchivePlan walks. A plan keeps a hash, a height and an index entry per block, about 150 bytes:
// some 40 MB at this bound, which is days of outage at testnet block rates. A longer outage is an operator restore.
const MaxPlanBlocks = 1 << 18

// planPutBatch is how many walked replica records are retained with one shared set of device flushes (as restorePutBatch).
const planPutBatch = 16

// ArchivePlan is the archive part of a long catch-up (bft-core#769, briefs/769-rejoin-design.md): the certified chain from a retained
// anchor (After) up to Top, walked back through the archive without FetchSuffix's cap. Walking is bounded by time and resumes where the
// previous call stopped; every walked record is verified (RecoverySource.decodeEntry, which accepts receipt-complete copies only) and retained in
// the local archive, so a resumed or restarted walk reads it back locally. The plan holds only block hashes. A page is read back from
// the local archive and verified again, and journal admission checks it once more: the plan is a locator and a staging area, never
// evidence.
type ArchivePlan struct {
	After shardnode.BlockRef
	Top   [32]byte

	walked  [][32]byte // newest first: Top, its parent, ...
	heights []uint64   // walked[i]'s height
	index   map[[32]byte]int
	next    [32]byte // the next block to walk while not joined
	joined  bool
}

// NewArchivePlan starts a plan from the retained anchor after up to top, a block above it that the archive holds.
func NewArchivePlan(after shardnode.BlockRef, top [32]byte) (*ArchivePlan, error) {
	if len(after.Hash) != 32 || len(after.StateRoot) != 32 || top == ([32]byte{}) || bytes.Equal(after.Hash, top[:]) {
		return nil, fmt.Errorf("%w: catch-up plan needs a retained anchor and a different top block", ErrArchiveRecoveryUnavailable)
	}
	return &ArchivePlan{After: after, Top: top, next: top, index: make(map[[32]byte]int)}, nil
}

// Joined reports whether the walk has reached the anchor.
func (p *ArchivePlan) Joined() bool { return p.joined }

// Walked is how many blocks the walk has verified and retained so far.
func (p *ArchivePlan) Walked() int { return len(p.walked) }

// Remaining is how many planned blocks lie above from, a block on the plan or its anchor; false when from is neither.
func (p *ArchivePlan) Remaining(from []byte) (int, bool) {
	if bytes.Equal(from, p.After.Hash) {
		return len(p.walked), true
	}
	if len(from) != 32 {
		return 0, false
	}
	i, ok := p.index[[32]byte(from)]
	return i, ok
}

// Extend walks the plan further back, until it joins the anchor, until is reached, or a record cannot be had. It retains each record
// fetched from a replica in the local archive before it returns. A record that is unavailable from every copy ends the call with
// ErrArchiveRecoveryUnavailable; a chain that passes the anchor's height without reaching it ends it with ErrArchiveRecoveryInvalid.
// Both keep what was walked, and the next call resumes there.
func (s *RecoverySource) Extend(ctx context.Context, p *ArchivePlan, until time.Time) (err error) {
	if s == nil || s.Local == nil || p == nil || !s.Limits.valid() {
		return ErrArchiveRecoveryUnavailable
	}
	var pendingQ []archive.Request
	var pendingRec []*archive.Record
	flush := func() error {
		if len(pendingQ) == 0 {
			return nil
		}
		if err := s.Local.PutBatch(pendingQ, pendingRec); err != nil {
			return fmt.Errorf("%w: retaining walked records: %v", ErrArchiveRecoveryUnavailable, err)
		}
		pendingQ, pendingRec = pendingQ[:0], pendingRec[:0]
		return nil
	}
	// The walk's position moves only with records that are retained (or were local already): a failed flush drops the batch's
	// positions, so a resumed walk fetches them again.
	mark := len(p.walked)
	defer func() {
		if flushErr := flush(); flushErr != nil {
			p.truncate(mark)
			if err == nil {
				err = flushErr
			}
		}
	}()
	for !p.joined {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !time.Now().Before(until) {
			return nil
		}
		if len(p.walked) >= MaxPlanBlocks {
			return fmt.Errorf("%w: catch-up gap exceeds %d blocks; restore the validator", ErrArchiveRecoveryUnavailable, MaxPlanBlocks)
		}
		q := archive.Request{Context: s.Subject, BlockHash: p.next}
		entry, rec, local, err := s.fetchVerifiedRecord(ctx, q)
		if err != nil {
			return fmt.Errorf("%w: %x: %v", ErrArchiveRecoveryUnavailable, p.next, err)
		}
		number := entry.Block.Number
		// Defence in depth: the walk follows certified parent hashes, so a height that breaks off (here and at the anchor below) needs
		// a forged certified record. The first record's height is checked against the anchor's (a Top at or below it).
		if n := len(p.walked); n > 0 && number+1 != p.heights[n-1] {
			return fmt.Errorf("%w: archive block %x is at height %d, its child at %d", ErrArchiveRecoveryInvalid, p.next, number, p.heights[n-1])
		}
		if number <= p.After.Number {
			if len(p.walked) > 0 {
				// a verified chain that came down from above the anchor's height without containing the anchor proves the anchor is not on it
				return fmt.Errorf("%w: %w: archive chain to %x passes the retained anchor's height %d without reaching it", ErrArchiveRecoveryInvalid, shardnode.ErrCertifiedChainForksAnchor, p.Top, p.After.Number)
			}
			return fmt.Errorf("%w: archive chain to %x passes the retained anchor's height %d without reaching it", ErrArchiveRecoveryInvalid, p.Top, p.After.Number)
		}
		joins := bytes.Equal(entry.Block.ParentHash, p.After.Hash)
		switch {
		case joins && number != p.After.Number+1:
			return fmt.Errorf("%w: archive chain joins the retained anchor at height %d, not %d", ErrArchiveRecoveryInvalid, number, p.After.Number+1)
		case !joins && (number == p.After.Number+1 || len(entry.Block.ParentHash) != 32):
			return fmt.Errorf("%w: %w: archive chain to %x does not reach the retained anchor %x", ErrArchiveRecoveryInvalid, shardnode.ErrCertifiedChainForksAnchor, p.Top, p.After.Hash)
		}
		// accepted: a refused record above is not recorded, so a resumed walk asks for it again
		if !local {
			pendingQ, pendingRec = append(pendingQ, q), append(pendingRec, rec)
		}
		p.index[p.next] = len(p.walked)
		p.walked, p.heights = append(p.walked, p.next), append(p.heights, number)
		if joins {
			p.joined = true
		} else {
			p.next = [32]byte(common.BytesToHash(entry.Block.ParentHash))
		}
		if len(pendingQ) == planPutBatch {
			if err := flush(); err != nil {
				return err
			}
			mark = len(p.walked)
		}
	}
	return nil
}

func (p *ArchivePlan) truncate(n int) {
	for _, h := range p.walked[n:] {
		delete(p.index, h)
	}
	if n < len(p.walked) {
		p.next, p.joined = p.walked[n], false
	}
	p.walked, p.heights = p.walked[:n], p.heights[:n]
}

// Page returns up to max verified entries of a joined plan, oldest first, starting above from: the plan's anchor or a block on the
// plan (the anchor recovery has reached by admitting earlier pages). Each record is read back (local archive first) and verified
// again, and the entries' parent states are chained from from's state root. A from that is not on the plan is
// ErrArchiveRecoveryUnavailable: the caller drops the plan and starts another.
func (s *RecoverySource) Page(ctx context.Context, p *ArchivePlan, from shardnode.BlockRef, max int) ([]shardnode.JournalFetchEntry, error) {
	if s == nil || p == nil || !p.joined || max <= 0 || len(from.StateRoot) != 32 {
		return nil, ErrArchiveRecoveryUnavailable
	}
	above, ok := p.Remaining(from.Hash)
	if !ok {
		return nil, fmt.Errorf("%w: anchor %x is not on the catch-up plan", ErrArchiveRecoveryUnavailable, from.Hash)
	}
	if above == 0 {
		return nil, fmt.Errorf("%w: the catch-up plan is consumed", ErrArchiveRecoveryUnavailable)
	}
	var out []shardnode.JournalFetchEntry
	parentHash, parentNumber, parentState := from.Hash, from.Number, bytes.Clone(from.StateRoot)
	for i := above - 1; i >= 0 && len(out) < max; i-- {
		q := archive.Request{Context: s.Subject, BlockHash: p.walked[i]}
		entry, _, _, err := s.fetchVerifiedRecord(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("%w: %x: %v", ErrArchiveRecoveryUnavailable, q.BlockHash, err)
		}
		// unreachable without a forged certified record (the plan is hash-linked); admission checks the links again
		if !bytes.Equal(entry.Block.ParentHash, parentHash) || entry.Block.Number != parentNumber+1 {
			return nil, fmt.Errorf("%w: planned block %x does not extend %x", ErrArchiveRecoveryInvalid, q.BlockHash, parentHash)
		}
		entry.ParentState = parentState
		out = append(out, entry)
		parentHash, parentNumber, parentState = entry.Block.Hash, entry.Block.Number, bytes.Clone(entry.Block.StateRoot)
	}
	return out, nil
}

// CatchUp is the archive side of a long catch-up as configuredadmission.ExecutionRecovery uses it (its ArchiveCatchUp): one plan at
// a time, walked with Source, and the frontier advanced by Frontier, which the node may set after the coordinator is built. Calls
// come serialized by the coordinator.
type CatchUp struct {
	Source   *RecoverySource
	Frontier *FrontierWorker
	plan     *ArchivePlan
}

// Walk continues the plan when after is its anchor, or a block on it once joined; otherwise it starts one from after up to top. A
// plan that is refused before its first block, or whose chain misses the anchor, is dropped: its top came from a peer's tail or an
// earlier target, and the next call starts from another.
func (c *CatchUp) Walk(ctx context.Context, after shardnode.BlockRef, top []byte, until time.Time) (bool, int, error) {
	if c.plan != nil {
		if _, on := c.plan.Remaining(after.Hash); !on || !c.plan.joined && !bytes.Equal(after.Hash, c.plan.After.Hash) {
			c.plan = nil
		}
	}
	if c.plan == nil {
		if len(top) != 32 {
			return false, 0, fmt.Errorf("%w: no block to start the archive walk from", ErrArchiveRecoveryUnavailable)
		}
		plan, err := NewArchivePlan(after, [32]byte(top))
		if err != nil {
			return false, 0, err
		}
		c.plan = plan
	}
	// the walk's time is bounded as a whole: a record fetch that blocks past until ends the walk, not the caller's call
	walkCtx, cancel := context.WithDeadline(ctx, until)
	err := c.Source.Extend(walkCtx, c.plan, until)
	cancel()
	if err != nil && errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		err = nil // its time budget, spent: the next call resumes
	}
	walked, joined := c.plan.Walked(), c.plan.Joined()
	if err != nil && (walked == 0 || errors.Is(err, ErrArchiveRecoveryInvalid)) {
		c.plan = nil
	}
	return joined, walked, err
}

// Live reports whether the plan continues from after: walking from it, or joined and holding it.
func (c *CatchUp) Live(after shardnode.BlockRef) bool {
	if c.plan == nil {
		return false
	}
	if bytes.Equal(after.Hash, c.plan.After.Hash) {
		return true
	}
	_, on := c.plan.Remaining(after.Hash)
	return on && c.plan.joined
}

func (c *CatchUp) Page(ctx context.Context, from shardnode.BlockRef, max int) ([]shardnode.JournalFetchEntry, int, error) {
	if c.plan == nil {
		return nil, 0, ErrArchiveRecoveryUnavailable
	}
	above, _ := c.plan.Remaining(from.Hash)
	entries, err := c.Source.Page(ctx, c.plan, from, max)
	return entries, above, err
}

func (c *CatchUp) Drop() { c.plan = nil }

func (c *CatchUp) AdvanceFrontier(ctx context.Context, max int) error {
	if c.Frontier == nil {
		return ErrConfig
	}
	return c.Frontier.Advance(ctx, max)
}
