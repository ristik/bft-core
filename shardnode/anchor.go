package shardnode

import (
	"bytes"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
)

/*
ExecutionAnchor is the last NON-QUIET certified block: the block hash the executor must be at, the
state root that block produced, and the partition round it was certified in.

Why it exists (issue #92, design docs/design/f6b-quiet-uc-recovery.md §3). Round.reconcile needs a
block hash to recover to, and takes it from the certificate in hand. A quiet certificate carries a
nil BlockHash by construction — the round built nothing — so a node that fell behind a
state-changing block and then receives a quiet certificate had no target at all, and asked its
executor to commit nothing. The anchor is that missing target: the block that produced the state the
quiet rounds have been sitting at.

It is not a cache. Everything about it is derived from certificates this node verified itself, and
it is discarded the moment the chain of evidence for it breaks.
*/
type ExecutionAnchor struct {
	BlockHash Hash
	StateRoot Hash
	Round     uint64
}

// continuityState is the live half of §3.3: the anchor plus the highest partition round through
// which this node has itself verified the interval quiet at the anchor's state.
//
// In-process only, and sound precisely because of that: this node observed and verified every
// certificate that advanced it, and process memory is not attacker-supplied input. The persisted
// form is a different problem — an older checkpoint replays perfectly (§6.1), which is why
// retaining this across a restart requires the evidence sequence AND the separate signing contract
// (#105), and why neither is in this file.
type continuityState struct {
	anchor *ExecutionAnchor
	// through is the highest partition round verified quiet at anchor.StateRoot. Equal to
	// anchor.Round when no quiet round has followed the anchor yet — the ordinary state of a
	// shard that just certified a block (§3.3.4's empty interval).
	through uint64
}

// anchorUpdate says what observing a certificate did to the continuity state, for logging and for
// tests that need to assert the transition rather than infer it from a later effect.
type anchorUpdate int

const (
	anchorUnchanged   anchorUpdate = iota // a repeat, or a certificate carrying no state yet
	anchorInstalled                       // a non-quiet certificate replaced the anchor
	anchorExtended                        // a quiet certificate extended the verified interval
	anchorInvalidated                     // the evidence chain broke; there is no usable anchor
)

func (u anchorUpdate) String() string {
	switch u {
	case anchorInstalled:
		return "installed"
	case anchorExtended:
		return "extended"
	case anchorInvalidated:
		return "invalidated"
	default:
		return "unchanged"
	}
}

// observe folds one verified certificate into the continuity state and reports what happened.
//
// The caller must already have authenticated uc (P-ctx). This function decides only where the
// certificate sits in the chain, never whether it is genuine.
func (c *continuityState) observe(uc *types.UnicityCertificate) anchorUpdate {
	if uc == nil || uc.InputRecord == nil {
		return anchorUnchanged
	}
	ir := uc.InputRecord

	// A non-quiet certificate carries its own block hash: it IS the new anchor, and it resets the
	// interval — nothing before it matters any more.
	if len(ir.BlockHash) > 0 {
		c.anchor = &ExecutionAnchor{
			BlockHash: Hash(ir.BlockHash),
			StateRoot: Hash(ir.Hash),
			Round:     ir.RoundNumber,
		}
		c.through = ir.RoundNumber
		return anchorInstalled
	}

	// Quiet from here. Nothing to extend without an anchor — a shard whose first certificates are
	// quiet (sync/genesis) has no certified block yet, which is not a fault.
	if c.anchor == nil {
		return anchorUnchanged
	}

	switch {
	case ir.RoundNumber == c.through:
		// A repeat of the round already covered. It neither advances nor invalidates: the
		// interval is keyed by partition round, so a repeat cannot extend it (§3.3.3). Its input
		// record must still agree, or the two certificates disagree about one round.
		if !bytes.Equal(ir.Hash, c.anchor.StateRoot) {
			c.invalidate()
			return anchorInvalidated
		}
		return anchorUnchanged

	case ir.RoundNumber == c.through+1 && bytes.Equal(ir.Hash, ir.PreviousHash) && bytes.Equal(ir.Hash, c.anchor.StateRoot):
		// The next round, quiet, at the anchor's state: the interval extends by exactly one.
		c.through = ir.RoundNumber
		return anchorExtended

	default:
		// A gap, or a quiet certificate at a state the anchor does not explain. Either way this
		// node can no longer say what happened in between, and a matching state root would prove
		// nothing — a missed non-quiet interval can return to the same state root by a DIFFERENT
		// block (§3.3.1). Fail closed.
		c.invalidate()
		return anchorInvalidated
	}
}

func (c *continuityState) invalidate() {
	c.anchor = nil
	c.through = 0
}

// recoveryTargetError says why no anchor could be offered, using the diagnostic names from the
// transition table (§4) so a log line maps to a row.
type recoveryTargetError struct {
	reason string
	detail string
}

func (e *recoveryTargetError) Error() string { return e.reason + ": " + e.detail }

// recoveryTarget returns the block hash reconcile should commit to in order to reach certifiedState,
// or an error naming which transition-table row refused.
//
// certifiedState is exp.PreviousHash — the state the next round builds on, which is the state the
// executor is supposed to already be at.
func (c *continuityState) recoveryTarget(certifiedState Hash) (Hash, error) {
	if c.anchor == nil {
		// Row 8. This is where the defect used to produce Commit(nil).
		return nil, &recoveryTargetError{"no-anchor",
			"no non-quiet certificate has been observed in this process, so no certified block identifies the state to recover to"}
	}
	if !bytes.Equal(c.anchor.StateRoot, certifiedState) {
		// Row 9. The anchor explains a different state; applying it would move the executor
		// somewhere the root chain did not certify for this round.
		return nil, &recoveryTargetError{"anchor-mismatch",
			fmt.Sprintf("retained anchor produces state %x but this round builds on %x", c.anchor.StateRoot, certifiedState)}
	}
	if len(c.anchor.BlockHash) == 0 {
		// Defence in depth: observe never installs an anchor without a block hash, so reaching
		// this is a bug in that logic rather than a condition of the chain. Commit(nil) must be
		// unreachable, so it is checked here too.
		return nil, &recoveryTargetError{"no-anchor", "retained anchor carries no block hash"}
	}
	return c.anchor.BlockHash, nil
}

// anchorHashForLog renders an anchor's block hash for a log line, including the "none" case, so a
// log never shows an empty string where a hash is expected and leaves the reader guessing whether
// the anchor was absent or the hash was.
func anchorHashForLog(a *ExecutionAnchor) string {
	if a == nil {
		return "none"
	}
	return fmt.Sprintf("%x", a.BlockHash)
}
