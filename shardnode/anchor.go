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

	// fromGenesisRound marks an anchor installed by the shard's FIRST certified round, which is
	// the one round whose certified block hash need not name a block the executor ever made
	// canonical. Two independent reasons, both structural (§4 row 13):
	//
	//   - "Genesis is always non-quiet" (docs/shard-protocol.md): the root chain's genesis
	//     PreviousHash is nil, so the first round is non-quiet however little happened, and it
	//     carries a block hash even when the state did not move. round.go then does NOT commit it
	//     (pendingSubmission.needsCommit is keyed on the executor's own head moving), so a real
	//     executor stays at its genesis block while the certificate names a block it built and
	//     discarded. Against reth that is the ordinary state of an idle shard.
	//   - Some executors have no block identity at genesis at all: BlockHashOrFallback substitutes
	//     the state root, and executortest.Fake's genesis Hash is nil.
	//
	// Recorded so the identity check can apply row 13's exception to THAT anchor only — where it
	// degenerates to "the executor is at its own genesis block, at the certified state" — instead
	// of loosening the check for every anchor.
	fromGenesisRound bool
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
	// expectedNext is the partition round the LAST observed certificate assigned as the next one,
	// taken from its TechnicalRecord. It is what "the next round" means; `through+1` is not.
	//
	// MEASURED CORRECTION. §3.3.3 and the first implementation both tested consecutiveness as
	// `RoundNumber == through+1`. Certified partition rounds are not consecutive integers: the root
	// chain assigns the next round in the technical record, and it skips numbers whenever a round
	// is abandoned. On a four-validator devnet the very first certificate did it —
	// `partitionRound=0 ... nextRound=2` — and a later one went `partitionRound=5 ... nextRound=7`.
	// Every such skip invalidated the anchor of every honest node, which under the P-id gate meant
	// they stopped voting, and the shard stalled below quorum within two minutes.
	//
	// The technical record is authenticated: its hash is committed in the certificate
	// (CertificationResponse.IsValid checks it against UC.TRHash before anything here runs), so
	// "the round the previous certificate said would come next" is evidence, not a guess. It is
	// also strictly tighter than a round-number gap test: a certificate for any round OTHER than
	// the assigned one means a certificate was genuinely missed.
	expectedNext uint64
	// broken distinguishes the two ways there can be no anchor, because they are different
	// operator situations with different answers: this process has never observed a certified
	// block (row 8, `no-anchor` — ordinary after a restart, and it resolves itself when the next
	// state-changing certificate arrives), or it observed one and then lost the thread of
	// evidence for it (row 10, `continuity-gap` — this node has missed certified history and
	// needs to resync). Collapsing them costs exactly the word that says which.
	broken bool
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

// The caller must already have authenticated uc (P-ctx). This function decides only where the
// certificate sits in the chain, never whether it is genuine.
// observe folds one verified certificate into the continuity state and reports what happened.
//
// assignedNextRound is the certificate's own TechnicalRecord.Round — the partition round the root
// chain has just told this shard to submit next, and therefore the only round whose certificate may
// legitimately follow this one. See continuityState.expectedNext.
func (c *continuityState) observe(uc *types.UnicityCertificate, assignedNextRound uint64) anchorUpdate {
	if uc == nil || uc.InputRecord == nil {
		return anchorUnchanged
	}
	ir := uc.InputRecord
	// Whatever this certificate does to the anchor, it re-states what comes next.
	prevExpected := c.expectedNext
	c.expectedNext = assignedNextRound

	// A non-quiet certificate carries its own block hash: it IS the new anchor, and it resets the
	// interval — nothing before it matters any more.
	if len(ir.BlockHash) > 0 {
		c.anchor = &ExecutionAnchor{
			BlockHash: Hash(ir.BlockHash),
			StateRoot: Hash(ir.Hash),
			Round:     ir.RoundNumber,
			// The genesis signature, and only it: the root chain had certified nothing before this
			// round, which is true of exactly one round per shard. Every later round builds on a
			// real certified PreviousHash.
			fromGenesisRound: len(ir.PreviousHash) == 0,
		}
		c.through = ir.RoundNumber
		c.broken = false
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

	case prevExpected != 0 && ir.RoundNumber == prevExpected &&
		bytes.Equal(ir.Hash, ir.PreviousHash) && bytes.Equal(ir.Hash, c.anchor.StateRoot):
		// THE round the previous certificate assigned, quiet, at the anchor's state: nothing was
		// missed, and the interval extends to cover it. Round numbers may jump — the root chain
		// abandons rounds — so what makes this contiguous is the assignment, not the arithmetic.
		c.through = ir.RoundNumber
		return anchorExtended

	default:
		// A certificate for a round other than the one assigned — so at least one certificate was
		// missed — or one at a state the anchor does not explain. Either way this node can no
		// longer say what happened in between, and a matching state root would prove nothing: a
		// missed non-quiet interval can return to the same state root by a DIFFERENT block
		// (§3.3.1). Fail closed.
		c.invalidate()
		return anchorInvalidated
	}
}

func (c *continuityState) invalidate() {
	c.anchor = nil
	c.through = 0
	c.broken = true
	// expectedNext is deliberately NOT cleared: it is a fact about the certified sequence, not
	// about the anchor, and the next certificate is judged against it either way.
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
		if c.broken {
			// Row 10, on the live path: an anchor WAS held and the evidence chain for it broke —
			// a round gap, or a quiet certificate at a state it cannot explain. A matching state
			// root must not resurrect it, because a missed non-quiet interval can return to the
			// same state root by a DIFFERENT block (§3.3.1).
			return nil, &recoveryTargetError{"continuity-gap",
				"an anchor was observed and then invalidated by a gap or a disagreeing certificate, so this node can no longer say which certified block produced this state"}
		}
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

// checkHeadIdentity enforces P-id (§4): the executor's head must be the exact certified execution
// head for certifiedState — the same BLOCK, not merely the same state.
//
// This is the precondition on every row that ends in a vote, and it is why HandleCertificate cannot
// decide "already reconciled" from state roots alone. Two different blocks can share a post-state,
// so a node that missed a non-quiet interval and returned to the same state root by a different
// block would otherwise build and sign on the wrong block (§3.3.1, table row 2). The earlier
// revision of the table had exactly that fast path; it was removed as unsound, and this function is
// what replaces it.
//
// certifiedState is exp.PreviousHash. The caller must have established that the executor's head
// state already equals it — either it always did (row 1) or reconcile just made it so (rows 3/6).
// The refusals reuse recoveryTarget's names so a log line still maps to a row.
func (c *continuityState) checkHeadIdentity(head BlockRef, certifiedState Hash, genesis *BlockRef) error {
	target, err := c.recoveryTarget(certifiedState)
	if err != nil {
		// Rows 8 and 9. Reaching them here rather than in reconcile means the executor's STATE
		// agrees while this node cannot say which certified block produced it — no weaker a
		// refusal, because a matching state root proves nothing on its own.
		return err
	}
	if bytes.Equal(head.Hash, target) {
		return nil // row 1
	}
	// Row 13, and nothing wider: "permitted only when the executor head is the configured genesis
	// block and the certificate is the shard's first". The first certified round's block hash may
	// name a block no executor ever made canonical (see ExecutionAnchor.fromGenesisRound), so
	// there is nothing to compare it against — and the row says what to compare instead: the
	// executor's own genesis block, BY HASH.
	//
	// `genesis` is the head this node's executor reported before it had processed any certificate,
	// which is the configured genesis block by construction: nothing has been committed yet. It is
	// compared in full — number, block hash and state root — and that completeness is what keeps
	// this from being a bypass. An earlier revision accepted any head at block NUMBER 0 whose state
	// matched, which let a head with a fabricated block hash through: the reviewer's own
	// same-state/different-block reproduction passed again. Only the actual genesis block is the
	// genesis block.
	//
	// This is not a standing exemption either. It applies to one anchor — the one installed by the
	// round the root chain certified against a nil PreviousHash — and the first state-changing
	// round replaces it, after which every comparison is by block hash.
	if c.anchor.fromGenesisRound && genesis != nil &&
		head.Number == genesis.Number && bytes.Equal(head.Hash, genesis.Hash) &&
		bytes.Equal(head.StateRoot, genesis.StateRoot) && bytes.Equal(head.StateRoot, c.anchor.StateRoot) {
		return nil
	}
	return &recoveryTargetError{"head-identity-mismatch",
		fmt.Sprintf("executor head block is %x at state %x, but the certified block for that state is %x",
			head.Hash, head.StateRoot, target)}
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
