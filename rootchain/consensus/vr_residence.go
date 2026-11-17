package consensus

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/vradmit"
)

// The live-vote residence rule of a validator-registry chain (design section 5.3.2, schema section 10.5): an honest root votes for a
// proposal carrying HandoffView(I, v+1) only once ceil(T(L, v) * 1000 * (1 + rho)) ms have passed on its local monotonic clock since it
// first held the committed opening of view v. It is a voting policy, never a validity rule: replay never evaluates it, the block is
// executed and found valid as usual, and a root that is not yet eligible defers its vote; it never marks the block invalid. A restart
// resets the start to the re-learning time (the tracker is not persisted).
//
// The opening is observed when this root learns it, from its committed root block only (never from a speculatively executed one): on
// every commit (processQC), at the start of a consensus context and after a recovery installs its state (#1177 review, sol). The opening
// of view v >= 1 is the committed backoff with intent I bound and LastView == v. The opening of view 0 is the commit of intent I's anchor
// block: it is held once the committed round reaches the anchor round of the intent derived over the committed state, for the committed
// attempt identity; until then no HandoffView(I, 1) is eligible, and the time is never shared with another intent (#1177 review, astra 2).

// residenceKey names the committed opening of one view of one intent of one attempt.
type residenceKey struct {
	epoch, attempt, view uint64
	intent               [32]byte
}

// vrResidence remembers, for the committed opening it last observed, when this root first held it, in monotonic milliseconds since base.
type vrResidence struct {
	base  time.Time
	clock func() time.Time // nil: time.Now
	key   residenceKey
	seen  uint64
	have  bool
}

func newVRResidence(now time.Time) *vrResidence { return &vrResidence{base: now} }

func (r *vrResidence) millis(now time.Time) uint64 {
	d := now.Sub(r.base) // monotonic: both readings carry the monotonic clock
	if d < 0 {
		return 0
	}
	return uint64(d.Milliseconds())
}

// openingOf is the committed opening the root holds, if any.
func openingOf(o storage.VROpening) (residenceKey, bool) {
	b := o.State.Backoff
	k := residenceKey{epoch: b.Epoch, attempt: b.Attempt, view: b.LastView}
	if b.LastView != 0 {
		copy(k.intent[:], b.Intent)
		return k, true
	}
	if !o.IntentOK || o.CommittedRound < o.Intent.AnchorRound {
		return k, false
	}
	k.intent = o.Intent.Digest
	return k, true
}

// observe records the committed opening the first time this root holds it; an opening already held keeps its first time.
func (r *vrResidence) observe(o storage.VROpening, now time.Time) {
	k, held := openingOf(o)
	switch {
	case !held:
		r.have = false
	case !r.have || k != r.key:
		r.key, r.seen, r.have = k, r.millis(now), true
	}
}

// wait is how many more milliseconds this root waits before it may vote for HandoffView(intent, view) over the committed opening o.
// held is false while this root does not hold the opening of view-1 yet (the caller re-checks later); ok is false when it may never vote
// for it on this committed state (the view is not the committed one's successor, another intent, or T is never).
func (r *vrResidence) wait(o storage.VROpening, intent [32]byte, view uint64, now time.Time) (wait uint64, held, ok bool) {
	r.observe(o, now)
	b := o.State.Backoff
	if view == 0 || view-1 != b.LastView {
		return 0, false, false
	}
	if b.LastView != 0 && !bytes.Equal(b.Intent, intent[:]) {
		return 0, false, false
	}
	if !r.have {
		return 0, false, true
	}
	if r.key != (residenceKey{epoch: b.Epoch, attempt: b.Attempt, view: view - 1, intent: intent}) {
		return 0, false, false // the held opening is of another intent
	}
	w, finite := vradmit.ResidenceWaitMillis(b.Level, view-1, b.N)
	if !finite {
		return 0, false, false
	}
	if elapsed := r.millis(now) - r.seen; elapsed < w {
		return w - elapsed, true, true
	}
	return 0, true, true
}

// observeVR records the committed VR opening this root holds now: called whenever the committed root may have changed.
func (x *ConsensusManager) observeVR() {
	o, on, err := x.blockStore.CommittedVROpening()
	if err != nil || !on {
		return
	}
	now := x.residenceNow()
	if x.residence == nil {
		x.residence = newVRResidence(now)
	}
	x.residence.observe(o, now)
}

// deferredVote is a vote this root holds back under the residence rule: the executed block and its state id, voted for when the wait ends
// if the round is still current and unvoted.
type deferredVote struct {
	block   *rctypes.BlockData
	stateID []byte
	timer   *time.Timer
}

// residenceDefers decides the residence rule for an executed proposal. It returns true when the vote is deferred (and schedules it), false
// when the root may vote now. A proposal it may never vote for on the committed state is not voted for (the root waits for the round to
// end); the block is not invalid.
func (x *ConsensusManager) residenceDefers(block *rctypes.BlockData, stateID []byte) (bool, error) {
	view, has := storage.HandoffViewOf(block)
	if !has {
		return false, nil
	}
	o, on, err := x.blockStore.CommittedVROpening()
	if err != nil || !on {
		return true, fmt.Errorf("residence rule: the committed VR state is unavailable: %v", err)
	}
	now := x.residenceNow()
	if x.residence == nil {
		x.residence = newVRResidence(now)
	}
	wait, held, ok := x.residence.wait(o, view.IntentDigest, view.View, now)
	switch {
	case !ok:
		return true, fmt.Errorf("residence rule: HandoffView %d is not the successor of the committed opening", view.View)
	case !held:
		x.deferVote(block, stateID, residenceRecheckMillis) // the opening is not committed here yet: re-check once it may be
		return true, nil
	case wait == 0:
		return false, nil
	}
	x.deferVote(block, stateID, wait)
	return true, nil
}

// residenceRecheckMillis is how soon a vote deferred for an opening this root does not hold yet is re-checked.
const residenceRecheckMillis = 250

// residenceNow is the residence clock: the monotonic wall clock, or a test's.
func (x *ConsensusManager) residenceNow() time.Time {
	if x.residence != nil && x.residence.clock != nil {
		return x.residence.clock()
	}
	return time.Now()
}

// maxResidenceChunk is the longest single sleep of the residence timer (design section 5.5.3: local timers sleep in chunks of at most
// 3,600 s and re-check).
const maxResidenceChunk = 3600 * 1000

func (x *ConsensusManager) deferVote(block *rctypes.BlockData, stateID []byte, waitMillis uint64) {
	if x.deferred != nil && x.deferred.timer != nil {
		x.deferred.timer.Stop()
	}
	chunk := min(waitMillis, maxResidenceChunk)
	x.deferred = &deferredVote{block: block, stateID: stateID, timer: time.AfterFunc(time.Duration(chunk)*time.Millisecond, func() {
		select {
		case x.deferredReady <- struct{}{}:
		default:
		}
	})}
}

// voteDeferred re-checks a deferred vote on the consensus loop and casts it once the root is eligible, while its round is current and
// unvoted.
func (x *ConsensusManager) voteDeferred(ctx context.Context) {
	d := x.deferred
	if d == nil {
		return
	}
	x.deferred = nil
	if d.block.Round != x.pacemaker.GetCurrentRound() || x.pacemaker.GetVoted() != nil {
		return
	}
	if deferred, err := x.residenceDefers(d.block, d.stateID); err != nil || deferred {
		if err != nil {
			x.log.DebugContext(ctx, "residence rule: deferred vote dropped", "round", d.block.Round, "error", err)
		}
		return
	}
	if err := x.castVote(ctx, d.block, d.stateID); err != nil {
		x.log.WarnContext(ctx, "residence rule: casting the deferred vote", "round", d.block.Round, "error", err)
	}
}
