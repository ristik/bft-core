package consensus

import (
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
// The opening of view v is the committed backoff with the intent bound and LastView == v; view 0 opens at the intent's anchor block, and
// is approximated here by the first committed observation of the attempt identity with no view yet (the anchor is at or after the
// attempt's opening; VT-05b, which derives the anchor, can tighten it).

// residenceKey names the committed opening of one view.
type residenceKey struct {
	epoch, attempt, view uint64
	intent               [32]byte
}

// vrResidence remembers, for the committed opening it last observed, when this root first held it, in monotonic milliseconds since base.
type vrResidence struct {
	base time.Time
	key  residenceKey
	seen uint64
	have bool
}

func newVRResidence(now time.Time) *vrResidence { return &vrResidence{base: now} }

func (r *vrResidence) millis(now time.Time) uint64 {
	d := now.Sub(r.base) // monotonic: both readings carry the monotonic clock
	if d < 0 {
		return 0
	}
	return uint64(d.Milliseconds())
}

func keyOf(s vradmit.RootState) residenceKey {
	k := residenceKey{epoch: s.Backoff.Epoch, attempt: s.Backoff.Attempt, view: s.Backoff.LastView}
	copy(k.intent[:], s.Backoff.Intent)
	return k
}

// observe records the committed state's opening the first time this root holds it.
func (r *vrResidence) observe(s vradmit.RootState, now time.Time) {
	if k := keyOf(s); !r.have || k != r.key {
		r.key, r.seen, r.have = k, r.millis(now), true
	}
}

// wait is how many more milliseconds this root waits before it may vote for HandoffView(intent, view) over the committed state s; ok is
// false when it may never vote for it on this committed state (the view it names is not the committed one's successor, or T is never).
func (r *vrResidence) wait(s vradmit.RootState, intent [32]byte, view uint64, now time.Time) (uint64, bool) {
	r.observe(s, now)
	b := s.Backoff
	zero := [32]byte{}
	switch {
	case view == 0:
		return 0, false
	case r.key.intent == zero && view == 1:
	case r.key.intent == intent && b.LastView == view-1:
	default:
		return 0, false
	}
	w, ok := vradmit.ResidenceWaitMillis(b.Level, view-1, b.N)
	if !ok {
		return 0, false
	}
	elapsed := r.millis(now) - r.seen
	if elapsed >= w {
		return 0, true
	}
	return w - elapsed, true
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
	s, on, err := x.blockStore.CommittedVRState()
	if err != nil || !on {
		return true, fmt.Errorf("residence rule: the committed VR state is unavailable: %v", err)
	}
	if x.residence == nil {
		x.residence = newVRResidence(time.Now())
	}
	wait, ok := x.residence.wait(s, view.IntentDigest, view.View, time.Now())
	if !ok {
		return true, fmt.Errorf("residence rule: HandoffView %d is not the successor of the committed view", view.View)
	}
	if wait == 0 {
		return false, nil
	}
	x.deferVote(block, stateID, wait)
	return true, nil
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
