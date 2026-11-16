package consensus

import (
	"context"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/unicitynetwork/bft-core/logger"
)

// Acquiring an activation from a root peer (#1086, PR 2). A root that does not commit the handoff out of its installed epoch E itself
// cannot capture its own evidence of it: a joiner (a follower of E, which receives no consensus traffic of E), any other follower of E,
// a member that lagged behind the commit (once the others switched, nobody serves E's blocks any more), or a member whose own evidence is
// incomplete. Such a root asks a root peer for the activation's bundle (q3delivery, the same as its install restart), authenticates it
// on the loop against its own verified history and install checks, and switches into it under the same barrier as a root that committed
// it. Nothing a peer serves is trusted before that authentication: the successor's trust comes from the verified lineage, never from the
// message that prompted the fetch, and the fetch itself starts no consensus.
//
// What prompts a fetch (acquireWanted):
//   - a proposal, vote or timeout of an epoch above the installed one, authenticated by the transport as sent by its author, a root of the
//     installed committee or of the staged successor: the successor has started, and this root is behind. A member of E waits
//     laggardGrace first, since its own commit (and its own evidence) is normally only milliseconds behind;
//   - a handoff this root committed itself but holds no own evidence of (checkEpochSwitch);
//   - a joiner (not a member of E) whose staged candidate names it for E+1: it asks every stagedPoll, so that it switches even when no
//     successor message reaches it first, as when it leads the successor's first round itself (nobody sends anything before that proposal).
//
// One fetch runs at a time, for the epoch after the installed one: a root several epochs behind installs the lineage one epoch at a
// time, each one a switch, because each bundle authenticates only against a history that holds its predecessor. The peers are asked in
// turn (the senders first, then the installed committee), each within acquireRequestTimeout; a round that finds nothing is retried after
// a doubling delay (acquireRetry to acquireRetryMax), and a peer whose bundle did not authenticate is not asked again for that epoch.

const (
	laggardGrace          = time.Second
	stagedPoll            = time.Second
	acquireRequestTimeout = 3 * time.Second
	acquireRetry          = 250 * time.Millisecond
	acquireRetryMax       = 4 * time.Second
	acquirePeers          = 16 // the senders remembered, and the peers one fetch asks
	acquireTick           = 250 * time.Millisecond
)

// acquisition is the loop-owned state of the acquisition: what this root learnt of later epochs (kept across a switch, so that a root
// several epochs behind goes on with the next one) and the fetch in flight.
type acquisition struct {
	ahead     uint64    // the highest epoch an authenticated root sent a message of
	seen      time.Time // when this root first learnt of an epoch above its installed one
	last      time.Time // the last such message
	senders   []peer.ID // their authenticated senders, the most recent first
	committed uint64    // an activation this root committed without its own evidence

	target   uint64 // the epoch being fetched; zero while no fetch runs
	gen      uint64 // the context generation the fetch started under
	poll     bool   // the fetch is the joiner's staged poll: it is paced at stagedPoll, not backed off
	cancel   context.CancelFunc
	failures int
	next     time.Time               // no fetch starts before
	refused  map[peer.ID]uint64      // a peer whose bundle of that epoch did not authenticate
	result   chan acquiredActivation // where the fetch hands its bundle to the loop
	attempts uint64                  // fetches started (status and tests)
}

// acquiredActivation is what a fetch hands the loop: the canonical bundle bytes one peer served, or the error of asking every peer.
type acquiredActivation struct {
	target uint64
	gen    uint64
	raw    []byte
	from   peer.ID
	err    error
}

// resetAttempts ends the fetch state at a switch: the next epoch's acquisition starts at once.
func (a *acquisition) resetAttempts() {
	if a.cancel != nil {
		a.cancel()
	}
	a.target, a.cancel, a.failures, a.next, a.committed = 0, nil, 0, time.Time{}, 0
}

// note records an authenticated sender of a message of a later epoch.
func (a *acquisition) note(epoch, installed uint64, from peer.ID, now time.Time) {
	if a.ahead <= installed || now.Sub(a.last) > futureMessageTTL {
		a.seen = now // the first sign, since the installed epoch, that a later one runs
	}
	a.ahead = max(a.ahead, epoch)
	a.last = now
	kept := []peer.ID{from}
	for _, p := range a.senders {
		if p != from && len(kept) < acquirePeers {
			kept = append(kept, p)
		}
	}
	a.senders = kept
}

// fail backs the next fetch off: acquireRetry, doubling to acquireRetryMax, or at least floor.
func (a *acquisition) fail(now time.Time, floor time.Duration) {
	a.failures++
	delay := acquireRetry << min(a.failures-1, 8)
	a.next = now.Add(max(min(delay, acquireRetryMax), floor))
}

// noteAhead records a message of an epoch above the installed one whose author the transport authenticated as its sender, a root of the
// installed committee or of the staged successor; anything else is not a sign of anything.
func (x *ConsensusManager) noteAhead(msg any, origin messageOrigin, now time.Time) {
	if !origin.known || x.acquirer() == nil {
		return
	}
	epoch, author, ok := futureEpochOf(msg)
	installed := x.InstalledRootEpoch()
	if !ok || installed == ^uint64(0) || epoch <= installed || author != origin.from.String() || !x.knownRoot(origin.from) {
		return
	}
	x.acq.note(epoch, installed, origin.from, now)
}

// acquireWanted reports whether a fetch of the epoch after the installed one is due now, and whether it is only the joiner's staged poll.
func (x *ConsensusManager) acquireWanted(installed uint64, now time.Time) (due, poll bool) {
	a := &x.acq
	target := installed + 1
	hinted := a.ahead > installed && now.Sub(a.last) <= futureMessageTTL
	staged := x.IsStagedRoot(x.id.String())
	if a.committed != target && !hinted && !staged {
		return false, false
	}
	member := x.safety.member(installed) == nil
	switch {
	case a.committed == target:
		return true, false
	case hinted && (!member || now.Sub(a.seen) >= laggardGrace):
		return true, false
	case staged && !member:
		return true, true
	}
	return false, false
}

// checkAcquire starts a fetch when one is due (acquireWanted) and none runs. It runs on the loop.
func (x *ConsensusManager) checkAcquire(ctx context.Context, now time.Time) {
	acq := x.acquirer()
	if acq == nil {
		return
	}
	a := &x.acq
	installed := x.InstalledRootEpoch()
	if a.target != 0 || now.Before(a.next) || installed == ^uint64(0) {
		return
	}
	if s := x.switchCtx.Load(); s != nil && (s.Phase == SwitchSwitching || s.Phase == SwitchFaulted) {
		return
	}
	due, poll := x.acquireWanted(installed, now)
	if !due {
		return
	}
	target := installed + 1
	peers := x.acquirePeersFor(target)
	if len(peers) == 0 {
		a.fail(now, stagedPoll)
		return
	}
	if poll {
		a.next = now.Add(stagedPoll) // the joiner's poll is paced whatever the fetch's outcome
	}
	fctx, cancel := context.WithCancel(ctx)
	a.target, a.gen, a.cancel, a.poll = target, x.contextGen(), cancel, poll
	a.attempts++
	if a.result == nil {
		a.result = make(chan acquiredActivation, 1)
	}
	out, gen := a.result, a.gen
	x.log.DebugContext(ctx, "asking root peers for the activation of the next epoch", "epoch", installed, "target", target, "peers", len(peers))
	go func() {
		res := acquiredActivation{target: target, gen: gen}
		for _, p := range peers {
			pctx, pcancel := context.WithTimeout(fctx, acquireRequestTimeout)
			raw, err := acq.FetchActivation(pctx, p, target)
			pcancel()
			if err == nil {
				res.raw, res.from, res.err = raw, p, nil
				break
			}
			res.err = fmt.Errorf("root %s: %w", p, err)
			if fctx.Err() != nil {
				break
			}
		}
		select {
		case out <- res:
		case <-fctx.Done():
		}
	}()
}

// acquirePeersFor are the peers a fetch of target asks, in turn: the authenticated senders of later epochs, then the installed committee,
// then the staged successor's roots; never this root, and never a peer whose bundle of target did not authenticate.
func (x *ConsensusManager) acquirePeersFor(target uint64) []peer.ID {
	seen := map[peer.ID]bool{x.id: true}
	var out []peer.ID
	add := func(p peer.ID) {
		if p == "" || seen[p] || x.acq.refused[p] == target || len(out) >= acquirePeers {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, p := range x.acq.senders {
		add(p)
	}
	if tb := x.trustBase.Load(); tb != nil {
		for _, p := range toIDSlice(tb.RootNodes, x.log) {
			add(p)
		}
	}
	if staged := x.pendingStaged(); staged != nil {
		for id := range staged.roots {
			if p, err := peer.Decode(id); err == nil {
				add(p)
			}
		}
	}
	return out
}

// acquiredResults is the channel the loop receives fetched bundles on; nil (never ready) for a manager that does not acquire.
func (x *ConsensusManager) acquiredResults() <-chan acquiredActivation {
	if x.acquirer() == nil {
		return nil
	}
	if x.acq.result == nil {
		x.acq.result = make(chan acquiredActivation, 1)
	}
	return x.acq.result
}

// acquireTicker paces checkAcquire while nothing else wakes the loop; nil for a manager that does not acquire.
func (x *ConsensusManager) acquireTicker() (<-chan time.Time, func()) {
	if x.acquirer() == nil {
		return nil, func() {}
	}
	t := time.NewTicker(acquireTick)
	return t.C, t.Stop
}

// onAcquired takes a fetched bundle on the loop: a stale one (another epoch, another context) is dropped; one that authenticates against
// this root's own history raises the barrier for its epoch, exactly as this root's own commit does. A failure backs the next fetch off,
// and a peer whose bundle did not authenticate is not asked again for that epoch.
func (x *ConsensusManager) onAcquired(ctx context.Context, res acquiredActivation, now time.Time) error {
	a := &x.acq
	acq := x.acquirer()
	if acq == nil || res.target == 0 || res.target != a.target || res.gen != a.gen {
		return nil // a fetch of a context already left
	}
	if a.cancel != nil {
		a.cancel()
	}
	a.target, a.cancel = 0, nil
	installed := x.InstalledRootEpoch()
	if res.target != installed+1 || res.gen != x.contextGen() {
		return nil
	}
	if res.err != nil || len(res.raw) == 0 {
		x.log.DebugContext(ctx, "no root peer served the activation of the next epoch yet", "target", res.target, logger.Error(res.err))
		if a.poll {
			a.next = now.Add(stagedPoll) // a joiner's poll keeps its pace through the wait for the commit: the first successor round may be its own
		} else {
			a.fail(now, 0)
		}
		return nil
	}
	captured, err := acq.AdoptActivation(ctx, res.raw, res.target)
	if err != nil {
		x.log.WarnContext(ctx, "a root peer served an activation that does not authenticate: not asked again for it", "peer", res.from,
			"target", res.target, logger.Error(err))
		if a.refused == nil {
			a.refused = map[peer.ID]uint64{}
		}
		if len(a.refused) >= 4*acquirePeers {
			clear(a.refused)
		}
		a.refused[res.from] = res.target
		a.fail(now, 0)
		return nil
	}
	x.logRole(ctx, installed, res.target, captured.Members())
	x.log.InfoContext(ctx, "the activation a root peer served authenticates: switching into it", "peer", res.from, "target", res.target)
	var id []byte
	if c, ok := captured.(interface{ Identity() []byte }); ok {
		id = c.Identity()
	}
	return x.enterSwitching(installed, res.target, id, captured)
}

// stopAcquire ends a fetch in flight; its result, should it still arrive, is of an attempt the loop no longer waits for.
func (x *ConsensusManager) stopAcquire() {
	if x.acq.cancel != nil {
		x.acq.cancel()
	}
	x.acq.target, x.acq.cancel = 0, nil
}
