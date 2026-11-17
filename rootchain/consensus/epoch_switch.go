package consensus

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The in-process epoch switch (bft-core#1086). At the commit of a Q3 activation a root that stays in the committee changes to the
// successor epoch inside its running process instead of being restarted with --install-handoff-epoch. It is the restart, without the
// process exit:
//
//   - the consensus worker (the loop and the certificate sender) stops at the commit, and nothing else can sign, mutate or dispatch
//     under the old context while it is replaced (the barrier below);
//   - the worker's volatile state is returned to what the constructor leaves (resetVolatile), the activation is installed through the
//     verified history's install journal exactly as at a process start (CapturedActivation.Install, which ends in InstallVerifiedEpoch),
//     and the process re-derives what it derives from the installed epoch at its start;
//   - the successor context is published once, and the worker is started again by the same start-up code (runWorker), so the pacemaker
//     is Reset at max(high QC, anchor slot) and the leader of anchor.Slot+1 proposes at once.
//
// The libp2p host, its listeners and connections, the shard subscriptions and every served protocol stay up across it: that is what the
// switch saves (the stop, the store copy, the container start and the listener poll of the restart, ~2.5-3 s per handoff).
//
// The state machine is Running(E) -> Switching(E, N, activation) -> Running(N) or Following(N); any failure after the barrier is
// Faulted: signing stays fenced and Run returns the error, so the process exits and its start-up recovery (the install journal's
// Recover, or the install restart of the drive) takes over. A switch never resumes epoch E.
//
// Scope (#1086). PR 1: a root that is a member of both E and N and holds the activation's committed evidence itself. PR 2: every root
// that runs, whatever its role:
//
//   - a member of E that stays, and a leaver (a member of E that N does not name), switch at their own commit from their own evidence;
//     the leaver's successor context is Following(N): it signs nothing, and goes on serving the activation evidence (its journal holds
//     the bundle) and the shard subscriptions as a follower;
//   - a root that does not hold the commit itself (a joiner, any follower of E, a member that lagged behind the commit, a root whose own
//     evidence is incomplete) acquires the activation from a root peer (acquire.go): an authenticated root of its committee sends it a
//     message of a later epoch, or it committed the handoff without the evidence, or (a joiner) its staged candidate names it. The
//     bundle a peer serves is authenticated against this root's own history on the loop before anything is staged, and installed under
//     the same barrier; a root several epochs behind installs the lineage one epoch at a time, each one a switch;
//   - a successor with joiners is switched into like any other: its joiners switch at its first messages instead of being installed
//     first across a restart (#1082), with their connections to the successor's committee kept from before the commit.
//
// A root that is down at the commit, faulted, or cannot get authenticated evidence from any peer installs across a restart as before.

// SwitchPhase is the phase of the in-process epoch switch.
type SwitchPhase uint32

const (
	// SwitchRunning is Running(E): the published context is the installed epoch and this root is a member of it.
	SwitchRunning SwitchPhase = iota
	// SwitchSwitching is Switching(E, N, activation): the worker is stopped or stopping, every signature is refused and the operator
	// entry points wait.
	SwitchSwitching
	// SwitchFollowing is Following(N): the successor is installed and this root is not a member of it; it signs nothing.
	SwitchFollowing
	// SwitchFaulted is a switch that failed after the barrier: signing stays fenced until the process restarts.
	SwitchFaulted
)

func (p SwitchPhase) String() string {
	switch p {
	case SwitchRunning:
		return "running"
	case SwitchSwitching:
		return "switching"
	case SwitchFollowing:
		return "following"
	case SwitchFaulted:
		return "faulted"
	}
	return fmt.Sprintf("phase(%d)", uint32(p))
}

// SwitchState is the published state of the in-process switch. Epoch is the epoch of the published context: the old one while
// switching, the successor once it is published. Target and Activation name the switch (the committed record's identity).
type SwitchState struct {
	Phase      SwitchPhase
	Epoch      uint64
	Target     uint64
	Activation []byte
	// Generation counts the published contexts: it changes when a switch begins and again when its successor is published. Work that
	// was started under one generation is refused under another.
	Generation uint64
	// Took is how long the last completed switch took from the barrier to the publication.
	Took time.Duration
	Err  string
	// Declined is the target of a committed activation this root does not switch into in process (it installs across a restart), with
	// the reason: no own evidence, for a switch that cannot acquire one from a peer.
	Declined       uint64
	DeclinedReason string
}

// switchContext is the published switch state and the channel closed when a pending switch ends (published or faulted).
type switchContext struct {
	SwitchState
	done chan struct{}
}

var (
	// ErrSwitching is returned while the root switches epoch in process, and after a switch that failed (until the process restarts).
	ErrSwitching = errors.New("consensus: the root is switching epoch in process")
	// ErrStaleContext refuses work that was started under a consensus context that has since been replaced, and a signature of an
	// epoch below the one the root switched into.
	ErrStaleContext = errors.New("consensus: work of a replaced consensus context")
)

// switchWait bounds how long a caller outside the consensus worker (the shard-facing node, an operator request) waits for a pending
// switch before it is refused. A switch is one install: tens of milliseconds.
const switchWait = 5 * time.Second

// EpochSwitch is what the process provides for the in-process switch: the capture of this root's own committed evidence of an
// activation and its installation through the install journal. Without it (WithEpochSwitch not given) the manager never switches, and
// a committed activation is installed across a restart as before.
type EpochSwitch interface {
	// Capture takes this root's own committed evidence of the activation into epoch and authenticates it (the verified history and the
	// install checks of the bundle itself), without writing anything. It runs on the consensus loop at the commit.
	Capture(ctx context.Context, epoch uint64) (CapturedActivation, error)
}

// CapturedActivation is an authenticated, immutable activation captured at the commit.
type CapturedActivation interface {
	// Members are the node identifiers of the successor committee the authenticated body names.
	Members() []string
	// Install stages the captured bundle through the install journal and carries every participant to completion (the manager's
	// InstallVerifiedEpoch among them), then re-derives what the process derives from the installed epoch at its start (the request
	// history selection, the committee it keeps connected). It runs with the worker stopped. An error is fatal for the process.
	Install(ctx context.Context) error
}

// EpochAcquirer is an EpochSwitch that also installs an activation this root does not hold the commit of itself, from a bundle a root
// peer serves (PR 2 of #1086): FetchActivation runs off the loop and trusts nothing, AdoptActivation authenticates the bytes on the loop
// against this root's own history and install checks, exactly as the install restart authenticates a peer's bundle.
type EpochAcquirer interface {
	EpochSwitch
	Acquires() bool
	FetchActivation(ctx context.Context, from peer.ID, epoch uint64) ([]byte, error)
	AdoptActivation(ctx context.Context, raw []byte, epoch uint64) (CapturedActivation, error)
}

// WithEpochSwitch enables the in-process epoch switch at a committed Q3 activation (#1086).
func WithEpochSwitch(s EpochSwitch) Option {
	return func(c *Optional) { c.EpochSwitch = s }
}

// errEpochSwitch is how the loop hands a switch to Run: it is returned by the loop once the barrier is up.
type errEpochSwitch struct {
	from, to   uint64
	activation []byte
	captured   CapturedActivation
	started    time.Time
}

func (e *errEpochSwitch) Error() string {
	return fmt.Sprintf("in-process switch from epoch %d to %d", e.from, e.to)
}

// SwitchState reports the in-process switch's state. A manager that never switched reports Running in its installed epoch.
func (x *ConsensusManager) SwitchState() SwitchState {
	out := SwitchState{Phase: SwitchRunning, Epoch: x.InstalledRootEpoch()}
	if s := x.switchCtx.Load(); s != nil {
		out = s.SwitchState
	}
	if d := x.switchDeclined.Load(); d != nil && d.target > out.Epoch {
		out.Declined, out.DeclinedReason = d.target, d.reason
	}
	return out
}

// contextGen is the generation of the published context.
func (x *ConsensusManager) contextGen() uint64 { return x.ctxGen.Load() }

// contextOpen reports whether work started under gen may still mutate, sign or dispatch: the context is published (not switching or
// faulted) and it is the one the work started under.
func (x *ConsensusManager) contextOpen(gen uint64) error {
	if s := x.switchCtx.Load(); s != nil && (s.Phase == SwitchSwitching || s.Phase == SwitchFaulted) {
		return ErrSwitching
	}
	if x.ctxGen.Load() != gen {
		return ErrStaleContext
	}
	return nil
}

// signingFence is the safety module's switch fence (WithSigningFence): nothing is signed while switching or after a failed switch, and
// nothing below the epoch the root switched into.
func (x *ConsensusManager) signingFence(epoch uint64) error {
	s := x.switchCtx.Load()
	if s == nil {
		return nil
	}
	if s.Phase == SwitchSwitching || s.Phase == SwitchFaulted {
		return ErrSwitching
	}
	if epoch < s.Epoch {
		return fmt.Errorf("%w: a signature of epoch %d after the switch into epoch %d", ErrStaleContext, epoch, s.Epoch)
	}
	return nil
}

// awaitContext is the entry check of a caller outside the consensus worker (the shard-facing node): while a switch is pending it waits
// for the successor context (bounded by switchWait); a faulted switch refuses.
func (x *ConsensusManager) awaitContext(ctx context.Context) error {
	s := x.switchCtx.Load()
	if s == nil || s.Phase == SwitchRunning || s.Phase == SwitchFollowing {
		return nil
	}
	if s.Phase == SwitchSwitching {
		t := time.NewTimer(switchWait)
		defer t.Stop()
		select {
		case <-s.done:
		case <-t.C:
			return ErrSwitching
		case <-ctx.Done():
			return ctx.Err()
		}
		if s = x.switchCtx.Load(); s.Phase == SwitchRunning || s.Phase == SwitchFollowing {
			return nil
		}
	}
	return ErrSwitching
}

// shardFacing runs a read of the shard-facing node (ShardInfo, RequestView, the admission of a certification request) against one
// published context: it waits (bounded) for a pending switch, then holds the barrier's read side while it reads, so a switch waits for
// a read in flight and no read observes a context being replaced. fn must not wait for the consensus worker.
func (x *ConsensusManager) shardFacing(ctx context.Context, fn func() error) error {
	if err := x.awaitContext(ctx); err != nil {
		return err
	}
	if err := x.readContext(ctx); err != nil {
		return err
	}
	defer x.ctxMu.RUnlock()
	if s := x.switchCtx.Load(); s != nil && (s.Phase == SwitchSwitching || s.Phase == SwitchFaulted) {
		return ErrSwitching
	}
	return fn()
}

// readContext takes the barrier's read side within the caller's context and switchWait: a switch that begins after awaitContext let the
// caller through holds the write side until it publishes or faults, and the caller waits for that no longer than it would have waited for
// a pending switch (#1086 review). A free barrier is taken at once.
func (x *ConsensusManager) readContext(ctx context.Context) error {
	if x.ctxMu.TryRLock() {
		return nil
	}
	bound := time.NewTimer(switchWait)
	defer bound.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !x.ctxMu.TryRLock() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-bound.C:
			return ErrSwitching
		case <-tick.C:
		}
	}
	return nil
}

// operator runs an operator entry point (a plan, an intent, an endorsement, an abort, a staged candidate, a submitted control) against
// one published context: it holds the barrier's read side, so a switch waits for it to finish and it never runs during a switch. The
// operation must not wait for the consensus loop.
func (x *ConsensusManager) operator(fn func() error) error {
	x.ctxMu.RLock()
	defer x.ctxMu.RUnlock()
	if s := x.switchCtx.Load(); s != nil && (s.Phase == SwitchSwitching || s.Phase == SwitchFaulted) {
		return ErrSwitching
	}
	return fn()
}

// checkEpochSwitch is the trigger, on the loop after every event: the committed root holds the commit of the handoff out of the
// installed epoch and this root's own evidence of the activation authenticates. It is evaluated once per committed root. The successor
// context is Running(N) for a member of N and Following(N) for a root N does not name (a leaver, a follower), decided by the installed
// committee after the install. A root that committed the handoff without its own evidence acquires it from a root peer, else it stays in
// its epoch, to be installed across a restart.
func (x *ConsensusManager) checkEpochSwitch(ctx context.Context) error {
	if x.switcher == nil || x.q3 == nil {
		return nil
	}
	record, round, ok := x.blockStore.CommittedHandoff()
	if !ok || round == x.switchCheckedRound {
		return nil
	}
	x.switchCheckedRound = round
	installed := x.InstalledRootEpoch()
	if record.Epoch != installed || installed == ^uint64(0) {
		return nil
	}
	target := installed + 1
	x.reconsiderSwitch(target)
	captured, err := x.switcher.Capture(ctx, target)
	if err != nil {
		if x.acquirer() != nil {
			x.log.WarnContext(ctx, "the epoch's handoff is committed but this root holds no evidence of its own: acquiring the activation from a root peer",
				"epoch", installed, "target", target, logger.Error(err))
			x.acq.committed = target
			return nil
		}
		x.log.WarnContext(ctx, "the epoch's handoff is committed but its activation could not be captured: the install restart is the fallback",
			"epoch", installed, "target", target, logger.Error(err))
		x.declineSwitch(target, "no own evidence")
		return nil
	}
	x.logRole(ctx, installed, target, captured.Members())
	return x.enterSwitching(installed, target, record.ID(), captured)
}

// logRole states what the switch makes of this root: a member that stays, a leaver (Following), a follower that joins or follows.
func (x *ConsensusManager) logRole(ctx context.Context, installed, target uint64, members []string) {
	inE, inN := x.safety.member(installed) == nil, slices.Contains(members, x.id.String())
	role := map[[2]bool]string{{true, true}: "stays", {true, false}: "leaves (follows the successor)", {false, true}: "joins",
		{false, false}: "follows the successor"}[[2]bool{inE, inN}]
	x.log.InfoContext(ctx, "switching into the committed activation in process: this root "+role, "epoch", installed, "target", target,
		"joiners", newcomers(members, x.trustBase.Load()))
}

// switchDecline is a committed activation this root decided not to switch into in process, and why: what the drive reads to restart it
// at once instead of waiting for a switch.
type switchDecline struct {
	target uint64
	reason string
}

// reconsiderSwitch resets an earlier decline of the activation into target: a new committed root evaluates it again, and the decline is
// stated again if it still holds. Until then nothing of target is parked.
func (x *ConsensusManager) reconsiderSwitch(target uint64) {
	if d := x.switchDeclined.Load(); d != nil && d.target == target {
		x.switchDeclined.Store(nil)
	}
}

func (x *ConsensusManager) declineSwitch(target uint64, reason string) {
	x.switchDeclined.Store(&switchDecline{target: target, reason: reason})
	x.dropFuture() // nothing parked for a successor this root does not switch into is kept
}

// newcomers are the members of the successor that the installed epoch does not name.
func newcomers(members []string, installed *types.RootTrustBaseV1) []string {
	known := map[string]bool{}
	if installed != nil {
		for _, n := range installed.RootNodes {
			if n != nil {
				known[n.NodeID] = true
			}
		}
	}
	var out []string
	for _, m := range members {
		if !known[m] {
			out = append(out, m)
		}
	}
	return out
}

// acquirer is the process's switch when it can install an activation from a root peer, else nil.
func (x *ConsensusManager) acquirer() EpochAcquirer {
	if a, ok := x.switcher.(EpochAcquirer); ok && x.q3 != nil && a.Acquires() {
		return a
	}
	return nil
}

// enterSwitching raises the barrier: it waits for the operator sections in flight, then publishes Switching(E, N, activation) under a
// new generation, which refuses every signature (signingFence), every operator entry point and every completion of work started before
// it. The barrier is held until the successor is published or the switch faults.
func (x *ConsensusManager) enterSwitching(from, to uint64, id []byte, captured CapturedActivation) error {
	started := time.Now()
	x.stopAcquire() // a fetch in flight is of the context being left
	x.ctxMu.Lock()
	if x.frontier != nil {
		x.frontier.eligible.Store(false)
	}
	gen := x.ctxGen.Add(1)
	x.switchCtx.Store(&switchContext{SwitchState: SwitchState{Phase: SwitchSwitching, Epoch: from, Target: to, Activation: id, Generation: gen},
		done: make(chan struct{})})
	x.log.Info("switching epoch in process at the committed activation", "epoch", from, "target", to, "activation", fmt.Sprintf("%X", id))
	return &errEpochSwitch{from: from, to: to, activation: id, captured: captured, started: started}
}

// switchEpoch replaces the stopped worker's context with the successor's. It runs on Run's goroutine with the worker stopped and the
// barrier held; it returns with the barrier released, the successor published, or an error after which the process must exit.
func (x *ConsensusManager) switchEpoch(ctx context.Context, sw *errEpochSwitch) (err error) {
	defer func() {
		if err != nil {
			x.faultSwitch(sw, err)
		}
	}()
	x.resetVolatile()
	if err := sw.captured.Install(ctx); err != nil {
		return fmt.Errorf("in-process install of epoch %d: %w", sw.to, err)
	}
	if got := x.InstalledRootEpoch(); got != sw.to || x.epochAnchor == nil || x.epochAnchor.Epoch != sw.to {
		return fmt.Errorf("in-process install of epoch %d left epoch %d installed", sw.to, got)
	}
	// the successor's pacemaker, trust base and leader are restored while still fenced, so the published context is a started one; its
	// first proposal, the parked messages and the loop follow the publication (runWorker)
	if err := x.startContext(ctx); err != nil {
		return fmt.Errorf("starting epoch %d: %w", sw.to, err)
	}
	phase := SwitchRunning
	if x.safety.member(sw.to) != nil {
		phase = SwitchFollowing
	}
	x.publishSwitch(sw, phase)
	return nil
}

// resetVolatile returns every piece of the worker's volatile state to what NewConsensusManager leaves in it, so that the successor is
// started from durable state alone, as a restarted process is. The fields the install itself replaces (trust base, leader policy,
// request verifier, T2 timeouts, anchor, handoff plans, retained requests) are replaced by it; switchFieldClasses lists every field.
func (x *ConsensusManager) resetVolatile() {
	x.pacemaker.Quiesce()
	select {
	case <-x.ucSink: // a batch the stopped sender did not take: it is of the old epoch, and a restart loses it too
	default:
	}
	x.voteBuffer = make(map[string]*abdrc.VoteMsg)
	x.recovery.reset()
	x.irReqBuffer = NewIrReqBuffer(x.log, x.params.NetworkProfileVersion)
	x.retained = nil
	x.leaderCheckedRound = 0
	x.switchCheckedRound = 0
	x.posQueue.reset()
	x.primaryCache.dropParked()
	x.v3Planned.Store(nil)
	x.q3Staged.Store(nil)
	x.q3StagedEVM.Store(nil)
	// the residence rule restarts with the context: the successor re-learns its views, as a restart does
	if x.deferred != nil && x.deferred.timer != nil {
		x.deferred.timer.Stop()
	}
	x.residence, x.deferred = nil, nil
	x.acq.resetAttempts() // what this root learnt of later epochs is kept: a root several epochs behind goes on with the next one
}

// publishSwitch publishes the successor context once, after every component is installed: a new generation, the phase, and the
// barrier released.
func (x *ConsensusManager) publishSwitch(sw *errEpochSwitch, phase SwitchPhase) {
	prev := x.switchCtx.Load()
	gen := x.ctxGen.Add(1)
	took := time.Since(sw.started)
	x.switchCtx.Store(&switchContext{SwitchState: SwitchState{Phase: phase, Epoch: sw.to, Target: sw.to, Activation: sw.activation, Generation: gen, Took: took}})
	close(prev.done)
	x.ctxMu.Unlock()
	x.log.Info("switched epoch in process", "epoch", sw.to, "from", sw.from, "phase", phase.String(), "took", took)
}

// faultSwitch ends a failed switch: signing stays fenced (Faulted) and the barrier is released so that the callers waiting on it are
// refused instead of blocked.
func (x *ConsensusManager) faultSwitch(sw *errEpochSwitch, err error) {
	prev := x.switchCtx.Load()
	gen := x.ctxGen.Add(1)
	x.switchCtx.Store(&switchContext{SwitchState: SwitchState{Phase: SwitchFaulted, Epoch: sw.from, Target: sw.to, Activation: sw.activation,
		Generation: gen, Err: err.Error()}})
	if prev != nil && prev.done != nil {
		close(prev.done)
	}
	x.ctxMu.Unlock()
	x.pacemaker.Stop() // a successor's clock started before the failure stops; nothing signs anyway
	x.dropFuture()
	x.stopAcquire()
	x.log.Error("in-process epoch switch failed: signing stays fenced and the process exits to its recovery", "epoch", sw.from, "target", sw.to,
		logger.Error(err))
}

// futureMessages holds consensus messages of the epoch after the installed one that arrive before this root has committed the
// activation itself (another member switched first). Nothing in them is trusted or used here: they are not verified (this root does
// not know the successor's trust yet) and are dropped unless the root switches, after which they are handled by the successor's
// worker through the ordinary handlers, which verify everything. Without them a member that commits a few milliseconds after the first
// successor leader would miss its first proposal and the round would time out. Owned by the consensus loop.
//
// What is retained is bounded by the authenticated transport, never by what a message claims (#1086 review): only a message whose
// sender the network authenticated (MessageOrigins) is kept, only from a root of the installed committee or of the staged successor,
// only when it claims that sender as its author, within a per-message wire size, a per-sender count and byte allowance and an aggregate
// byte budget, and for at most futureMessageTTL. A declined switch drops them all.
type futureMessages struct {
	epoch  uint64
	items  []parkedMessage
	bytes  uint64
	byPeer map[peer.ID]parkedShare
}

type parkedMessage struct {
	msg  any
	from peer.ID
	size uint64
	at   time.Time
}

type parkedShare struct {
	n     int
	bytes uint64
}

const (
	maxFutureMessageBytes    = 2 << 20  // one parked message's wire frame
	maxFutureBytesPerPeer    = 2 << 20  // what one authenticated sender may have parked
	maxFutureMessagesPerPeer = 8        // and in how many messages (a proposal, votes and timeouts of the first rounds)
	maxFutureBytes           = 64 << 20 // all parked messages: every sender of a committee of up to 32 has its full allowance
	futureMessageTTL         = 30 * time.Second
)

// MessageOrigins is implemented by a root network that authenticates the sender of each received message (network.LibP2PNetwork): once
// TrackOrigins is called, TakeOrigin returns, and forgets, the authenticated remote peer and the wire frame size of every message it
// delivers. The manager enables it when it may switch epoch in process, and takes the origin of every message it receives.
type MessageOrigins interface {
	TrackOrigins()
	TakeOrigin(msg any) (from peer.ID, size uint64, ok bool)
}

// messageOrigin is the authenticated origin of a received message; known is false when the network does not tell it.
type messageOrigin struct {
	from  peer.ID
	size  uint64
	known bool
}

func (x *ConsensusManager) takeOrigin(msg any) messageOrigin {
	if x.origins == nil {
		return messageOrigin{}
	}
	from, size, ok := x.origins.TakeOrigin(msg)
	return messageOrigin{from: from, size: size, known: ok}
}

// futureEpochOf is the epoch and author a proposal, vote or timeout claims, unverified; ok is false for any other message or a
// proposal, vote or timeout without its round data.
func futureEpochOf(msg any) (epoch uint64, author string, ok bool) {
	switch m := msg.(type) {
	case *abdrc.ProposalMsg:
		if m.Block != nil {
			return m.Block.Epoch, m.Block.Author, true
		}
	case *abdrc.VoteMsg:
		if m.VoteInfo != nil && m.LedgerCommitInfo != nil {
			return m.VoteInfo.Epoch, m.Author, true
		}
	case *abdrc.TimeoutMsg:
		if m.Timeout != nil {
			return m.Timeout.Epoch, m.Author, true
		}
	}
	return 0, "", false
}

// knownRoot reports whether the authenticated sender is a root of the installed committee or of the successor staged here.
func (x *ConsensusManager) knownRoot(id peer.ID) bool {
	if tb := x.trustBase.Load(); tb != nil {
		for _, n := range tb.RootNodes {
			if n != nil && n.NodeID == id.String() {
				return true
			}
		}
	}
	return x.IsStagedRoot(id.String())
}

// parkFuture decides on a message of the next epoch: it reports whether the message was one (it is then kept, or dropped as it would
// have been refused); any other message is handled as before.
func (x *ConsensusManager) parkFuture(msg any, origin messageOrigin, now time.Time) bool {
	if x.switcher == nil || x.q3 == nil {
		return false
	}
	epoch, author, ok := futureEpochOf(msg)
	installed := x.InstalledRootEpoch()
	if !ok || installed == ^uint64(0) || epoch != installed+1 {
		return false
	}
	if d := x.switchDeclined.Load(); d != nil && d.target == epoch {
		return true // this root does not switch into that epoch: nothing of it is kept (refused, as before)
	}
	f := &x.future
	if f.epoch != epoch {
		*f = futureMessages{epoch: epoch, byPeer: map[peer.ID]parkedShare{}}
	}
	f.expire(now)
	switch {
	case !origin.known:
		return true // not authenticated by the transport: refused, as before
	case author != origin.from.String() || !x.knownRoot(origin.from):
		return true // a sender that is not a root, or a message it did not author
	case origin.size == 0 || origin.size > maxFutureMessageBytes || f.bytes+origin.size > maxFutureBytes:
		return true
	}
	share := f.byPeer[origin.from]
	if share.n >= maxFutureMessagesPerPeer || share.bytes+origin.size > maxFutureBytesPerPeer {
		return true
	}
	f.items = append(f.items, parkedMessage{msg: msg, from: origin.from, size: origin.size, at: now})
	f.bytes += origin.size
	f.byPeer[origin.from] = parkedShare{n: share.n + 1, bytes: share.bytes + origin.size}
	return true
}

// expire drops the parked messages older than futureMessageTTL.
func (f *futureMessages) expire(now time.Time) {
	kept := f.items[:0]
	for _, m := range f.items {
		if now.Sub(m.at) <= futureMessageTTL {
			kept = append(kept, m)
			continue
		}
		f.bytes -= m.size
		share := f.byPeer[m.from]
		if share.n--; share.n <= 0 {
			delete(f.byPeer, m.from)
		} else {
			share.bytes -= m.size
			f.byPeer[m.from] = share
		}
	}
	clear(f.items[len(kept):])
	f.items = kept
}

// sweepFuture is the loop's periodic expiry of the parked messages: their lifetime holds without another arrival.
func (x *ConsensusManager) sweepFuture(now time.Time) { x.future.expire(now) }

// futureSweep is the period of sweepFuture; nil (no sweep) for a manager that never parks.
func (x *ConsensusManager) futureSweep() (<-chan time.Time, func()) {
	if x.switcher == nil || x.q3 == nil {
		return nil, func() {}
	}
	t := time.NewTicker(futureMessageTTL / 6)
	return t.C, t.Stop
}

// dropFuture forgets every parked message.
func (x *ConsensusManager) dropFuture() { x.future = futureMessages{} }

// replayFuture hands the parked messages of the now installed epoch to the ordinary handlers, once, and drops the rest.
func (x *ConsensusManager) replayFuture(ctx context.Context) {
	for _, msg := range x.replayable(time.Now()) {
		if err := x.handleRootNetMsg(ctx, msg); err != nil {
			x.log.DebugContext(ctx, fmt.Sprintf("replaying a %T parked before the switch", msg), logger.Error(err))
		}
	}
}

// replayable takes the parked messages to replay: those of the installed epoch still within their lifetime. Nothing stays parked.
func (x *ConsensusManager) replayable(now time.Time) []any {
	x.future.expire(now) // nothing older than its lifetime is handled
	f := x.future
	x.future = futureMessages{}
	if f.epoch == 0 || f.epoch != x.InstalledRootEpoch() {
		return nil
	}
	out := make([]any, 0, len(f.items))
	for _, m := range f.items {
		out = append(out, m.msg)
	}
	return out
}
