package consensus

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
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
// Scope (PR 1 of #1086): the trigger is a root that is a member of both E and N and holds the activation's committed evidence itself.
// A joiner (a follower of E), a leaver (not a member of N), a root whose own evidence is not available, and a root that is down at the
// commit install across a restart as before.

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
	if s := x.switchCtx.Load(); s != nil {
		return s.SwitchState
	}
	return SwitchState{Phase: SwitchRunning, Epoch: x.InstalledRootEpoch()}
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
// installed epoch, this root is a member of that epoch, its own evidence of the activation authenticates, and the successor body names
// it. It is evaluated once per committed root. Anything else leaves the root in its epoch, to be installed across a restart.
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
	if err := x.safety.member(installed); err != nil {
		x.log.InfoContext(ctx, "the epoch's handoff is committed; this root follows the epoch and installs the successor across a restart",
			"epoch", installed, "target", target)
		return nil
	}
	captured, err := x.switcher.Capture(ctx, target)
	if err != nil {
		x.log.WarnContext(ctx, "the epoch's handoff is committed but its activation could not be captured: the install restart is the fallback",
			"epoch", installed, "target", target, logger.Error(err))
		return nil
	}
	if !slices.Contains(captured.Members(), x.id.String()) {
		x.log.InfoContext(ctx, "the epoch's handoff is committed and this root leaves the committee: the install restart makes it a follower",
			"epoch", installed, "target", target)
		return nil
	}
	return x.enterSwitching(installed, target, record, captured)
}

// enterSwitching raises the barrier: it waits for the operator sections in flight, then publishes Switching(E, N, activation) under a
// new generation, which refuses every signature (signingFence), every operator entry point and every completion of work started before
// it. The barrier is held until the successor is published or the switch faults.
func (x *ConsensusManager) enterSwitching(from, to uint64, record evmroot.OrderedHandoffRecord, captured CapturedActivation) error {
	started := time.Now()
	x.ctxMu.Lock()
	if x.frontier != nil {
		x.frontier.eligible.Store(false)
	}
	gen := x.ctxGen.Add(1)
	id := record.ID()
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
	x.log.Error("in-process epoch switch failed: signing stays fenced and the process exits to its recovery", "epoch", sw.from, "target", sw.to,
		logger.Error(err))
}

// futureMessages holds consensus messages of the epoch after the installed one that arrive before this root has committed the
// activation itself (another member switched first). Nothing in them is trusted or used here: they are not verified (this root does
// not know the successor's trust yet) and are dropped unless the root switches, after which they are handled by the successor's
// worker through the ordinary handlers, which verify everything. Without them a member that commits a few milliseconds after the first
// successor leader would miss its first proposal and the round would time out. Owned by the consensus loop.
type futureMessages struct {
	epoch    uint64
	items    []any
	byAuthor map[string]int
}

const (
	maxFutureMessages          = 64
	maxFutureMessagesPerAuthor = 8
)

// futureEpochOf is the epoch and author a proposal, vote or timeout claims, unverified.
func futureEpochOf(msg any) (epoch uint64, author string, ok bool) {
	switch m := msg.(type) {
	case *abdrc.ProposalMsg:
		if m.Block != nil {
			return m.Block.Epoch, m.Block.Author, true
		}
	case *abdrc.VoteMsg:
		if m.VoteInfo != nil {
			return m.VoteInfo.Epoch, m.Author, true
		}
	case *abdrc.TimeoutMsg:
		if m.Timeout != nil {
			return m.Timeout.Epoch, m.Author, true
		}
	}
	return 0, "", false
}

// parkFuture keeps a message of the next epoch while this root may still switch into it; it reports whether it took the message.
func (x *ConsensusManager) parkFuture(msg any) bool {
	if x.switcher == nil || x.q3 == nil {
		return false
	}
	epoch, author, ok := futureEpochOf(msg)
	installed := x.InstalledRootEpoch()
	if !ok || installed == ^uint64(0) || epoch != installed+1 {
		return false
	}
	f := &x.future
	if f.epoch != epoch {
		*f = futureMessages{epoch: epoch, byAuthor: map[string]int{}}
	}
	if len(f.items) >= maxFutureMessages || f.byAuthor[author] >= maxFutureMessagesPerAuthor {
		return true // over the bound: dropped, as it would have been refused
	}
	f.items = append(f.items, msg)
	f.byAuthor[author]++
	return true
}

// replayFuture hands the parked messages of the now installed epoch to the ordinary handlers, once, and drops the rest.
func (x *ConsensusManager) replayFuture(ctx context.Context) {
	f := x.future
	x.future = futureMessages{}
	if f.epoch == 0 || f.epoch != x.InstalledRootEpoch() {
		return
	}
	for _, msg := range f.items {
		if err := x.handleRootNetMsg(ctx, msg); err != nil {
			x.log.DebugContext(ctx, fmt.Sprintf("replaying a %T parked before the switch", msg), logger.Error(err))
		}
	}
}
