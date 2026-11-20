package vrrules

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/unicitynetwork/bft-core/vrschema"
)

// The activation schedule as a node that is not a root reads it (design section 7.4: shard nodes, followers and authorities "enumerate
// the committed schedule, and fence before installing an epoch >= E when they lack a rule"). A root reads it from its own committed
// state (rootchain/consensus/vr_upgrade.go); the other roles read VR's activations[] through a Source, over EVM JSON-RPC.

// MaxActivations is VR's bound on the schedule (MAX_ACTIVATIONS); MaxPending bounds the pending changes a read accepts.
const (
	MaxActivations = 64
	MaxPending     = 32
)

// PendingEntry is a kind-9 change that is queued or scheduled but not yet in the committed schedule: warning only, never enforced.
type PendingEntry struct {
	Activation vrschema.Activation
	State      string
}

// Evidence is one authenticated read of the schedule: every field comes from ONE VR state, the block named by BlockHash, whose VR
// deployment was verified and which holds root epochs up to CoveredEpoch (VR's knownRootEpoch there).
type Evidence struct {
	BlockHash    [32]byte
	BlockNumber  uint64
	CoveredEpoch uint64
	Schedule     []vrschema.Activation
	Pending      []PendingEntry
}

// ErrNotCovered is a read of a state that does not yet hold the root epochs the decision needs: retry, never pass.
var ErrNotCovered = errors.New("activation schedule source has not caught up with the epoch")

// CoverNeeded is the VR state a decision about root epoch epoch needs: one that knows root epoch epoch-1. Design 7.2: a schedule for E
// is committed by a handoff into <= E-2 and its recovery into <= E-1, so once VR knows epoch-1 it holds every entry with E <= epoch.
// (Requiring VR to know epoch itself would make the shard wait for its own EVM's boundary into that epoch.)
func CoverNeeded(epoch uint64) uint64 {
	if epoch == 0 {
		return 0
	}
	return epoch - 1
}

// Source yields the committed activation schedule from one pinned, deployment-checked VR state.
type Source interface {
	Read(ctx context.Context) (Evidence, error)
}

// The EVM JSON-RPC implementation is vrclient.ScheduleSource (kept there so this package stays light).

// StaticSource is a fixed read, or a fixed failure when Err is set (tests, and a deployment that pins a schedule). Covered 0 means it
// covers every epoch.
type StaticSource struct {
	Entries []vrschema.Activation
	Pending []PendingEntry
	Covered uint64
	Err     error
}

// Read implements Source.
func (s StaticSource) Read(context.Context) (Evidence, error) {
	if s.Err != nil {
		return Evidence{}, s.Err
	}
	c := s.Covered
	if c == 0 {
		c = ^uint64(0)
	}
	return Evidence{CoveredEpoch: c, Schedule: s.Entries, Pending: s.Pending}, nil
}

// readTimeout bounds one source read.
const readTimeout = 10 * time.Second

// Gate is a role's fence over a Source: Check before installing or signing for a root epoch, Watch for the early warning. A nil *Gate
// fences nothing (no source configured); the roots then carry the fence.
//
// It caches the best EVIDENCE read (the pinned block, the epoch it covers, the schedule), not an answer per epoch: evidence that covers
// CoverNeeded(epoch) decides that epoch without another read, so a restart that replays many completed epochs costs one read.
type Gate struct {
	src   Source
	rules Set
	log   *slog.Logger

	mu      sync.Mutex
	best    *Evidence
	pending []vrschema.Activation
	preview []vrschema.Activation // pending (queued/scheduled) entries this binary lacks: warning only
	logged  map[string]bool
}

// NewGate returns a gate over src, or nil when src is nil, logging once that the upgrade fence then relies on the roots. A nil rules set
// is this binary's Known().
func NewGate(src Source, rules Set, log *slog.Logger) *Gate {
	if log == nil {
		log = slog.Default()
	}
	if src == nil {
		log.Info("no activation schedule source configured: upgrade fence relies on the roots")
		return nil
	}
	if rules == nil {
		rules = Known()
	}
	return &Gate{src: src, rules: rules, log: log, logged: map[string]bool{}}
}

func validEvidence(ev Evidence) error {
	if len(ev.Schedule) > MaxActivations || len(ev.Pending) > MaxPending {
		return fmt.Errorf("activation schedule evidence exceeds VR's bounds (%d entries, %d pending)", len(ev.Schedule), len(ev.Pending))
	}
	return nil
}

// Check refuses root epoch epoch when an effective rule with E <= epoch is lacking. It decides from cached evidence that covers
// CoverNeeded(epoch); otherwise it reads one pinned state. A failed or not-yet-covering read fails closed (the caller retries): it never
// passes silently and never decides from evidence that is behind the epoch.
func (g *Gate) Check(ctx context.Context, epoch uint64) error {
	if g == nil {
		return nil
	}
	need := CoverNeeded(epoch)
	g.mu.Lock()
	best := g.best
	g.mu.Unlock()
	var ev Evidence
	if best != nil && best.CoveredEpoch >= need {
		ev = *best
	} else {
		rctx, cancel := context.WithTimeout(ctx, readTimeout)
		defer cancel()
		got, err := g.src.Read(rctx)
		if err == nil {
			err = validEvidence(got)
		}
		if err == nil && got.CoveredEpoch < need {
			err = fmt.Errorf("%w: the pinned VR state knows root epoch %d, root epoch %d needs %d", ErrNotCovered, got.CoveredEpoch, epoch, need)
		}
		if err != nil {
			g.log.Error("refusing epoch: no adequate evidence of the activation schedule yet", "event", "upgrade.refused", "epoch", epoch, "error", err)
			return fmt.Errorf("activation schedule unavailable for root epoch %d, refusing until it can be read: %w", epoch, err)
		}
		g.remember(got)
		ev = got
	}
	g.mu.Lock()
	g.noteLocked(ev, epoch)
	g.mu.Unlock()
	if ferr := Fence(ev.Schedule, g.rules, epoch); ferr != nil {
		g.log.Error("refusing to install an epoch past an activation this binary lacks", "event", "upgrade.refused", "epoch", epoch, "error", ferr)
		return ferr
	}
	return nil
}

// CheckCheckpoint is Check over an AUTHENTICATED checkpoint: sched is the committed schedule of the verified handoff checkpoint that
// installs root epoch epoch (vradmit.AuthenticatedSchedule). By design 7.2 it holds every entry with E <= epoch, whichever VR blocks the
// EVM has reached, so it needs no read and no coverage: a recovery that skips an intermediate Boundary (K to K+2) decides here. It is
// kept as evidence for epochs up to epoch.
func (g *Gate) CheckCheckpoint(epoch uint64, sched []vrschema.Activation) error {
	if g == nil {
		return nil
	}
	if len(sched) > MaxActivations {
		return fmt.Errorf("checkpoint schedule exceeds VR's bound (%d entries)", len(sched))
	}
	ev := Evidence{CoveredEpoch: CoverNeeded(epoch), Schedule: sched}
	g.mu.Lock()
	g.noteLocked(ev, epoch)
	g.mu.Unlock()
	if err := Fence(sched, g.rules, epoch); err != nil {
		g.log.Error("refusing to install an epoch past an activation this binary lacks", "event", "upgrade.refused", "epoch", epoch, "source", "checkpoint", "error", err)
		return err
	}
	g.remember(ev)
	return nil
}

// remember keeps the evidence that covers the most epochs (the later block on a tie).
func (g *Gate) remember(ev Evidence) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.best == nil || ev.CoveredEpoch > g.best.CoveredEpoch || (ev.CoveredEpoch == g.best.CoveredEpoch && ev.BlockNumber >= g.best.BlockNumber) {
		cp := ev
		g.best = &cp
	}
}

// noteLocked records the unsupported entries, effective and pending, and warns once per entry.
func (g *Gate) noteLocked(ev Evidence, epoch uint64) {
	g.pending = Pending(ev.Schedule, g.rules)
	g.preview = nil
	for _, p := range ev.Pending {
		if !g.rules.Has(p.Activation.RuleID) {
			g.preview = append(g.preview, p.Activation)
		}
	}
	warn := func(a vrschema.Activation, state string) {
		k := fmt.Sprintf("%s/%x/%x/%d", state, a.RuleID[:], a.ReleaseDigest[:], a.RootEpoch)
		if g.logged[k] {
			return
		}
		g.logged[k] = true
		g.log.Warn("UPGRADE REQUIRED: the activation schedule holds a rule this binary does not support",
			"event", "upgrade.required", "state", state, "rule", fmt.Sprintf("%x", a.RuleID[:]), "release", fmt.Sprintf("%x", a.ReleaseDigest[:]),
			"activationEpoch", a.RootEpoch, "currentEpoch", epoch, "notBeforeUcTime", a.NotBeforeUcTime)
	}
	for _, a := range g.pending {
		warn(a, "effective")
	}
	for _, a := range g.preview {
		warn(a, "pending")
	}
}

// Poll reads the schedule once, remembers the evidence and warns about every unsupported entry, effective or pending; the epoch is only
// context for the log line. Enforcement stays on Check.
func (g *Gate) Poll(ctx context.Context, epoch uint64) error {
	if g == nil {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	ev, err := g.src.Read(rctx)
	if err == nil {
		err = validEvidence(ev)
	}
	if err != nil {
		return err
	}
	g.remember(ev)
	g.mu.Lock()
	g.noteLocked(ev, epoch)
	g.mu.Unlock()
	return nil
}

// Watch polls every interval until ctx ends, so the warning starts as soon as the schedule holds the entry (at its Queued event);
// epoch gives the role's current root epoch for the log line (nil: 0).
func (g *Gate) Watch(ctx context.Context, interval time.Duration, epoch func() uint64) {
	if g == nil {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		var e uint64
		if epoch != nil {
			e = epoch()
		}
		if err := g.Poll(ctx, e); err != nil && ctx.Err() == nil {
			g.log.Warn("activation schedule poll failed", "event", "upgrade.source_error", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Pending is the unsupported effective entries last seen.
func (g *Gate) Pending() []vrschema.Activation {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]vrschema.Activation(nil), g.pending...)
}

// Preview is the unsupported queued or scheduled (not yet effective) entries last seen: warning only.
func (g *Gate) Preview() []vrschema.Activation {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]vrschema.Activation(nil), g.preview...)
}

// RegisterMetric exposes unicity_upgrade_required{rule, epoch, state}: 1 for each unsupported entry, state "effective" for the committed
// schedule and "pending" for a queued or scheduled change (the roots' gauge has the first two labels).
func (g *Gate) RegisterMetric(m metric.Meter) error {
	if g == nil || m == nil {
		return nil
	}
	_, err := m.Int64ObservableGauge("unicity_upgrade_required",
		metric.WithDescription("1 for each activation-schedule rule this binary does not support (labels: rule id hex, activation root epoch, state effective or pending)"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			obs := func(list []vrschema.Activation, state string) {
				for _, a := range list {
					o.Observe(1, metric.WithAttributes(attribute.String("rule", fmt.Sprintf("%x", a.RuleID[:])),
						attribute.String("epoch", strconv.FormatUint(a.RootEpoch, 10)), attribute.String("state", state)))
				}
			}
			obs(g.Pending(), "effective")
			obs(g.Preview(), "pending")
			return nil
		}))
	return err
}
