package vrrules

import (
	"context"
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

// Source yields the committed activation schedule.
type Source interface {
	Schedule(ctx context.Context) ([]vrschema.Activation, error)
}

// The EVM JSON-RPC implementation is vrclient.ScheduleSource (kept there so this package stays light).

// StaticSource is a fixed schedule, or a fixed failure when Err is set (tests, and a deployment that pins a schedule).
type StaticSource struct {
	Entries []vrschema.Activation
	Err     error
}

// Schedule implements Source.
func (s StaticSource) Schedule(context.Context) ([]vrschema.Activation, error) {
	return s.Entries, s.Err
}

// MaxCachedEpochs bounds the per-epoch cache (the schedule itself holds at most 64 entries).
const MaxCachedEpochs = 64

// readTimeout bounds one source read.
const readTimeout = 10 * time.Second

// Gate is a role's fence over a Source: Check before installing or signing for a root epoch, Watch for the early warning. A nil *Gate
// fences nothing (no source configured); the roots then carry the fence.
type Gate struct {
	src   Source
	rules Set
	log   *slog.Logger

	mu      sync.Mutex
	cache   map[uint64][]vrschema.Activation // the schedule last read when checking that epoch
	pending []vrschema.Activation
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
	return &Gate{src: src, rules: rules, log: log, cache: map[uint64][]vrschema.Activation{}, logged: map[string]bool{}}
}

// Check refuses root epoch epoch when an effective rule with E <= epoch is lacking. It reads the schedule afresh; when the read fails
// it falls back to what the last check of this very epoch read, and with nothing known for the epoch it fails closed (the caller
// retries): it never passes silently.
func (g *Gate) Check(ctx context.Context, epoch uint64) error {
	if g == nil {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	sched, err := g.src.Schedule(rctx)
	g.mu.Lock()
	if err != nil {
		cached, ok := g.cache[epoch]
		g.mu.Unlock()
		if !ok {
			g.log.Error("refusing epoch: the activation schedule cannot be read and none is known for it", "event", "upgrade.refused", "epoch", epoch, "error", err)
			return fmt.Errorf("activation schedule unavailable for root epoch %d, refusing until it can be read: %w", epoch, err)
		}
		g.log.Warn("activation schedule read failed; using the schedule last read for this epoch", "event", "upgrade.source_error", "epoch", epoch, "error", err)
		sched = cached
		g.mu.Lock()
	} else {
		g.remember(epoch, sched)
	}
	g.noteLocked(sched, epoch)
	g.mu.Unlock()
	if ferr := Fence(sched, g.rules, epoch); ferr != nil {
		g.log.Error("refusing to install an epoch past an activation this binary lacks", "event", "upgrade.refused", "epoch", epoch, "error", ferr)
		return ferr
	}
	return nil
}

func (g *Gate) remember(epoch uint64, sched []vrschema.Activation) {
	if _, ok := g.cache[epoch]; !ok && len(g.cache) >= MaxCachedEpochs {
		low, first := uint64(0), true
		for e := range g.cache {
			if first || e < low {
				low, first = e, false
			}
		}
		delete(g.cache, low)
	}
	g.cache[epoch] = sched
}

// noteLocked records the unsupported entries and warns once per entry.
func (g *Gate) noteLocked(sched []vrschema.Activation, epoch uint64) {
	g.pending = Pending(sched, g.rules)
	for _, a := range g.pending {
		k := fmt.Sprintf("%x/%x/%d", a.RuleID[:], a.ReleaseDigest[:], a.RootEpoch)
		if g.logged[k] {
			continue
		}
		g.logged[k] = true
		g.log.Warn("UPGRADE REQUIRED: the committed activation schedule holds a rule this binary does not support",
			"event", "upgrade.required", "rule", fmt.Sprintf("%x", a.RuleID[:]), "release", fmt.Sprintf("%x", a.ReleaseDigest[:]),
			"activationEpoch", a.RootEpoch, "currentEpoch", epoch, "notBeforeUcTime", a.NotBeforeUcTime)
	}
}

// Poll reads the schedule once and warns about every unsupported entry; the epoch is only context for the log line.
func (g *Gate) Poll(ctx context.Context, epoch uint64) error {
	if g == nil {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	sched, err := g.src.Schedule(rctx)
	if err != nil {
		return err
	}
	g.mu.Lock()
	g.noteLocked(sched, epoch)
	g.mu.Unlock()
	return nil
}

// Watch polls every interval until ctx ends, so the warning starts as soon as the schedule holds the entry; epoch gives the role's
// current root epoch for the log line (nil: 0).
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

// RegisterMetric exposes unicity_upgrade_required{rule, epoch} (the name and meaning the roots use).
func (g *Gate) RegisterMetric(m metric.Meter) error {
	if g == nil || m == nil {
		return nil
	}
	_, err := m.Int64ObservableGauge("unicity_upgrade_required",
		metric.WithDescription("1 for each effective activation-schedule rule this binary does not support (labels: rule id hex, activation root epoch)"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for _, a := range g.Pending() {
				o.Observe(1, metric.WithAttributes(attribute.String("rule", fmt.Sprintf("%x", a.RuleID[:])),
					attribute.String("epoch", strconv.FormatUint(a.RootEpoch, 10))))
			}
			return nil
		}))
	return err
}
