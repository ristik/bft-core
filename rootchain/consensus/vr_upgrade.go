package consensus

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/unicitynetwork/bft-core/logger"
	"github.com/unicitynetwork/bft-core/vrrules"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// The activation schedule's fences and warnings on a root (design section 7.4, VT-07a): a root that lacks a rule the committed schedule
// makes effective refuses to install or run an epoch >= E, with UpgradeRequired, and warns from the moment the schedule holds the entry.

// upgradeWatch is the warning state: the entries this binary lacks, as last seen in the committed schedule.
type upgradeWatch struct {
	mu      sync.Mutex
	pending []vrschema.Activation
	logged  map[string]bool
}

// supportedRules is the rule set of this binary (overridable by tests).
func (x *ConsensusManager) supportedRules() vrrules.Set {
	if x.rules != nil {
		return x.rules
	}
	return vrrules.Known()
}

// noteSchedule records the committed schedule's unsupported entries: a warning log once per entry and the gauge.
func (x *ConsensusManager) noteSchedule(schedule []vrschema.Activation, epoch uint64) {
	pend := vrrules.Pending(schedule, x.supportedRules())
	w := &x.upgrades
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending = pend
	if w.logged == nil {
		w.logged = map[string]bool{}
	}
	for _, a := range pend {
		k := fmt.Sprintf("%x/%x/%d", a.RuleID[:], a.ReleaseDigest[:], a.RootEpoch)
		if w.logged[k] {
			continue
		}
		w.logged[k] = true
		x.log.Warn("UPGRADE REQUIRED: the committed activation schedule holds a rule this binary does not support",
			"event", "upgrade.required", "rule", fmt.Sprintf("%x", a.RuleID[:]), "release", fmt.Sprintf("%x", a.ReleaseDigest[:]),
			"activationEpoch", a.RootEpoch, "currentEpoch", epoch, "notBeforeUcTime", a.NotBeforeUcTime)
	}
}

// upgradeFence refuses an epoch >= E of an effective rule this binary lacks, over the committed schedule.
func (x *ConsensusManager) upgradeFence(epoch uint64) error {
	sched, cur, ok, err := x.blockStore().CommittedSchedule()
	if err != nil {
		return fmt.Errorf("reading the committed activation schedule: %w", err)
	}
	if !ok {
		return nil
	}
	x.noteSchedule(sched, cur)
	if err := vrrules.Fence(sched, x.supportedRules(), epoch); err != nil {
		x.log.Error("refusing to run past an activation this binary lacks", "event", "upgrade.refused", "epoch", epoch, logger.Error(err))
		return err
	}
	return nil
}

// registerUpgradeMetric exposes unicity_upgrade_required{rule, epoch}: 1 for every effective schedule entry this binary lacks.
func (x *ConsensusManager) registerUpgradeMetric(m metric.Meter) error {
	_, err := m.Int64ObservableGauge("unicity_upgrade_required",
		metric.WithDescription("1 for each effective activation-schedule rule this binary does not support (labels: rule id hex, activation root epoch)"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			x.upgrades.mu.Lock()
			defer x.upgrades.mu.Unlock()
			for _, a := range x.upgrades.pending {
				o.Observe(1, metric.WithAttributes(attribute.String("rule", fmt.Sprintf("%x", a.RuleID[:])),
					attribute.String("epoch", strconv.FormatUint(a.RootEpoch, 10))))
			}
			return nil
		}))
	return err
}
