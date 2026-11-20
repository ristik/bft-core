package monitoring

import (
	"fmt"
	"sort"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// UpgradeRule is an activation rule the committed schedule holds that this binary does not implement (design 7.3).
type UpgradeRule struct {
	RuleID        [32]byte
	ReleaseDigest [32]byte
	RootEpoch     uint64 // the root epoch the rule activates from
}

// UpgradeTracker is the process's set of schedule rules it cannot support. The activation-schedule code (vrschedule member, VT-07) calls
// Require when it finds one and Clear when the schedule no longer holds it (superseded) or the binary was replaced; the metrics read it.
type UpgradeTracker struct {
	mu    sync.Mutex
	rules map[[32]byte]UpgradeRule
}

// Upgrades is the process-wide tracker behind unicity_upgrade_required.
var Upgrades = &UpgradeTracker{rules: map[[32]byte]UpgradeRule{}}

// Require records a rule this binary does not implement.
func (t *UpgradeTracker) Require(r UpgradeRule) {
	t.mu.Lock()
	t.rules[r.RuleID] = r
	t.mu.Unlock()
}

// Clear forgets a rule (superseded in the schedule).
func (t *UpgradeTracker) Clear(ruleID [32]byte) {
	t.mu.Lock()
	delete(t.rules, ruleID)
	t.mu.Unlock()
}

// Reset forgets every rule.
func (t *UpgradeTracker) Reset() {
	t.mu.Lock()
	t.rules = map[[32]byte]UpgradeRule{}
	t.mu.Unlock()
}

func (t *UpgradeTracker) snapshot() []UpgradeRule {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]UpgradeRule, 0, len(t.rules))
	for _, r := range t.rules {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RootEpoch < out[j].RootEpoch })
	return out
}

// RegisterUpgrades registers the tracker's metrics: unicity_upgrade_required (0 or 1), unicity_upgrade_activation_epoch (the earliest
// root epoch of a rule this binary lacks; absent while none) and unicity_upgrade_rule_info{rule,release,activation_epoch} (one series
// per rule, value 1).
func RegisterUpgrades(r *Registry, t *UpgradeTracker) {
	r.GaugeFunc("unicity_upgrade_required", "1 while the committed activation schedule holds a rule this binary does not implement: the node must be upgraded before the rule's root epoch (VT-07).", func() float64 {
		if len(t.snapshot()) > 0 {
			return 1
		}
		return 0
	})
	r.Collector(upgradeCollector{t: t,
		epoch: prometheus.NewDesc("unicity_upgrade_activation_epoch", "The earliest root epoch at which a rule this binary does not implement activates; absent while there is none.", nil, nil),
		info:  prometheus.NewDesc("unicity_upgrade_rule_info", "A schedule rule this binary does not implement.", []string{"rule", "release", "activation_epoch"}, nil)})
}

type upgradeCollector struct {
	t           *UpgradeTracker
	epoch, info *prometheus.Desc
}

func (c upgradeCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.epoch; ch <- c.info }

func (c upgradeCollector) Collect(ch chan<- prometheus.Metric) {
	rules := c.t.snapshot()
	if len(rules) == 0 {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.epoch, prometheus.GaugeValue, float64(rules[0].RootEpoch))
	for _, r := range rules {
		ch <- prometheus.MustNewConstMetric(c.info, prometheus.GaugeValue, 1, fmt.Sprintf("%x", r.RuleID[:8]), fmt.Sprintf("%x", r.ReleaseDigest[:8]), fmt.Sprint(r.RootEpoch))
	}
}
