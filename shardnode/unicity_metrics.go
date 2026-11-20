package shardnode

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/unicitynetwork/bft-core/monitoring"
)

// finalizer is the optional part of an executor that reports its finalized block (the Engine API adapter has it).
type finalizer interface {
	Finalized(ctx context.Context) (BlockRef, error)
}

// RegisterUnicityMetrics registers the shard node's unicity_* metrics (docs/operations/monitoring/metrics-catalogue.md): the health snapshot's
// figures and the paired execution client's head, read at scrape time. exec may be nil.
func RegisterUnicityMetrics(r *monitoring.Registry, h *Health, exec Executor) {
	snap := func() Snapshot { return h.Snapshot() }
	b2f := func(b bool) float64 {
		if b {
			return 1
		}
		return 0
	}
	r.GaugeFunc("unicity_shard_executor_ok", "1 while the shard node's last executor (Engine API) call succeeded.", func() float64 { return b2f(snap().ExecutorOK) })
	r.GaugeFunc("unicity_shard_certified_round", "The shard round of the latest unicity certificate this node holds.", func() float64 { return float64(snap().LastUCRound) })
	r.GaugeFunc("unicity_shard_root_round", "The root round of the latest unicity certificate this node holds.", func() float64 { return float64(snap().LastUCRootRound) })
	r.GaugeFunc("unicity_shard_submitted_round", "The shard round of the latest certification request this node submitted.", func() float64 { return float64(snap().LastSubmittedRound) })
	r.GaugeFunc("unicity_shard_certified_lag_rounds", "Shard rounds submitted but not yet certified (submitted minus certified). 1 is normal; a value that stays above a few means the roots are not certifying this shard's work.", func() float64 {
		s := snap()
		if s.LastSubmittedRound > s.LastUCRound {
			return float64(s.LastSubmittedRound - s.LastUCRound)
		}
		return 0
	})
	r.GaugeFunc("unicity_shard_voting", "1 while this shard node contributes certification requests (0: deliberately withheld, see the health snapshot's nonVotingReason).", func() float64 { return b2f(snap().Voting) })
	r.GaugeFunc("unicity_shard_active", "1 while this shard node's published role is active (a validator of the installed assignment), 0 for a follower.", func() float64 {
		s := snap()
		return b2f(s.Role == "" || s.Role == "active")
	})
	r.GaugeFunc("unicity_shard_health_age_seconds", "Seconds since the shard node's health state last changed; large with a stuck shard.", func() float64 { return snap().SecondsSinceUpdate })
	r.GaugeFunc("unicity_shard_execution_ready", "1 while the execution recovery coordinator reports ready (or is not configured), 0 while the shard is catching its executor up.", func() float64 {
		s := snap()
		return b2f(s.ExecutionRecovery == "" || s.ExecutionRecovery == "ready")
	})
	if exec != nil {
		r.Collector(newEVMCollector(exec))
	}
}

// evmCollector reads the execution client's head and finalized block through the adapter, at most once per refresh.
type evmCollector struct {
	exec Executor

	mu            sync.Mutex
	at            time.Time
	head, final   uint64
	finalKnown    bool
	err           bool
	lastHeadMoved time.Time
	lastHead      uint64

	headDesc, finalDesc, errDesc, unfinDesc, stuckDesc *prometheus.Desc
}

const evmRefresh = 5 * time.Second

func newEVMCollector(exec Executor) *evmCollector {
	return &evmCollector{exec: exec,
		headDesc:  prometheus.NewDesc("unicity_evm_head_number", "Block number of the execution client's head as the shard node reads it.", nil, nil),
		finalDesc: prometheus.NewDesc("unicity_evm_finalized_number", "Block number of the execution client's finalized block.", nil, nil),
		unfinDesc: prometheus.NewDesc("unicity_evm_unfinalized_blocks", "Blocks between the execution client's head and its finalized block.", nil, nil),
		stuckDesc: prometheus.NewDesc("unicity_evm_head_stuck_seconds", "Seconds the execution client's head has not advanced, as seen at scrape times.", nil, nil),
		errDesc:   prometheus.NewDesc("unicity_evm_unreachable", "1 when the shard node could not read the execution client's head (it is down, or the Engine API refuses).", nil, nil)}
}

func (c *evmCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.headDesc
	ch <- c.finalDesc
	ch <- c.unfinDesc
	ch <- c.stuckDesc
	ch <- c.errDesc
}

func (c *evmCollector) refresh() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.at) < evmRefresh {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c.at = time.Now()
	h, err := c.exec.Head(ctx)
	if err != nil {
		c.err = true
		return
	}
	c.err = false
	c.head = h.Number
	if h.Number != c.lastHead || c.lastHeadMoved.IsZero() {
		c.lastHead, c.lastHeadMoved = h.Number, time.Now()
	}
	if f, ok := c.exec.(finalizer); ok {
		if fb, err := f.Finalized(ctx); err == nil {
			c.final, c.finalKnown = fb.Number, true
		}
	}
}

func (c *evmCollector) Collect(ch chan<- prometheus.Metric) {
	c.refresh()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err {
		ch <- prometheus.MustNewConstMetric(c.errDesc, prometheus.GaugeValue, 1)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.errDesc, prometheus.GaugeValue, 0)
	ch <- prometheus.MustNewConstMetric(c.headDesc, prometheus.GaugeValue, float64(c.head))
	ch <- prometheus.MustNewConstMetric(c.stuckDesc, prometheus.GaugeValue, time.Since(c.lastHeadMoved).Seconds())
	if c.finalKnown {
		ch <- prometheus.MustNewConstMetric(c.finalDesc, prometheus.GaugeValue, float64(c.final))
		if c.head >= c.final {
			ch <- prometheus.MustNewConstMetric(c.unfinDesc, prometheus.GaugeValue, float64(c.head-c.final))
		}
	}
}
