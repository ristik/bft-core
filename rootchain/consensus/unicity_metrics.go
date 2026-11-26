package consensus

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/unicitynetwork/bft-core/monitoring"
)

// missedVoteWarnRun is how many consecutive rounds a committee member must end without any vote before it logs root.vote.missed (a single
// round without a vote is normal around a proposal that never arrived; the counter still counts every one).
const missedVoteWarnRun = 3

// initUnicityMetrics registers the root's unicity_* metrics (docs/operations/monitoring/metrics-catalogue.md). Everything here is read at
// scrape time from state the manager already keeps, or counted at the call sites below; without a Prometheus registerer the metrics exist
// and nothing reads them.
func (x *ConsensusManager) initUnicityMetrics() {
	m := x.mon
	x.votesMissed = m.CounterVec("unicity_root_votes_missed_total",
		"Rounds this root ended, as a member of the epoch's committee, without sending a vote of the given kind: no_vote (it signed nothing in the round) or timeout_only (it signed a timeout vote but no vote for a proposal).", "reason")
	x.proposals = m.Counter("unicity_root_proposals_total", "Proposals this root signed and sent as the round's leader.")
	x.handoffRefusedCnt = m.CounterVec("unicity_root_handoff_refused_total",
		"Leader rounds in which this root left a handoff record of the given kind (prepare, freeze, commit, abort) out of its proposal because its own executor refuses it: class deterministic (every honest root refuses it; remembered and not ordered again for that intent) or local (an input this root lacks; this round only).", "kind", "class")
	m.GaugeFunc("unicity_root_handoff_refused_open", "Handoff records this root's leader holds as deterministically refused (volatile; pruned when the intent dies).", func() float64 { return float64(x.refused.len()) })
	x.roundTimeout = m.Counter("unicity_root_round_timeouts_total", "Rounds in which this root's round timer fired (counted once per round; no QC or TC ended the round in time). A follower root also times out every round.")
	m.GaugeFunc("unicity_root_round", "The root round this node is in.", func() float64 { return float64(x.pacemaker.GetCurrentRound()) })
	m.GaugeFunc("unicity_root_epoch", "The root epoch (trust base epoch) this node is in.", func() float64 { return float64(x.trustBase.Load().Epoch) })
	m.GaugeFunc("unicity_root_committed_round", "The round of the latest committed root block.", func() float64 {
		if s := x.blockStore(); s != nil {
			return float64(s.CommittedRound())
		}
		return 0
	})
	m.GaugeFunc("unicity_root_round_lag", "Rounds between the round in progress and the latest committed root block. About 3 in a healthy chain (the commit rule); grows while rounds time out or this node is behind.", func() float64 {
		if s := x.blockStore(); s != nil {
			if cur, c := x.pacemaker.GetCurrentRound(), s.CommittedRound(); cur > c {
				return float64(cur - c)
			}
		}
		return 0
	})
	m.Collector(&recordsProjected{count: func() (uint64, bool) {
		if s := x.blockStore(); s != nil {
			return s.RecordCount()
		}
		return 0, false
	}})
	m.GaugeFunc("unicity_root_member", "1 while this root is a member of its epoch's root committee (signs), 0 for a follower.", func() float64 {
		if x.isCommitteeMember() {
			return 1
		}
		return 0
	})
	m.GaugeFunc("unicity_root_committee_size", "Root nodes in the epoch's committee.", func() float64 { return float64(len(x.trustBase.Load().RootNodes)) })
}

func (x *ConsensusManager) isCommitteeMember() bool {
	if x.memberOverride != nil {
		return x.memberOverride()
	}
	tb := x.trustBase.Load()
	if tb == nil {
		return false
	}
	for _, n := range tb.RootNodes {
		if n.NodeID == x.id.String() {
			return true
		}
	}
	return false
}

func (x *ConsensusManager) noteProposal() {
	if x.proposals != nil {
		x.proposals.Inc()
	}
}

// noteRoundTimeout counts the first local timeout of a round: the timer fires again for a round that stays open (the vote is re-broadcast), and
// those repeats are the same round.
func (x *ConsensusManager) noteRoundTimeout(round uint64) {
	if round == x.lastTimeoutRound {
		return
	}
	x.lastTimeoutRound = round
	if x.roundTimeout != nil {
		x.roundTimeout.Inc()
	}
}

// roundEnded is the pacemaker's report that a round is over and which of this node's votes it sent. A follower sends none and misses none.
func (x *ConsensusManager) roundEnded(round uint64, voted, timeoutVoted bool) {
	if round == 0 || x.votesMissed == nil || !x.isCommitteeMember() {
		return
	}
	switch {
	case voted:
		x.missedRun = 0
		return
	case timeoutVoted:
		x.votesMissed.WithLabelValues("timeout_only").Inc()
	default:
		x.votesMissed.WithLabelValues("no_vote").Inc()
	}
	x.missedRun++
	if x.missedRun == missedVoteWarnRun && x.log != nil {
		x.log.Warn("this root ended rounds without a vote", slog.Uint64("round", round), slog.Int("consecutiveRounds", x.missedRun),
			slog.Bool("timeoutVoted", timeoutVoted), monitoring.Event(monitoring.EvRootVoteMissed))
	}
}

// recordsProjected exports unicity_root_records_projected, and nothing when the record store is unavailable or unreadable: an unknown count
// is absent, never zero (zero would say the root projected nothing and silence the import-lag alert).
type recordsProjected struct{ count func() (uint64, bool) }

var recordsProjectedDesc = prometheus.NewDesc("unicity_root_records_projected",
	"Root records (P85/VR source log) the committed root chain has projected: the root target of the record catch-up counters. Absent while the record store cannot be read.", nil, nil)

func (c *recordsProjected) Describe(ch chan<- *prometheus.Desc) { ch <- recordsProjectedDesc }

func (c *recordsProjected) Collect(ch chan<- prometheus.Metric) {
	if n, ok := c.count(); ok {
		ch <- prometheus.MustNewConstMetric(recordsProjectedDesc, prometheus.GaugeValue, float64(n))
	}
}
