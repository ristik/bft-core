package consensus

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/monitoring"
)

// TestRoundEndedCountsMissedVotes: a member that ends rounds without a vote counts them by kind, logs root.vote.missed on the third in a row,
// and a vote resets the run; a follower counts nothing.
func TestRoundEndedCountsMissedVotes(t *testing.T) {
	var buf bytes.Buffer
	x := &ConsensusManager{log: slog.New(slog.NewTextHandler(&buf, nil))}
	reg := prometheus.NewRegistry()
	x.votesMissed = monitoring.New(reg).CounterVec("unicity_root_votes_missed_total", "x", "reason")
	x.roundEnded(5, false, false) // not a member: nothing
	require.Zero(t, counted(x))

	member := func() { x.memberOverride = func() bool { return true } }
	member()
	x.roundEnded(5, false, false)
	x.roundEnded(6, false, true)
	require.Equal(t, 1.0, got(t, x, "no_vote"))
	require.Equal(t, 1.0, got(t, x, "timeout_only"))
	require.NotContains(t, buf.String(), "event=root.vote.missed")
	x.roundEnded(7, false, false)
	require.Contains(t, buf.String(), "event=root.vote.missed")
	x.roundEnded(8, true, false)
	require.Zero(t, x.missedRun)
}

func counted(x *ConsensusManager) int {
	ch := make(chan prometheus.Metric, 8)
	go func() { x.votesMissed.Collect(ch); close(ch) }()
	n := 0
	for range ch {
		n++
	}
	return n
}

func got(t *testing.T, x *ConsensusManager, reason string) float64 {
	var m dto.Metric
	require.NoError(t, x.votesMissed.WithLabelValues(reason).Write(&m))
	return m.GetCounter().GetValue()
}
