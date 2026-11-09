package consensus

import (
	"bytes"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPhaseProfileSplitsAHandlerRunIntoLaps(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	var p phaseProfile
	t0 := time.Unix(1000, 0)
	p.report(log, t0) // starts the period
	for i := 0; i < 3; i++ {
		l := p.begin()
		time.Sleep(2 * time.Millisecond)
		l.lap("verify")
		l.lap("execute")
		l.rest() // an early return records the remainder
	}
	require.Equal(t, 3, p.phases["verify"].count)
	require.GreaterOrEqual(t, p.phases["verify"].total, 6*time.Millisecond)
	require.Equal(t, 3, p.phases["rest"].count)
	p.report(log, t0.Add(loopProfileInterval-time.Second))
	require.Empty(t, buf.String(), "nothing before the interval")
	p.report(log, t0.Add(loopProfileInterval))
	require.Contains(t, buf.String(), "phase=verify")
	require.Contains(t, buf.String(), "count=3")
	buf.Reset()
	p.report(log, t0.Add(loopProfileInterval+time.Second))
	require.Empty(t, buf.String(), "reset after a report")
}
