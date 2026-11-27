package consensus

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type profMsgA struct{}
type profMsgB struct{}

func TestLoopProfileReportsPerTypeTimeOnceThePeriodHasPassed(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	var p loopProfile
	t0 := time.Unix(1000, 0)
	p.report(log, t0) // starts the period
	p.observe(profMsgA{}, 30*time.Millisecond)
	p.observe(profMsgA{}, 10*time.Millisecond)
	p.observe(&profMsgB{}, 5*time.Millisecond)
	p.report(log, t0.Add(loopProfileInterval-time.Second))
	require.Empty(t, buf.String(), "nothing before the interval has passed")
	p.report(log, t0.Add(loopProfileInterval))
	out := buf.String()
	require.Contains(t, out, "type=consensus.profMsgA")
	require.Contains(t, out, "count=2")
	require.Contains(t, out, "totalMs=40")
	require.Contains(t, out, "type=*consensus.profMsgB")
	require.Contains(t, out, "rootNetBusyMs=45")
	require.Less(t, strings.Index(out, "profMsgA"), strings.Index(out, "profMsgB"), "largest total time first")
	buf.Reset()
	p.report(log, t0.Add(2*loopProfileInterval))
	require.Empty(t, buf.String(), "the period was reset")

	// a new period starts at the report: a message observed right after it does not make the next report fire at once (without the reset of
	// p.start every later report would fire on the next message)
	p.observe(profMsgA{}, time.Millisecond)
	p.report(log, t0.Add(loopProfileInterval+time.Second))
	require.Empty(t, buf.String(), "less than an interval after the previous report")
	p.report(log, t0.Add(3*loopProfileInterval))
	require.Contains(t, buf.String(), "type=consensus.profMsgA")
}
