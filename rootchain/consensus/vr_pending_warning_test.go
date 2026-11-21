package consensus

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/vrrules"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// A ScheduleActivation change bound into the open VR output, with the committed (effective) schedule empty, still produces the root's
// warning and a gauge sample (state pending); a rule the binary supports does not; enforcement is untouched (astra r2 item 6).
func TestRootWarnsOfAQueuedChangeWithAnEmptyEffectiveSchedule(t *testing.T) {
	var logs bytes.Buffer
	x := &ConsensusManager{log: slog.New(slog.NewTextHandler(&logs, nil)), rules: vrrules.Set{vrschema.RuleID("known"): "known"}}
	unknown := vrschema.Activation{RuleID: vrschema.RuleID("unknown"), ReleaseDigest: vrschema.Word{7}, RootEpoch: 12, State: vrschema.ActActive, ChangeID: 3}
	known := vrschema.Activation{RuleID: vrschema.RuleID("known"), RootEpoch: 12, State: vrschema.ActActive, ChangeID: 4}

	x.noteSchedule(nil, 5) // the effective schedule is empty
	x.notePending([]vrschema.Activation{unknown, known}, 5)
	require.Contains(t, logs.String(), "upgrade.required")
	require.Contains(t, logs.String(), "state=pending")
	x.upgrades.mu.Lock()
	require.Len(t, x.upgrades.queued, 1, "only the unsupported change")
	require.Empty(t, x.upgrades.pending, "nothing effective")
	x.upgrades.mu.Unlock()

	// the output closes: the warning state clears; the committed schedule is what is enforced
	x.notePending(nil, 5)
	x.upgrades.mu.Lock()
	require.Empty(t, x.upgrades.queued)
	x.upgrades.mu.Unlock()
}

// The stable lifecycle events: a latched entry logs activation.latched once, and an entry whose E has been reached logs activation.active
// once, on every call of the committed-schedule note (VT-12's catalogue).
func TestRootLogsTheActivationLifecycleEvents(t *testing.T) {
	var logs bytes.Buffer
	x := &ConsensusManager{log: slog.New(slog.NewTextHandler(&logs, nil)), rules: vrrules.Set{vrschema.RuleID("r"): "r"}}
	a := vrschema.Activation{RuleID: vrschema.RuleID("r"), ReleaseDigest: vrschema.Word{9}, RootEpoch: 6, State: vrschema.ActActive, ChangeID: 1}
	x.noteSchedule([]vrschema.Activation{a}, 5)
	require.NotContains(t, logs.String(), "activation.latched")
	require.NotContains(t, logs.String(), "activation.active")
	a.State = vrschema.ActLatched
	x.noteSchedule([]vrschema.Activation{a}, 6)
	x.noteSchedule([]vrschema.Activation{a}, 7)
	require.Equal(t, 1, strings.Count(logs.String(), "event=activation.latched"))
	require.Equal(t, 1, strings.Count(logs.String(), "event=activation.active"))
}
