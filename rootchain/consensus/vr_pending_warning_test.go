package consensus

import (
	"bytes"
	"log/slog"
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
