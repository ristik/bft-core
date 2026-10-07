package q3format

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1state"
)

func TestB1MissingConfigurationNeverDefaultsToLegacy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Entry)
		want   error
	}{
		{"genesis-version", func(e *Entry) { e.version = 2 }, ErrConfig},
		{"genesis-scheme", func(e *Entry) { e.scheme = 2 }, ErrConfig},
		{"key-width", func(e *Entry) { e.tb.RootNodes[0].SigKey = append(e.tb.RootNodes[0].SigKey, 1) }, b1state.ErrMembers},
		{"member-semantic", func(e *Entry) { e.tb.RootNodes[0].Stake = 0 }, b1state.ErrMembers},
		{"quorum-policy", func(e *Entry) { e.tb.QuorumThreshold++ }, ErrConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t, 0)
			tc.change(&w.h.entries[0])
			_, err := w.h.B1Entries(^uint64(0))
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestB1RefusesMissingOrChangedSuccessorConfiguration(t *testing.T) {
	for _, missing := range []bool{false, true} {
		w := newWorld(t, 0)
		h, err := w.h.WithV3(w.link(spec{}))
		require.NoError(t, err)
		if missing {
			h.entries[1].config = nil
		} else {
			h.entries[1].config.Revision++
		}
		_, err = h.B1Entries(^uint64(0))
		require.ErrorIs(t, err, ErrConfig)
	}
}
