package cmd

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestShardStartupRestoresHandoffLineageBeforeJournalInitialize(t *testing.T) {
	currentEpoch := uint64(1)
	var steps []string
	err := runProfile2JournalStartup(context.Background(),
		func(context.Context) error {
			steps = append(steps, "restore")
			currentEpoch = 3
			return nil
		},
		func(context.Context) error {
			steps = append(steps, "initialize")
			require.Equal(t, uint64(3), currentEpoch,
				"the startup journal replay must see the installed handoff epoch")
			return nil
		},
		func(context.Context) error { steps = append(steps, "enable"); return nil },
		func(context.Context) error { steps = append(steps, "repair"); return nil })
	require.NoError(t, err)
	require.Equal(t, []string{"restore", "initialize", "enable", "repair"}, steps,
		"shard_node_run uses this seam to order handoff restore, journal replay and terminal-certificate repair")
}

type handoffStartupJournal struct {
	observations map[string]struct{}
}

func (j *handoffStartupJournal) BackfillJournalObservation(_ context.Context, _ configuredprogress.Context, _ configuredprogress.JournalLimits,
	uc *types.UnicityCertificate, _ *certification.TechnicalRecord) error {
	if uc == nil || uc.UnicitySeal == nil || uc.InputRecord == nil {
		return configuredprogress.ErrUntrusted
	}
	key := fmt.Sprintf("%d/%d/%d", uc.GetRootEpoch(), uc.GetRootRoundNumber(), uc.GetRoundNumber())
	j.observations[key] = struct{}{}
	return nil
}

func TestShardStartupRepairsSavedHandoffTerminalAfterCrashAndIsIdempotent(t *testing.T) {
	crash := errors.New("crash after handoff save before journal commit")
	saved := false
	journal := &handoffStartupJournal{observations: make(map[string]struct{})}
	terminal := handoffTerminalCertificate{
		uc: &types.UnicityCertificate{
			UnicitySeal: &types.UnicitySeal{Epoch: 2, RootChainRoundNumber: 41},
			InputRecord: &types.InputRecord{RoundNumber: 9},
		},
		tr: &certification.TechnicalRecord{Round: 9},
	}

	// The live follower's ordering is save bundle, then invoke OnInstalled. Inject
	// a crash at the gap before OnInstalled can commit the terminal certificate.
	firstRunOnInstalled := func() error {
		saved = true
		return crash
	}
	require.ErrorIs(t, firstRunOnInstalled(), crash)
	require.True(t, saved, "the handoff record reached disk before the injected crash")
	require.Empty(t, journal.observations)

	terminals := []handoffTerminalCertificate{}
	restore := func(context.Context) error {
		require.True(t, saved, "restart must replay the saved handoff record")
		terminals = append(terminals, terminal)
		return nil
	}
	repair := func(ctx context.Context) error {
		return reapplyHandoffTerminalCertificates(ctx, journal, configuredprogress.Context{}, configuredprogress.JournalLimits{}, terminals)
	}
	startup := func() error {
		return runProfile2JournalStartup(context.Background(), restore,
			func(context.Context) error { return nil },
			func(context.Context) error { return nil }, repair)
	}
	require.NoError(t, startup())
	require.Len(t, journal.observations, 1, "restart repairs the missing old-epoch terminal observation")
	require.NoError(t, startup(), "replaying the same saved handoff terminal must be idempotent")
	require.Len(t, journal.observations, 1)
}
