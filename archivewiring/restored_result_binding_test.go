package archivewiring

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

// A restored journal can have the repeat UC for a block but not the earlier UC
// that originally certified it. When archive recovery inserts the historical
// body before backfilling its recorded result pair, that repeat must not become
// the archive record's resulting certificate.
func TestRestoredArchiveCandidateKeepsArchivedResultBinding(t *testing.T) {
	ctx := context.Background()
	f := newWiringFixture(t, 1)
	source := f.entries[0]
	request, archivedRecord := f.record(t, 0)

	path := t.TempDir() + "/restored-journal.db"
	restored, err := configuredprogress.OpenConfiguredV2(path, configuredprogress.Settings{Retain: 16})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restored.Close()) })
	_, _, err = restored.Initialize(ctx, f.context)
	require.NoError(t, err)
	require.NoError(t, restored.EnableJournal(ctx, f.context, f.limits))
	admit := func(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) {
		t.Helper()
		o, authErr := rootinput.AuthenticateObservationV2(ctx, f.context.Observation, uc, tr)
		require.NoError(t, authErr)
		prepared, _, prepErr := restored.PrepareObservation(ctx, f.context, o)
		require.NoError(t, prepErr)
		_, _, commitErr := restored.CommitObservation(prepared)
		require.NoError(t, commitErr)
	}

	// Restore progress from the authorizing certificate, then observe a later
	// repeat of the same input record. The original result UC is intentionally
	// absent from this node's observation journal, as in archive fallback.
	admit(source.Candidate.AuthorizingUC, source.Candidate.AuthorizingTR)
	repeatUC, repeatTR := signWiring(t, f.chain, source.ResultingUC.InputRecord,
		source.Candidate.Round+1, source.ResultingUC.GetRootRoundNumber()+1)
	admit(repeatUC, repeatTR)

	// This is the order used by configuredadmission.admitFetched for a fetched
	// historical body: put the candidate first, then backfill its archive pair.
	require.NoError(t, restored.PutHistoricalCertifiedJournalCandidate(ctx, f.context, f.limits, source.Candidate,
		source.ResultingUC, source.ResultingTR))
	require.NoError(t, restored.BackfillJournalObservation(ctx, f.context, f.limits, source.ResultingUC, source.ResultingTR))

	image, err := restored.LoadJournal(ctx, f.context, f.limits)
	require.NoError(t, err)
	require.Len(t, image.Candidates, 1)
	local := image.Candidates[0]
	require.True(t, local.Certified)
	require.Equal(t, source.ResultingUC.GetRootRoundNumber(), local.ResultingUC.GetRootRoundNumber())
	require.NotEqual(t, repeatUC.GetRootRoundNumber(), local.ResultingUC.GetRootRoundNumber())

	// The replica has the canonical archive record from before restoration. Its
	// strict verifier must accept the restored node's reconstruction after the
	// store preserves the archive's original result certificate association.
	localRequest, localRecord, err := FromJournal(ctx, f.context, f.subject, nil, local)
	require.NoError(t, err)
	require.Equal(t, request.BlockHash, localRequest.BlockHash)
	verify := JournalVerifier(f.store, f.context, f.limits, f.subject)
	require.NoError(t, verify(ctx, request, archivedRecord))
	require.NoError(t, verify(ctx, localRequest, localRecord))
}
