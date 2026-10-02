package archivewiring

import (
	"bytes"
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// unobservedSuccessor builds the certified block after parent, and its certificates, without retaining or observing it: a terminal
// that a restart or restore would find missing from the journal.
func unobservedSuccessor(t *testing.T, f *wiringFixture, parent configuredprogress.JournalEntry, number uint64) configuredprogress.JournalEntry {
	t.Helper()
	var state [32]byte
	state[0], state[31] = byte(number), byte(number+17)
	hash, raw, size := wiringBlock(t, [32]byte(parent.Candidate.Hash), state, number, parent.ResultingUC.GetRootRoundNumber(), parent.ResultingUC, parent.ResultingTR)
	candidate := configuredprogress.JournalCandidate{Round: number, Number: number, ParentNumber: number - 1, Hash: hash[:], StateRoot: state[:],
		ParentHash: parent.Candidate.Hash, ParentState: parent.Candidate.StateRoot, Raw: raw, BlockSize: size,
		AuthorizingUC: parent.ResultingUC, AuthorizingTR: parent.ResultingTR}
	ir := &types.InputRecord{Version: 1, RoundNumber: number, PreviousHash: bytes.Clone(parent.Candidate.StateRoot), Hash: state[:], BlockHash: hash[:],
		SummaryValue: []byte{}, Timestamp: 1700000000 + number}
	uc, tr := signWiring(t, f.chain, ir, number+1, 4+number)
	return configuredprogress.JournalEntry{Candidate: candidate, Certified: true, ResultingUC: uc, ResultingTR: tr}
}

// repairTerminal is the production repair step for one terminal as the CLI runs it, minus the CLI's archive lookup: a terminal the
// authenticated discharge covers is skipped, any other is retained as a historical body and then its observation is backfilled.
func repairTerminal(ctx context.Context, store *configuredprogress.Store, c configuredprogress.Context, limits configuredprogress.JournalLimits,
	discharge configuredprogress.TerminalDischarge, e configuredprogress.JournalEntry) (repaired bool, err error) {
	if discharge.Covers(e.ResultingUC) {
		return false, nil
	}
	candidate := e.Candidate
	candidate.LocallyBuilt = false
	if err = store.PutHistoricalCertifiedJournalCandidate(ctx, c, limits, candidate, e.ResultingUC, e.ResultingTR); err != nil {
		return false, err
	}
	return true, store.BackfillJournalObservation(ctx, c, limits, e.ResultingUC, e.ResultingTR)
}

// A restart finds many historical handoff terminals the persisted frontier already pruned. The repair must skip them (the control
// shows that inserting one once the frontier is enabled is a conflict, and that doing so before the frontier would resurrect the body),
// and must still repair a terminal the frontier does not yet cover.
func TestAuditPrunedTerminalRepairBeforeFrontier(t *testing.T) {
	ctx := context.Background()
	f := newWiringFixtureWithLimits(t, 6, configuredprogress.JournalLimits{Candidates: 6, Observations: 20, Bytes: 16 << 20})
	copies := map[string]*archive.Store{}
	for _, name := range []string{"first", "second"} {
		s, err := archive.Open(t.TempDir())
		require.NoError(t, err)
		copies[peer.ID(name).String()] = s
		for i := range f.entries {
			q, r := f.record(t, i)
			require.NoError(t, s.Put(q, r))
		}
	}
	pair := [2]peer.ID{"first", "second"}
	policy := frontier.Policy{Context: f.subject, Replicas: [2]string{pair[0].String(), pair[1].String()},
		Binding: CertifiedBinding{Context: f.context, Subject: f.subject}, Availability: fixtureAvailability{copies}}
	require.NoError(t, f.store.EnableFrontier(ctx, f.context, f.limits, policy))
	var tip configuredprogress.JournalEntry
	var old configuredprogress.JournalEntry
	for _, e := range f.entries {
		if e.Candidate.Number == 6 {
			tip = e
		}
		if e.Candidate.Number == 2 {
			old = e
		}
	}
	require.NotNil(t, old.ResultingUC)
	worker := &FrontierWorker{Journal: f.store, Context: f.context, Limits: f.limits, Archive: copies[peer.ID("first").String()], Subject: f.subject,
		Replicas: pair, Finalized: func(context.Context) (shardnode.BlockRef, error) {
			return shardnode.BlockRef{Number: tip.Candidate.Number, Hash: tip.Candidate.Hash}, nil
		}}
	require.NoError(t, worker.Pass(ctx))
	require.NoError(t, worker.Pass(ctx))
	// Keep producing and pruning under the same six-candidate cap, as a long-lived validator does.
	all := append([]configuredprogress.JournalEntry(nil), f.entries...)
	for number := uint64(7); number <= 12; number++ {
		next := unobservedSuccessor(t, f, tip, number)
		require.NoError(t, f.store.PutJournalCandidate(ctx, f.context, f.limits, next.Candidate))
		o, err := rootinput.AuthenticateObservationV2(ctx, f.context.Observation, next.ResultingUC, next.ResultingTR)
		require.NoError(t, err)
		p, _, err := f.store.PrepareObservation(ctx, f.context, o)
		require.NoError(t, err)
		_, _, err = f.store.CommitObservation(p)
		require.NoError(t, err)
		tip = next
		all = append(all, tip)
		q, r, err := FromJournal(ctx, f.context, f.subject, nil, tip)
		require.NoError(t, err)
		for _, a := range copies {
			require.NoError(t, a.Put(q, r))
		}
		require.NoError(t, worker.Pass(ctx))
	}
	pruned, err := f.store.LoadJournal(ctx, f.context, f.limits)
	require.NoError(t, err)
	require.NotNil(t, pruned.Frontier)
	anchorHeight := pruned.Frontier.Anchor.Height
	require.Greater(t, anchorHeight, uint64(old.Candidate.Number), "the old terminal is below the frontier anchor")
	hot := len(pruned.Candidates)
	require.NoError(t, f.store.Close())

	reopened, err := configuredprogress.OpenConfiguredV2(f.path, configuredprogress.Settings{Retain: 16})
	require.NoError(t, err)
	defer reopened.Close()
	_, _, err = reopened.Initialize(ctx, f.context)
	require.NoError(t, err)
	require.NoError(t, reopened.EnableJournal(ctx, f.context, f.limits))
	// The discharge is authenticated evidence: without the enabled frontier it is refused, never guessed from the raw bytes.
	_, err = reopened.LoadTerminalDischarge(ctx, f.context, f.limits)
	require.ErrorIs(t, err, configuredprogress.ErrSettings)
	require.NoError(t, reopened.EnableFrontier(ctx, f.context, f.limits, policy))

	// Control: the covered body cannot be inserted once the frontier is enabled, so the repair must skip it rather than retry it.
	candidate := old.Candidate
	candidate.LocallyBuilt = false
	require.ErrorIs(t, reopened.PutHistoricalCertifiedJournalCandidate(ctx, f.context, f.limits, candidate, old.ResultingUC, old.ResultingTR), configuredprogress.ErrConflict)

	discharge, err := reopened.LoadTerminalDischarge(ctx, f.context, f.limits)
	require.NoError(t, err)
	for _, e := range all {
		covered := e.Candidate.Number <= anchorHeight
		require.Equal(t, covered, discharge.Covers(e.ResultingUC), "height %d", e.Candidate.Number)
		repaired, err := repairTerminal(ctx, reopened, f.context, f.limits, discharge, e)
		require.NoError(t, err, "height %d", e.Candidate.Number)
		require.Equal(t, !covered, repaired, "a covered terminal at height %d is skipped, not repaired", e.Candidate.Number)
	}
	after, err := reopened.LoadJournal(ctx, f.context, f.limits)
	require.NoError(t, err)
	require.Len(t, after.Candidates, hot, "no pruned body is resurrected and the cap is not reached")

	// A terminal the frontier does not cover yet and whose body is missing is still repaired.
	missing := unobservedSuccessor(t, f, tip, 13)
	require.False(t, discharge.Covers(missing.ResultingUC))
	repaired, err := repairTerminal(ctx, reopened, f.context, f.limits, discharge, missing)
	require.NoError(t, err)
	require.True(t, repaired)
	final, err := reopened.LoadJournal(ctx, f.context, f.limits)
	require.NoError(t, err)
	var present bool
	for _, e := range final.Candidates {
		present = present || bytes.Equal(e.Candidate.Hash, missing.Candidate.Hash)
	}
	require.True(t, present, "the not-yet-covered terminal body is retained")
}

// After a restore the journal holds only the verified base, which already covers the whole replayed history: repairing the handoff
// terminals below it must neither refill the three-candidate journal (ErrBounds) nor retain any body, while a terminal beyond the base
// is still repaired.
func TestAuditRestoreTerminalHistoryExceedsTheHotJournalCap(t *testing.T) {
	ctx := context.Background()
	f := newRetryRestoreFixture(t, 0, FetchRetry{})
	require.NoError(t, f.restore.Restore(ctx), "bounded replay itself succeeds for five blocks with a three-candidate cap")
	image, err := f.journal.LoadJournal(ctx, f.wf.context, f.limits)
	require.NoError(t, err)
	require.NotNil(t, image.RestoreBase)
	require.EqualValues(t, 5, image.RestoreBase.Height)
	hot := len(image.Candidates)

	discharge, err := f.journal.LoadTerminalDischarge(ctx, f.wf.context, f.limits)
	require.NoError(t, err)
	var last configuredprogress.JournalEntry
	for _, e := range f.wf.entries {
		require.True(t, discharge.Covers(e.ResultingUC), "height %d is covered by the restore base", e.Candidate.Number)
		repaired, err := repairTerminal(ctx, f.journal, f.wf.context, f.limits, discharge, e)
		require.NoError(t, err)
		require.False(t, repaired)
		if e.Candidate.Number == 5 {
			last = e
		}
	}
	after, err := f.journal.LoadJournal(ctx, f.wf.context, f.limits)
	require.NoError(t, err)
	require.Len(t, after.Candidates, hot)

	missing := unobservedSuccessor(t, f.wf, last, 6)
	require.False(t, discharge.Covers(missing.ResultingUC))
	repaired, err := repairTerminal(ctx, f.journal, f.wf.context, f.limits, discharge, missing)
	require.NoError(t, err)
	require.True(t, repaired)

	// Control: without the discharge the same repair of the historical terminals exhausts the cap.
	var bounded bool
	for _, e := range f.wf.entries {
		if e.Candidate.Number < 2 || e.Candidate.Number > 4 {
			continue // below the genesis-adjacent block and not the retained base body itself
		}
		candidate := e.Candidate
		candidate.LocallyBuilt = false
		if err := f.journal.PutHistoricalCertifiedJournalCandidate(ctx, f.wf.context, f.limits, candidate, e.ResultingUC, e.ResultingTR); err != nil {
			require.ErrorIs(t, err, configuredprogress.ErrBounds)
			bounded = true
			break
		}
	}
	require.True(t, bounded, "unfiltered repair of the historical terminals would hit ErrBounds")
}
