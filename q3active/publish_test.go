package q3active

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3format"
)

func snapshotOf(epoch uint64, record byte) *Snapshot {
	s := &Snapshot{claim: q3format.Claim{Epoch: epoch}}
	s.claim.CommitID[0] = record
	return s
}

func TestASnapshotMayOnlyBeSupersededForward(t *testing.T) {
	require.NoError(t, supersedes(nil, snapshotOf(2, 1)), "the first snapshot")
	require.NoError(t, supersedes(snapshotOf(2, 1), snapshotOf(2, 1)), "the same record again")
	require.NoError(t, supersedes(snapshotOf(2, 1), snapshotOf(3, 9)), "a later epoch")
	require.ErrorIs(t, supersedes(snapshotOf(3, 1), snapshotOf(2, 1)), ErrRegress, "an earlier epoch")
	require.ErrorIs(t, supersedes(snapshotOf(2, 1), snapshotOf(2, 2)), ErrRegress, "another record of the same epoch")
}

// publish is the last install step: it publishes an activation only, and never another record over a published one.
func TestPublishRefusesAnEntryThatIsNotAnActivationAndAnotherRecordOfThePublishedEpoch(t *testing.T) {
	a, b := q3fixture.New(t, q3fixture.Options{}), q3fixture.New(t, q3fixture.Options{})
	entry := func(f *q3fixture.Fixture) (activated, genesis q3format.Entry) {
		h, err := q3format.NewHistory(f.Old)
		require.NoError(t, err)
		next, err := h.VerifyEnvelope(f.Envelope)
		require.NoError(t, err)
		return next.Tip(), h.Tip()
	}
	first, genesis := entry(a)
	other, _ := entry(b)
	require.NotEqual(t, first.Claim(), other.Claim())

	r := &Runtime{}
	require.ErrorIs(t, r.publish(genesis), ErrHistory, "a legacy entry is no activation")
	require.ErrorIs(t, r.publish(q3format.Entry{}), ErrHistory)
	require.Nil(t, r.Snapshot())
	require.NoError(t, r.publish(first))
	require.Nil(t, r.Snapshot(), "a provisional snapshot is not served before its epoch is complete")
	require.NoError(t, r.publish(first), "the same record again, after a restart")
	require.ErrorIs(t, r.publish(other), ErrRegress)
	require.Equal(t, first.Claim(), r.snap.Load().Claim(), "the provisional handle was not replaced")
	r.complete(first.Epoch())
	require.Equal(t, first.Claim(), r.Snapshot().Claim(), "served once the epoch is complete")
}
