package q3active_test

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3process"
	"github.com/unicitynetwork/bft-core/q3active"
)

func TestTheActivationRecordReportsTheOldCommitteesSignersAndWeights(t *testing.T) {
	ctx := context.Background()
	f := q3fixture.New(t, q3fixture.Options{})
	p := q3process.New(t, f)
	rt := p.Start()
	require.NoError(t, rt.Recover(ctx))

	_, err := rt.ActivationRecord(f.Claim.Epoch)
	require.ErrorIs(t, err, q3active.ErrNoActivation, "nothing is staged before the activation")

	require.NoError(t, rt.Activate(ctx, p.Bundle()))
	rec, err := rt.ActivationRecord(f.Claim.Epoch)
	require.NoError(t, err)
	require.Equal(t, f.Claim.Epoch, rec.Epoch)
	require.EqualValues(t, 2, rec.SigningScheme, "the activated epoch's scheme")
	require.Equal(t, hex.EncodeToString(f.Claim.BodyID[:]), rec.V3BodyID)
	require.Equal(t, f.Claim.Start, rec.ActivationRound)
	require.GreaterOrEqual(t, rec.ActivationRound, rec.MinActivationRound, "A* >= A_min")
	require.Equal(t, hex.EncodeToString(f.Claim.CommitID[:]), rec.ActivationCommitID)

	// the commit is the OLD committee's: the unit genesis epoch, three signers of weight 1, threshold 3 of W=4
	require.EqualValues(t, 1, rec.Commit.Epoch)
	require.EqualValues(t, 1, rec.Commit.Scheme, "the old epoch signs under scheme 1")
	require.Len(t, rec.Commit.Signers, 3)
	for _, s := range rec.Commit.Signers {
		require.EqualValues(t, 1, s.Weight)
	}
	require.EqualValues(t, 3, rec.Commit.SignedTotal)
	require.EqualValues(t, 3, rec.Commit.Threshold)
	require.Equal(t, hex.EncodeToString(f.ProofBytes), rec.Commit.Proof)

	_, err = rt.ActivationRecord(f.Claim.Epoch + 1)
	require.ErrorIs(t, err, q3active.ErrNoActivation)
}

func TestTheSecondActivationsCommitIsReportedUnderTheWeightedEpoch(t *testing.T) {
	ctx := context.Background()
	first := q3fixture.New(t, q3fixture.Options{})
	second := q3fixture.New(t, q3fixture.Options{After: first})
	p := q3process.New(t, first)
	rt := p.Start()
	require.NoError(t, rt.Recover(ctx))
	require.NoError(t, rt.Activate(ctx, p.Bundle()))
	l2, c2 := evidenceOf(second)
	b2, err := rt.BundleFor(l2, second.Snapshot, c2)
	require.NoError(t, err)
	require.NoError(t, rt.Activate(ctx, b2))

	rec, err := rt.ActivationRecord(second.Claim.Epoch)
	require.NoError(t, err)
	require.EqualValues(t, 2, rec.Commit.Epoch, "signed by the first activation's committee")
	require.EqualValues(t, 2, rec.Commit.Scheme, "under scheme 2")
	var total uint64
	for _, s := range rec.Commit.Signers {
		total += s.Weight
	}
	require.Equal(t, total, rec.Commit.SignedTotal)
	require.GreaterOrEqual(t, rec.Commit.SignedTotal, rec.Commit.Threshold, "the weighted quorum: heavy plus one light is 7 of 9")
	require.EqualValues(t, 7, rec.Commit.Threshold)
}

func TestTheHistoryEntriesAreTheVerifiedChainFromTheGenesis(t *testing.T) {
	ctx := context.Background()
	first := q3fixture.New(t, q3fixture.Options{})
	second := q3fixture.New(t, q3fixture.Options{After: first})
	p := q3process.New(t, first)
	rt := p.Start()
	require.NoError(t, rt.Recover(ctx))

	es, err := rt.HistoryEntries()
	require.NoError(t, err)
	require.Len(t, es, 1, "the genesis alone")
	require.EqualValues(t, 1, es[0].Epoch)
	require.Empty(t, es[0].CommitID, "the genesis has no activation commit")

	require.NoError(t, rt.Activate(ctx, p.Bundle()))
	l2, c2 := evidenceOf(second)
	b2, err := rt.BundleFor(l2, second.Snapshot, c2)
	require.NoError(t, err)
	require.NoError(t, rt.Activate(ctx, b2))
	es, err = rt.HistoryEntries()
	require.NoError(t, err)
	require.Len(t, es, 3)
	for i, e := range es {
		require.EqualValues(t, i+1, e.Epoch)
	}
	require.EqualValues(t, 1, es[0].Scheme)
	require.EqualValues(t, 2, es[1].Scheme)
	require.Equal(t, hex.EncodeToString(first.Claim.BodyID[:]), es[1].BodyID)
	require.Equal(t, hex.EncodeToString(second.Claim.CommitID[:]), es[2].CommitID)
}
