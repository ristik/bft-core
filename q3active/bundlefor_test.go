package q3active_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3process"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
)

// evidenceOf is what consensus.Q3ActivationEvidence hands over: the fixture's link without the claim the history derives.
func evidenceOf(f *q3fixture.Fixture) (q3format.Link, []byte) {
	l := f.Link
	l.Claim = q3format.Claim{}
	return l, f.Candidate
}

func TestBundleForAssemblesTheActivationTheHistoryAuthenticates(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{Assignment: true})
	p := q3process.New(t, f)
	rt := p.Start()
	link, candidate := evidenceOf(f)

	b, err := rt.BundleFor(link, f.Snapshot, candidate)
	require.NoError(t, err)
	_, env, err := q3active.DecodeBundle(mustEncode(t, b))
	require.NoError(t, err)
	require.Len(t, env.Links, 1)
	require.Equal(t, f.Claim, env.Links[0].Claim, "the claim is the history's derivation, not the caller's")
	require.Equal(t, f.Candidate, b.Candidate)

}

func TestAnAssembledBundleInstallsThroughTheJournalAndIsThenServedAsStaged(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	p := q3process.New(t, f)
	rt := p.Start()
	link, candidate := evidenceOf(f)
	b, err := rt.BundleFor(link, f.Snapshot, candidate)
	require.NoError(t, err)
	require.NoError(t, rt.Recover(context.Background()))
	require.NoError(t, rt.Activate(context.Background(), b))
	require.NoError(t, rt.Admit(f.Claim.Epoch))

	again, err := rt.BundleFor(link, f.Snapshot, candidate)
	require.NoError(t, err)
	require.Equal(t, mustEncode(t, b), mustEncode(t, again), "once staged, the journal's own bundle is what is served")
}

func TestBundleForRefusesWhatTheHistoryDoesNotAuthenticate(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	for name, tc := range map[string]struct {
		mutate func(*q3format.Link)
		want   error
	}{
		"a commit proof that is not a proof":    {func(l *q3format.Link) { l.Proof = []byte("not a proof") }, q3format.ErrFormat},
		"a receipt set that misses a member":    {func(l *q3format.Link) { l.Receipts = l.Receipts[:len(l.Receipts)-1] }, q3format.ErrReceiptMissing},
		"another frozen parent in the evidence": {func(l *q3format.Link) { l.Evidence.FrozenParent = append([]byte{9}, l.Evidence.FrozenParent...) }, q3format.ErrBinding},
	} {
		p := q3process.New(t, f)
		rt := p.Start()
		link, candidate := evidenceOf(f)
		tc.mutate(&link)
		_, err := rt.BundleFor(link, f.Snapshot, candidate)
		require.ErrorIs(t, err, tc.want, name)
	}
}

func TestBundleForChainsTheLineageOfEarlierActivations(t *testing.T) {
	first := q3fixture.New(t, q3fixture.Options{})
	second := q3fixture.New(t, q3fixture.Options{After: first})
	p := q3process.New(t, first)
	rt := p.Start()
	l1, c1 := evidenceOf(first)
	b1, err := rt.BundleFor(l1, first.Snapshot, c1)
	require.NoError(t, err)
	require.NoError(t, rt.Recover(context.Background()))
	require.NoError(t, rt.Activate(context.Background(), b1))

	l2, c2 := evidenceOf(second)
	b2, err := rt.BundleFor(l2, second.Snapshot, c2)
	require.NoError(t, err)
	_, env, err := q3active.DecodeBundle(mustEncode(t, b2))
	require.NoError(t, err)
	require.Len(t, env.Links, 2, "the second activation's envelope retains the first")
	require.EqualValues(t, 2, env.Links[0].Body.Epoch)
	require.EqualValues(t, 3, env.Links[1].Body.Epoch)
}

func mustEncode(t *testing.T, b q3active.Bundle) []byte {
	t.Helper()
	raw, err := q3active.EncodeBundle(b)
	require.NoError(t, err)
	return raw
}
