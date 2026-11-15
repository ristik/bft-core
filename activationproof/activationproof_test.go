package activationproof_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/activationproof"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3active"
)

// A lineage is persistent: an extension copies nothing of the lineage it extends, leaves it as it was, and every epoch's trust stays
// reachable from the tip. The per-extension time is logged for a chain of successive activations (the measurement astra asked for on
// #1087; the history's own envelope verification grows with the links a bundle carries).
func TestALongLineageExtendsWithoutCopyingAndKeepsEveryEpoch(t *testing.T) {
	const epochs = 10
	chain := []*q3fixture.Fixture{q3fixture.New(t, q3fixture.Options{})}
	for len(chain) < epochs-1 {
		chain = append(chain, q3fixture.New(t, q3fixture.Options{After: chain[len(chain)-1]}))
	}
	l, err := activationproof.NewLineage(chain[0].Old, chain[0].UTB)
	require.NoError(t, err)
	lineages := []*activationproof.Lineage{l}
	for _, f := range chain {
		raw, err := q3active.EncodeBundle(q3active.Bundle{Envelope: f.EnvelopeBytes, Snapshot: f.Snapshot, Candidate: f.Candidate})
		require.NoError(t, err)
		start := time.Now()
		next, step, err := l.Extend(raw)
		require.NoError(t, err)
		t.Logf("epoch %d: extend %s (%d bytes)", step.Epoch, time.Since(start), len(raw))
		require.False(t, step.Replay)
		require.Equal(t, l.Tip()+1, next.Tip())
		lineages = append(lineages, next)
		l = next
	}
	require.EqualValues(t, epochs, l.Tip())
	for i, old := range lineages {
		require.EqualValues(t, i+1, old.Tip(), "an extension leaves the lineage it extends as it was")
	}
	for epoch := uint64(1); epoch <= epochs; epoch++ {
		tb, err := l.Trust(epoch)
		require.NoError(t, err)
		require.Equal(t, epoch, tb.Epoch)
	}
	_, err = l.Trust(epochs + 1)
	require.ErrorIs(t, err, activationproof.ErrLineage)
}

// activationproof decodes the root's bundle itself (the signing authority must not depend on the root's install runtime, whose stores
// import the consensus storage); the two decoders accept the same bytes and the same contents.
func TestTheBundleDecodersAgree(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{Assignment: true})
	raw, err := q3active.EncodeBundle(q3active.Bundle{Envelope: f.EnvelopeBytes, Snapshot: f.Snapshot, Candidate: f.Candidate})
	require.NoError(t, err)
	a, envA, err := activationproof.DecodeBundle(raw)
	require.NoError(t, err)
	b, envB, err := q3active.DecodeBundle(raw)
	require.NoError(t, err)
	require.Equal(t, b.Envelope, a.Envelope)
	require.Equal(t, b.Snapshot, a.Snapshot)
	require.Equal(t, b.Candidate, a.Candidate)
	require.Equal(t, len(envB.Links), len(envA.Links))
	for _, bad := range [][]byte{nil, raw[:len(raw)-1], append(append([]byte(nil), raw...), 0)} {
		_, _, errA := activationproof.DecodeBundle(bad)
		_, _, errB := q3active.DecodeBundle(bad)
		require.Equal(t, errB == nil, errA == nil, "the same bytes are refused by both")
	}
}
