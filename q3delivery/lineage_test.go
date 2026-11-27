package q3delivery

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3process"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
)

// lineageEpochs is the tip epoch of the long-chain tests: Q3_LINEAGE_EPOCHS, or 300 (four and a half times what one envelope may carry).
func lineageEpochs(t *testing.T) uint64 {
	t.Helper()
	n := uint64(300)
	if s := os.Getenv("Q3_LINEAGE_EPOCHS"); s != "" {
		v, err := strconv.ParseUint(s, 10, 64)
		require.NoError(t, err)
		n = v
	}
	require.Greater(t, n, uint64(q3format.MaxLinks+2), "the chain must outgrow one envelope")
	return n
}

// lineageChain is a root-only activation chain of epochs 2..tip, every fixture authenticated by the previous one's committee. chain[i] is
// the activation of epoch i+2.
func lineageChain(t *testing.T, tip uint64) []*q3fixture.Fixture {
	t.Helper()
	chain := []*q3fixture.Fixture{q3fixture.New(t, q3fixture.Options{})}
	for e := uint64(3); e <= tip; e++ {
		chain = append(chain, q3fixture.New(t, q3fixture.Options{After: chain[len(chain)-1], LastLinkOnly: true}))
	}
	require.EqualValues(t, tip, chain[len(chain)-1].Claim.Epoch)
	return chain
}

// stagedOnly serves what the source's journal staged, as a root does once the roots have moved on past the epoch.
type stagedOnly struct{ rt *q3active.Runtime }

func (p stagedOnly) Q3Bundle(_ context.Context, epoch uint64) (q3active.Bundle, error) {
	b, ok, err := p.rt.StagedBundle(epoch)
	if err != nil {
		return q3active.Bundle{}, err
	}
	if !ok {
		return q3active.Bundle{}, errors.New("not staged here")
	}
	return b, nil
}

// legacyBundle is the bundle an earlier version assembled for chain[i]: the whole lineage from epoch 2, which a journal staged before the
// fix holds. It fits in an envelope only while i < q3format.MaxLinks.
func legacyBundle(chain []*q3fixture.Fixture, i int) (q3active.Bundle, error) {
	f := chain[i]
	links := make([]q3format.Link, 0, i+1)
	for _, g := range chain[:i+1] {
		links = append(links, g.Link)
	}
	env := q3format.Envelope{RootInput: f.Proof.Record.Bytes(), TargetParent: f.Link.Evidence.FrozenParent, Links: links}
	raw, err := env.Encode()
	if err != nil {
		return q3active.Bundle{}, err
	}
	return q3active.Bundle{Envelope: raw, Snapshot: f.Snapshot}, nil
}

// An activation's bundle carries one link whatever the chain's length (#1035): a chain of several hundred epochs is assembled, served,
// fetched, verified and installed through the journal by a receiver that is up to date, one far behind, a fresh one starting from the pin,
// and one whose journal an earlier version staged with the whole lineage. Each restarts over its journal and rebuilds the same history.
func TestALongLineageTravelsOneEpochPerBundle(t *testing.T) {
	ctx := context.Background()
	tip := lineageEpochs(t)
	began := time.Now()
	chain := lineageChain(t, tip)
	t.Logf("fixtures for epochs 2..%d: %v", tip, time.Since(began).Round(time.Millisecond))

	// the source validator assembles every activation from its own evidence (BundleFor) and installs it through its journal
	began = time.Now()
	source := q3process.New(t, chain[0])
	src := source.Start()
	require.NoError(t, src.Recover(ctx))
	minSize, maxSize := 0, 0
	for _, f := range chain {
		l := f.Link
		l.Claim = q3format.Claim{} // the history derives the claim
		b, err := src.BundleFor(l, f.Snapshot, f.Candidate)
		require.NoError(t, err, "epoch %d", f.Claim.Epoch)
		raw, err := q3active.EncodeBundle(b)
		require.NoError(t, err)
		_, env, err := q3active.DecodeBundle(raw)
		require.NoError(t, err)
		require.Len(t, env.Links, 1, "epoch %d: the bundle carries the activating link only", f.Claim.Epoch)
		require.Equal(t, f.Claim, env.Links[0].Claim)
		if minSize == 0 || len(raw) < minSize {
			minSize = len(raw)
		}
		maxSize = max(maxSize, len(raw))
		require.NoError(t, src.Activate(ctx, b), "epoch %d", f.Claim.Epoch)
	}
	require.EqualValues(t, tip, src.ActiveEpoch())
	require.LessOrEqual(t, maxSize, 2*minSize, "a bundle does not grow with the chain")
	t.Logf("source assembled and installed epochs 2..%d: %v; bundle sizes %d..%d bytes", tip, time.Since(began).Round(time.Millisecond), minSize, maxSize)
	want, err := src.HistoryEntries()
	require.NoError(t, err)

	server, err := NewServer(stagedOnly{src})
	require.NoError(t, err)
	fetch := func(epoch uint64) q3active.Bundle {
		t.Helper()
		b, err := serveOnce(t, server, epoch)
		require.NoError(t, err, "fetch epoch %d", epoch)
		return b
	}
	// catchUp is what installQ3Epochs and the Q3 follower do: the next epoch after the receiver's own verified one, in order, to target
	catchUp := func(rt *q3active.Runtime, target uint64) {
		t.Helper()
		for epoch := max(rt.ActiveEpoch(), 1) + 1; epoch <= target; epoch++ {
			require.NoError(t, rt.Activate(ctx, fetch(epoch)), "install epoch %d", epoch)
			require.NoError(t, rt.Admit(epoch))
		}
		require.EqualValues(t, target, rt.ActiveEpoch())
	}
	// restart rebuilds the runtime over the journal: the history from the pin and every staged bundle, then the recovery pass
	restart := func(p *q3process.Process) *q3active.Runtime {
		t.Helper()
		began := time.Now()
		rt := p.Start()
		require.NoError(t, rt.Recover(ctx))
		t.Logf("restart at epoch %d: %v", rt.History().Tip().Epoch(), time.Since(began).Round(time.Millisecond))
		return rt
	}
	same := func(rt *q3active.Runtime) {
		t.Helper()
		got, err := rt.HistoryEntries()
		require.NoError(t, err)
		require.Equal(t, want, got, "the receiver's history is the source's")
	}

	t.Run("a fresh receiver starting from the pin", func(t *testing.T) {
		p := q3process.New(t, chain[0])
		rt := p.Start()
		require.NoError(t, rt.Recover(ctx))
		require.EqualValues(t, 1, rt.History().Tip().Epoch(), "nothing but the pin")
		began := time.Now()
		catchUp(rt, tip)
		t.Logf("fresh receiver installed epochs 2..%d: %v", tip, time.Since(began).Round(time.Millisecond))
		same(rt)
		rt = restart(p)
		require.NoError(t, rt.Admit(tip))
		same(rt)
	})

	t.Run("a receiver far behind", func(t *testing.T) {
		p := q3process.New(t, chain[0])
		rt := p.Start()
		require.NoError(t, rt.Recover(ctx))
		catchUp(rt, 10)
		rt = restart(p)

		// the network's tip is not something it can verify yet: it is told what it lacks, and stages nothing
		require.ErrorIs(t, rt.Activate(ctx, fetch(tip)), q3format.ErrMissingHistory)
		_, ok, err := rt.StagedBundle(tip)
		require.NoError(t, err)
		require.False(t, ok)

		began := time.Now()
		catchUp(rt, tip)
		t.Logf("receiver at epoch 10 installed epochs 11..%d: %v", tip, time.Since(began).Round(time.Millisecond))
		same(rt)
		rt = restart(p)
		require.NoError(t, rt.Admit(tip))
		same(rt)
	})

	t.Run("an up-to-date receiver", func(t *testing.T) {
		p := q3process.New(t, chain[0])
		rt := p.Start()
		require.NoError(t, rt.Recover(ctx))
		catchUp(rt, tip-1)
		rt = restart(p)

		b := fetch(tip)
		raw, err := q3active.EncodeBundle(b)
		require.NoError(t, err)
		_, env, err := q3active.DecodeBundle(raw)
		require.NoError(t, err)
		require.Len(t, env.Links, 1, "the delta of a receiver one epoch behind is one link")
		require.NoError(t, rt.Activate(ctx, b))
		require.NoError(t, rt.Admit(tip))
		same(rt)
		rt = restart(p)
		same(rt)
	})

	t.Run("a journal staged with the whole lineage by an earlier version", func(t *testing.T) {
		// an earlier version staged every activation with the whole lineage, and could do so up to the epoch whose lineage is
		// q3format.MaxLinks links (epoch 65); the next one did not fit, which is where such a network stopped handing off
		last := q3format.MaxLinks - 1
		_, err := legacyBundle(chain, last+1)
		require.Error(t, err, "the whole lineage of epoch %d does not fit in an envelope", chain[last+1].Claim.Epoch)

		p := q3process.New(t, chain[0])
		rt := p.Start()
		require.NoError(t, rt.Recover(ctx))
		for i := 0; i <= last; i++ {
			b, err := legacyBundle(chain, i)
			require.NoError(t, err)
			require.NoError(t, rt.Activate(ctx, b), "legacy epoch %d", chain[i].Claim.Epoch)
		}
		require.EqualValues(t, chain[last].Claim.Epoch, rt.ActiveEpoch())

		// the upgraded process replays that journal, serves its staged bundles as they are, and continues one link per epoch
		rt = restart(p)
		staged, ok, err := rt.StagedBundle(chain[last].Claim.Epoch)
		require.NoError(t, err)
		require.True(t, ok)
		raw, err := q3active.EncodeBundle(staged)
		require.NoError(t, err)
		_, env, err := q3active.DecodeBundle(raw)
		require.NoError(t, err)
		require.Len(t, env.Links, q3format.MaxLinks, "a legacy bundle is served as it was staged")

		began := time.Now()
		catchUp(rt, tip)
		t.Logf("legacy journal at epoch %d installed epochs %d..%d: %v", chain[last].Claim.Epoch, chain[last].Claim.Epoch+1, tip,
			time.Since(began).Round(time.Millisecond))
		same(rt)
		rt = restart(p)
		require.NoError(t, rt.Admit(tip))
		same(rt)
	})

	t.Run("a legacy bundle from a peer that is not upgraded", func(t *testing.T) {
		// a receiver one epoch behind accepts the whole-lineage bundle an earlier version serves, while it fits
		last := q3format.MaxLinks - 1
		p := q3process.New(t, chain[0])
		rt := p.Start()
		require.NoError(t, rt.Recover(ctx))
		catchUp(rt, chain[last-1].Claim.Epoch)
		b, err := legacyBundle(chain, last)
		require.NoError(t, err)
		require.NoError(t, rt.Activate(ctx, b))
		catchUp(rt, chain[last+1].Claim.Epoch)
		rt = restart(p)
		require.EqualValues(t, chain[last+1].Claim.Epoch, rt.History().Tip().Epoch())
	})
}
