package shardnode

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/types"
)

/*
Serving integration: the buffer is fed by the node's own certificate path.

What this fixes is the gap the design record's §6.1 named — a peer could verify the chain and had
nothing to serve — and it is wired at the one place where a certificate and the technical record
bound to it arrive together, already authenticated. Everything asserted here is provider-side. No
round outcome changes with a buffer attached, and nothing here recovers anything: using somebody
else's buffer to repair this node's own anchor is a separate decision.
*/

// headlessExecutor fails at the first fallible step of HandleCertificate, so the certificate is
// observed and the round then fails. It exists to pin the ordering, not the failure.
type headlessExecutor struct{ err error }

func (e *headlessExecutor) Head(context.Context) (BlockRef, error) {
	return BlockRef{}, e.err
}
func (e *headlessExecutor) GenesisBlock(context.Context) (BlockRef, error) {
	return BlockRef{Number: 0, Hash: []byte{0x00}, StateRoot: []byte{0x00}}, nil
}
func (e *headlessExecutor) Commit(context.Context, Hash) (Status, error) { return StatusValid, nil }
func (e *headlessExecutor) Build(context.Context, RoundParams) (BuildID, error) {
	return "", errors.New("headless")
}
func (e *headlessExecutor) Seal(context.Context, BuildID) (Block, error) {
	return Block{}, errors.New("headless")
}
func (e *headlessExecutor) Verify(context.Context, Block, RoundParams) (Status, error) {
	return StatusValid, nil
}

func servingRound(t *testing.T, exec Executor) (*Round, *EvidenceBuffer) {
	t.Helper()
	b := newTestBuffer(t)
	r := NewRound("provider-node", evidencePartitionID, types.ShardID{}, exec, NewLoopbackDisseminator(), nil, nil, nil)
	r.SetEvidenceBuffer(b)
	return r, b
}

func TestRound_FeedsTheEvidenceBuffer(t *testing.T) {
	ctx := context.Background()

	t.Run("what the node handles is what it can serve", func(t *testing.T) {
		f := newEvidenceFixture(t)
		obs := quietTailObserved(t, f)
		r, b := servingRound(t, &headlessExecutor{err: errors.New("no executor in this test")})

		for _, l := range obs {
			// Each round fails at the executor; the certificate is observed regardless.
			require.Error(t, r.HandleCertificate(ctx, l.UC, l.Technical))
		}

		count, from, to := b.Retained()
		require.Equal(t, len(obs), count)
		require.EqualValues(t, 10, from)
		require.EqualValues(t, 21, to)

		// End to end, from the node's own certificate path to a chain the predicate accepts.
		held := obs[2].UC
		ev, err := exchange(t, testServer(t, b), requestFor(t, held), DefaultEvidenceTransportLimits)
		require.NoError(t, err)
		anchor, err := verifyAssembled(t, f, ev, held)
		require.NoError(t, err)
		require.Equal(t, Hash(h32(0xbb)), anchor.BlockHash)
	})

	t.Run("retention survives a round that fails to apply", func(t *testing.T) {
		// The same ordering the anchor itself depends on (§5): a certificate that names a block is
		// retained when it VERIFIES, not when this node manages to act on it. Otherwise a transient
		// executor failure would also erase this node's ability to help anybody else.
		f := newEvidenceFixture(t)
		source := f.cert(10, 100, h32(0x0a), h32(0x0b), h32(0xbb), 12)
		r, b := servingRound(t, &headlessExecutor{err: errors.New("executor unreachable")})

		err := r.HandleCertificate(ctx, source.UC, source.Technical)
		require.Error(t, err)
		require.True(t, b.Ready(), "the block was certified and observed; that this node stumbled afterwards is a different fact")
	})

	t.Run("a node without a buffer runs exactly as before", func(t *testing.T) {
		f := newEvidenceFixture(t)
		obs := quietTailObserved(t, f)
		exec := &headlessExecutor{err: errors.New("no executor in this test")}
		with, _ := servingRound(t, exec)
		without := NewRound("plain-node", evidencePartitionID, types.ShardID{}, exec, NewLoopbackDisseminator(), nil, nil, nil)

		for _, l := range obs {
			a := with.HandleCertificate(ctx, l.UC, l.Technical)
			c := without.HandleCertificate(ctx, l.UC, l.Technical)
			require.Equal(t, c == nil, a == nil, "the buffer must not change a round's outcome")
		}
	})

	t.Run("an observation the buffer refuses does not fail the round", func(t *testing.T) {
		// Retention is an availability property of OTHER nodes' recovery. A buffer that will not
		// stand behind what it was handed says so in the log and the round carries on; the round's
		// own certificate handling is unaffected either way.
		f := newEvidenceFixture(t)
		source := f.cert(10, 100, h32(0x0a), h32(0x0b), h32(0xbb), 12)
		r, b := servingRound(t, &headlessExecutor{err: errors.New("executor unreachable")})

		unbound := *source.Technical
		unbound.Round = 99 // a technical record this certificate does not commit to
		require.ErrorIs(t, b.Observe(source.UC, &unbound), ErrObservationRejected)

		before := r.HandleCertificate(ctx, source.UC, &unbound)
		count, _, _ := b.Retained()
		require.Zero(t, count, "nothing unbound is retained")
		require.Error(t, before, "the round still fails at the executor, for the executor's reason")
		require.NotErrorIs(t, before, ErrObservationRejected)
	})
}
