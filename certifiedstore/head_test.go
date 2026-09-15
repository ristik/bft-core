package certifiedstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTheHeadKeyIsBoundToItsVerifiedRecord is P2 of the review of #162: the head key is unsigned storage
// metadata, so neither Load nor the publication decision reads anything from it. A head that is missing,
// unverifiable or stored under another key than its record's own is refused and not replaced.
func TestTheHeadKeyIsBoundToItsVerifiedRecord(t *testing.T) {
	ctx := context.Background()

	t.Run("an authentic record copied under an earlier round's key", func(t *testing.T) {
		f := newFixture(t, 3)
		s := f.open(tempDB(t), 8)
		f.publishChain(s, 3)
		raw := contents(t, s)[string(recordKey(f.record(3)))]
		alias := string(keyFor(3, 1, f.blocks[3].Hash.Bytes()))
		putRaw(t, s, alias, raw)
		putRaw(t, s, string(headKey), []byte(alias))
		before := contents(t, s)

		_, err := s.Load(ctx, f.ctx)
		require.ErrorIs(t, err, ErrRecordUntrusted, "the record verifies, but not as the record its key names")
		err = s.Publish(ctx, f.ctx, f.record(2))
		require.ErrorIs(t, err, ErrRecordUntrusted, "round 2 does not replace a head that verifies as round 3")
		require.NotErrorIs(t, err, ErrStaleRecord)
		require.Equal(t, before, contents(t, s))
	})

	t.Run("a head record that does not verify", func(t *testing.T) {
		f := newFixture(t, 3)
		s := f.open(tempDB(t), 8)
		f.publishChain(s, 2)
		k := string(recordKey(f.record(2)))
		raw := contents(t, s)[k]
		raw[len(raw)/2] ^= 0x01
		putRaw(t, s, k, raw)
		before := contents(t, s)

		err := s.Publish(ctx, f.ctx, f.record(3))
		require.ErrorIs(t, err, ErrRecordUntrusted)
		require.Equal(t, before, contents(t, s), "an unverifiable head is not replaced, even by a later round")
	})

	t.Run("a head naming a record that is not there", func(t *testing.T) {
		f := newFixture(t, 3)
		s := f.open(tempDB(t), 8)
		f.publishChain(s, 2)
		deleteRaw(t, s, string(recordKey(f.record(2))))
		before := contents(t, s)

		err := s.Publish(ctx, f.ctx, f.record(3))
		require.ErrorIs(t, err, ErrRecordUntrusted)
		require.Equal(t, before, contents(t, s))
	})

	t.Run("a head of another deployment", func(t *testing.T) {
		f := newFixture(t, 3)
		other := newFixtureFor(t, 4, 3)
		s := f.open(tempDB(t), 8)
		f.publishChain(s, 1)
		enc, _, err := encodeRecord(other.ctx, other.record(2))
		require.NoError(t, err)
		putRaw(t, s, string(recordKey(other.record(2))), enc)
		putRaw(t, s, string(headKey), recordKey(other.record(2)))
		before := contents(t, s)

		err = s.Publish(ctx, f.ctx, f.record(3))
		require.ErrorIs(t, err, ErrWrongContext)
		require.Equal(t, before, contents(t, s))
	})
}

// TestCommitRequiresTheHeadPrepareDecidedAgainst: a prepared record is committed only while the head is the
// one Prepare verified, so a decision cannot be applied to a store another publication has since changed.
func TestCommitRequiresTheHeadPrepareDecidedAgainst(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 3)

	t.Run("the head changed", func(t *testing.T) {
		s := f.open(tempDB(t), 8)
		f.publishChain(s, 1)
		p, err := s.Prepare(ctx, f.ctx, f.record(2))
		require.NoError(t, err)
		require.NoError(t, s.Publish(ctx, f.ctx, f.record(3)))
		before := contents(t, s)

		err = s.Commit(p)
		require.ErrorIs(t, err, ErrHeadChanged)
		require.Equal(t, before, contents(t, s))
		l, err := s.Load(ctx, f.ctx)
		require.NoError(t, err)
		require.Equal(t, f.blocks[3].Hash, l.BlockHash())
	})

	t.Run("the head is unchanged", func(t *testing.T) {
		s := f.open(tempDB(t), 8)
		f.publishChain(s, 1)
		p, err := s.Prepare(ctx, f.ctx, f.record(2))
		require.NoError(t, err)
		require.NoError(t, s.Commit(p))
		l, err := s.Load(ctx, f.ctx)
		require.NoError(t, err)
		require.Equal(t, f.blocks[2].Hash, l.BlockHash())
	})

	t.Run("the head was moved to an identical copy of its record under another key", func(t *testing.T) {
		s := f.open(tempDB(t), 8)
		f.publishChain(s, 1)
		p, err := s.Prepare(ctx, f.ctx, f.record(2))
		require.NoError(t, err)
		raw := contents(t, s)[string(recordKey(f.record(1)))]
		putRaw(t, s, "record/copy", raw)
		putRaw(t, s, string(headKey), []byte("record/copy"))
		before := contents(t, s)

		require.ErrorIs(t, s.Commit(p), ErrHeadChanged, "the same bytes under another name are another head")
		require.Equal(t, before, contents(t, s))
	})

	t.Run("the head record's bytes changed under the same key", func(t *testing.T) {
		s := f.open(tempDB(t), 8)
		f.publishChain(s, 1)
		p, err := s.Prepare(ctx, f.ctx, f.record(2))
		require.NoError(t, err)
		k := string(recordKey(f.record(1)))
		raw := contents(t, s)[k]
		raw[len(raw)/2] ^= 0x01
		putRaw(t, s, k, raw)
		before := contents(t, s)

		require.ErrorIs(t, s.Commit(p), ErrHeadChanged, "the same name over other bytes is another head")
		require.Equal(t, before, contents(t, s))
	})

	t.Run("an empty store gained a head", func(t *testing.T) {
		s := f.open(tempDB(t), 8)
		p, err := s.Prepare(ctx, f.ctx, f.record(1))
		require.NoError(t, err)
		require.NoError(t, s.Publish(ctx, f.ctx, f.record(0)))
		require.ErrorIs(t, s.Commit(p), ErrHeadChanged)
	})

	t.Run("a record prepared by another store", func(t *testing.T) {
		a, b := f.open(tempDB(t), 8), f.open(tempDB(t), 8)
		p, err := a.Prepare(ctx, f.ctx, f.record(0))
		require.NoError(t, err)
		require.ErrorIs(t, b.Commit(p), errPublishFailed)
		require.ErrorIs(t, b.Commit(Prepared{}), errPublishFailed)
		keys, err := b.Keys()
		require.NoError(t, err)
		require.Empty(t, keys)
	})
}
