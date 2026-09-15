package certifiedstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// recordFor is the verified record for b, a block executed on parent, certified at b's round.
func (f *fixture) recordFor(b, parent block) Record {
	ir := &types.InputRecord{
		Version: 1, RoundNumber: b.Round, Epoch: 0, Hash: b.StateRoot.Bytes(), PreviousHash: parent.StateRoot.Bytes(),
		BlockHash: b.Hash.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_000 + b.Round,
	}
	tr := technicalFor(b.Round)
	return Record{
		BlockHash: b.Hash, BlockNumber: b.Number, StateRoot: b.StateRoot, PartitionRound: b.Round,
		Certificate: f.certify(f.signer, ir, tr, 4+b.Round), Technical: tr, Witness: b.Evidence,
	}
}

// TestPublishNeverReplacesALaterHead is the store half of W2's stale-completion rule: a publication that
// completes late or out of order is refused inside the transaction and changes nothing.
func TestPublishNeverReplacesALaterHead(t *testing.T) {
	f := newFixture(t, 3)
	cases := map[string]func() Record{
		"a record of an earlier round": func() Record { return f.record(2) },
		"another block for the head's round": func() Record {
			return f.recordFor(f.executedWith(f.blocks[2], 3, 7, []byte("another block at round 3")), f.blocks[2])
		},
		"the genesis record over an ordinary head": func() Record { return f.record(0) },
		// Quiet genesis history can advance the genesis certificate's round past the head's, so the
		// round comparison alone would let this through.
		"the genesis record with its certificate round advanced past the head's": func() Record {
			return f.recordWith(0, func(ir *types.InputRecord, tr *certification.TechnicalRecord, r *Record) {
				ir.RoundNumber, tr.Round, r.PartitionRound = 9, 10, 9
			})
		},
	}
	for name, record := range cases {
		t.Run(name, func(t *testing.T) {
			s := f.open(tempDB(t), 8)
			f.publishChain(s, 3)
			r := record()
			require.NotEqual(t, recordKey(f.record(3)), recordKey(r), "premise: not the head record")
			before := contents(t, s)
			err := s.Publish(context.Background(), f.ctx, r)
			require.ErrorIs(t, err, ErrStaleRecord)
			require.Equal(t, before, contents(t, s), "a refused publication changes nothing")
			l, err := s.Load(context.Background(), f.ctx)
			require.NoError(t, err)
			require.Equal(t, f.blocks[3].Hash, l.BlockHash())
		})
	}

	t.Run("republishing the head and publishing a later round are allowed", func(t *testing.T) {
		s := f.open(tempDB(t), 8)
		f.publishChain(s, 2)
		require.NoError(t, s.Publish(context.Background(), f.ctx, f.record(2)))
		require.NoError(t, s.Publish(context.Background(), f.ctx, f.record(3)))
		l, err := s.Load(context.Background(), f.ctx)
		require.NoError(t, err)
		require.Equal(t, f.blocks[3].Hash, l.BlockHash())
	})

	t.Run("an ordinary record over the genesis head, skipping rounds", func(t *testing.T) {
		s := f.open(tempDB(t), 8)
		require.NoError(t, s.Publish(context.Background(), f.ctx, f.record(0)))
		require.NoError(t, s.Publish(context.Background(), f.ctx, f.record(2)))
		l, err := s.Load(context.Background(), f.ctx)
		require.NoError(t, err)
		require.Equal(t, f.blocks[2].Hash, l.BlockHash())
	})

	t.Run("a head that names no record key is not overwritten", func(t *testing.T) {
		s := f.open(tempDB(t), 8)
		f.publishChain(s, 2)
		putRaw(t, s, string(headKey), []byte("record/not-a-round"))
		before := contents(t, s)
		err := s.Publish(context.Background(), f.ctx, f.record(3))
		require.ErrorIs(t, err, ErrRecordUntrusted)
		require.Equal(t, before, contents(t, s))
	})
}
