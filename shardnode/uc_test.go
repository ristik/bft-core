package shardnode

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/types"
)

// uc builds a minimal UnicityCertificate sufficient for ClassifyUC, which
// only inspects InputRecord and UnicitySeal.RootChainRoundNumber — no
// signatures, shard tree, or unicity tree needed.
func uc(round, rootRound uint64, prevHash, hash, blockHash []byte) *types.UnicityCertificate {
	return &types.UnicityCertificate{
		Version: 1,
		InputRecord: &types.InputRecord{
			Version:      1,
			RoundNumber:  round,
			PreviousHash: prevHash,
			Hash:         hash,
			BlockHash:    blockHash,
			SummaryValue: []byte{},
			Timestamp:    1000,
		},
		UnicitySeal: &types.UnicitySeal{
			Version:              1,
			RootChainRoundNumber: rootRound,
			Timestamp:            1000,
		},
	}
}

func TestClassifyUC(t *testing.T) {
	h0 := []byte{0x00}
	h1 := []byte{0x01}
	h2 := []byte{0x02}
	blk1 := []byte{0xb1}
	blk2 := []byte{0xb2}

	t.Run("first UC ever seen is valid", func(t *testing.T) {
		class, err := ClassifyUC(nil, uc(1, 10, h0, h1, blk1))
		require.NoError(t, err)
		require.Equal(t, UCValid, class)
	})

	t.Run("next round extending certified state is valid", func(t *testing.T) {
		prev := uc(1, 10, h0, h1, blk1)
		next := uc(2, 11, h1, h2, blk2)
		class, err := ClassifyUC(prev, next)
		require.NoError(t, err)
		require.Equal(t, UCValid, class)
	})

	t.Run("same root round is a duplicate", func(t *testing.T) {
		prev := uc(1, 10, h0, h1, blk1)
		dup := uc(1, 10, h0, h1, blk1)
		class, err := ClassifyUC(prev, dup)
		require.NoError(t, err)
		require.Equal(t, UCDuplicate, class)
	})

	t.Run("same input record, later root round is a repeat (timeout)", func(t *testing.T) {
		prev := uc(1, 10, h0, h1, blk1)
		repeat := uc(1, 11, h0, h1, blk1) // T2 fired, root chain re-issued the same IR
		class, err := ClassifyUC(prev, repeat)
		require.NoError(t, err)
		require.Equal(t, UCRepeat, class)
	})

	t.Run("repeat after repeat (root chain still not hearing from this shard) is still a repeat", func(t *testing.T) {
		prev := uc(1, 10, h0, h1, blk1)
		repeat1 := uc(1, 11, h0, h1, blk1)
		repeat2 := uc(1, 12, h0, h1, blk1)

		class, err := ClassifyUC(prev, repeat1)
		require.NoError(t, err)
		require.Equal(t, UCRepeat, class)

		class, err = ClassifyUC(repeat1, repeat2)
		require.NoError(t, err)
		require.Equal(t, UCRepeat, class)
	})

	t.Run("older root round than previous is equivocating", func(t *testing.T) {
		prev := uc(2, 11, h1, h2, blk2)
		older := uc(1, 10, h0, h1, blk1)
		_, err := ClassifyUC(prev, older)
		require.ErrorIs(t, err, ErrEquivocatingUC)
	})

	t.Run("different input record for the same round is equivocating", func(t *testing.T) {
		prev := uc(1, 10, h0, h1, blk1)
		conflicting := uc(1, 11, h0, []byte{0xEE}, []byte{0xEF})
		_, err := ClassifyUC(prev, conflicting)
		require.ErrorIs(t, err, ErrEquivocatingUC)
	})

	t.Run("next round that does not extend the certified state is equivocating", func(t *testing.T) {
		prev := uc(1, 10, h0, h1, blk1)
		disconnected := uc(2, 11, []byte{0xDE, 0xAD}, h2, blk2) // PreviousHash != prev.Hash
		_, err := ClassifyUC(prev, disconnected)
		require.ErrorIs(t, err, ErrEquivocatingUC)
	})
}
