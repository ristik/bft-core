package shardnode

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/types"
)

/*
TestUCDisposition is the disposition table issue #93 asks for: every arrangement of two
INDEPENDENTLY AUTHENTIC certificates, and what each one is.

The defect it pins: types.CheckNonEquivocatingCertificates tests "older root round" before it
compares anything, and ClassifyUC wrapped that as ErrEquivocatingUC. So a delayed certificate was
reported as equivocation at ERROR — and, worse, a REAL conflict was decided by arrival order,
because when the older of two conflicting certificates arrived second the ordering test fired
before the input records were ever compared.

Authentication is not this table's subject: every row assumes both certificates already verified
against the trust base, which is what BFTClient does before calling ClassifyUC.
*/
func TestUCDisposition(t *testing.T) {
	h0, h1, h2 := []byte{0x00}, []byte{0x01}, []byte{0x02}
	blk1, blk2 := []byte{0xb1}, []byte{0xb2}

	t.Run("routine stale", func(t *testing.T) {
		t.Run("the exact 70 -> 67 case from the ticket", func(t *testing.T) {
			// PR #91 run 34149484532: validator 1 held root round 70 and then received 67.
			// It logged ErrEquivocatingUC at ERROR, recovered, and the later scenarios passed —
			// a routine delayed response wearing a fatal diagnostic.
			held := uc(9, 70, h1, h2, blk2)
			delayed := uc(8, 67, h0, h1, blk1)
			class, err := ClassifyUC(held, delayed)
			require.NoError(t, err, "a delayed authentic certificate is not a fault")
			require.Equal(t, UCStale, class)
		})

		t.Run("same round, same input record, earlier root round", func(t *testing.T) {
			// A repeat certificate re-issued earlier and delivered late. Same statement, so
			// there is nothing to conflict with.
			held := uc(5, 40, h0, h1, blk1)
			delayed := uc(5, 38, h0, h1, blk1)
			class, err := ClassifyUC(held, delayed)
			require.NoError(t, err)
			require.Equal(t, UCStale, class)
		})

		t.Run("many rounds behind", func(t *testing.T) {
			held := uc(100, 400, h1, h2, blk2)
			delayed := uc(3, 12, h0, h1, blk1)
			class, err := ClassifyUC(held, delayed)
			require.NoError(t, err)
			require.Equal(t, UCStale, class)
		})
	})

	t.Run("exact duplicate", func(t *testing.T) {
		held := uc(5, 40, h0, h1, blk1)
		same := uc(5, 40, h0, h1, blk1)
		class, err := ClassifyUC(held, same)
		require.NoError(t, err)
		require.Equal(t, UCDuplicate, class)
	})

	t.Run("repeat", func(t *testing.T) {
		held := uc(5, 40, h0, h1, blk1)
		repeat := uc(5, 44, h0, h1, blk1)
		class, err := ClassifyUC(held, repeat)
		require.NoError(t, err)
		require.Equal(t, UCRepeat, class)
	})

	t.Run("valid successor", func(t *testing.T) {
		held := uc(5, 40, h0, h1, blk1)
		next := uc(6, 41, h1, h2, blk2)
		class, err := ClassifyUC(held, next)
		require.NoError(t, err)
		require.Equal(t, UCValid, class)
	})

	t.Run("genuine conflict surfaces in BOTH arrival orders", func(t *testing.T) {
		// The regression this ticket exists for. Two authentic certificates for partition
		// round 5 with different input records, certified at different root rounds. Whichever
		// arrives second, the node must refuse.
		a := uc(5, 40, h0, h1, blk1)
		b := uc(5, 44, h0, []byte{0xEE}, []byte{0xEF})

		t.Run("newer arrives second", func(t *testing.T) {
			_, err := ClassifyUC(a, b)
			require.ErrorIs(t, err, ErrEquivocatingUC)
			require.ErrorContains(t, err, "different input records for same partition round 5")
		})

		t.Run("older arrives second", func(t *testing.T) {
			// Before #93 this returned the "older root round" error instead: the conflict was
			// never compared, and the two orders disagreed about what had happened.
			_, err := ClassifyUC(b, a)
			require.ErrorIs(t, err, ErrEquivocatingUC)
			require.ErrorContains(t, err, "different input records for same partition round 5")
		})

		t.Run("and it is never reported as merely stale", func(t *testing.T) {
			class, err := ClassifyUC(b, a)
			require.Error(t, err)
			require.NotEqual(t, UCStale, class)
		})
	})

	t.Run("gap requiring recovery is still refused", func(t *testing.T) {
		// A forward jump whose PreviousHash does not extend the held state. Consecutive rounds
		// must chain; this one does not.
		held := uc(5, 40, h0, h1, blk1)
		disconnected := uc(6, 41, []byte{0xDE, 0xAD}, h2, blk2)
		_, err := ClassifyUC(held, disconnected)
		require.ErrorIs(t, err, ErrEquivocatingUC)
	})

	t.Run("impossible round combinations are a DISTINCT error", func(t *testing.T) {
		// Not equivocation — no two conflicting statements about one round — but a sequence no
		// honest root chain issues. #93 requires these stay distinguishable from both stale and
		// equivocation, because they send an operator somewhere else entirely.
		t.Run("later partition round at an earlier root round", func(t *testing.T) {
			held := uc(5, 40, h0, h1, blk1)
			impossible := uc(6, 33, h1, h2, blk2)
			_, err := ClassifyUC(held, impossible)
			require.ErrorIs(t, err, ErrImpossibleUCOrder)
			require.NotErrorIs(t, err, ErrEquivocatingUC)
		})

		t.Run("later partition round at the same root round", func(t *testing.T) {
			held := uc(5, 40, h0, h1, blk1)
			impossible := uc(6, 40, h1, h2, blk2)
			_, err := ClassifyUC(held, impossible)
			require.ErrorIs(t, err, ErrImpossibleUCOrder)
		})

		t.Run("earlier partition round at a later root round", func(t *testing.T) {
			held := uc(5, 40, h0, h1, blk1)
			impossible := uc(4, 44, h0, h1, blk1)
			_, err := ClassifyUC(held, impossible)
			require.ErrorIs(t, err, ErrImpossibleUCOrder)
			require.NotErrorIs(t, err, ErrEquivocatingUC)
		})
	})

	t.Run("the stale diagnostic does not contain the words the harness treats as fatal", func(t *testing.T) {
		// scripts/chaos-evm.sh matches /diverges|equivocat|cannot safely build round/ case
		// insensitively. #93 requires that detection stay intact, so the routine class must not
		// produce a string it matches — this is what stops the fix from being "grep it out".
		require.NotContains(t, UCStale.String(), "equivocat")
		require.NotContains(t, UCStale.String(), "diverge")
		require.Equal(t, "stale", UCStale.String())
	})
}

// TestUCDispositionNilInputRecord pins that a structurally broken certificate is refused rather
// than crashing the node. Every round getter answers 0 for a nil InputRecord, so without an explicit
// guard two such certificates look like "the same partition round" and reach the canonical-bytes
// comparison, which dereferences it.
func TestUCDispositionNilInputRecord(t *testing.T) {
	good := uc(5, 40, []byte{0x00}, []byte{0x01}, []byte{0xb1})
	broken := &types.UnicityCertificate{
		Version:     1,
		UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 41, Timestamp: 1000},
	}

	t.Run("new certificate has none", func(t *testing.T) {
		_, err := ClassifyUC(good, broken)
		require.ErrorIs(t, err, ErrImpossibleUCOrder)
	})

	t.Run("held certificate has none", func(t *testing.T) {
		_, err := ClassifyUC(broken, good)
		require.ErrorIs(t, err, ErrImpossibleUCOrder)
	})

	t.Run("both have none", func(t *testing.T) {
		_, err := ClassifyUC(broken, broken)
		require.ErrorIs(t, err, ErrImpossibleUCOrder)
	})
}

func TestUCDispositionEqualRootRoundBothOrders(t *testing.T) {
	a := uc(5, 40, []byte{0}, []byte{1}, []byte{0xb1})
	b := uc(6, 40, []byte{1}, []byte{2}, []byte{0xb2})
	for _, pair := range [][2]*types.UnicityCertificate{{a, b}, {b, a}} {
		_, err := ClassifyUC(pair[0], pair[1])
		require.ErrorIs(t, err, ErrImpossibleUCOrder)
	}
}
