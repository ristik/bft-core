package shardnode

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestUCConflictDisposition pins what a shard node does after it rejects a certificate for
// equivocation, which CI reproduced and which the error string alone could not settle
// (F1 #9, review 5132493933). It is a disposition record, not an endorsement: the behaviour
// in the third case is worth a deliberate decision by F2 (#10).
func TestUCConflictDisposition(t *testing.T) {
	h0 := []byte{0x00}
	hA, hB, hC := []byte{0x0a}, []byte{0x0b}, []byte{0x0c}
	blkA, blkB, blkC := []byte{0xba}, []byte{0xbb}, []byte{0xbc}

	// This node's stored certificate is one branch of a same-round conflict.
	stored := uc(4, 50, h0, hA, blkA)

	t.Run("a different input record for the same round is rejected", func(t *testing.T) {
		_, err := ClassifyUC(stored, uc(4, 51, h0, hB, blkB))
		require.ErrorIs(t, err, ErrEquivocatingUC)
		require.ErrorContains(t, err, "different input records for same partition round 4")
	})

	t.Run("the next consecutive round on the other branch is also rejected", func(t *testing.T) {
		// Continuity is checkable here, and it fails: the node cannot follow the branch it
		// did not store. Combined with the case above, and with c.luc being left unchanged on
		// error, a node in this state rejects everything the shard produces from here on.
		_, err := ClassifyUC(stored, uc(5, 52, hB, hC, blkC))
		require.ErrorIs(t, err, ErrEquivocatingUC)
		require.ErrorContains(t, err, "does not extend previous state hash")
	})

	t.Run("a NON-consecutive later round on the other branch is accepted unchecked", func(t *testing.T) {
		// CheckNonEquivocatingCertificates draws no conclusion across a round gap ("if it is
		// not from consecutive rounds then it is simply not possible to make any conclusions"),
		// so the same branch the node just rejected twice becomes acceptable once a round is
		// skipped. That is how a wedged node escapes — by taking the least-verified path.
		class, err := ClassifyUC(stored, uc(20, 70, hB, hC, blkC))
		require.NoError(t, err)
		require.Equal(t, UCValid, class)
	})

	t.Run("a timestamp-only difference is also called equivocation", func(t *testing.T) {
		// This is the shape worth looking for first in the next CI occurrence. A round's IR
		// timestamp is copied from the seal of the certificate that authorised it
		// (inputrecord.go's ExpectedIR: Timestamp = uc.UnicitySeal.Timestamp). So if a round is
		// attempted twice — the first attempt timing out and the second being authorised by a
		// later certificate — honest validators produce two input records for the same partition
		// round that differ ONLY in timestamp. Nothing Byzantine has happened, but this check
		// compares whole IR bytes and reports "equivocating".
		//
		// Whether that actually occurred in CI is exactly what DescribeUCConflict's
		// "differing IR fields" list will settle: [timestamp] alone means a re-attempted round;
		// hash/blockHash differences mean something substantively different was certified.
		later := uc(4, 51, h0, hA, blkA)
		later.InputRecord.Timestamp = stored.InputRecord.Timestamp + 1
		_, err := ClassifyUC(stored, later)
		require.ErrorIs(t, err, ErrEquivocatingUC)
		require.Contains(t, DescribeUCConflict(stored, later), "differing IR fields: [timestamp]")
	})

	t.Run("the rejection describes which field differed and both root rounds", func(t *testing.T) {
		got := DescribeUCConflict(stored, uc(4, 51, h0, hB, blkB))
		require.Contains(t, got, "hash")
		require.Contains(t, got, "blockHash")
		require.NotContains(t, strings.SplitN(got, ";", 2)[0], "timestamp")
		require.Contains(t, got, "rootRound=50")
		require.Contains(t, got, "rootRound=51")
	})

	t.Run("equal input records report no differing fields", func(t *testing.T) {
		require.Contains(t, DescribeUCConflict(stored, uc(4, 51, h0, hA, blkA)),
			"differing IR fields: [none (input records are equal)]")
	})
}
