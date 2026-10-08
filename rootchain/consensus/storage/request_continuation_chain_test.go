package storage

import (
	"bytes"
	"crypto"
	"maps"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

var (
	fxBody3 = bytes.Repeat([]byte{0xC3}, 32)
	fxBody4 = bytes.Repeat([]byte{0xC4}, 32)
)

// chainWithTwoContinuations is anchor -> two root-only continuations -> the genuine assignment of s.pdr1 under a later root interval.
func (s *scenario) chainWithTwoContinuations(t *testing.T) (chain []*RequestActivation, c1, c2, real *RequestActivation) {
	t.Helper()
	c1 = continuationOf(t, s.anchor, 4, fxBody1, fxActivate-8)
	c2 = continuationOf(t, c1, 5, fxBody2, fxActivate-4)
	cp := *s.succ
	cp.rootEpoch, cp.rootBody, cp.start = 6, bytes.Clone(fxBody3), fxActivate
	real = &cp
	return []*RequestActivation{s.anchor, c1, c2, real}, c1, c2, real
}

// An EVM assignment (unit-mirrored, or heavy) continued across two root-only epochs keeps its weights and quorum under each root interval;
// a genuine coupled assignment after them advances the shard epoch exactly once, under its own weights, and the proofs of the old
// assignment are refused there. The unit EVM case is the one before its first coupled assignment.
func TestEVMAssignmentIsContinuedAcrossRootOnlyEpochsThenGenuinelyReplaced(t *testing.T) {
	for name, tc := range map[string]struct {
		w0, w1           []uint64
		total, quorum    uint64
		oldAlone, oldWho int // a signer that certifies alone under the old assignment, or -1
	}{
		"heavy (6,1,1,1) to (1,6,1,1)":        {[]uint64{6, 1, 1, 1}, []uint64{1, 6, 1, 1}, 9, 5, 0, 0},
		"unit (1,1,1,1) to the first coupled": {[]uint64{1, 1, 1, 1}, []uint64{6, 1, 1, 1}, 4, 3, -1, -1},
	} {
		t.Run(name, func(t *testing.T) {
			s := newScenario(t, tc.w0, tc.w1, nil)
			chain, _, _, _ := s.chainWithTwoContinuations(t)
			snap := s.snapshotWith(s.parent, chain...)

			var oldView *RequestRoundView
			for _, step := range []struct {
				round, epoch uint64
				body         []byte
			}{{fxActivate - 6, 4, fxBody1}, {fxActivate - 2, 5, fxBody2}} {
				v := s.mustResolve(snap, step.round, step.epoch, step.body, PurposeExecute)
				oldView = v
				require.EqualValues(t, tc.total, v.Context().TotalWeight())
				require.EqualValues(t, tc.quorum, v.Context().Threshold())
				require.EqualValues(t, 0, v.ExpectedTR().Epoch, "a continuation is not a shard transition")
				if tc.oldAlone >= 0 {
					_, err := v.VerifyIRChangeReq(quorumProof(s.request(v, tc.oldAlone, tc.oldAlone, 2)), t2Rounds)
					require.NoError(t, err, "the heavy signer alone, under every root interval")
					_, err = v.VerifyIRChangeReq(quorumProof(s.request(v, 1, 1, 2), s.request(v, 2, 2, 2), s.request(v, 3, 3, 2)), t2Rounds)
					require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached, "three light signers")
				} else {
					_, err := v.VerifyIRChangeReq(quorumProof(s.request(v, 0, 0, 2), s.request(v, 1, 1, 2), s.request(v, 2, 2, 2)), t2Rounds)
					require.NoError(t, err)
					_, err = v.VerifyIRChangeReq(quorumProof(s.request(v, 0, 0, 2), s.request(v, 1, 1, 2)), t2Rounds)
					require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached)
				}
			}
			oldProof := quorumProof(s.request(oldView, 0, 0, 2), s.request(oldView, 1, 1, 2), s.request(oldView, 2, 2, 2), s.request(oldView, 3, 3, 2))

			// the genuine assignment: one shard-epoch advance, the new weights, and no old proof counts
			fresh := s.mustResolve(snap, fxActivate+1, 6, fxBody3, PurposeExecute)
			require.EqualValues(t, 1, fresh.ExpectedTR().Epoch, "exactly one shard-epoch advance")
			require.Equal(t, s.succTR, fresh.ExpectedTR())
			w, _ := fresh.Context().SignerWeight(s.f.id(0))
			require.EqualValues(t, tc.w1[0], w)
			_, err := fresh.VerifyIRChangeReq(oldProof, t2Rounds)
			require.Error(t, err, "the old assignment's proofs name the old epoch and round")
			_, err = fresh.VerifyIRChangeReq(quorumProof(s.request(fresh, 0, 0, 2), s.request(fresh, 1, 1, 2), s.request(fresh, 2, 2, 2), s.request(fresh, 3, 3, 2)), t2Rounds)
			require.NoError(t, err, "the new assignment's own proofs")

			// the old root identities no longer authorise the new interval, and the new identity does not authorise the old
			_, err = s.resolve(snap, fxActivate+1, 5, fxBody2, PurposeExecute)
			require.Error(t, err, "the second continuation's identity at a round of the real assignment")
		})
	}
}

// The certified-record branch of #461 through continuations: the parent holds the successor epoch's last certified record while the
// acknowledgement is pending, several real timeout transitions advance its round and leader, and neither the epoch, the configuration nor the
// accumulators roll again.
func TestSuccessorCertifiedParentThroughContinuationsWithRepeatedTimeouts(t *testing.T) {
	s := newScenario(t, []uint64{6, 1, 1, 1}, []uint64{1, 6, 1, 1}, nil)
	c1 := continuationOf(t, s.succ, 5, fxBody2, fxActivate+10)
	c2 := continuationOf(t, c1, 6, fxBody3, fxActivate+20)

	parent := s.f.shardAt(s.pdr1, certification.TechnicalRecord{Round: 7, Epoch: 1, Leader: s.f.id(0)})
	feesBefore, prevBefore, confBefore := maps.Clone(parent.Fees), bytes.Clone(parent.PrevEpochFees), bytes.Clone(parent.ShardConfHash)
	for repeats := 0; repeats <= 3; repeats++ {
		cur := *parent
		cur.Fees = maps.Clone(parent.Fees)
		for i := 0; i < repeats; i++ {
			require.NoError(t, cur.nextRoundWith(nil, s.pdr1, crypto.SHA256, resetMembers))
		}
		snap := s.snapshotWith(&cur, s.anchor, s.succ, c1, c2)
		v := s.mustResolve(snap, fxActivate+25, 6, fxBody3, PurposeExecute)
		require.Equal(t, parent.LastCR.Technical, v.ExpectedTR(), "repeats %d: the certified record, whatever the execution TR advanced to", repeats)
		require.EqualValues(t, 7+uint64(repeats), cur.TR.Round, "the execution TR advanced by the real timeouts")
		require.EqualValues(t, 1, v.ExpectedTR().Epoch)
		require.Equal(t, feesBefore, cur.Fees, "no fee roll")
		require.Equal(t, prevBefore, []byte(cur.PrevEpochFees))
		require.Equal(t, confBefore, []byte(cur.ShardConfHash))
		_, err := v.VerifyIRChangeReq(quorumProof(s.request(v, 1, 1, 2)), t2Rounds)
		require.NoError(t, err, "the new heavy signer alone, repeats %d", repeats)
	}
}

// A view cached for the real chain is not an authority for a spliced sibling: a continuation of another root body fails the resolution of the
// real identity with a typed error, no view, and leaves the cache as it was.
func TestWarmCacheDoesNotServeASplicedSiblingContinuation(t *testing.T) {
	s := newScenario(t, []uint64{6, 1, 1, 1}, []uint64{1, 6, 1, 1}, nil)
	c1 := continuationOf(t, s.succ, 5, fxBody2, fxActivate+10)
	sibling := continuationOf(t, s.succ, 5, fxBody4, fxActivate+10) // the same epoch number under another body
	inst := s.installed(1)
	good := s.snapshotWith(inst, s.anchor, s.succ, c1)
	spliced := s.snapshotWith(inst, s.anchor, s.succ, sibling)

	cache := NewRequestViewCache()
	q := s.query(good, fxActivate+12, 5, fxBody2, PurposeExecute)
	warm, err := cache.Resolve(q, good)
	require.NoError(t, err)
	size := cache.Len()
	require.NotZero(t, size)

	view, err := cache.Resolve(q, spliced)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)
	require.Nil(t, view)
	require.Equal(t, size, cache.Len(), "nothing is added by the refusal")
	again, err := cache.Resolve(q, good)
	require.NoError(t, err)
	require.Equal(t, warm.ViewKey(), again.ViewKey(), "the real chain's cached view is intact")

	// and the sibling's own identity resolves only against the sibling's snapshot
	other := s.query(spliced, fxActivate+12, 5, fxBody4, PurposeExecute)
	_, err = cache.Resolve(other, spliced)
	require.NoError(t, err)
	_, err = cache.Resolve(other, good)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)
}
