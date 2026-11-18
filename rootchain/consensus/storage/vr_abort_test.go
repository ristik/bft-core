package storage_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

// #1177 review (astra 1): a valid Freeze F that this root executed and retained, but that lost (no certificate; another branch extends the
// Prepare), must not change what the Abort on the winning branch does. Two roots execute the same Abort on the same prepared parent, one
// having retained F's candidate and one not: same state, same root hash, and R stays open (a pre-Freeze Abort closes nothing).
func TestVRAbortIsIndependentOfALosingFreezesRetention(t *testing.T) {
	f := newVXFixture(t)
	g := f.genesis()
	prep := f.must(g, f.block(g, 11, 1_010, [][]byte{f.record("prepare", 0, 11).Bytes()}))
	losing := f.must(prep, f.block(prep, 12, 1_020, [][]byte{f.record("freeze", 0, 12).Bytes(), f.freezeV5(0)}))
	_, _, v5, _, ok := storage.VRRetainedForTest(losing)
	require.True(t, ok)
	abort := f.block(prep, 13, 1_030, [][]byte{f.record("abort", 0, 13).Bytes()})

	cold := f.must(prep, abort)
	body := f.q3.Identity()
	f.candidates[string(body[:])] = v5 // the store retains an admitted Freeze before it has a certificate
	warm := f.must(prep, abort)
	require.Equal(t, cold.RootHash, warm.RootHash, "local retention outside the branch never changes execution")
	require.Equal(t, cold.ShardState.Control.Digest(), warm.ShardState.Control.Digest())
	require.False(t, posState(t, cold).IsResolved(f.r), "a pre-Freeze Abort closes nothing")
	require.Empty(t, cold.ShardState.Records)
	// and replaying the winning branch from scratch gives the same root again
	g2 := f.genesis()
	prep2 := f.must(g2, f.block(g2, 11, 1_010, [][]byte{f.record("prepare", 0, 11).Bytes()}))
	require.Equal(t, cold.RootHash, f.must(prep2, abort).RootHash)
}

// The Abort of an endorsed attempt (its Freeze v5 is an ancestor) closes the staged primary's result once, from the branch's staged state,
// whether or not this root still holds the retained candidate; it clears the staging.
func TestVRAbortAfterTheFreezeClosesTheStagedPrimaryFromTheBranch(t *testing.T) {
	run := func(retained bool) *storage.ExecutedBlock {
		f := newVXFixture(t)
		g := f.genesis()
		prep := f.must(g, f.block(g, 11, 1_010, [][]byte{f.record("prepare", 0, 11).Bytes()}))
		fz := f.must(prep, f.block(prep, 12, 1_020, [][]byte{f.record("freeze", 0, 12).Bytes(), f.freezeV5(0)}))
		if retained {
			_, _, v5, _, _ := storage.VRRetainedForTest(fz)
			body := f.q3.Identity()
			f.candidates[string(body[:])] = v5
		}
		b := f.must(fz, f.block(fz, 13, 1_030, [][]byte{f.record("abort", 0, 13).Bytes()}))
		require.True(t, posState(t, b).IsResolved(f.r))
		require.Len(t, b.ShardState.Records, 1)
		require.Equal(t, rootrecords.KindSessionClosed, b.ShardState.Records[0].Kind)
		require.Equal(t, f.r[:], b.ShardState.Records[0].Data)
		require.Zero(t, rootState(t, b).StagedBody)
		return b
	}
	require.Equal(t, run(false).RootHash, run(true).RootHash)
}

// The same determinism on a P85 chain (a behaviour change of the pre-VR executor): an Abort extending a prepared parent closes nothing,
// even when this root holds a retained primary candidate for the attempt's body from a Freeze on another branch.
func TestP85AbortOfAPreparedAttemptIgnoresARetainedCandidate(t *testing.T) {
	f := newVXFixture(t)
	g := f.genesis()
	g.ShardState.Control.VR = nil
	f.svc.Registry = nil
	prep := f.must(g, f.block(g, 11, 1_010, [][]byte{f.record("prepare", 0, 11).Bytes()}))
	abort := f.block(prep, 12, 1_020, [][]byte{f.record("abort", 0, 12).Bytes()})
	cold := f.must(prep, abort)
	body := f.q3.Identity()
	v5 := f.v5Bytes()
	f.candidates[string(body[:])] = v5
	warm := f.must(prep, abort)
	require.Equal(t, cold.RootHash, warm.RootHash)
	require.False(t, posState(t, warm).IsResolved(f.r))
}
