package storage

import (
	"crypto"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
)

// boundaryHistory answers the root identity by round: the anchor's before A*, the successor's from it.
type boundaryHistory struct {
	s        *scenario
	chainErr error
	rootErr  error
	noChain  bool
}

func (h boundaryHistory) Chain(types.PartitionID, types.ShardID) ([]*RequestActivation, error) {
	if h.chainErr != nil {
		return nil, h.chainErr
	}
	if h.noChain {
		return nil, nil
	}
	return []*RequestActivation{h.s.anchor, h.s.succ}, nil
}
func (h boundaryHistory) Network() uint64 { return fxNetwork }
func (h boundaryHistory) Version() uint64 { return fxVersion }
func (h boundaryHistory) RootIdentity(round uint64) (uint64, []byte, error) {
	if h.rootErr != nil {
		return 0, nil, h.rootErr
	}
	if round >= fxActivate {
		return 4, fxBody1, nil
	}
	return 3, fxBody0, nil
}

func TestCacheReturnsOneViewPerKeyAndRebuildsIdenticalKeysAfterRestart(t *testing.T) {
	s := newScenario(t, []uint64{6, 1, 1, 1}, []uint64{1, 6, 1, 1}, nil)
	snap := s.snapshot(s.parent, nil)
	c := NewRequestViewCache()
	q := s.query(snap, fxActivate, 4, fxBody1, PurposeExecute)
	v1, err := c.Resolve(q, snap)
	require.NoError(t, err)
	v2, err := c.Resolve(q, snap)
	require.NoError(t, err)
	require.Same(t, v1, v2, "the cached view answers the same query")
	require.Equal(t, 1, c.Len())
	got, ok := c.Get(v1.ViewKey())
	require.True(t, ok)
	require.Same(t, v1, got)
	_, ok = c.Get([]byte("unknown"))
	require.False(t, ok)

	// restart: an empty cache and a snapshot rebuilt from the same committed history reproduce the keys
	fresh := NewRequestViewCache()
	rebuilt, err := NewRequestSnapshot(fxNetwork, crypto.SHA256, s.parent, s.parentID, nil, s.anchor, s.succ)
	require.NoError(t, err)
	r, err := fresh.Resolve(q, rebuilt)
	require.NoError(t, err)
	require.Equal(t, v1.ViewKey(), r.ViewKey())
	require.Equal(t, v1.AssignmentKey(), r.AssignmentKey())
	require.NotSame(t, v1, r)
}

func TestCacheRefusesEqualKeysWithOtherContentsAndNeverReplaces(t *testing.T) {
	s := newScenario(t, []uint64{1, 1, 1, 1}, []uint64{1, 1, 1, 1}, nil)
	snap := s.snapshot(s.parent, nil)
	v := s.mustResolve(snap, fxActivate-1, 3, fxBody0, PurposeCertify)
	c := NewRequestViewCache()
	require.NoError(t, c.Put(v))
	require.NoError(t, c.Put(v), "the same key with the same content is idempotent")
	require.Equal(t, 1, c.Len())

	other := *v
	pdr, err := clonePDR(v.pdr)
	require.NoError(t, err)
	pdr.T2Timeout *= 2
	other.pdr = pdr
	require.ErrorIs(t, c.Put(&other), quorumweight.ErrRequestContext, "same assignment key, other configuration")
	got, _ := c.Get(v.ViewKey())
	require.Same(t, v, got, "nothing was replaced")

	// the same view key with other view content (another expected leader) is refused although the assignment is the same
	moved := *v
	moved.expectedTR.Leader = "someone-else"
	require.ErrorIs(t, c.Put(&moved), quorumweight.ErrRequestContext)
	// each remaining canonical component is compared on its own
	trMoved := *v
	trMoved.trDigest = []byte("another committed record")
	require.ErrorIs(t, c.Put(&trMoved), quorumweight.ErrRequestContext, "activation record digest")
	ucMoved := *v
	ucMoved.ucDigest = []byte("another previous UC")
	require.ErrorIs(t, c.Put(&ucMoved), quorumweight.ErrRequestContext, "previous UC digest")
	collMoved := *v
	collMoved.collection = !v.collection
	require.ErrorIs(t, c.Put(&collMoved), quorumweight.ErrRequestContext, "collection-only flag")
	// another view of an assignment whose key is cached with other contents is refused too
	other.viewKey = []byte("another view key")
	require.ErrorIs(t, c.Put(&other), quorumweight.ErrRequestContext)
	require.Equal(t, 1, c.Len())
	require.ErrorIs(t, c.Put(nil), quorumweight.ErrRequestContext)
}

// A failed resolution is never cached, and a later resolution against a new verified snapshot starts clean.
func TestCacheNeverRemembersAFailure(t *testing.T) {
	s := newScenario(t, []uint64{1, 1, 1, 1}, []uint64{1, 1, 1, 1}, nil)
	snap := s.snapshot(s.parent, nil)
	c := NewRequestViewCache()
	_, err := c.Resolve(RequestQuery{}, nil)
	require.ErrorIs(t, err, ErrAssignmentHistory)
	q := s.query(snap, fxActivate-1, 3, fxBody0, PurposeCertify)
	q.Version++
	_, err = c.Resolve(q, snap)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)
	require.Zero(t, c.Len())
	q.Version--
	_, err = c.Resolve(q, snap)
	require.NoError(t, err)
	require.Equal(t, 1, c.Len())
}

// Supersession: the round advanced, so views of other parents are retired; other shards' and the current parent's stay.
func TestCacheSupersedesViewsOfOtherParents(t *testing.T) {
	s := newScenario(t, []uint64{1, 1, 1, 1}, []uint64{1, 1, 1, 1}, nil)
	c := NewRequestViewCache()
	snap := s.snapshot(s.parent, nil)
	old, err := c.Resolve(s.query(snap, fxActivate-1, 3, fxBody0, PurposeCertify), snap)
	require.NoError(t, err)
	require.Zero(t, c.Supersede(1, types.ShardID{}, s.parentID), "views of the current parent stay")
	require.Zero(t, c.Supersede(2, types.ShardID{}, []byte("x")), "another partition is untouched")
	left, _ := types.ShardID{}.Split()
	require.Zero(t, c.Supersede(1, left, []byte("x")), "another shard of the partition is untouched")
	require.Equal(t, 1, c.Supersede(1, types.ShardID{}, []byte("the next parent")))
	_, ok := c.Get(old.ViewKey())
	require.False(t, ok)
	// the retired view is reconstructible and the caller's pointer stays valid
	again, err := c.Resolve(s.query(snap, fxActivate-1, 3, fxBody0, PurposeCertify), snap)
	require.NoError(t, err)
	require.Equal(t, old.ViewKey(), again.ViewKey())
	require.NotNil(t, old.Context())
}

// The leader's resolution at the boundary, through the shared resolver with the committed parent deliberately lagging: before
// A* the old assignment, at A* the successor, and an old-assignment proof is stale there, whatever the cache holds.
func TestResolveParentViewAtTheBoundaryUsesCommittedHistoryNotTheLaggingState(t *testing.T) {
	s := newScenario(t, []uint64{6, 1, 1, 1}, []uint64{1, 6, 1, 1}, nil)
	h := boundaryHistory{s: s}
	c := NewRequestViewCache()

	before, err := ResolveParentView(h, nil, s.parent, s.parentID, fxActivate-1, crypto.SHA256, PurposeCertify, c)
	require.NoError(t, err)
	require.EqualValues(t, 0, before.ExpectedTR().Epoch)
	at, err := ResolveParentView(h, nil, s.parent, s.parentID, fxActivate, crypto.SHA256, PurposeCertify, c)
	require.NoError(t, err)
	require.EqualValues(t, 1, at.ExpectedTR().Epoch)
	require.NotEqual(t, before.AssignmentKey(), at.AssignmentKey())
	require.Equal(t, 2, c.Len())

	oldProof := quorumProof(s.request(before, 0, 0, 1)) // weight 6 under the old assignment
	_, err = before.VerifyIRChangeReq(oldProof, t2Rounds)
	require.NoError(t, err)
	_, err = at.VerifyIRChangeReq(oldProof, t2Rounds)
	require.ErrorIs(t, err, ErrStaleRequestContext)
	fresh := quorumProof(s.request(at, 1, 1, 1)) // weight 6 under the successor
	_, err = at.VerifyIRChangeReq(fresh, t2Rounds)
	require.NoError(t, err)
	freshA := quorumProof(s.request(at, 0, 0, 1)) // weight 1 only
	_, err = at.VerifyIRChangeReq(freshA, t2Rounds)
	require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached)
}

func TestResolveParentViewRefusesMissingHistoryAndParent(t *testing.T) {
	s := newScenario(t, []uint64{1, 1, 1, 1}, []uint64{1, 1, 1, 1}, nil)
	boom := errors.New("store unavailable")
	for name, tc := range map[string]struct {
		h      RequestHistory
		parent *ShardInfo
	}{
		"no history":        {nil, s.parent},
		"no parent":         {boundaryHistory{s: s}, nil},
		"chain unavailable": {boundaryHistory{s: s, chainErr: boom}, s.parent},
		"empty chain":       {boundaryHistory{s: s, noChain: true}, s.parent},
		"root identity":     {boundaryHistory{s: s, rootErr: boom}, s.parent},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := ResolveParentView(tc.h, nil, tc.parent, s.parentID, fxActivate-1, crypto.SHA256, PurposeCertify, nil)
			require.ErrorIs(t, err, ErrAssignmentHistory)
			require.Nil(t, v)
		})
	}
}

// ShardInfo's round tag is the view's: the shard round, epoch, previous state hash and the previous UC timestamp.
func TestRoundTagOfShardInfoIsTheViewsAndMovesWithTheRound(t *testing.T) {
	s := newScenario(t, []uint64{1, 1, 1, 1}, []uint64{1, 1, 1, 1}, nil)
	v := s.mustResolve(s.snapshot(s.parent, nil), fxActivate-1, 3, fxBody0, PurposeCertify)
	require.Equal(t, s.parent.RoundTag(), v.RoundTag())
	moved := *s.parent
	lastCR := *s.parent.LastCR
	lastCR.Technical.Round++
	moved.LastCR = &lastCR
	require.NotEqual(t, s.parent.RoundTag(), moved.RoundTag())
	moved = *s.parent
	moved.RootHash = []byte("another state")
	require.NotEqual(t, s.parent.RoundTag(), moved.RoundTag())
	require.Empty(t, (&ShardInfo{}).RoundTag())
}

// Every component of the shard round/anchor tag moves it, and the view's identity is its assignment key.
func TestRoundTagBindsEachComponentAndIdentityIsTheAssignmentKey(t *testing.T) {
	base := roundTag(5, 1, []byte("state"), 1000)
	require.Equal(t, base, roundTag(5, 1, []byte("state"), 1000))
	for name, other := range map[string]string{
		"round":     roundTag(6, 1, []byte("state"), 1000),
		"epoch":     roundTag(5, 2, []byte("state"), 1000),
		"state":     roundTag(5, 1, []byte("other"), 1000),
		"timestamp": roundTag(5, 1, []byte("state"), 1001),
	} {
		require.NotEqual(t, base, other, name)
	}
	s := newScenario(t, []uint64{1, 1, 1, 1}, []uint64{1, 1, 1, 1}, nil)
	snap := s.snapshot(s.parent, nil)
	v := s.mustResolve(snap, fxActivate-1, 3, fxBody0, PurposeCertify)
	require.NotEmpty(t, v.Identity())
	require.Equal(t, hex.EncodeToString(v.AssignmentKey()), v.Identity())
	other := s.mustResolve(snap, fxActivate, 4, fxBody1, PurposeCertify)
	require.NotEqual(t, v.Identity(), other.Identity(), "another assignment is another identity")
}

// The frozen pipeline change is part of the view: the flag reports it, and the cache compares its content.
func TestPendingChangeIsFlaggedAndComparedByTheCache(t *testing.T) {
	s := newScenario(t, []uint64{1, 1, 1, 1}, []uint64{1, 1, 1, 1}, nil)
	free := s.mustResolve(s.snapshot(s.parent, nil), fxActivate-1, 3, fxBody0, PurposeCertify)
	require.False(t, free.HasPendingChange())
	ir := &types.InputRecord{Version: 1, RoundNumber: 6, Hash: []byte{0xEE}, BlockHash: []byte{0xEF}, PreviousHash: []byte{1}, SummaryValue: []byte{3}}
	busy := s.mustResolve(s.snapshot(s.parent, ir), fxActivate-1, 3, fxBody0, PurposeCertify)
	require.True(t, busy.HasPendingChange())

	c := NewRequestViewCache()
	require.NoError(t, c.Put(busy))
	moved := *busy
	other := *ir
	other.Hash = []byte{0xAA}
	moved.pending = &other
	require.ErrorIs(t, c.Put(&moved), quorumweight.ErrRequestContext, "same key, another pending change")
	dropped := *busy
	dropped.pending = nil
	require.ErrorIs(t, c.Put(&dropped), quorumweight.ErrRequestContext, "same key, no pending change")
}
