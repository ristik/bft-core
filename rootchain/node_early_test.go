package rootchain

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-go-base/types"
)

// futureRequests are the signed requests of the given nodes for the round after the current one: built under the view the shard's
// next committed parent resolves to, then the fixture is put back on the current parent. The shard nodes hold the certificate of the
// current round already; this root has not applied its commit yet.
func (f *fixture) futureRequests(group byte, nodes ...int) (current, next *storage.RequestRoundView, reqs []*certification.BlockCertificationRequest) {
	f.t.Helper()
	current = f.view()
	f.setParent(1, f.pdr)
	next = f.view()
	for _, i := range nodes {
		reqs = append(reqs, f.request(i, next, group, nil))
	}
	f.setParent(0, f.pdr)
	require.Equal(f.t, current.ViewKey(), f.view().ViewKey(), "premise: back on the current parent")
	require.Equal(f.t, current.ExpectedTR().Round+1, next.ExpectedTR().Round, "premise: the requests are one round ahead")
	return current, next, reqs
}

func (f *fixture) replay() {
	f.node.replayEarly(context.Background(), shardRef{partition: 1, shard: types.ShardID{}})
}

// A request for round N+1 that arrives while the committed context is at N is held, counted for nothing and not answered; after the
// commit it is admitted under the new context and counted toward the quorum.
func TestNearFutureRequestIsHeldThenCountedAfterTheCommit(t *testing.T) {
	f := newFixture(t, fxOpts{}) // unit: quorum 3 of 4
	_, _, reqs := f.futureRequests(9, 0, 1, 2)
	for _, r := range reqs {
		require.NoError(t, f.submit(r), "held, not refused")
	}
	require.Zero(t, f.counted(), "nothing is counted before the matching context exists")
	require.Empty(t, f.certs())
	require.Zero(t, f.sentCount(), "no rejection carrying the old certificate is sent")
	require.Equal(t, 3, f.node.early.len())

	f.replay() // before the commit: still ahead, held again
	require.Zero(t, f.counted())
	require.Equal(t, 3, f.node.early.len())

	f.setParent(1, f.pdr) // the commit of round N applies
	f.replay()
	require.Zero(t, f.node.early.len())
	certs := f.certs()
	require.Len(t, certs, 1, "the three held requests, revalidated under the new context, are the quorum")
	require.Equal(t, consensus.Quorum, certs[0].Reason)
	require.Len(t, certs[0].Requests, 3)
}

// The certificate of the commit wakes the held requests through the node's own loops.
func TestNearFutureRequestIsReplayedOnTheCertificate(t *testing.T) {
	f := newFixture(t, fxOpts{})
	_, _, reqs := f.futureRequests(9, 0, 1, 2)
	for _, r := range reqs {
		require.NoError(t, f.submit(r))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = f.node.handleConsensus(ctx) }()
	f.setParent(1, f.pdr)
	f.cm.res <- f.si.LastCR
	select {
	case <-f.node.early.notify: // what the partition loop receives
		refs := f.node.early.takeReady()
		require.Equal(t, []shardRef{{partition: 1, shard: types.ShardID{}}}, refs)
		f.node.replayEarly(ctx, refs[0])
	case <-time.After(2 * time.Second):
		t.Fatal("the certificate did not signal the held requests")
	}
	require.Len(t, f.certs(), 1)
}

// The parent is committed while the request is being resolved: the first view is the old one, a view resolved again is the new one.
// The request is judged again under the new view and counted at once, never refused as stale.
func TestCommitDuringResolutionIsResolvedAgain(t *testing.T) {
	f := newFixture(t, fxOpts{})
	old := *f
	_, next, reqs := f.futureRequests(9, 0)
	oldSI, oldID := old.si, old.parentID
	f.setParent(1, f.pdr)
	newSI, newID := f.si, f.parentID
	anchor, err := storage.NewRequestAnchor(f.pdr, crypto.SHA256, fxRootEp, fxBody, fxVersion)
	require.NoError(t, err)
	calls := 0
	parent := func(types.PartitionID, types.ShardID) (*storage.ShardInfo, []byte, *types.InputRecord, error) {
		calls++
		if calls == 1 {
			return oldSI, oldID, nil, nil // read before the commit applied
		}
		return newSI, newID, nil, nil
	}
	resolver, err := consensus.NewRequestViewResolver(fxHistory{anchor}, crypto.SHA256, parent, nil)
	require.NoError(t, err)
	f.cm.resolver = resolver
	require.NoError(t, f.submit(reqs[0]))
	require.Equal(t, 2, calls, "resolved again after the stale refusal")
	require.Equal(t, 1, f.counted(), "counted under the new view at once")
	require.Zero(t, f.node.early.len(), "nothing held")
	require.Equal(t, QuorumInProgress, f.node.incomingRequests.IsConsensusReceived(1, types.ShardID{}, next))
}

// Only an authentic request exactly one round ahead is held; everything else is refused as before.
func TestOnlyAuthenticNextRoundRequestsAreHeld(t *testing.T) {
	t.Run("two rounds ahead", func(t *testing.T) {
		f := newFixture(t, fxOpts{})
		v := f.view()
		err := f.submit(f.request(0, v, 9, func(r *certification.BlockCertificationRequest) { r.InputRecord.RoundNumber += 2 }))
		require.ErrorIs(t, err, storage.ErrStaleRequestContext)
		require.Zero(t, f.node.early.len())
		require.Equal(t, 1, f.sentCount())
	})
	t.Run("not a member", func(t *testing.T) {
		f := newFixture(t, fxOpts{})
		_, _, reqs := f.futureRequests(9, 0)
		reqs[0].NodeID = "not-a-member"
		require.ErrorIs(t, f.submit(reqs[0]), storage.ErrNodeNotInTrustBase)
		require.Zero(t, f.node.early.len())
	})
	t.Run("bad signature", func(t *testing.T) {
		f := newFixture(t, fxOpts{})
		_, _, reqs := f.futureRequests(9, 0)
		reqs[0].InputRecord.Hash = []byte{10}
		require.Error(t, f.submit(reqs[0]))
		require.Zero(t, f.node.early.len())
	})
	t.Run("a held request that is invalid under the committed context is refused then", func(t *testing.T) {
		f := newFixture(t, fxOpts{})
		cur := f.view()
		// one round ahead but on another previous state: authentic, held, and refused once the context it claims is committed
		req := f.request(0, cur, 9, func(r *certification.BlockCertificationRequest) {
			r.InputRecord.RoundNumber++
			r.InputRecord.PreviousHash = bytes.Repeat([]byte{7}, 32)
		})
		require.NoError(t, f.submit(req))
		require.Equal(t, 1, f.node.early.len())
		f.setParent(1, f.pdr)
		f.replay()
		require.Zero(t, f.node.early.len())
		require.Zero(t, f.counted(), "full revalidation refuses it")
		require.Equal(t, 1, f.sentCount(), "and the node is told why")
	})
}

// Two different requests of one node for the same future round: the first stays held, the second is refused (and answered).
func TestConflictingNearFutureRequestsAreRefused(t *testing.T) {
	f := newFixture(t, fxOpts{})
	_, next, reqs := f.futureRequests(9, 0)
	other := f.request(0, next, 10, nil)
	require.NoError(t, f.submit(reqs[0]))
	require.NoError(t, f.submit(reqs[0]), "the same bytes again are idempotent")
	err := f.submit(other)
	require.ErrorIs(t, err, errEarlyConflict)
	require.ErrorIs(t, err, storage.ErrStaleRequestContext)
	require.Equal(t, 1, f.sentCount())
	require.Equal(t, 1, f.node.early.len())
	f.setParent(1, f.pdr)
	f.replay()
	require.Equal(t, 1, f.counted(), "the first request is the one counted")
}

// At an activation boundary the commit installs another assignment: the held request is judged under it, and a node the new
// assignment does not hold is not counted.
func TestHeldRequestAtAnActivationBoundaryIsJudgedUnderTheNewAssignment(t *testing.T) {
	f := newFixture(t, fxOpts{})
	_, _, reqs := f.futureRequests(9, 0, 1, 2, 3)
	for _, r := range reqs {
		require.NoError(t, f.submit(r))
	}
	// the successor assignment drops node 3
	succ := *f.pdr
	succ.Validators = f.pdr.Validators[:3]
	f.setParent(1, &succ)
	f.replay()
	certs := f.certs()
	require.Len(t, certs, 1, "three of the new three members are a quorum")
	for _, r := range certs[0].Requests {
		require.NotEqual(t, f.infos[3].NodeID, r.NodeID, "the dropped member is not counted")
	}
}

// The buffer's bounds: one request per node and round, a cap per shard, on rounds per shard and on shards, a size cap per request and
// a byte budget, and an entry expires at its first deadline however often it is held again.
func TestEarlyRequestBufferBoundsAndExpiry(t *testing.T) {
	nodes, _ := testutils.CreateTestNodes(t, 1)
	now := time.Unix(1000, 0)
	b := newEarlyRequests()
	b.now = func() time.Time { return now }
	req := func(partition types.PartitionID, node string, round uint64) *certification.BlockCertificationRequest {
		r := &certification.BlockCertificationRequest{PartitionID: partition, NodeID: node, InputRecord: &types.InputRecord{Version: 1, RoundNumber: round,
			PreviousHash: []byte{1}, Hash: []byte{2}, BlockHash: []byte{3}, SummaryValue: []byte{4}, Timestamp: 1}}
		require.NoError(t, r.Sign(nodes[0].Signer))
		return r
	}
	for i := range earlyRequestsPerShard {
		require.NoError(t, b.hold(req(1, string(rune('a'+i)), 5), time.Time{}))
	}
	require.ErrorIs(t, b.hold(req(1, "overflow", 5), time.Time{}), errEarlyFull)
	require.ErrorIs(t, b.hold(req(1, "a", 6), time.Time{}), errEarlyFull, "a newer round never displaces what is held")
	require.Equal(t, earlyRequestsPerShard, b.len())

	for p := 2; p <= earlyRequestShards; p++ {
		require.NoError(t, b.hold(req(types.PartitionID(p), "a", 5), time.Time{}))
	}
	require.ErrorIs(t, b.hold(req(types.PartitionID(earlyRequestShards+1), "a", 5), time.Time{}), errEarlyFull)

	// expiry at the first deadline, also across a take and a re-hold
	now = now.Add(earlyRequestTTL / 2)
	taken := b.take(1, types.ShardID{})
	require.Len(t, taken, earlyRequestsPerShard)
	o := taken[0].origin
	o.replay, o.reserved = true, taken[0].size
	require.NoError(t, b.holdOrigin(taken[0].req, &o))
	require.True(t, o.reheld)
	for _, e := range taken[1:] {
		b.release(e) // admitted or refused: released
	}
	now = now.Add(earlyRequestTTL/2 + time.Millisecond)
	require.Zero(t, b.len(), "everything expired")
	require.Zero(t, b.bytes, "and its bytes are released")
	require.Empty(t, b.shardsHeld())
	require.Error(t, b.hold(taken[0].req, taken[0].origin.deadline), "an expired entry is never held again")
	require.NoError(t, b.hold(req(1, "a", 5), time.Time{}), "the buffer is usable after expiry")
}

// Two rounds per shard at most, each its own set: a request for the round after the held one (the context advanced before the held set
// was replayed) is held beside it, a third round is refused, and the held set is replayed first.
func TestEarlyRequestBufferKeepsAHeldRoundBesideANewerOne(t *testing.T) {
	nodes, _ := testutils.CreateTestNodes(t, 1)
	b := newEarlyRequests()
	req := func(node string, round uint64) *certification.BlockCertificationRequest {
		r := &certification.BlockCertificationRequest{PartitionID: 1, NodeID: node, InputRecord: &types.InputRecord{Version: 1, RoundNumber: round,
			PreviousHash: []byte{1}, Hash: []byte{2}, BlockHash: []byte{3}, SummaryValue: []byte{4}, Timestamp: 1}}
		require.NoError(t, r.Sign(nodes[0].Signer))
		return r
	}
	for _, n := range []string{"a", "b", "c"} {
		require.NoError(t, b.hold(req(n, 5), time.Time{}))
	}
	require.NoError(t, b.hold(req("a", 6), time.Time{}))
	require.ErrorIs(t, b.hold(req("a", 7), time.Time{}), errEarlyFull)
	taken := b.take(1, types.ShardID{})
	require.Len(t, taken, 4, "the held quorum of round 5 is intact")
	for i := 0; i < 3; i++ {
		require.EqualValues(t, 5, taken[i].req.IRRound(), "the older round first")
	}
	require.EqualValues(t, 6, taken[3].req.IRRound())
}

// A request whose encoding is larger than the per-request bound (its proof is verified only at admission) is not held, and the byte
// budget bounds what all held requests may carry.
func TestEarlyRequestBufferBoundsTheBytesItHolds(t *testing.T) {
	nodes, _ := testutils.CreateTestNodes(t, 1)
	b := newEarlyRequests()
	req := func(partition types.PartitionID, proof int) *certification.BlockCertificationRequest {
		r := &certification.BlockCertificationRequest{PartitionID: partition, NodeID: fmt.Sprintf("n%d", partition), InputRecord: &types.InputRecord{Version: 1, RoundNumber: 5,
			PreviousHash: []byte{1}, Hash: []byte{2}, BlockHash: []byte{3}, SummaryValue: []byte{4}, Timestamp: 1}, ZkProof: make([]byte, proof)}
		require.NoError(t, r.Sign(nodes[0].Signer))
		return r
	}
	require.ErrorIs(t, b.hold(req(1, 8<<20), time.Time{}), errEarlyTooLarge, "an 8 MB proof is never retained unverified")
	require.Zero(t, b.len())
	near := earlyRequestMaxBytes - 4096
	n := 0
	for p := types.PartitionID(1); ; p++ {
		err := b.hold(req(p, near), time.Time{})
		if err != nil {
			require.ErrorIs(t, err, errEarlyFull)
			break
		}
		n++
	}
	require.LessOrEqual(t, b.bytes, earlyRequestBudget)
	require.Equal(t, earlyRequestBudget/earlyRequestMaxBytes, n, "the budget, not the shard count, bounds large requests")

	// one signer's bytes over all shards are bounded on their own
	s := newEarlyRequests()
	held := 0
	for p := types.PartitionID(1); p <= 10; p++ {
		r := req(p, near)
		r.NodeID = "one"
		require.NoError(t, r.Sign(nodes[0].Signer))
		if err := s.hold(r, time.Time{}); err != nil {
			require.ErrorIs(t, err, errEarlyFull)
			break
		}
		held++
	}
	require.Equal(t, earlyRequestsPerSigner/earlyRequestMaxBytes, held, "the signer budget")
}

// epochCM is the fixture's manager with an installed root epoch.
type epochCM struct {
	*viewCM
	epoch uint64
}

func (c *epochCM) InstalledRootEpoch() uint64 { return c.epoch }

// The T6 failure mode (#1032): a request held in the closing root epoch must not be admitted after the activation, where it would be
// certified without the transition the new epoch's first block carries. It is dropped at replay; one held and replayed within one
// epoch is admitted.
func TestAHeldRequestIsNeverCarriedAcrossARootActivation(t *testing.T) {
	f := newFixture(t, fxOpts{})
	cm := &epochCM{viewCM: f.cm, epoch: 1}
	f.node.consensusManager = cm
	_, _, reqs := f.futureRequests(9, 0, 1, 2)
	for _, r := range reqs {
		require.NoError(t, f.submit(r))
	}
	require.Equal(t, 3, f.node.early.len())
	f.setParent(1, f.pdr)
	cm.epoch = 2 // the commit that advanced the shard's context also activated the next root epoch
	f.replay()
	require.Zero(t, f.node.early.len())
	require.Zero(t, f.counted(), "nothing of the closed epoch is counted")
	require.Empty(t, f.certs())

	// within one epoch the same flow certifies
	g := newFixture(t, fxOpts{})
	g.node.consensusManager = &epochCM{viewCM: g.cm, epoch: 2}
	_, _, reqs = g.futureRequests(9, 0, 1, 2)
	for _, r := range reqs {
		require.NoError(t, g.submit(r))
	}
	g.setParent(1, g.pdr)
	g.replay()
	require.Len(t, g.certs(), 1)
}

// A newer request reaching the node before the replay of a ready held quorum does not displace it: after the commit the held quorum is
// certified.
func TestANewerRequestDoesNotEvictAReadyHeldQuorum(t *testing.T) {
	f := newFixture(t, fxOpts{})
	_, next, reqs := f.futureRequests(9, 0, 1, 2)
	for _, r := range reqs {
		require.NoError(t, f.submit(r))
	}
	f.setParent(1, f.pdr) // the commit applies, the replay has not run yet
	// a request two rounds ahead of the held ones' predecessor: one ahead of the context now in force
	newer := f.request(3, next, 9, func(r *certification.BlockCertificationRequest) { r.InputRecord.RoundNumber++ })
	require.NoError(t, f.submit(newer), "held beside the ready set")
	require.Equal(t, 4, f.node.early.len())
	f.replay()
	require.Len(t, f.certs(), 1, "the held quorum is certified")
}

// The legacy dispatch (no view-aware branch selected, before the first activation) holds a near-future request the same way.
func TestLegacyDispatchHoldsTheNextRoundRequest(t *testing.T) {
	f := newFixture(t, fxOpts{})
	_, _, reqs := f.futureRequests(9, 0, 1, 2)
	f.cm.enabled = false
	for _, r := range reqs {
		require.NoError(t, f.submit(r), "held under the committed ShardInfo, not refused")
	}
	require.Zero(t, f.sentCount())
	require.Zero(t, f.counted())
	require.Equal(t, 3, f.node.early.len())
	f.setParent(1, f.pdr)
	f.replay()
	require.Len(t, f.certs(), 1, "admitted under the advanced ShardInfo, a quorum of three")
	two := f.request(3, f.viewEnabled(), 9, func(r *certification.BlockCertificationRequest) { r.InputRecord.RoundNumber += 2 })
	require.Error(t, f.submit(two), "two rounds ahead is refused")
	require.Zero(t, f.node.early.len())
}

// viewEnabled is the view the collector would resolve, whether or not the branch is selected.
func (f *fixture) viewEnabled() *storage.RequestRoundView {
	f.t.Helper()
	f.cm.mu.Lock()
	was := f.cm.enabled
	f.cm.enabled = true
	f.cm.mu.Unlock()
	v := f.view()
	f.cm.mu.Lock()
	f.cm.enabled = was
	f.cm.mu.Unlock()
	return v
}

// Ready signals are never lost: many shards becoming ready at once wake the loop once and are all drained.
func TestReplaySignalsAreNotLost(t *testing.T) {
	nodes, _ := testutils.CreateTestNodes(t, 1)
	b := newEarlyRequests()
	for p := types.PartitionID(1); p <= 50; p++ {
		r := &certification.BlockCertificationRequest{PartitionID: p, NodeID: "a", InputRecord: &types.InputRecord{Version: 1, RoundNumber: 5,
			PreviousHash: []byte{1}, Hash: []byte{2}, BlockHash: []byte{3}, SummaryValue: []byte{4}, Timestamp: 1}}
		require.NoError(t, r.Sign(nodes[0].Signer))
		require.NoError(t, b.hold(r, time.Time{}))
	}
	for p := types.PartitionID(1); p <= 60; p++ { // ten shards without held requests are not marked
		b.markReady(p, types.ShardID{})
	}
	<-b.notify
	require.Len(t, b.takeReady(), 50)
	select {
	case <-b.notify:
		t.Fatal("one wake-up for all of them")
	default:
	}
}

// A refusal under a view that is no longer in force is judged again: an activation that admits a new member between the resolution
// and the check does not refuse the member's request.
func TestMembershipRefusalIsJudgedAgainUnderTheCurrentView(t *testing.T) {
	f := newFixture(t, fxOpts{})
	// the current assignment lacks node 3; the next one holds it
	without := *f.pdr
	without.Validators = f.pdr.Validators[:3]
	f.setParent(0, &without)
	oldSI, oldID := f.si, f.parentID
	f.setParent(1, f.pdr)
	next := f.view()
	newSI, newID := f.si, f.parentID
	req := f.request(3, next, 9, nil)
	calls := 0
	anchorOld, err := storage.NewRequestAnchor(&without, crypto.SHA256, fxRootEp, fxBody, fxVersion)
	require.NoError(t, err)
	anchorNew, err := storage.NewRequestAnchor(f.pdr, crypto.SHA256, fxRootEp, fxBody, fxVersion)
	require.NoError(t, err)
	hist := &switchingHistory{old: anchorOld, new: anchorNew}
	parent := func(types.PartitionID, types.ShardID) (*storage.ShardInfo, []byte, *types.InputRecord, error) {
		calls++
		if calls == 1 {
			return oldSI, oldID, nil, nil
		}
		hist.switched = true
		return newSI, newID, nil, nil
	}
	resolver, err := consensus.NewRequestViewResolver(hist, crypto.SHA256, parent, nil)
	require.NoError(t, err)
	f.cm.resolver = resolver
	require.NoError(t, f.submit(req))
	require.Equal(t, 2, calls)
	require.Equal(t, 1, f.counted())
}

// switchingHistory serves the old anchor until the activation switches it to the new one.
type switchingHistory struct {
	old, new *storage.RequestActivation
	switched bool
}

func (h *switchingHistory) Chain(types.PartitionID, types.ShardID) ([]*storage.RequestActivation, error) {
	if h.switched {
		return []*storage.RequestActivation{h.new}, nil
	}
	return []*storage.RequestActivation{h.old}, nil
}
func (*switchingHistory) Network() uint64 { return fxNetwork }
func (*switchingHistory) Version() uint64 { return fxVersion }
func (*switchingHistory) RootIdentity(uint64) (uint64, []byte, error) {
	return fxRootEp, fxBody, nil
}

// authorityHistory is the fixture's one-anchor history whose root authority (epoch and body) the test moves, as a root-only
// continuation does: the assignment, keys and shard continuity stay, only the authorising root identity changes.
type authorityHistory struct {
	anchor *storage.RequestActivation
	mu     sync.Mutex
	epoch  uint64
	body   []byte
}

func (h *authorityHistory) Chain(types.PartitionID, types.ShardID) ([]*storage.RequestActivation, error) {
	return []*storage.RequestActivation{h.anchor}, nil
}
func (*authorityHistory) Network() uint64 { return fxNetwork }
func (*authorityHistory) Version() uint64 { return fxVersion }
func (h *authorityHistory) RootIdentity(uint64) (uint64, []byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.epoch, h.body, nil
}

// fencedFixture is the fixture under a manager with an installed root epoch, with a hook run on every parent read of a resolution
// (the point where an activation can land between the replay's start and the count).
type fencedFixture struct {
	*fixture
	cm      *epochCM
	hist    *authorityHistory
	onParse func(call int)
	calls   int
}

func newFencedFixture(t *testing.T) *fencedFixture {
	f := newFixture(t, fxOpts{})
	ff := &fencedFixture{fixture: f, cm: &epochCM{viewCM: f.cm, epoch: 3}}
	f.node.consensusManager = ff.cm
	anchor, err := storage.NewRequestAnchor(f.pdr, crypto.SHA256, fxRootEp, fxBody, fxVersion)
	require.NoError(t, err)
	ff.hist = &authorityHistory{anchor: anchor, epoch: fxRootEp, body: fxBody}
	ff.rewire(t)
	return ff
}

// rewire resolves through the authority history over the fixture's current parent, calling the hook on every resolution.
func (ff *fencedFixture) rewire(t *testing.T) {
	parent := func(types.PartitionID, types.ShardID) (*storage.ShardInfo, []byte, *types.InputRecord, error) {
		ff.calls++
		if ff.onParse != nil {
			ff.onParse(ff.calls)
		}
		return ff.si, ff.parentID, nil, nil
	}
	resolver, err := consensus.NewRequestViewResolver(ff.hist, crypto.SHA256, parent, nil)
	require.NoError(t, err)
	ff.fixture.cm.resolver = resolver
}

// advance commits the shard's round (the fixture's parent moves on) under the authority history.
func (ff *fencedFixture) advance(t *testing.T) {
	ff.setParent(1, ff.pdr)
	ff.rewire(t)
}

func (ff *fencedFixture) held(t *testing.T) []*certification.BlockCertificationRequest {
	_, _, reqs := ff.futureRequests(9, 0, 1, 2)
	ff.rewire(t)
	for _, r := range reqs {
		require.NoError(t, ff.submit(r))
	}
	require.Equal(t, 3, ff.node.early.len())
	return reqs
}

// An activation lands after the batch replay started and before the held requests are counted: none of them is counted or handed over,
// and their reservations are released.
func TestActivationDuringBatchReplayCountsNoHeldRequest(t *testing.T) {
	ff := newFencedFixture(t)
	ff.held(t)
	ff.advance(t)
	ff.calls = 0
	ff.onParse = func(call int) {
		if call == 1 {
			ff.cm.epoch = 4 // the first replayed request's resolution races the activation
		}
	}
	ff.replay()
	require.Empty(t, ff.certs(), "no quorum of the closed epoch is handed over")
	require.Zero(t, ff.counted())
	require.Zero(t, ff.node.early.len())
	require.Zero(t, ff.node.early.bytes, "every reservation released")
}

// A root-only continuation moves the root authority while the installed epoch, the assignment, keys and continuity stay: a held request
// is not admitted under the continuation's view.
func TestHeldRequestIsNotAdmittedUnderARootOnlyContinuation(t *testing.T) {
	ff := newFencedFixture(t)
	ff.held(t)
	ff.advance(t)
	ff.hist.mu.Lock()
	ff.hist.epoch, ff.hist.body = fxRootEp+1, bytes.Repeat([]byte{0xA1}, 32)
	ff.hist.mu.Unlock()
	ff.replay()
	require.Empty(t, ff.certs())
	require.Zero(t, ff.counted(), "membership and continuity pass; the root authority does not")
	require.Zero(t, ff.node.early.bytes)
}

// A replay without progress re-holds the requests under their first origin; an activation during that replay re-holds nothing (the
// current epoch is never stamped on an old request), and a later replay cannot hand the old quorum over.
func TestReholdWithoutProgressKeepsTheOriginAndAnActivationDropsIt(t *testing.T) {
	ff := newFencedFixture(t)
	ff.held(t)
	ff.replay() // no commit: still one round ahead
	require.Equal(t, 3, ff.node.early.len())
	for _, s := range ff.node.early.shards {
		for _, set := range s.rounds {
			for _, e := range set {
				require.EqualValues(t, 3, e.origin.epoch, "the first origin is kept")
				require.NotNil(t, e.origin.authority)
			}
		}
	}
	bytesHeld := ff.node.early.bytes
	require.Positive(t, bytesHeld)
	ff.calls = 0
	ff.onParse = func(call int) {
		if call == 1 {
			ff.cm.epoch = 4
		}
	}
	ff.replay() // the activation lands during this replay, still without progress
	require.Zero(t, ff.node.early.len(), "nothing re-held under epoch 4")
	require.Zero(t, ff.node.early.bytes)
	ff.onParse = nil
	ff.advance(t)
	ff.replay()
	require.Empty(t, ff.certs())
}

// An activation during the resolution of a request just received: it is not held under either epoch.
func TestActivationDuringResolutionHoldsNothing(t *testing.T) {
	ff := newFencedFixture(t)
	_, _, reqs := ff.futureRequests(9, 0)
	ff.rewire(t)
	ff.calls = 0
	ff.onParse = func(call int) {
		if call == 1 {
			ff.cm.epoch = 4
		}
	}
	require.ErrorIs(t, ff.submit(reqs[0]), errHeldAcrossActivation)
	require.Zero(t, ff.node.early.len())
}

// A replayed request counted into a shard's buffer fences every hand-over of the shard to its epoch; the shard's buffer and fence clear
// with its certificate.
func TestAReplayedQuorumIsHandedOverWithItsRootEpoch(t *testing.T) {
	ff := newFencedFixture(t)
	ff.held(t)
	ff.advance(t)
	ff.replay()
	certs := ff.certs()
	require.Len(t, certs, 1)
	require.EqualValues(t, 3, certs[0].RootEpoch)
	ff.node.clearShard(context.Background(), 1, types.ShardID{})
	require.Zero(t, ff.node.fencedEpoch(1, types.ShardID{}))
}

// Reservations are conserved across take, re-hold, admission and refusal.
func TestEarlyReservationsAreConservedAcrossReplay(t *testing.T) {
	nodes, _ := testutils.CreateTestNodes(t, 1)
	b := newEarlyRequests()
	r := &certification.BlockCertificationRequest{PartitionID: 1, NodeID: "a", InputRecord: &types.InputRecord{Version: 1, RoundNumber: 5,
		PreviousHash: []byte{1}, Hash: []byte{2}, BlockHash: []byte{3}, SummaryValue: []byte{4}, Timestamp: 1}, ZkProof: make([]byte, earlyRequestMaxBytes-4096)}
	require.NoError(t, r.Sign(nodes[0].Signer))
	require.NoError(t, b.hold(r, time.Time{}))
	size := b.bytes
	taken := b.take(1, types.ShardID{})
	require.Len(t, taken, 1)
	require.Equal(t, size, b.bytes, "a taken request keeps its reservation")
	// while the taken request is out, the signer's budget still counts it
	other := *r
	other.PartitionID = 2
	require.NoError(t, other.Sign(nodes[0].Signer))
	require.NoError(t, b.hold(&other, time.Time{}))
	third := *r
	third.PartitionID = 3
	require.NoError(t, third.Sign(nodes[0].Signer))
	require.ErrorIs(t, b.hold(&third, time.Time{}), errEarlyFull, "the signer budget counts the taken request")
	// re-hold transfers the reservation
	o := taken[0].origin
	o.replay, o.reserved = true, taken[0].size
	require.NoError(t, b.holdOrigin(taken[0].req, &o))
	require.True(t, o.reheld)
	require.Equal(t, 2*size, b.bytes)
	// a refused replay releases it
	again := b.take(1, types.ShardID{})
	b.release(again[0])
	require.Equal(t, size, b.bytes)
}
