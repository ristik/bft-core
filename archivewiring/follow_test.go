package archivewiring

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredadmission"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

type followRecord struct {
	q   archive.Request
	rec *archive.Record
}

// followSource is an archive replica holding the given records that serves a non-validator follower through its public read budget.
func followSource(t *testing.T, follower *network.Peer, f *wiringFixture, records []followRecord) peer.ID {
	t.Helper()
	remote := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	follower.Network().Peerstore().AddAddrs(remote.ID(), remote.MultiAddresses(), peerstore.PermanentAddrTTL)
	store, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	for _, r := range records {
		require.NoError(t, store.Put(r.q, r.rec))
	}
	server, err := NewServer(store, f.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{"validator"}, DefaultLimits())
	require.NoError(t, err)
	require.NoError(t, server.SetPublicReads(Limits{Deadline: 5 * time.Second, Pending: 4, PerPeer: 2}))
	server.Register(context.Background(), remote)
	return remote.ID()
}

// The root-free head follower offers the newest certificate it can verify from any source, ignores a source whose newer head is forged,
// offers nothing twice, and offers nothing while the node is active.
func TestHeadFollowerOffersTheNewestVerifiedHeadOnly(t *testing.T) {
	t.Parallel()
	f := newWiringFixture(t, 4)
	follower := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	var all, behind []followRecord
	for i := range f.entries {
		q, rec := f.record(t, i)
		all = append(all, followRecord{q, rec})
		if i < 2 {
			behind = append(behind, followRecord{q, rec})
		}
	}
	// a source whose newest record (block 4) carries a forged resulting certificate: a higher root round with a broken seal
	forged := append([]followRecord(nil), behind...)
	q4, rec4 := f.record(t, 3)
	bad := *rec4
	var result types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(rec4.ResultingUC, &result))
	result.UnicitySeal.RootChainRoundNumber += 100
	raw, err := types.Cbor.Marshal(&result)
	require.NoError(t, err)
	bad.ResultingUC = raw
	forged = append(forged, followRecord{q4, &bad})

	sources := []peer.ID{followSource(t, follower, f, forged), followSource(t, follower, f, behind), followSource(t, follower, f, all)}
	var offered []*types.UnicityCertificate
	active := false
	h := &HeadFollower{Binding: CertifiedBinding{Context: f.context, Subject: f.subject}, Host: follower, Limits: DefaultLimits(),
		Sources: func() []peer.ID { return sources }, Active: func() bool { return active },
		Offer: func(uc *types.UnicityCertificate, _ *certification.TechnicalRecord) bool {
			offered = append(offered, uc)
			return true
		}}
	require.True(t, h.Poll(context.Background()))
	require.Len(t, offered, 1)
	var want types.UnicityCertificate
	newest := uint64(0)
	for _, r := range all { // the newest genuine record's resulting certificate
		var uc types.UnicityCertificate
		require.NoError(t, types.Cbor.Unmarshal(r.rec.ResultingUC, &uc))
		if uc.GetRootRoundNumber() > newest {
			newest, want = uc.GetRootRoundNumber(), uc
		}
	}
	require.Equal(t, want.GetRootRoundNumber(), offered[0].GetRootRoundNumber(), "the newest verified head, not the forged one")
	require.Equal(t, want.InputRecord.BlockHash, offered[0].InputRecord.BlockHash)
	require.False(t, h.Poll(context.Background()), "the same head is not offered twice")

	active = true
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	h.offered, h.Interval = nil, 10*time.Millisecond
	require.NoError(t, h.Run(ctx))
	require.Len(t, offered, 1, "an active node takes its certificates from the roots, not the follower")
}

// The continuous root-free follower end to end below the process: a node that starts empty follows the archive head, the journal
// admission's archive catch-up executes the missing suffix, and as the chain grows the node extends from its retained journal and
// execution state. A process restart in the middle keeps the state and continues: nothing is restored or wiped, and the executor's
// finalized head only moves forward.
func TestHeadFollowerFollowsIncrementallyFromRetainedState(t *testing.T) {
	t.Parallel()
	const total = 24
	p := newPlanFixture(t, total)
	p.serve(t, 1, 10)
	n := newReturningNode(t, p, map[string]*archive.Store{replicaA: p.replica, replicaB: p.second})
	recovery := n.recovery
	var finalized []uint64
	offer := func(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) bool {
		ctx := context.Background()
		for calls := 0; calls < 60; calls++ {
			err := recovery.AcquireForCertificate(ctx, uc, tr)
			if err == nil {
				head, err := recovery.Recover(ctx, uc)
				require.NoError(t, err)
				finalized = append(finalized, head.Number)
				return true
			}
			require.ErrorIs(t, err, configuredadmission.ErrRecoveryUnavailable)
			require.False(t, recovery.Terminal(err), "%v", err)
		}
		t.Fatal("the followed head was not reached")
		return false
	}
	h := &HeadFollower{Binding: CertifiedBinding{Context: p.f.context, Subject: p.f.subject}, Host: p.source.Host, Limits: DefaultLimits(),
		Sources: func() []peer.ID { return p.source.Replicas }, Offer: offer}

	require.True(t, h.Poll(context.Background()))
	require.EqualValues(t, 10, n.exec.finalized.Number, "followed from empty to the archive head")

	p.serve(t, 11, 17)
	require.True(t, h.Poll(context.Background()))
	require.EqualValues(t, 17, n.exec.finalized.Number, "extended from the retained state")

	// a process restart that keeps its state: a new coordinator over the same journal and execution client
	recovery = &configuredadmission.ExecutionRecovery{Store: n.store, Context: p.f.context, JournalLimits: n.limits, Executor: n.exec, Gate: shardnode.NewFinalityGate(),
		Genesis: p.genesis, Limits: n.recovery.Limits, FetchArchive: p.source.FetchSuffix, ArchiveCatchUp: &CatchUp{Source: p.source, Frontier: n.worker}}
	h.offered = nil
	p.serve(t, 18, total)
	require.True(t, h.Poll(context.Background()))
	require.EqualValues(t, total, n.exec.finalized.Number, "continued after the restart without a restore")
	require.Equal(t, []uint64{10, 17, total}, finalized, "the finalized head only moves forward")
	require.False(t, h.Poll(context.Background()), "nothing newer: nothing offered")
}
