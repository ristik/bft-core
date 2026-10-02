package archivewiring

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/frontier"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
)

// A replaced archive replica leaves a persisted, unpruned frontier whose
// acknowledgments name the retired replica. The worker must keep auditing the
// retained replica, refrain from pruning until the new pair acknowledges beyond
// the position, then advance and prune under the configured pair.
func TestFrontierWorkerResumesAfterArchiveReplicaReplacement(t *testing.T) {
	t.Parallel()
	f := newWiringFixture(t, 6)
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	remotes := make([]*network.Peer, 3)
	stores := make([]*archive.Store, 3)
	for i := range remotes {
		remotes[i] = testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
		sender.Network().Peerstore().AddAddrs(remotes[i].ID(), remotes[i].MultiAddresses(), peerstore.PermanentAddrTTL)
		var err error
		stores[i], err = archive.Open(t.TempDir())
		require.NoError(t, err)
		server, err := NewServer(stores[i], f.subject, JournalVerifier(f.store, f.context, f.limits, f.subject), []peer.ID{sender.ID()}, DefaultLimits())
		require.NoError(t, err)
		server.Register(context.Background(), remotes[i])
	}
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	for i := range f.entries {
		q, rec := f.record(t, i)
		for _, s := range append([]*archive.Store{local}, stores...) {
			require.NoError(t, s.Put(q, rec))
		}
	}
	policyFor := func(replicas [2]peer.ID) frontier.Policy {
		return frontier.Policy{Context: f.subject, Replicas: [2]string{replicas[0].String(), replicas[1].String()}, Binding: CertifiedBinding{Context: f.context, Subject: f.subject},
			Availability: ReplicaAvailability{Context: context.Background(), Host: sender, Replicas: replicas, Limits: DefaultLimits()}}
	}
	before := [2]peer.ID{remotes[0].ID(), remotes[1].ID()}
	require.NoError(t, f.store.EnableFrontier(context.Background(), f.context, f.limits, policyFor(before)))

	// Height one is acknowledged by the original pair and not yet pruned.
	index := -1
	for i, entry := range f.entries {
		if entry.Candidate.Number == 1 {
			index = i
		}
	}
	require.GreaterOrEqual(t, index, 0)
	q, rec := f.record(t, index)
	request, err := archive.EncodeRequest(q)
	require.NoError(t, err)
	digest, err := archive.ManifestDigest(q, rec)
	require.NoError(t, err)
	var state [32]byte
	copy(state[:], f.entries[index].Candidate.StateRoot)
	ack := sha256.Sum256(request)
	item := frontier.Coverage{Anchor: frontier.Record{Sequence: 1, Height: 1, Epoch: f.entries[index].ResultingUC.GetRootEpoch(), Round: f.entries[index].ResultingUC.GetRootRoundNumber(), StateRoot: state, Subject: q,
		Acks: [2]frontier.Acknowledgment{{Replica: before[0].String(), RequestDigest: ack, ManifestDigest: digest}, {Replica: before[1].String(), RequestDigest: ack, ManifestDigest: digest}}}, Material: rec}
	require.NoError(t, f.store.AdvanceFrontier(context.Background(), f.context, f.limits, []frontier.Coverage{item}))

	// The second replica is replaced by the third.
	after := [2]peer.ID{remotes[0].ID(), remotes[2].ID()}
	require.NoError(t, f.store.EnableFrontier(context.Background(), f.context, f.limits, policyFor(after)))
	snap, err := f.store.LoadFrontier(context.Background(), f.context, f.limits)
	require.NoError(t, err)
	require.True(t, snap.Anchor.Migrated())
	require.Zero(t, snap.Floor)

	worker := &FrontierWorker{Journal: f.store, Context: f.context, Limits: f.limits, Archive: local, Subject: f.subject, Replicas: after, Host: sender, TransportLimits: DefaultLimits()}
	require.NoError(t, worker.Pass(context.Background()), "audit, copy verification and the prune gate must tolerate the dropped acknowledgment")
	snap, err = f.store.LoadFrontier(context.Background(), f.context, f.limits)
	require.NoError(t, err)
	require.Greater(t, snap.Anchor.Height, uint64(1), "the configured pair acknowledged beyond the position")
	require.False(t, snap.Anchor.Migrated())
	require.Equal(t, snap.Anchor.Height, snap.Floor, "pruning resumed under the configured pair")
	require.Equal(t, after[1].String(), snap.Anchor.Acks[1].Replica)
}
