package archivewiring

import (
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/frontier"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// adoptionHarness: #879's four independent journals made real. Three replica journals hold the canonical certificate A for every block and have archived, covered and pruned
// them; each runs a real archive server over its own archive store and its own journal. The sender's journal holds the other valid certificate B for block 2. Its frontier worker
// talks to the replicas over the real transport with the derived three-replica policy.
type adoptionHarness struct {
	*divergenceFixture
	local      *archive.Store
	stores     []*archive.Store
	peers      []peer.ID
	sender     *network.Peer
	senderJrnl *wiringFixture
	digestA    [32]byte
	digestB    [32]byte
	qBlock     archive.Request
	recA, recB *archive.Record
	finalized  uint64
}

const adoptionBlocks, adoptionDiverged = 6, 2

func newAdoptionHarness(t *testing.T) *adoptionHarness {
	t.Helper()
	d := newDivergenceFixture(t, adoptionBlocks, adoptionDiverged)
	h := &adoptionHarness{divergenceFixture: d, senderJrnl: d.sender}
	ri, si := d.replicas[0].indexOf(t, adoptionDiverged), d.sender.indexOf(t, adoptionDiverged)
	h.qBlock, h.recA = d.replicas[0].record(t, ri)
	_, h.recB = d.sender.record(t, si)
	var err error
	h.digestA, err = archive.ManifestDigest(h.qBlock, h.recA)
	require.NoError(t, err)
	h.digestB, err = archive.ManifestDigest(h.qBlock, h.recB)
	require.NoError(t, err)
	require.NotEqual(t, h.digestA, h.digestB)

	h.stores = make([]*archive.Store, 3)
	for i, r := range d.replicas {
		h.stores[i] = r.archiveAll(t)
	}
	for i, r := range d.replicas {
		r.pruneThrough(t, adoptionBlocks, h.stores[i], h.stores[(i+1)%3], h.stores[(i+2)%3])
	}
	h.sender = testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	for i, r := range d.replicas {
		remote := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
		h.peers = append(h.peers, remote.ID())
		h.sender.Network().Peerstore().AddAddrs(remote.ID(), remote.MultiAddresses(), peerstore.PermanentAddrTTL)
		server, err := NewServer(h.stores[i], r.subject, JournalVerifier(r.store, r.context, d.limits, r.subject), []peer.ID{h.sender.ID()}, DefaultLimits())
		require.NoError(t, err)
		server.Register(context.Background(), remote)
	}
	h.local = d.sender.archiveAll(t) // the sender's own records: B for block 2
	h.finalized = adoptionBlocks
	var names []string
	for _, id := range h.peers {
		names = append(names, id.String())
	}
	policy := frontier.Policy{Context: d.sender.subject, Eligible: names, PolicyDigest: testPolicyDigest, Binding: CertifiedBinding{Context: d.sender.context, Subject: d.sender.subject},
		Availability: ReplicaAvailability{Context: context.Background(), Host: h.sender, Replicas: h.peers, Limits: DefaultLimits()}}
	require.NoError(t, d.sender.store.EnableFrontier(context.Background(), d.sender.context, d.sender.limits, policy))
	return h
}

// worker is a fresh frontier worker of the sender (a restart: no volatile state).
func (h *adoptionHarness) worker() *FrontierWorker {
	f := h.sender
	_ = f
	return &FrontierWorker{Journal: h.senderJrnl.store, Context: h.senderJrnl.context, Limits: h.senderJrnl.limits, Archive: h.local, Subject: h.senderJrnl.subject, Replicas: h.peers,
		PolicyDigest: testPolicyDigest, Host: h.sender, TransportLimits: DefaultLimits(),
		Finalized: func(context.Context) (shardnode.BlockRef, error) {
			for _, e := range h.senderJrnl.entries {
				if e.Candidate.Number == h.finalized {
					return shardnode.BlockRef{Number: e.Candidate.Number, Hash: e.Candidate.Hash}, nil
				}
			}
			return shardnode.BlockRef{}, nil
		}}
}

func (h *adoptionHarness) anchorHeight(t *testing.T) uint64 {
	t.Helper()
	img, err := h.senderJrnl.store.LoadJournal(context.Background(), h.senderJrnl.context, h.senderJrnl.limits)
	require.NoError(t, err)
	if img.Frontier == nil || img.Frontier.Anchor == nil {
		return 0
	}
	return img.Frontier.Anchor.Height
}

// Red today (#879): the sender holds B, the replicas covered and pruned A, every RPC healthy. Its frontier cannot pass block 2. With adoption it selects A (two replicas return the
// exact A, the full binding and the equal-field rules hold), keeps B's bytes, advances and prunes.
func TestAdoptReplicaManifestUnblocksRestartDivergence(t *testing.T) {
	t.Parallel()
	h := newAdoptionHarness(t)
	ctx := context.Background()
	for pass := 0; pass < 6; pass++ {
		_ = h.worker().Pass(ctx)
	}
	require.EqualValues(t, adoptionBlocks, h.anchorHeight(t), "the frontier passes the diverged block and covers everything")

	// B is untouched: the journal's association, the base object of the request, the local archive's B bytes
	img, err := h.senderJrnl.store.LoadJournal(ctx, h.senderJrnl.context, h.senderJrnl.limits)
	require.NoError(t, err)
	baseGot, err := h.local.Get(h.qBlock)
	require.NoError(t, err)
	gotDigest, err := archive.ManifestDigest(h.qBlock, baseGot)
	require.NoError(t, err)
	require.Equal(t, h.digestB, gotDigest, "the base object of the request is still B")
	exactA, err := h.local.GetExact(h.qBlock, h.digestA)
	require.NoError(t, err)
	require.Equal(t, h.recA.ResultingUC, exactA.ResultingUC, "A is stored as its own immutable object")

	// the coverage promise at block 2 is A's manifest, and the block's coverage was made once
	cov, err := h.senderJrnl.store.LoadCoverage(ctx, h.senderJrnl.context, h.senderJrnl.limits, 0, 16)
	require.NoError(t, err)
	var promise [32]byte
	for _, r := range cov {
		if r.Height == adoptionDiverged {
			promise = r.Acks[0].ManifestDigest
		}
	}
	require.Equal(t, h.digestA, promise, "the frontier promised A's manifest for block 2")
	_ = img
	_ = configuredprogress.ErrConflict
}
