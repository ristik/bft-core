package archivewiring

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// Four independent validator journals over ONE certified chain (one archive subject): the first three hold the canonical resulting certificate A for
// every block; the fourth ("the restarted node") certified block `diverged` with the other valid certificate B (a repeat of the same input record at a later
// root round, the first one it verified). Both bind the same execution block; their archive manifests differ (bft-core#876, arch's lead 2).
type divergenceFixture struct {
	chain    *certifiedchain.Chain
	replicas []*wiringFixture
	sender   *wiringFixture
	diverged int // the block number
	limits   configuredprogress.JournalLimits
}

func newDivergenceFixture(t *testing.T, blocks, diverged int) *divergenceFixture {
	t.Helper()
	chain := certifiedchain.New(t, 3, 0)
	limits := configuredprogress.JournalLimits{Candidates: 16, Observations: 32, Bytes: 32 << 20}
	d := &divergenceFixture{chain: chain, diverged: diverged, limits: limits}
	for i := 0; i < 3; i++ {
		d.replicas = append(d.replicas, newWiringFixtureOpts(t, wiringOpts{blocks: blocks, limits: limits, chain: chain, timeouts: true}))
	}
	d.sender = newWiringFixtureOpts(t, wiringOpts{blocks: blocks, limits: limits, chain: chain, timeouts: true, associated: map[int]uint64{diverged: 1}})
	return d
}

func (f *wiringFixture) indexOf(t *testing.T, number int) int {
	t.Helper()
	for i, e := range f.entries {
		if e.Candidate.Number == uint64(number) {
			return i
		}
	}
	t.Fatalf("no block %d", number)
	return -1
}

// archiveAll puts every record of the journal into a fresh archive store.
func (f *wiringFixture) archiveAll(t *testing.T) *archive.Store {
	t.Helper()
	s, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	for i := range f.entries {
		q, rec := f.record(t, i)
		require.NoError(t, s.Put(q, rec))
	}
	return s
}

// pruneThrough advances and prunes the journal's frontier through the given height with two archive copies (the legacy two-replica policy, the availability
// adapter standing for the replicas' stores).
func (f *wiringFixture) pruneThrough(t *testing.T, height uint64, local, first, second *archive.Store) {
	t.Helper()
	peers := []peer.ID{"first", "second"}
	policy := frontier.Policy{Context: f.subject, Replicas: [2]string{peers[0].String(), peers[1].String()}, Binding: CertifiedBinding{Context: f.context, Subject: f.subject},
		Availability: fixtureAvailability{stores: map[string]*archive.Store{peers[0].String(): first, peers[1].String(): second}}}
	require.NoError(t, f.store.EnableFrontier(context.Background(), f.context, f.limits, policy))
	var upTo shardnode.BlockRef
	for _, e := range f.entries {
		if e.Candidate.Number == height {
			upTo = shardnode.BlockRef{Number: height, Hash: e.Candidate.Hash}
		}
	}
	require.NotZero(t, upTo.Number)
	w := &FrontierWorker{Journal: f.store, Context: f.context, Limits: f.limits, Archive: local, Subject: f.subject, Replicas: peers,
		Finalized: func(context.Context) (shardnode.BlockRef, error) { return upTo, nil }}
	for i := 0; i < 4; i++ {
		require.NoError(t, w.Pass(context.Background()))
	}
	img, err := f.store.LoadJournal(context.Background(), f.context, f.limits)
	require.NoError(t, err)
	require.EqualValues(t, height, img.Frontier.Anchor.Height)
}

func TestRestartRepeatCertificateDivergesFromPrunedReplicaManifest(t *testing.T) {
	t.Parallel()
	const blocks, diverged = 6, 2
	d := newDivergenceFixture(t, blocks, diverged)
	ri, si := d.replicas[0].indexOf(t, diverged), d.sender.indexOf(t, diverged)
	qA, recA := d.replicas[0].record(t, ri)
	qB, recB := d.sender.record(t, si)

	// the same execution block under two different, individually valid certificates
	require.Equal(t, qA, qB, "one archive subject, one block hash")
	require.Equal(t, recA.Header, recB.Header)
	require.Equal(t, recA.Body, recB.Body)
	require.NotEqual(t, recA.ResultingUC, recB.ResultingUC, "the resulting certificate differs: A and its repeat B")
	digestA, err := archive.ManifestDigest(qA, recA)
	require.NoError(t, err)
	digestB, err := archive.ManifestDigest(qB, recB)
	require.NoError(t, err)
	require.NotEqual(t, digestA, digestB, "so does the manifest the archive requires to be byte-identical")
	// the other blocks agree: the divergence is exactly the one block
	for _, n := range []int{1, 3, 4, 5, 6} {
		q1, r1 := d.replicas[0].record(t, d.replicas[0].indexOf(t, n))
		q2, r2 := d.sender.record(t, d.sender.indexOf(t, n))
		g1, _ := archive.ManifestDigest(q1, r1)
		g2, _ := archive.ManifestDigest(q2, r2)
		require.Equal(t, g1, g2, "block %d", n)
	}

	// A replica that still holds the block hot refuses B with the binding error (it compares the exact reconstructed bytes)
	hot := JournalVerifier(d.replicas[0].store, d.replicas[0].context, d.limits, d.replicas[0].subject)
	require.ErrorIs(t, hot(context.Background(), qB, recB), ErrBinding)
	require.NoError(t, hot(context.Background(), qA, recA))

	// Every replica archives all six blocks, covers and prunes past block 2
	stores := make([]*archive.Store, 3)
	for i, r := range d.replicas {
		stores[i] = r.archiveAll(t)
	}
	for i, r := range d.replicas {
		r.pruneThrough(t, blocks, stores[i], stores[(i+1)%3], stores[(i+2)%3])
	}
	// ... after which B is refused as "no certified association", and the cause says: the covered manifest is another one
	for i, r := range d.replicas {
		verify := JournalVerifier(r.store, r.context, d.limits, r.subject)
		err := verify(context.Background(), qB, recB)
		require.ErrorIs(t, err, ErrUncertified, "replica %d", i)
		require.ErrorIs(t, err, frontier.ErrInvalid, "replica %d", i)
		require.ErrorContains(t, err, "is not the covered manifest", "replica %d", i)
		require.NoError(t, verify(context.Background(), qA, recA), "replica %d: the canonical copy is accepted", i)
	}

	// The restarted node's frontier: all RPCs healthy, every replica holds every block, but not THIS manifest of block 2. It cannot pass block 2, pass after pass,
	// and a fresh worker (a restart) does no better. (The legacy two-replica policy used here plans every block of a pass together, so the whole pass fails; the derived
	// three-replica policy covers block 1 and stops at block 2. Either way the frontier is pinned at the diverged block.)
	local := d.sender.archiveAll(t)
	for pass := 0; pass < 3; pass++ {
		peers := []peer.ID{"first", "second"}
		policy := frontier.Policy{Context: d.sender.subject, Replicas: [2]string{peers[0].String(), peers[1].String()}, Binding: CertifiedBinding{Context: d.sender.context, Subject: d.sender.subject},
			Availability: fixtureAvailability{stores: map[string]*archive.Store{peers[0].String(): stores[0], peers[1].String(): stores[1]}}}
		if pass == 0 {
			require.NoError(t, d.sender.store.EnableFrontier(context.Background(), d.sender.context, d.sender.limits, policy))
		}
		w := &FrontierWorker{Journal: d.sender.store, Context: d.sender.context, Limits: d.sender.limits, Archive: local, Subject: d.sender.subject, Replicas: peers}
		passErr := w.Pass(context.Background())
		require.ErrorIs(t, passErr, frontier.ErrAcknowledgment, "pass %d: no two replicas hold this manifest of block 2", pass)
		img, err := d.sender.store.LoadJournal(context.Background(), d.sender.context, d.sender.limits)
		require.NoError(t, err)
		if img.Frontier != nil && img.Frontier.Anchor != nil {
			require.Less(t, img.Frontier.Anchor.Height, uint64(diverged), "pass %d: the frontier does not pass the diverged block", pass)
		}
	}

	// Historical insertion of A does not repair it: the first verified association is immutable, B stays pinned
	cand := d.sender.entries[si].Candidate
	require.NoError(t, d.sender.store.PutHistoricalCertifiedJournalCandidate(context.Background(), d.sender.context, d.limits, cand, d.replicas[0].entries[ri].ResultingUC, d.replicas[0].entries[ri].ResultingTR))
	img, err := d.sender.store.LoadJournal(context.Background(), d.sender.context, d.sender.limits)
	require.NoError(t, err)
	for _, e := range img.Candidates {
		if e.Candidate.Number == uint64(diverged) {
			q2, r2 := FromJournalMust(t, d.sender, e)
			g, _ := archive.ManifestDigest(q2, r2)
			require.Equal(t, digestB, g, "the association stays B after a peer supplies A")
		}
	}
	_ = bytes.Equal
}

// FromJournalMust rebuilds the archive record of a journal entry (test helper).
func FromJournalMust(t *testing.T, f *wiringFixture, e configuredprogress.JournalEntry) (archive.Request, *archive.Record) {
	t.Helper()
	q, rec, err := FromJournal(context.Background(), f.context, f.subject, nil, e)
	require.NoError(t, err)
	return q, rec
}

// ---- arch's lead 3: a restart re-enters the historical audit; one old promise that cannot be restored to two exact copies blocks the NEW frontier -------

// auditHarness is twoOfThree with a switchable replica verifier ("coverage missing": the records the replicas would have to accept to be repaired are refused with
// ErrUncertified, as a replica restored above them refuses them) and a worker whose execution finality the test sets.
type auditHarness struct {
	*twoOfThree
	reject    *atomic.Bool
	finalized *atomic.Uint64
}

func newAuditHarness(t *testing.T, blocks int) *auditHarness {
	t.Helper()
	f := newWiringFixture(t, blocks)
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	x := &twoOfThree{f: f, stores: make([]*archive.Store, 3), sender: sender}
	h := &auditHarness{twoOfThree: x, reject: new(atomic.Bool), finalized: new(atomic.Uint64)}
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	x.local = local
	base := JournalVerifier(f.store, f.context, f.limits, f.subject)
	verify := func(ctx context.Context, q archive.Request, rec *archive.Record) error {
		if h.reject.Load() {
			return fmt.Errorf("%w: test: this replica holds no coverage for the offered record", ErrUncertified)
		}
		return base(ctx, q, rec)
	}
	for i := range x.stores {
		remote := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
		x.peers = append(x.peers, remote.ID())
		x.remotes = append(x.remotes, remote)
		x.stores[i], err = archive.Open(t.TempDir())
		require.NoError(t, err)
		sender.Network().Peerstore().AddAddrs(remote.ID(), remote.MultiAddresses(), peerstore.PermanentAddrTTL)
		server, err := NewServer(x.stores[i], f.subject, verify, []peer.ID{sender.ID()}, DefaultLimits())
		require.NoError(t, err)
		server.Register(context.Background(), remote)
	}
	for i := range f.entries {
		q, rec := f.record(t, i)
		require.NoError(t, local.Put(q, rec))
		for _, s := range x.stores {
			require.NoError(t, s.Put(q, rec))
		}
	}
	x.enable(t, sender, []int{0, 1, 2}, testPolicyDigest)
	return h
}

// worker is a fresh worker (a restarted node: the audit cursor is back at the coverage base) bounded by the execution finality the test has set.
func (h *auditHarness) worker() *FrontierWorker {
	o := h.twoOfThree.worker
	return &FrontierWorker{Journal: o.Journal, Context: o.Context, Limits: o.Limits, Archive: o.Archive, Subject: o.Subject, Replicas: o.Replicas, PolicyDigest: o.PolicyDigest,
		Host: o.Host, TransportLimits: o.TransportLimits,
		Finalized: func(context.Context) (shardnode.BlockRef, error) {
			for _, e := range h.f.entries {
				if e.Candidate.Number == h.finalized.Load() {
					return shardnode.BlockRef{Number: e.Candidate.Number, Hash: e.Candidate.Hash}, nil
				}
			}
			return shardnode.BlockRef{}, fmt.Errorf("no block at finality %d", h.finalized.Load())
		}}
}

// forget removes a block's record from an archive store (a lost disk): both representations the store keeps.
func forget(t *testing.T, s *archive.Store, q archive.Request) {
	t.Helper()
	enc, err := archive.EncodeRequest(q)
	require.NoError(t, err)
	sum := sha256.Sum256(enc)
	name := hex.EncodeToString(sum[:])
	dir := reflect.ValueOf(s).Elem().FieldByName("dir").String()
	for _, n := range []string{name, "v2-" + name} {
		require.NoError(t, os.RemoveAll(filepath.Join(dir, n)))
	}
}

func (h *auditHarness) height(t *testing.T) uint64 {
	t.Helper()
	img, err := h.f.store.LoadJournal(context.Background(), h.f.context, h.f.limits)
	require.NoError(t, err)
	if img.Frontier == nil || img.Frontier.Anchor == nil {
		return 0
	}
	return img.Frontier.Anchor.Height
}

func TestRestartAuditOldPromiseBlocksNewFrontier(t *testing.T) {
	t.Parallel()
	h := newAuditHarness(t, 8)
	ctx := context.Background()
	// phase 1: execution finality 4, three healthy replicas: the frontier covers and prunes through block 4
	h.finalized.Store(4)
	for i := 0; i < 3; i++ {
		require.NoError(t, h.worker().Pass(ctx))
	}
	require.EqualValues(t, 4, h.height(t))

	// the old promise at block 2 loses two of its copies and the local one (lost disks); the replicas now refuse the repair for lack of coverage; blocks 5-8 are
	// fully available everywhere and finality has moved on
	var q2 archive.Request
	for i, e := range h.f.entries {
		if e.Candidate.Number == 2 {
			q2, _ = h.f.record(t, i)
		}
	}
	forget(t, h.stores[1], q2)
	forget(t, h.stores[2], q2)
	forget(t, h.local, q2)
	h.reject.Store(true)
	h.finalized.Store(8)

	// after the restart the audit visits promise 2 first, restores the local record from the one surviving replica, finds one copy and no way to the second:
	// the same old hash blocks every pass, and the new blocks do not move the frontier
	for i := 0; i < 3; i++ {
		err := h.worker().Pass(ctx)
		require.ErrorIs(t, err, frontier.ErrUnavailable, "pass %d", i)
		require.EqualValues(t, 4, h.height(t), "pass %d: the frontier does not advance behind the old promise", i)
	}
	// ... and not because the new blocks are missing: restoring the second exact copy lets the very next pass advance
	_, rec2 := h.f.record(t, h.f.indexOf(t, 2))
	require.NoError(t, h.stores[1].Put(q2, rec2))
	require.NoError(t, h.worker().Pass(ctx))
	require.EqualValues(t, 8, h.height(t), "restoring the second copy of the old promise releases the frontier at once")
}

// The control: one acknowledger of the old promise down but two eligible copies intact (and the replicas refusing every repair) does not block anything.
func TestRestartAuditWithTwoIntactCopiesAdvances(t *testing.T) {
	t.Parallel()
	h := newAuditHarness(t, 8)
	ctx := context.Background()
	h.finalized.Store(4)
	for i := 0; i < 3; i++ {
		require.NoError(t, h.worker().Pass(ctx))
	}
	require.EqualValues(t, 4, h.height(t))
	var q2 archive.Request
	for i, e := range h.f.entries {
		if e.Candidate.Number == 2 {
			q2, _ = h.f.record(t, i)
		}
	}
	forget(t, h.stores[2], q2) // one copy lost; the local one and two replicas remain
	h.reject.Store(true)
	h.finalized.Store(8)
	require.NoError(t, h.worker().Pass(ctx))
	require.NoError(t, h.worker().Pass(ctx))
	require.EqualValues(t, 8, h.height(t))
}
