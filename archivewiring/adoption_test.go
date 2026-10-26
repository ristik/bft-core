package archivewiring

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
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
	basetypes "github.com/unicitynetwork/bft-go-base/types"
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
	legacy     bool // the legacy two-replica policy (no derived policy digest)
}

const adoptionBlocks, adoptionDiverged = 6, 2

func newAdoptionHarness(t *testing.T) *adoptionHarness {
	t.Helper()
	return newAdoptionHarnessOpts(t, false, configuredprogress.JournalLimits{Candidates: 16, Observations: 32, Bytes: 32 << 20})
}

func newAdoptionHarnessOpts(t *testing.T, legacy bool, limits configuredprogress.JournalLimits) *adoptionHarness {
	t.Helper()
	d := newDivergenceFixtureLimits(t, adoptionBlocks, adoptionDiverged, limits)
	h := &adoptionHarness{divergenceFixture: d, senderJrnl: d.sender, legacy: legacy}
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
	if legacy {
		h.peers = h.peers[:2]
	}
	require.NoError(t, d.sender.store.EnableFrontier(context.Background(), d.sender.context, d.sender.limits, h.policy()))
	return h
}

// policy is the frontier policy over the configured replicas: the derived three-replica policy, or the legacy pair.
func (h *adoptionHarness) policy() frontier.Policy {
	availability := ReplicaAvailability{Context: context.Background(), Host: h.sender, Replicas: h.peers, Limits: DefaultLimits()}
	if h.legacy {
		return frontier.Policy{Context: h.senderJrnl.subject, Replicas: [2]string{h.peers[0].String(), h.peers[1].String()}, Binding: CertifiedBinding{Context: h.senderJrnl.context, Subject: h.senderJrnl.subject}, Availability: availability}
	}
	var names []string
	for _, id := range h.peers {
		names = append(names, id.String())
	}
	return frontier.Policy{Context: h.senderJrnl.subject, Eligible: names, PolicyDigest: testPolicyDigest, Binding: CertifiedBinding{Context: h.senderJrnl.context, Subject: h.senderJrnl.subject}, Availability: availability}
}

func (h *adoptionHarness) digest() [32]byte {
	if h.legacy {
		return [32]byte{}
	}
	return testPolicyDigest
}

// worker is a fresh frontier worker of the sender (a restart: no volatile state).
func (h *adoptionHarness) worker() *FrontierWorker {
	f := h.sender
	_ = f
	return &FrontierWorker{Journal: h.senderJrnl.store, Context: h.senderJrnl.context, Limits: h.senderJrnl.limits, Archive: h.local, Subject: h.senderJrnl.subject, Replicas: h.peers,
		PolicyDigest: h.digest(), Host: h.sender, TransportLimits: DefaultLimits(),
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

func (h *adoptionHarness) senderEntry(t *testing.T) configuredprogress.JournalEntry {
	t.Helper()
	img, err := h.senderJrnl.store.LoadJournal(context.Background(), h.senderJrnl.context, h.senderJrnl.limits)
	require.NoError(t, err)
	for _, e := range img.Candidates {
		if e.Candidate.Number == adoptionDiverged {
			return e
		}
	}
	t.Fatal("the diverged block is no longer a journal candidate")
	return configuredprogress.JournalEntry{}
}

func clone(r *archive.Record) *archive.Record {
	c := *r
	c.Extensions = map[string][]byte{}
	for k, v := range r.Extensions {
		c.Extensions[k] = bytes.Clone(v)
	}
	for _, f := range []*[]byte{&c.Header, &c.Body, &c.CanonicalRootInput, &c.OriginalUC, &c.OriginalTR, &c.ResultingUC, &c.ResultingTR, &c.Companion, &c.ParentAccounting} {
		*f = bytes.Clone(*f)
	}
	return &c
}

// ---- adoption refuses what is not another proof of the same certified result ------------------------------------------------------------------------------

func TestAdoptionRejectsUncertifiedOrDifferentResult(t *testing.T) {
	t.Parallel()
	h := newAdoptionHarness(t)
	w := h.worker()
	entry := h.senderEntry(t)
	// the legitimate repeat, differing only in its result pair, is another proof of the same result
	require.NoError(t, w.equivalentRepresentation(entry, h.qBlock, h.recB, h.recA))

	flip := func(b []byte) []byte { c := bytes.Clone(b); c[len(c)/2] ^= 1; return c }
	otherIR := func() (uc, tr []byte) {
		var cur basetypes.UnicityCertificate
		require.NoError(t, basetypes.Cbor.Unmarshal(h.recA.ResultingUC, &cur))
		ir := *cur.InputRecord
		ir.Timestamp++
		u, r := signWiring(t, h.chain, &ir, ir.RoundNumber+1, cur.GetRootRoundNumber()+1)
		ub, err := basetypes.Cbor.Marshal(u)
		require.NoError(t, err)
		rb, err := basetypes.Cbor.Marshal(r)
		require.NoError(t, err)
		return ub, rb
	}
	for name, mutate := range map[string]func(*archive.Record){
		"another original input":                      func(r *archive.Record) { r.OriginalUC = flip(r.OriginalUC) },
		"another original technical":                  func(r *archive.Record) { r.OriginalTR = flip(r.OriginalTR) },
		"another body":                                func(r *archive.Record) { r.Body = flip(r.Body) },
		"another canonical root input":                func(r *archive.Record) { r.CanonicalRootInput = flip(r.CanonicalRootInput) },
		"another companion":                           func(r *archive.Record) { r.Companion = flip(r.Companion) },
		"an extension":                                func(r *archive.Record) { r.Extensions["future-proof"] = []byte("x") },
		"a forged result certificate":                 func(r *archive.Record) { r.ResultingUC = flip(r.ResultingUC) },
		"a forged result technical":                   func(r *archive.Record) { r.ResultingTR = flip(r.ResultingTR) },
		"a valid certificate of another input record": func(r *archive.Record) { r.ResultingUC, r.ResultingTR = otherIR() },
	} {
		bad := clone(h.recA)
		mutate(bad)
		require.Error(t, w.equivalentRepresentation(entry, h.qBlock, h.recB, bad), name)
	}
	// another block entirely (valid, signed, certified), offered for this one
	_, other := h.replicas[0].record(t, h.replicas[0].indexOf(t, 3))
	require.Error(t, w.equivalentRepresentation(entry, h.qBlock, h.recB, other), "another block")
	// no historical trust to authenticate it against
	w.Context.Observation.TrustBases = failingTrust{}
	require.Error(t, w.equivalentRepresentation(entry, h.qBlock, h.recB, h.recA), "unavailable historical trust")
}

type failingTrust struct{}

func (failingTrust) GetByEpoch(context.Context, uint64) (*basetypes.RootTrustBaseV1, error) {
	return nil, errors.New("no trust base")
}

// Two replicas repeating the SAME bad record do not help: nothing is selected and the frontier stays where it is.
func TestAdoptionIgnoresTwoReplicasRepeatingABadRecord(t *testing.T) {
	t.Parallel()
	h := newAdoptionHarness(t)
	ctx := context.Background()
	bad := clone(h.recA)
	bad.Companion = append([]byte(nil), bad.Companion...)
	bad.Companion[len(bad.Companion)/2] ^= 1
	for _, i := range []int{0, 1, 2} {
		forget(t, h.stores[i], h.qBlock)
		require.NoError(t, h.stores[i].Put(h.qBlock, bad))
	}
	for pass := 0; pass < 3; pass++ {
		_ = h.worker().Pass(ctx)
	}
	require.EqualValues(t, 1, h.anchorHeight(t), "nothing past block 2")
	require.Nil(t, h.senderEntry(t).Archive, "no selection was made")
	_, err := h.local.GetExact(h.qBlock, mustDigest(t, h.qBlock, bad))
	require.Error(t, err, "and the bad record was never stored")
}

func mustDigest(t *testing.T, q archive.Request, r *archive.Record) [32]byte {
	t.Helper()
	d, err := archive.ManifestDigest(q, r)
	require.NoError(t, err)
	return d
}

// ---- two exact configured copies are required --------------------------------------------------------------------------------------------------------------

func TestAdoptionRequiresTwoExactConfiguredCopies(t *testing.T) {
	t.Parallel()
	h := newAdoptionHarness(t)
	ctx := context.Background()
	// replicas 1 and 2 lose A (lost disks): only replica 0 holds it
	forget(t, h.stores[1], h.qBlock)
	forget(t, h.stores[2], h.qBlock)
	for pass := 0; pass < 3; pass++ {
		h.worker().adoptAt = nil
		_ = h.worker().Pass(ctx)
	}
	require.EqualValues(t, 1, h.anchorHeight(t), "one honest copy is not enough")
	require.Nil(t, h.senderEntry(t).Archive)

	// a second replica holding a DIFFERENT manifest does not make two
	other := clone(h.recA)
	other.Companion = append([]byte(nil), other.Companion...)
	other.Companion[len(other.Companion)/2] ^= 1
	require.NoError(t, h.stores[1].Put(h.qBlock, other))
	for pass := 0; pass < 3; pass++ {
		_ = h.worker().Pass(ctx)
	}
	require.EqualValues(t, 1, h.anchorHeight(t), "mismatched manifests are not copies of the same representation")
	require.Nil(t, h.senderEntry(t).Archive)

	// the second exact copy lets it through: replica 1 gets A as an exact object next to what it holds
	require.NoError(t, h.stores[1].PutVariant(h.qBlock, h.recA))
	// the default read of replica 1 is still its own base object (the odd record): it offers that, not A; a second exact A copy elsewhere is what counts
	require.NoError(t, h.stores[2].Put(h.qBlock, h.recA))
	for pass := 0; pass < 6; pass++ {
		_ = h.worker().Pass(ctx)
	}
	require.EqualValues(t, adoptionBlocks, h.anchorHeight(t), "two replicas return the exact manifest: the frontier passes block 2")
}

// ---- crash cuts --------------------------------------------------------------------------------------------------------------------------------------------

// reopenSender closes the sender's journal and local archive and opens them again from disk (a process restart): the frontier policy is re-enabled before the journal is read.
func (h *adoptionHarness) reopenSender(t *testing.T, localDir string) {
	t.Helper()
	require.NoError(t, h.senderJrnl.store.Close())
	s, err := configuredprogress.OpenConfiguredV2(h.senderJrnl.path, configuredprogress.Settings{Retain: 16})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	require.NoError(t, s.EnableJournal(context.Background(), h.senderJrnl.context, h.senderJrnl.limits))
	require.NoError(t, s.EnableFrontier(context.Background(), h.senderJrnl.context, h.senderJrnl.limits, h.policy()))
	h.senderJrnl.store = s
	local, err := archive.Open(localDir)
	require.NoError(t, err)
	h.local = local
}

func TestArchiveAdoptionCrashCuts(t *testing.T) {
	for _, cut := range []struct {
		name        string
		hook        func(h *adoptionHarness, fail *bool)
		wantAfter   string // which representation a reopened node exposes: B (no selection) or A (selected)
		objectAfter bool   // A's object is on disk after the crash
	}{
		{"before the object is published", func(h *adoptionHarness, fail *bool) {
			h.local.Fault = func(point string) error {
				if *fail && point == "before-publish" {
					return errors.New("crash")
				}
				return nil
			}
		}, "B", false},
		{"after the object, before the selection", func(h *adoptionHarness, fail *bool) {
			h.senderJrnl.store.SetFaultHook(func(point string) error {
				if *fail && point == "before-archive-selection" {
					return errors.New("crash")
				}
				return nil
			})
		}, "B", true},
		{"before the selection commits", func(h *adoptionHarness, fail *bool) {
			h.senderJrnl.store.SetFaultHook(func(point string) error {
				if *fail && point == "before-archive-selection-commit" {
					return errors.New("crash")
				}
				return nil
			})
		}, "B", true},
		{"after the selection commits", func(h *adoptionHarness, fail *bool) {
			h.senderJrnl.store.SetFaultHook(func(point string) error {
				if *fail && point == "after-archive-selection" {
					return errors.New("crash")
				}
				return nil
			})
		}, "A", true},
	} {
		cut := cut
		t.Run(cut.name, func(t *testing.T) {
			t.Parallel()
			h := newAdoptionHarness(t)
			ctx := context.Background()
			localDir := reflect.ValueOf(h.local).Elem().FieldByName("dir").String()
			fail := true
			cut.hook(h, &fail)
			_ = h.worker().Pass(ctx) // covers block 1 and then adopts: the cut fails the adoption
			_ = h.worker().Pass(ctx)
			h.reopenSender(t, localDir)
			fail = false

			entry := h.senderEntry(t)
			if cut.wantAfter == "A" {
				require.NotNil(t, entry.Archive, "the selection committed before the crash")
				require.Equal(t, h.digestA, entry.Archive.NewDigest)
			} else {
				require.Nil(t, entry.Archive, "no selection was committed: readers still see B")
			}
			_, err := h.local.GetExact(h.qBlock, h.digestA)
			if cut.objectAfter {
				require.NoError(t, err, "A's object is on disk")
			} else {
				require.ErrorIs(t, err, archive.ErrUnavailable, "A's object was never published")
			}
			// the retry is idempotent and completes, from either side of the cut
			h.finalized = adoptionBlocks
			for pass := 0; pass < 6; pass++ {
				_ = h.worker().Pass(ctx)
			}
			require.EqualValues(t, adoptionBlocks, h.anchorHeight(t))
		})
	}
}

// A selected representation whose bytes are lost after the selection committed stays unavailable: the node does not fall back to B, and recovers that exact digest.
func TestSelectedRepresentationMissingAfterReopenStaysUnavailable(t *testing.T) {
	t.Parallel()
	h := newAdoptionHarness(t)
	ctx := context.Background()
	localDir := reflect.ValueOf(h.local).Elem().FieldByName("dir").String()
	_ = h.worker().Pass(ctx)
	_ = h.worker().Pass(ctx)
	require.NotNil(t, h.senderEntry(t).Archive, "A is selected")
	h.finalized = 2 // keep block 2 hot: the frontier stops at the finality bound and block 2 is not pruned yet
	h.reopenSender(t, localDir)
	// lose A's object (the base object B stays)
	enc, err := archive.EncodeRequest(h.qBlock)
	require.NoError(t, err)
	sum := sha256.Sum256(enc)
	for _, name := range []string{"v2-" + hex.EncodeToString(sum[:]) + "-" + hex.EncodeToString(h.digestA[:])} {
		require.NoError(t, os.RemoveAll(filepath.Join(localDir, name)))
	}
	_, err = h.local.GetExact(h.qBlock, h.digestA)
	require.Error(t, err)
	h.finalized = adoptionBlocks
	for pass := 0; pass < 3; pass++ {
		err := h.worker().Pass(ctx)
		require.ErrorIs(t, err, archive.ErrUnavailable, "pass %d: the selected representation is missing, not replaced by B", pass)
		require.EqualValues(t, 1, h.anchorHeight(t), "pass %d: block 2 is not covered", pass)
	}
	got, err := h.local.Get(h.qBlock)
	require.NoError(t, err)
	require.Equal(t, h.digestB, mustDigest(t, h.qBlock, got), "B is still the base object, untouched")
	// the local publisher rebuilds that exact digest from the journal (it carries the selected pair) and nothing else
	p := &Publisher{Journal: h.senderJrnl.store, Context: h.senderJrnl.context, JournalLimits: h.senderJrnl.limits, Archive: h.local, Subject: h.senderJrnl.subject, ack: make(map[[32]byte]ackSet)}
	require.NoError(t, p.pass(ctx))
	_, err = h.local.GetExact(h.qBlock, h.digestA)
	require.NoError(t, err, "A is back")
	for pass := 0; pass < 6; pass++ {
		_ = h.worker().Pass(ctx)
	}
	require.EqualValues(t, adoptionBlocks, h.anchorHeight(t), "and the frontier proceeds on A")
}

// ---- adoption and coverage never rewrite each other ------------------------------------------------------------------------------------------------------

func (h *adoptionHarness) selectA(ctx context.Context) error {
	return h.senderJrnl.store.SelectArchiveRepresentation(ctx, h.senderJrnl.context, h.senderJrnl.limits, configuredprogress.ArchiveSelectionRequest{
		BlockHash: h.qBlock.BlockHash, Prior: configuredprogress.PairID(h.recB.ResultingUC, h.recB.ResultingTR), OldDigest: h.digestB, NewDigest: h.digestA,
		UC: h.recA.ResultingUC, TR: h.recA.ResultingTR})
}

func (h *adoptionHarness) promiseAt(t *testing.T, height uint64) [32]byte {
	t.Helper()
	cov, err := h.senderJrnl.store.LoadCoverage(context.Background(), h.senderJrnl.context, h.senderJrnl.limits, 0, 16)
	require.NoError(t, err)
	for _, r := range cov {
		if r.Height == height {
			return r.Acks[0].ManifestDigest
		}
	}
	return [32]byte{}
}

func TestAdoptionCannotRewriteCoveredManifest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// B coverage wins: every replica also holds B exactly, the frontier covers B, and a later selection of A is refused
	h := newAdoptionHarness(t)
	for _, s := range h.stores {
		require.NoError(t, s.PutVariant(h.qBlock, h.recB))
	}
	for pass := 0; pass < 4; pass++ {
		_ = h.worker().Pass(ctx)
	}
	require.EqualValues(t, adoptionBlocks, h.anchorHeight(t))
	require.Equal(t, h.digestB, h.promiseAt(t, adoptionDiverged), "the promise at block 2 is B")
	err := h.selectA(ctx)
	require.ErrorIs(t, err, configuredprogress.ErrConflict, "a covered block refuses a selection")

	// the selection wins: a coverage planned against B (the image was read before) fails inside its own transaction and is replanned with A
	h2 := newAdoptionHarness(t)
	for _, s := range h2.stores {
		require.NoError(t, s.PutVariant(h2.qBlock, h2.recB))
	}
	require.NoError(t, h2.local.PutVariant(h2.qBlock, h2.recA)) // the selected representation is on hand locally
	fired := false
	w := h2.worker()
	finalized := w.Finalized
	w.Finalized = func(c context.Context) (shardnode.BlockRef, error) {
		if !fired { // after the pass read the journal image, before it commits: the other worker's selection lands
			fired = true
			require.NoError(t, h2.selectA(ctx))
		}
		return finalized(c)
	}
	err = w.Pass(ctx)
	require.ErrorIs(t, err, frontier.ErrInvalid, "the stale B coverage is refused in the transaction")
	require.Less(t, h2.anchorHeight(t), uint64(adoptionDiverged), "and nothing past block 1 was covered with B")
	for pass := 0; pass < 4; pass++ {
		_ = h2.worker().Pass(ctx)
	}
	require.EqualValues(t, adoptionBlocks, h2.anchorHeight(t))
	require.Equal(t, h2.digestA, h2.promiseAt(t, adoptionDiverged), "and only A is promised")

	// restore base: a selection at or below the coverage base is refused too (the block is covered by the base)
	require.ErrorIs(t, h2.selectA(ctx), configuredprogress.ErrConflict)
}

// Another node may already have counted our B copy (or promised it). After we adopt A, our default read answers A, the exact B read still answers B, unchanged.
func TestAdoptionPreservesEarlierReplicaPromises(t *testing.T) {
	t.Parallel()
	h := newAdoptionHarness(t)
	ctx := context.Background()
	for pass := 0; pass < 6; pass++ {
		_ = h.worker().Pass(ctx)
	}
	require.EqualValues(t, adoptionBlocks, h.anchorHeight(t))

	// the sender serves its own archive; a peer that earlier counted our B asks for it again
	server := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	client := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	client.Network().Peerstore().AddAddrs(server.ID(), server.MultiAddresses(), peerstore.PermanentAddrTTL)
	srv, err := NewServer(h.local, h.senderJrnl.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{client.ID()}, DefaultLimits())
	require.NoError(t, err)
	srv.SetDefaultRepresentation(func(q archive.Request) ([32]byte, bool) {
		return h.senderJrnl.store.ArchiveDigestOf(ctx, h.senderJrnl.context, h.senderJrnl.limits, q.BlockHash)
	})
	srv.Register(ctx, server)

	def, err := Fetch(ctx, client, server.ID(), h.qBlock, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, h.digestA, mustDigest(t, h.qBlock, def), "the default read answers the selected representation")
	exactB, err := FetchExact(ctx, client, server.ID(), h.qBlock, h.digestB, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, h.recB.ResultingUC, exactB.ResultingUC, "the exact read of B is unchanged")
	require.Equal(t, h.digestB, mustDigest(t, h.qBlock, exactB))
	exactA, err := FetchExact(ctx, client, server.ID(), h.qBlock, h.digestA, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, h.digestA, mustDigest(t, h.qBlock, exactA))
	_, err = FetchExact(ctx, client, server.ID(), h.qBlock, [32]byte{7}, DefaultLimits())
	require.Error(t, err, "a digest nobody stored")
}

// An acknowledgement of the OTHER manifest, a transfer still in flight when the selection committed, must not count for the selected one.
func TestAdoptionInvalidatesInFlightManifestAcks(t *testing.T) {
	t.Parallel()
	h := newAdoptionHarness(t)
	ctx := context.Background()
	entryB := h.senderEntry(t) // the image the replica pass reads: B

	release := make(chan struct{})
	started := make(chan struct{}, 4)
	remote := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	h.sender.Network().Peerstore().AddAddrs(remote.ID(), remote.MultiAddresses(), peerstore.PermanentAddrTTL)
	store, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	var once sync.Once
	server, err := NewServer(store, h.senderJrnl.subject, func(context.Context, archive.Request, *archive.Record) error {
		once.Do(func() { started <- struct{}{} })
		<-release
		return nil
	}, []peer.ID{h.sender.ID()}, DefaultLimits())
	require.NoError(t, err)
	server.Register(ctx, remote)
	require.NoError(t, h.local.PutVariant(h.qBlock, h.recA))
	p := &Publisher{Journal: h.senderJrnl.store, Context: h.senderJrnl.context, JournalLimits: h.senderJrnl.limits, Archive: h.local, Subject: h.senderJrnl.subject, Host: h.sender,
		Replicas: []peer.ID{remote.ID()}, Limits: DefaultLimits(), ack: make(map[[32]byte]ackSet), replicaCursor: make([]int, 1), replicaProgress: make([]ReplicaProgress, 1)}
	done := make(chan error, 1)
	go func() { done <- p.replicaPass(ctx, 0) }()
	<-started // a PUT of B (the lowest block first is block 1; let the pass reach block 2) is in flight
	for i := 0; i < 4; i++ {
		select {
		case <-started:
		default:
		}
	}
	require.NoError(t, h.selectA(ctx)) // the selection commits while the transfer is in flight
	close(release)
	require.NoError(t, <-done)

	entryA := h.senderEntry(t)
	require.NotNil(t, entryA.Archive)
	p.mu.Lock()
	defer p.mu.Unlock()
	require.NotEqual(t, ackKey(entryB), ackKey(entryA), "the caches are keyed by block AND manifest")
	require.NotZero(t, p.ack[ackKey(entryB)]&1, "the completed transfer acknowledged the manifest it carried (B)")
	require.Zero(t, p.ack[ackKey(entryA)]&1, "and did not acknowledge A")
}

// Both replica policies: the legacy two-replica pair plans a whole pass together, so the blocked block is found when the advance is refused.
func TestAdoptReplicaManifestWithTheLegacyTwoReplicaPolicy(t *testing.T) {
	t.Parallel()
	h := newAdoptionHarnessOpts(t, true, configuredprogress.JournalLimits{Candidates: 16, Observations: 32, Bytes: 32 << 20})
	ctx := context.Background()
	for pass := 0; pass < 8; pass++ {
		_ = h.worker().Pass(ctx)
	}
	require.EqualValues(t, adoptionBlocks, h.anchorHeight(t))
	require.Equal(t, h.digestA, h.promiseAt(t, adoptionDiverged))
}

// The selection survives the node: after a restart, and after the block was covered and pruned, the default read still routes to A and the covered promise is A's.
func TestAdoptionSurvivesReopenAndPruning(t *testing.T) {
	t.Parallel()
	h := newAdoptionHarness(t)
	ctx := context.Background()
	localDir := reflect.ValueOf(h.local).Elem().FieldByName("dir").String()
	for pass := 0; pass < 6; pass++ {
		_ = h.worker().Pass(ctx)
	}
	require.EqualValues(t, adoptionBlocks, h.anchorHeight(t))
	h.reopenSender(t, localDir)
	d, ok := h.senderJrnl.store.ArchiveDigestOf(ctx, h.senderJrnl.context, h.senderJrnl.limits, h.qBlock.BlockHash)
	require.True(t, ok, "the selection row outlives the candidate's pruning")
	require.Equal(t, h.digestA, d)
	require.Equal(t, h.digestA, h.promiseAt(t, adoptionDiverged))
	// the audit of the old promise after the restart: the local copy of that exact manifest is A's variant object, and it verifies
	w := h.worker()
	require.NoError(t, w.Pass(ctx))
	require.NoError(t, w.Pass(ctx))
}

// A journal that is full because the frontier is stuck admits again after adoption: the capacity wait ends without a restart.
func TestAdoptionFreesAFullJournal(t *testing.T) {
	t.Parallel()
	h := newAdoptionHarnessOpts(t, false, configuredprogress.JournalLimits{Candidates: adoptionBlocks, Observations: 32, Bytes: 32 << 20})
	ctx := context.Background()
	last := h.senderEntry(t)
	for _, e := range h.senderJrnl.entries {
		if e.Candidate.Number == adoptionBlocks {
			last = e
		}
	}
	branch := last.Candidate
	branch.Hash = bytes.Repeat([]byte{0xab}, 32)
	put := func() error {
		return h.senderJrnl.store.PutJournalCandidate(ctx, h.senderJrnl.context, h.senderJrnl.limits, branch)
	}
	require.ErrorIs(t, put(), configuredprogress.ErrCapacity, "the journal is full while the frontier is stuck behind block 2")
	for pass := 0; pass < 8; pass++ {
		_ = h.worker().Pass(ctx)
	}
	require.EqualValues(t, adoptionBlocks, h.anchorHeight(t))
	require.NotErrorIs(t, put(), configuredprogress.ErrCapacity, "after adoption and pruning there is room again")
}

// A selected pair has to bind after the candidate's authorization exactly as an association does (rev2's note on the design): a valid certificate of the same input record
// at an earlier root position than the block's authorization is refused by the selection, so the frontier's increasing root-position rule can never see it.
func TestSelectionRefusesAPairThatDoesNotFollowTheAuthorization(t *testing.T) {
	t.Parallel()
	h := newAdoptionHarness(t)
	var cur basetypes.UnicityCertificate
	require.NoError(t, basetypes.Cbor.Unmarshal(h.recA.ResultingUC, &cur))
	var auth basetypes.UnicityCertificate
	require.NoError(t, basetypes.Cbor.Unmarshal(h.recA.OriginalUC, &auth))
	require.Greater(t, auth.GetRootRoundNumber(), uint64(1))
	early, earlyTR := signWiring(t, h.chain, cur.InputRecord, cur.InputRecord.RoundNumber+1, auth.GetRootRoundNumber()-1)
	uc, err := basetypes.Cbor.Marshal(early)
	require.NoError(t, err)
	tr, err := basetypes.Cbor.Marshal(earlyTR)
	require.NoError(t, err)
	err = h.senderJrnl.store.SelectArchiveRepresentation(context.Background(), h.senderJrnl.context, h.senderJrnl.limits, configuredprogress.ArchiveSelectionRequest{
		BlockHash: h.qBlock.BlockHash, Prior: configuredprogress.PairID(h.recB.ResultingUC, h.recB.ResultingTR), OldDigest: h.digestB, NewDigest: [32]byte{1}, UC: uc, TR: tr})
	require.Error(t, err)
	require.Nil(t, h.senderEntry(t).Archive)
}
