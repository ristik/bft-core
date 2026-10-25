package archivewiring

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sort"
	"testing"
	"time"

	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// planFixture is a certified chain of n blocks, a replica archive serving the given records over the archive protocol, and an empty local
// archive: the state of a validator that comes back after the others have pruned the gap from their journals (#769).
type planFixture struct {
	f       *wiringFixture
	replica *archive.Store // served over the archive protocol
	second  *archive.Store // the second copy, for the frontier's two acknowledgments
	local   *archive.Store
	source  *RecoverySource
	genesis shardnode.BlockRef
}

func newPlanFixture(t *testing.T, n int) *planFixture {
	t.Helper()
	f := newWiringFixtureWithLimits(t, n, configuredprogress.JournalLimits{Candidates: 64, Observations: 128, Bytes: 32 << 20})
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	host := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	sender.Network().Peerstore().AddAddrs(host.ID(), host.MultiAddresses(), peerstore.PermanentAddrTTL)
	replica, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	server, err := NewServer(replica, f.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{sender.ID()}, DefaultLimits())
	require.NoError(t, err)
	server.Register(context.Background(), host)
	second, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	// the journal image lists candidates in its own order: index them by height
	sort.Slice(f.entries, func(i, j int) bool { return f.entries[i].Candidate.Number < f.entries[j].Candidate.Number })
	for i, e := range f.entries {
		require.Equal(t, uint64(i+1), e.Candidate.Number)
	}
	first := f.entries[0].Candidate
	return &planFixture{f: f, replica: replica, second: second, local: local, genesis: shardnode.BlockRef{Number: first.ParentNumber, Hash: first.ParentHash, StateRoot: first.ParentState},
		source: &RecoverySource{Context: f.context, Subject: f.subject, Local: local, Host: sender, Replicas: []peer.ID{host.ID()}, Limits: DefaultLimits(), MaxBlocks: 8}}
}

// serve puts blocks from..to (1-based heights) into the replica.
func (p *planFixture) serve(t *testing.T, from, to int) {
	t.Helper()
	for h := from; h <= to; h++ {
		q, rec := p.f.record(t, h-1)
		require.True(t, archive.HasReceiptList(rec), "the fixture's empty blocks are receipt-complete")
		require.NoError(t, p.replica.Put(q, rec))
		require.NoError(t, p.second.Put(q, rec))
	}
}

func (p *planFixture) hash(h int) [32]byte { return [32]byte(p.f.entries[h-1].Candidate.Hash) }

func (p *planFixture) ref(h int) shardnode.BlockRef {
	c := p.f.entries[h-1].Candidate
	return shardnode.BlockRef{Number: c.Number, Hash: c.Hash, StateRoot: c.StateRoot}
}

func far() time.Time { return time.Now().Add(time.Minute) }

func heights(entries []shardnode.JournalFetchEntry) []uint64 {
	var out []uint64
	for _, e := range entries {
		out = append(out, e.Block.Number)
	}
	return out
}

func TestArchivePlan_WalksPastTheSuffixCapAndPagesFromTheAnchor(t *testing.T) {
	t.Parallel()
	p := newPlanFixture(t, 20)
	p.serve(t, 1, 20)
	top := p.hash(20)
	_, err := p.source.FetchSuffix(context.Background(), p.genesis, top[:])
	require.ErrorIs(t, err, ErrArchiveSuffixTooLong, "MaxBlocks 8 stands for the 256 cap: one recovery refuses the gap for its length")
	require.ErrorIs(t, err, ErrArchiveRecoveryInvalid, "and keeps its class until the paged mode (PR 2) handles it")

	plan, err := NewArchivePlan(p.genesis, top)
	require.NoError(t, err)
	require.NoError(t, p.source.Extend(context.Background(), plan, far()))
	require.True(t, plan.Joined())
	require.Equal(t, 20, plan.Walked())
	for h := 1; h <= 20; h++ {
		_, err := p.local.GetReceiptComplete(archive.Request{Context: p.f.subject, BlockHash: p.hash(h)})
		require.NoError(t, err, "block %d is retained receipt-complete in the local archive (the frontier's local copy)", h)
	}

	page, err := p.source.Page(context.Background(), plan, p.genesis, 8)
	require.NoError(t, err)
	require.Equal(t, []uint64{1, 2, 3, 4, 5, 6, 7, 8}, heights(page))
	require.True(t, bytes.Equal(page[0].ParentState, p.genesis.StateRoot))
	for i := 1; i < len(page); i++ {
		require.True(t, bytes.Equal(page[i].ParentState, page[i-1].Block.StateRoot), "parent states are chained from the anchor")
	}
	page, err = p.source.Page(context.Background(), plan, p.ref(8), 8)
	require.NoError(t, err)
	require.Equal(t, []uint64{9, 10, 11, 12, 13, 14, 15, 16}, heights(page))
	page, err = p.source.Page(context.Background(), plan, p.ref(16), 8)
	require.NoError(t, err)
	require.Equal(t, []uint64{17, 18, 19, 20}, heights(page))
	remaining, ok := plan.Remaining(p.ref(16).Hash)
	require.True(t, ok)
	require.Equal(t, 4, remaining)

	_, err = p.source.Page(context.Background(), plan, p.ref(20), 8)
	require.ErrorIs(t, err, ErrArchiveRecoveryUnavailable, "a consumed plan")
	off := p.ref(3)
	off.Hash = bytes.Repeat([]byte{7}, 32)
	_, err = p.source.Page(context.Background(), plan, off, 8)
	require.ErrorIs(t, err, ErrArchiveRecoveryUnavailable, "an anchor off the plan: the caller drops it")
	require.False(t, errors.Is(err, ErrArchiveRecoveryInvalid))
}

func TestArchivePlan_ResumesWhereAMissingRecordStoppedIt(t *testing.T) {
	t.Parallel()
	p := newPlanFixture(t, 12)
	p.serve(t, 7, 12) // the replica lacks 1..6 for now
	plan, err := NewArchivePlan(p.genesis, p.hash(12))
	require.NoError(t, err)
	err = p.source.Extend(context.Background(), plan, far())
	require.ErrorIs(t, err, ErrArchiveRecoveryUnavailable)
	require.False(t, errors.Is(err, ErrArchiveRecoveryInvalid), "a record missing everywhere is unavailable, not invalid")
	require.False(t, plan.Joined())
	require.Equal(t, 6, plan.Walked(), "what was walked before the missing record is kept")
	_, err = p.source.Page(context.Background(), plan, p.genesis, 8)
	require.ErrorIs(t, err, ErrArchiveRecoveryUnavailable, "an unjoined plan has no pages")

	p.serve(t, 1, 6)
	require.NoError(t, p.source.Extend(context.Background(), plan, far()))
	require.True(t, plan.Joined())
	require.Equal(t, 12, plan.Walked(), "the resumed walk does not record a block twice")
	page, err := p.source.Page(context.Background(), plan, p.genesis, 64)
	require.NoError(t, err)
	require.Equal(t, []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, heights(page))
}

func TestArchivePlan_ARestartedWalkReadsTheRetainedRecordsLocally(t *testing.T) {
	t.Parallel()
	p := newPlanFixture(t, 10)
	p.serve(t, 1, 10)
	plan, err := NewArchivePlan(p.genesis, p.hash(10))
	require.NoError(t, err)
	stopped := plan.Walked()
	require.NoError(t, p.source.Extend(context.Background(), plan, time.Now()), "a spent time budget is not an error")
	require.Equal(t, stopped, plan.Walked(), "and walks nothing")
	require.NoError(t, p.source.Extend(context.Background(), plan, far()))

	// a restarted node: a new plan, and no replica to ask
	offline := *p.source
	offline.Host, offline.Replicas = nil, nil
	again, err := NewArchivePlan(p.genesis, p.hash(10))
	require.NoError(t, err)
	require.NoError(t, offline.Extend(context.Background(), again, far()))
	require.True(t, again.Joined())
	page, err := offline.Page(context.Background(), again, p.genesis, 64)
	require.NoError(t, err)
	require.Len(t, page, 10)
}

func TestArchivePlan_Refusals(t *testing.T) {
	t.Parallel()
	t.Run("a replica copy without receipts is passed over", func(t *testing.T) {
		p := newPlanFixture(t, 3)
		p.serve(t, 1, 2)
		q, rec := p.f.record(t, 2)
		bare := withoutReceipts(rec)
		require.NoError(t, p.replica.Put(q, bare))
		binding := CertifiedBinding{Context: p.f.context, Subject: p.f.subject}
		fr := frontierRecordForRecovery(q, header(t, rec), resulting(t, rec))
		require.NoError(t, binding.VerifyCertified(fr, rec))
		require.Error(t, binding.VerifyCertified(fr, bare), "the binding refuses a copy only for its missing receipts: what keeps the retained copies receipt-complete")
		plan, err := NewArchivePlan(p.genesis, p.hash(3))
		require.NoError(t, err)
		err = p.source.Extend(context.Background(), plan, far())
		require.ErrorIs(t, err, ErrArchiveRecoveryUnavailable)
		require.ErrorContains(t, err, "certified binding")
		require.Zero(t, plan.Walked())
	})
	t.Run("a local copy without receipts does not stand in for a receipt-complete one", func(t *testing.T) {
		p := newPlanFixture(t, 3)
		p.serve(t, 1, 3)
		q, rec := p.f.record(t, 2)
		require.NoError(t, p.local.Put(q, withoutReceipts(rec)))
		plan, err := NewArchivePlan(p.genesis, p.hash(3))
		require.NoError(t, err)
		require.NoError(t, p.source.Extend(context.Background(), plan, far()))
		_, err = p.local.GetReceiptComplete(q)
		require.NoError(t, err, "the replica's receipt-complete copy is retained beside the bare one (the frontier needs it)")
	})
	t.Run("a tampered certificate is passed over", func(t *testing.T) {
		p := newPlanFixture(t, 3)
		p.serve(t, 1, 2)
		q, rec := p.f.record(t, 2)
		altered := *rec
		var result types.UnicityCertificate
		require.NoError(t, types.Cbor.Unmarshal(rec.ResultingUC, &result))
		result.InputRecord.Hash[0] ^= 0xff
		var err error
		altered.ResultingUC, err = types.Cbor.Marshal(&result)
		require.NoError(t, err)
		require.NoError(t, p.replica.Put(q, &altered))
		plan, err := NewArchivePlan(p.genesis, p.hash(3))
		require.NoError(t, err)
		err = p.source.Extend(context.Background(), plan, far())
		require.ErrorIs(t, err, ErrArchiveRecoveryUnavailable)
		require.Zero(t, plan.Walked())
		_, err = p.local.Get(q)
		require.ErrorIs(t, err, archive.ErrUnavailable, "nothing refused is retained")
	})
	t.Run("a chain that does not reach the anchor is invalid", func(t *testing.T) {
		p := newPlanFixture(t, 6)
		p.serve(t, 1, 6)
		other := p.ref(3)
		other.Hash = bytes.Repeat([]byte{9}, 32) // an anchor at height 3 that is not this chain's block 3
		plan, err := NewArchivePlan(other, p.hash(6))
		require.NoError(t, err)
		err = p.source.Extend(context.Background(), plan, far())
		require.ErrorIs(t, err, ErrArchiveRecoveryInvalid)
		require.ErrorIs(t, err, shardnode.ErrCertifiedChainForksAnchor, "a verified chain that comes down to the anchor's height without it proves the anchor is not on it (#843)")
		require.False(t, plan.Joined())
		require.Equal(t, 2, plan.Walked(), "blocks 6 and 5 are walked; block 4 does not join and is not recorded")
		walked := plan.Walked()
		require.ErrorIs(t, p.source.Extend(context.Background(), plan, far()), ErrArchiveRecoveryInvalid, "again on resume")
		require.Equal(t, walked, plan.Walked())
	})
	t.Run("FetchSuffix names the same proof, and a top at or below the anchor proves nothing", func(t *testing.T) {
		p := newPlanFixture(t, 6)
		p.serve(t, 1, 6)
		h3, h6 := p.hash(3), p.hash(6)
		other := p.ref(3)
		other.Hash = bytes.Repeat([]byte{9}, 32)
		_, err := p.source.FetchSuffix(context.Background(), other, h6[:])
		require.ErrorIs(t, err, ErrArchiveRecoveryInvalid)
		require.ErrorIs(t, err, shardnode.ErrCertifiedChainForksAnchor)
		// the anchor is genuinely on the chain: no proof of a fork
		entries, err := p.source.FetchSuffix(context.Background(), p.ref(3), h6[:])
		require.NoError(t, err)
		require.Len(t, entries, 3)
		// a top below the anchor says nothing about the anchor
		_, err = p.source.FetchSuffix(context.Background(), p.ref(5), h3[:])
		require.ErrorIs(t, err, ErrArchiveRecoveryInvalid)
		require.NotErrorIs(t, err, shardnode.ErrCertifiedChainForksAnchor)
		plan, err := NewArchivePlan(p.ref(5), p.hash(3))
		require.NoError(t, err)
		err = p.source.Extend(context.Background(), plan, far())
		require.ErrorIs(t, err, ErrArchiveRecoveryInvalid)
		require.NotErrorIs(t, err, shardnode.ErrCertifiedChainForksAnchor)
	})
	t.Run("a walk whose records cannot be retained does not move", func(t *testing.T) {
		p := newPlanFixture(t, 4)
		p.serve(t, 1, 4)
		dir := t.TempDir()
		local, err := archive.Open(dir)
		require.NoError(t, err)
		require.NoError(t, os.Chmod(dir, 0o555)) // the local archive refuses writes
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		p.source.Local = local
		plan, err := NewArchivePlan(p.genesis, p.hash(4))
		require.NoError(t, err)
		err = p.source.Extend(context.Background(), plan, far())
		require.ErrorIs(t, err, ErrArchiveRecoveryUnavailable)
		require.False(t, plan.Joined(), "a walk is joined only with its records retained")
		require.Zero(t, plan.Walked(), "positions of records that were not retained are dropped, so a resumed walk fetches them again")
		require.NoError(t, os.Chmod(dir, 0o755))
		require.NoError(t, p.source.Extend(context.Background(), plan, far()))
		require.True(t, plan.Joined())
		require.Equal(t, 4, plan.Walked())
	})
	t.Run("a top at or below the anchor's height is invalid", func(t *testing.T) {
		p := newPlanFixture(t, 6)
		p.serve(t, 1, 6)
		for _, top := range []int{3, 5} {
			plan, err := NewArchivePlan(p.ref(5), p.hash(top))
			if top == 5 {
				require.ErrorIs(t, err, ErrArchiveRecoveryUnavailable, "the anchor itself is no top")
				continue
			}
			require.NoError(t, err)
			err = p.source.Extend(context.Background(), plan, far())
			require.ErrorIs(t, err, ErrArchiveRecoveryInvalid, "top %d", top)
			require.Zero(t, plan.Walked())
		}
	})
	t.Run("a plan needs an anchor and another top", func(t *testing.T) {
		p := newPlanFixture(t, 1)
		_, err := NewArchivePlan(p.ref(1), p.hash(1))
		require.ErrorIs(t, err, ErrArchiveRecoveryUnavailable)
		_, err = NewArchivePlan(shardnode.BlockRef{}, p.hash(1))
		require.ErrorIs(t, err, ErrArchiveRecoveryUnavailable)
	})
}

// withoutReceipts is rec with its receipt list removed (a certified legacy record): the extension map stays non-nil, as SameArchiveCore strips it.
func withoutReceipts(rec *archive.Record) *archive.Record {
	cp := *rec
	cp.Extensions = make(map[string][]byte, len(rec.Extensions))
	for k, v := range rec.Extensions {
		if k != archive.ReceiptListKey {
			cp.Extensions[k] = v
		}
	}
	return &cp
}

func header(t *testing.T, rec *archive.Record) *gethtypes.Header {
	t.Helper()
	var h gethtypes.Header
	require.NoError(t, rlp.DecodeBytes(rec.Header, &h))
	return &h
}

func resulting(t *testing.T, rec *archive.Record) *types.UnicityCertificate {
	t.Helper()
	var uc types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(rec.ResultingUC, &uc))
	return &uc
}
