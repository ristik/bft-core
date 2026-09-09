package shardnode

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

/*
Tests for the provider half of authenticated anchor recovery
(docs/design/f6b-quiet-tail-anchor-recovery.md §6.1).

They reuse the signed-certificate fixture from anchorevidence_test.go, so every certificate here is
genuinely signed by a real key and every assembled bundle can be — and is — fed to the real
VerifyAnchorEvidence rather than inspected field by field. That end-to-end check is the point: the
buffer's contract is not "returns plausible-looking certificates", it is "returns something the
accepted predicate accepts, or nothing at all".

Rounds are non-consecutive throughout (10 → 12 → 16 → 21 …), so any reintroduction of round+1
arithmetic on the serving side fails here as well.
*/

func newTestBuffer(t *testing.T) *EvidenceBuffer {
	t.Helper()
	b, err := NewEvidenceBuffer(DefaultEvidenceBufferLimits)
	require.NoError(t, err)
	return b
}

func mustObserve(t *testing.T, b *EvidenceBuffer, links ...EvidenceLink) {
	t.Helper()
	for _, l := range links {
		require.NoError(t, b.Observe(l.UC, l.Technical))
	}
}

// requestFor pins a request to a certificate the way a requester would: round plus the canonical
// input-record identity.
func requestFor(t *testing.T, uc *types.UnicityCertificate) EvidenceRequest {
	t.Helper()
	id, err := uc.InputRecord.Bytes()
	require.NoError(t, err)
	return EvidenceRequest{HeldRound: uc.InputRecord.RoundNumber, HeldIdentity: id}
}

// verifyAssembled runs an assembled bundle through the real predicate, with the held certificate the
// request was pinned to. Nothing in these tests asserts a bundle is good without doing this.
func verifyAssembled(t *testing.T, f *evidenceFixture, ev AnchorEvidence, held *types.UnicityCertificate) (*ExecutionAnchor, error) {
	t.Helper()
	return VerifyAnchorEvidence(context.Background(), ev, AnchorEvidenceContext{
		PartitionID:   evidencePartitionID,
		ShardConfHash: f.conf,
		TrustBases:    f.trust,
		Held:          held,
	}, DefaultAnchorEvidenceLimits)
}

// quietTailObserved is the measured situation from the provider's side: a block certified in round
// 10, then quiet rounds at the state it produced. A peer that stayed up observed all of it.
func quietTailObserved(t *testing.T, f *evidenceFixture) []EvidenceLink {
	t.Helper()
	stateA, stateB, blockB := h32(0x0a), h32(0x0b), h32(0xbb)
	return []EvidenceLink{
		f.cert(10, 100, stateA, stateB, blockB, 12),
		f.cert(12, 110, stateB, stateB, nil, 16),
		f.cert(16, 120, stateB, stateB, nil, 21),
		f.cert(21, 130, stateB, stateB, nil, 25),
	}
}

func TestEvidenceBuffer_ServesAChainThePredicateAccepts(t *testing.T) {
	f := newEvidenceFixture(t)
	b := newTestBuffer(t)
	obs := quietTailObserved(t, f)
	mustObserve(t, b, obs...)

	// A returning node holds round 16 and is missing the block certified in round 10.
	held := obs[2].UC
	ev, err := b.Assemble(requestFor(t, held))
	require.NoError(t, err)

	anchor, err := verifyAssembled(t, f, ev, held)
	require.NoError(t, err)
	require.Equal(t, Hash(h32(0xbb)), anchor.BlockHash)
	require.EqualValues(t, 10, anchor.Round)

	// The window stops at the requested round: nothing after it is served, even though the provider
	// has moved on to round 21.
	require.Len(t, ev.Tail, 2)
	require.EqualValues(t, 16, ev.Tail[len(ev.Tail)-1].UC.InputRecord.RoundNumber)

	count, from, to := b.Retained()
	require.Equal(t, 4, count)
	require.EqualValues(t, 10, from)
	require.EqualValues(t, 21, to)
}

func TestEvidenceBuffer_RepeatsAndDuplicates(t *testing.T) {
	t.Run("a duplicate delivery is idempotent", func(t *testing.T) {
		// Delivery retries make these ordinary: the quiet-tail measurement saw 168 deliveries over
		// 20 distinct rounds.
		f := newEvidenceFixture(t)
		b := newTestBuffer(t)
		obs := quietTailObserved(t, f)
		mustObserve(t, b, obs...)
		before, _, _ := b.Retained()

		for i := 0; i < 5; i++ {
			mustObserve(t, b, obs[3])
		}
		after, _, to := b.Retained()
		require.Equal(t, before, after)
		require.EqualValues(t, 21, to)

		held := obs[2].UC
		ev, err := b.Assemble(requestFor(t, held))
		require.NoError(t, err)
		_, err = verifyAssembled(t, f, ev, held)
		require.NoError(t, err)
	})

	t.Run("a repeat supersedes the assignment in place", func(t *testing.T) {
		f := newEvidenceFixture(t)
		b := newTestBuffer(t)
		stateA, stateB := h32(0x0a), h32(0x0b)
		source := f.cert(10, 100, stateA, stateB, h32(0xbb), 12)
		mid := f.cert(12, 110, stateB, stateB, nil, 16)
		// A root-chain timeout re-certified round 12, now assigning 15 instead of 16.
		repeat := f.cert(12, 115, stateB, stateB, nil, 15)
		next := f.cert(15, 118, stateB, stateB, nil, 19)
		mustObserve(t, b, source, mid, repeat, next)

		// One entry per round: the repeat replaced round 12's assignment rather than being appended.
		count, from, to := b.Retained()
		require.Equal(t, 3, count)
		require.EqualValues(t, 10, from)
		require.EqualValues(t, 15, to)

		ev, err := b.Assemble(requestFor(t, next.UC))
		require.NoError(t, err)
		anchor, err := verifyAssembled(t, f, ev, next.UC)
		require.NoError(t, err)
		require.Equal(t, Hash(h32(0xbb)), anchor.BlockHash)
	})

	t.Run("a repeat that does not advance the root round abandons the interval", func(t *testing.T) {
		f := newEvidenceFixture(t)
		b := newTestBuffer(t)
		stateA, stateB := h32(0x0a), h32(0x0b)
		source := f.cert(10, 100, stateA, stateB, h32(0xbb), 12)
		mid := f.cert(12, 110, stateB, stateB, nil, 16)
		stale := f.cert(12, 110, stateB, stateB, nil, 15) // same round, same root round, new assignment
		mustObserve(t, b, source, mid, stale)

		count, _, _ := b.Retained()
		require.Equal(t, 1, count, "the interval is rebuilt from the offending certificate")
		require.False(t, b.Ready())
	})

	t.Run("two authenticated certificates for one round that disagree abandon the interval", func(t *testing.T) {
		f := newEvidenceFixture(t)
		b := newTestBuffer(t)
		stateA, stateB := h32(0x0a), h32(0x0b)
		source := f.cert(10, 100, stateA, stateB, h32(0xbb), 12)
		mid := f.cert(12, 110, stateB, stateB, nil, 16)
		rival := f.cert(12, 115, stateB, h32(0x0c), h32(0xdd), 16)
		mustObserve(t, b, source, mid, rival)

		// Whatever the shard's history is, this node can no longer prove the interval before the
		// contradiction, so none of it is served.
		count, from, _ := b.Retained()
		require.Equal(t, 1, count)
		require.EqualValues(t, 12, from)
		_, err := b.Assemble(requestFor(t, mid.UC))
		require.ErrorIs(t, err, ErrProviderMismatch, "the retained round 12 is not the one that requester holds")

		// The rebuilt interval starts at the rival itself, which this node did receive and
		// authenticate; it can serve that and nothing earlier.
		ev, err := b.Assemble(requestFor(t, rival.UC))
		require.NoError(t, err)
		require.Empty(t, ev.Tail)
		anchor, err := verifyAssembled(t, f, ev, rival.UC)
		require.NoError(t, err)
		require.Equal(t, Hash(h32(0xdd)), anchor.BlockHash)
	})
}

func TestEvidenceBuffer_GapsAndReadiness(t *testing.T) {
	t.Run("a restarted provider is not ready and serves nothing", func(t *testing.T) {
		f := newEvidenceFixture(t)
		b := newTestBuffer(t)
		require.False(t, b.Ready())
		_, err := b.Assemble(EvidenceRequest{HeldRound: 16})
		require.ErrorIs(t, err, ErrProviderNotReady)

		// It receives only quiet certificates — the ordinary state of a node that restarted into a
		// quiet shard. It has certificates and still nothing that names a block.
		stateB := h32(0x0b)
		q1 := f.cert(12, 110, stateB, stateB, nil, 16)
		q2 := f.cert(16, 120, stateB, stateB, nil, 21)
		mustObserve(t, b, q1, q2)
		require.False(t, b.Ready())
		_, err = b.Assemble(requestFor(t, q2.UC))
		require.ErrorIs(t, err, ErrProviderNotReady)
	})

	t.Run("a missed assignment abandons the interval rather than bridging it", func(t *testing.T) {
		f := newEvidenceFixture(t)
		b := newTestBuffer(t)
		stateA, stateB := h32(0x0a), h32(0x0b)
		source := f.cert(10, 100, stateA, stateB, h32(0xbb), 12)
		// Round 12 was assigned; round 16 arrives. At least one certificate was missed.
		skipped := f.cert(16, 120, stateB, stateB, nil, 21)
		mustObserve(t, b, source, skipped)

		count, from, _ := b.Retained()
		require.Equal(t, 1, count)
		require.EqualValues(t, 16, from)
		_, err := b.Assemble(requestFor(t, skipped.UC))
		require.ErrorIs(t, err, ErrProviderEvicted, "it had a source and lost the thread to it")
	})

	t.Run("a request ahead of this provider is behind, not evicted", func(t *testing.T) {
		f := newEvidenceFixture(t)
		b := newTestBuffer(t)
		obs := quietTailObserved(t, f)
		mustObserve(t, b, obs[0], obs[1])
		_, err := b.Assemble(EvidenceRequest{HeldRound: 99})
		require.ErrorIs(t, err, ErrProviderBehind)
	})

	t.Run("a shard epoch change restarts the interval", func(t *testing.T) {
		// The predicate refuses a chain that crosses an epoch boundary, so retaining across one
		// could only produce chains nobody may use. Same-epoch scope, stated in the behaviour.
		f := newEvidenceFixture(t)
		b := newTestBuffer(t)
		obs := quietTailObserved(t, f)
		mustObserve(t, b, obs...)
		require.True(t, b.Ready())

		next := f.certAtEpoch(25, 140, h32(0x0b), h32(0x0b), nil, 30, 1)
		mustObserve(t, b, next)
		count, from, _ := b.Retained()
		require.Equal(t, 1, count)
		require.EqualValues(t, 25, from)
		require.False(t, b.Ready())
	})
}

func TestEvidenceBuffer_OlderHeldRoundsAfterANewerSource(t *testing.T) {
	// The correction a single "latest source" pointer gets wrong: once a newer block is certified,
	// a request pinned BEHIND it must still be answered from the source that was current then.
	f := newEvidenceFixture(t)
	b := newTestBuffer(t)
	stateA, stateB, stateC := h32(0x0a), h32(0x0b), h32(0x0c)
	source1 := f.cert(10, 100, stateA, stateB, h32(0xbb), 12)
	quiet1 := f.cert(12, 110, stateB, stateB, nil, 16)
	source2 := f.cert(16, 120, stateB, stateC, h32(0xcc), 21)
	quiet2 := f.cert(21, 130, stateC, stateC, nil, 25)
	mustObserve(t, b, source1, quiet1, source2, quiet2)

	t.Run("a request behind the newer source is answered from the older one", func(t *testing.T) {
		ev, err := b.Assemble(requestFor(t, quiet1.UC))
		require.NoError(t, err)
		require.EqualValues(t, 10, ev.Source.InputRecord.RoundNumber)
		anchor, err := verifyAssembled(t, f, ev, quiet1.UC)
		require.NoError(t, err)
		require.Equal(t, Hash(h32(0xbb)), anchor.BlockHash)
	})

	t.Run("a request at the newer source is answered from it", func(t *testing.T) {
		ev, err := b.Assemble(requestFor(t, quiet2.UC))
		require.NoError(t, err)
		require.EqualValues(t, 16, ev.Source.InputRecord.RoundNumber)
		require.Len(t, ev.Tail, 1)
		anchor, err := verifyAssembled(t, f, ev, quiet2.UC)
		require.NoError(t, err)
		require.Equal(t, Hash(h32(0xcc)), anchor.BlockHash)
	})

	t.Run("a request pinned to a different certificate for the round is a mismatch", func(t *testing.T) {
		req := requestFor(t, quiet1.UC)
		req.HeldIdentity = h32(0xee)
		_, err := b.Assemble(req)
		require.ErrorIs(t, err, ErrProviderMismatch)
	})
}

func TestEvidenceBuffer_Eviction(t *testing.T) {
	build := func(t *testing.T, f *evidenceFixture, rounds int) []EvidenceLink {
		t.Helper()
		stateA, stateB := h32(0x0a), h32(0x0b)
		out := []EvidenceLink{f.cert(10, 100, stateA, stateB, h32(0xbb), 12)}
		round, root := uint64(12), uint64(110)
		for i := 0; i < rounds; i++ {
			next := round + 4 // never +1
			out = append(out, f.cert(round, root, stateB, stateB, nil, next))
			round, root = next, root+10
		}
		return out
	}

	t.Run("the middle of an interval cannot be evicted without the source going first", func(t *testing.T) {
		// Eviction is oldest-first, so the source is always the first casualty. That is what makes
		// "no source at or before the requested round" the sharp question, rather than a search for
		// a hole in the middle.
		f := newEvidenceFixture(t)
		b, err := NewEvidenceBuffer(EvidenceBufferLimits{MaxEntries: 3, MaxBytes: 1 << 20})
		require.NoError(t, err)
		obs := build(t, f, 5)
		mustObserve(t, b, obs...)

		count, from, to := b.Retained()
		require.Equal(t, 3, count)
		require.EqualValues(t, obs[len(obs)-3].UC.InputRecord.RoundNumber, from)
		require.EqualValues(t, obs[len(obs)-1].UC.InputRecord.RoundNumber, to)
		require.False(t, b.Ready(), "the only source has been evicted")

		_, err = b.Assemble(requestFor(t, obs[len(obs)-1].UC))
		require.ErrorIs(t, err, ErrProviderEvicted)
	})

	t.Run("an evicted round is evicted, not behind", func(t *testing.T) {
		f := newEvidenceFixture(t)
		b, err := NewEvidenceBuffer(EvidenceBufferLimits{MaxEntries: 3, MaxBytes: 1 << 20})
		require.NoError(t, err)
		obs := build(t, f, 5)
		mustObserve(t, b, obs...)
		_, err = b.Assemble(requestFor(t, obs[0].UC))
		require.ErrorIs(t, err, ErrProviderEvicted)
	})

	t.Run("the byte bound evicts too, and never below one entry", func(t *testing.T) {
		f := newEvidenceFixture(t)
		obs := build(t, f, 4)
		b, err := NewEvidenceBuffer(EvidenceBufferLimits{MaxEntries: 512, MaxBytes: 1})
		require.NoError(t, err)
		mustObserve(t, b, obs...)
		count, _, to := b.Retained()
		require.Equal(t, 1, count, "a single entry is retained even under an impossible byte bound")
		require.EqualValues(t, obs[len(obs)-1].UC.InputRecord.RoundNumber, to)
	})

	t.Run("as long as a source survives, the window it can serve is served in full", func(t *testing.T) {
		f := newEvidenceFixture(t)
		b, err := NewEvidenceBuffer(EvidenceBufferLimits{MaxEntries: 4, MaxBytes: 1 << 20})
		require.NoError(t, err)
		stateA, stateB, stateC := h32(0x0a), h32(0x0b), h32(0x0c)
		mustObserve(t, b,
			f.cert(10, 100, stateA, stateB, h32(0xbb), 12),
			f.cert(12, 110, stateB, stateB, nil, 16),
			f.cert(16, 120, stateB, stateC, h32(0xcc), 21), // a newer source
			f.cert(21, 130, stateC, stateC, nil, 25),
		)
		last := f.cert(25, 140, stateC, stateC, nil, 30)
		mustObserve(t, b, last) // evicts round 10, the older source

		ev, err := b.Assemble(requestFor(t, last.UC))
		require.NoError(t, err)
		require.EqualValues(t, 16, ev.Source.InputRecord.RoundNumber)
		anchor, err := verifyAssembled(t, f, ev, last.UC)
		require.NoError(t, err)
		require.Equal(t, Hash(h32(0xcc)), anchor.BlockHash)
	})

	t.Run("the default buffer never assembles more than a requester will accept", func(t *testing.T) {
		require.LessOrEqual(t, DefaultEvidenceBufferLimits.MaxEntries, DefaultAnchorEvidenceLimits.MaxCertificates,
			"a provider must not build a chain the far end refuses for a length this side chose")
	})

	t.Run("both bounds must be positive", func(t *testing.T) {
		for _, l := range []EvidenceBufferLimits{{}, {MaxEntries: 8}, {MaxBytes: 8}} {
			_, err := NewEvidenceBuffer(l)
			require.Error(t, err)
		}
	})
}

func TestEvidenceBuffer_RejectsObservationsItCannotStandBehind(t *testing.T) {
	f := newEvidenceFixture(t)
	b := newTestBuffer(t)

	t.Run("nil input", func(t *testing.T) {
		require.ErrorIs(t, b.Observe(nil, nil), ErrObservationRejected)
	})

	t.Run("a technical record the certificate does not commit to", func(t *testing.T) {
		// The caller has already authenticated the certificate; what this buffer re-checks is the
		// one binding that would otherwise let a local defect become a chain served to a peer.
		link := f.cert(10, 100, h32(0x0a), h32(0x0b), h32(0xbb), 12)
		unbound := &certification.TechnicalRecord{
			Round: 99, Epoch: 0, Leader: "leader", StatHash: h32(0xa1), FeeHash: h32(0xa2),
		}
		require.ErrorIs(t, b.Observe(link.UC, unbound), ErrObservationRejected)
		count, _, _ := b.Retained()
		require.Zero(t, count)
	})
}

func TestEvidenceBuffer_ReturnedDataDoesNotAliasTheBuffer(t *testing.T) {
	f := newEvidenceFixture(t)
	b := newTestBuffer(t)
	obs := quietTailObserved(t, f)
	mustObserve(t, b, obs...)
	held := obs[2].UC

	t.Run("mutating what the caller kept does not change what is retained", func(t *testing.T) {
		// obs[0].UC is still the caller's own object; the buffer copied it on observation.
		saved := append([]byte(nil), obs[0].UC.InputRecord.BlockHash...)
		obs[0].UC.InputRecord.BlockHash = h32(0xee)
		defer func() { obs[0].UC.InputRecord.BlockHash = saved }()

		ev, err := b.Assemble(requestFor(t, held))
		require.NoError(t, err)
		require.Equal(t, saved, []byte(ev.Source.InputRecord.BlockHash))
	})

	t.Run("mutating an assembled bundle does not change the next one", func(t *testing.T) {
		first, err := b.Assemble(requestFor(t, held))
		require.NoError(t, err)
		first.Source.InputRecord.BlockHash = h32(0xee)
		first.Tail[0].Technical.Round = 4242

		second, err := b.Assemble(requestFor(t, held))
		require.NoError(t, err)
		require.Equal(t, h32(0xbb), []byte(second.Source.InputRecord.BlockHash))
		require.EqualValues(t, 16, second.Tail[0].Technical.Round)

		// And the untouched copy still verifies, which is the property that actually matters.
		_, err = verifyAssembled(t, f, second, held)
		require.NoError(t, err)
	})
}

func TestEvidenceBuffer_ConcurrentAppendAndAssemble(t *testing.T) {
	// Run with -race. Assembly happens under the lock that observation appends under, so a
	// certificate arriving mid-assembly can neither lengthen nor truncate an answer: every bundle
	// returned here must verify, whenever it was taken.
	f := newEvidenceFixture(t)
	b := newTestBuffer(t)
	stateA, stateB := h32(0x0a), h32(0x0b)

	source := f.cert(10, 100, stateA, stateB, h32(0xbb), 12)
	mustObserve(t, b, source)

	var later []EvidenceLink
	round, root := uint64(12), uint64(110)
	for i := 0; i < 40; i++ {
		next := round + 4
		later = append(later, f.cert(round, root, stateB, stateB, nil, next))
		round, root = next, root+10
	}
	held := later[0]
	mustObserve(t, b, held)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for _, l := range later[1:] {
			require.NoError(t, b.Observe(l.UC, l.Technical))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			ev, err := b.Assemble(requestFor(t, held.UC))
			require.NoError(t, err)
			require.EqualValues(t, 10, ev.Source.InputRecord.RoundNumber)
			require.Len(t, ev.Tail, 1, "the window ends at the requested round however far the provider has moved")
		}
	}()
	wg.Wait()

	ev, err := b.Assemble(requestFor(t, held.UC))
	require.NoError(t, err)
	_, err = verifyAssembled(t, f, ev, held.UC)
	require.NoError(t, err)
}
