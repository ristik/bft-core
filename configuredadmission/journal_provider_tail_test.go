package configuredadmission

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// TestJournalProviderServesItsTailForAZeroAncestor: a zero ancestor asks for the certified chain ending at the target as far back as the
// journal retains it (#769: the newest blocks of a long catch-up, not yet archived), while an exact ancestor keeps its exact meaning.
func TestJournalProviderServesItsTailForAZeroAncestor(t *testing.T) {
	store, chain, journalCtx, limits := tailFixture(t, 5)
	served := JournalProvider{Store: store, Context: journalCtx, Limits: limits}
	target := chain.Blocks[5].Hash.Bytes()

	entries, err := served.FetchJournal(context.Background(), shardnode.JournalFetchRequest{TargetHash: target, AfterHash: make([]byte, 32)})
	require.NoError(t, err, "the tail stops at the first block the journal does not retain (genesis here)")
	require.Equal(t, []uint64{1, 2, 3, 4, 5}, numbers(entries))

	entries, err = served.FetchJournal(context.Background(), shardnode.JournalFetchRequest{TargetHash: chain.Blocks[3].Hash.Bytes(), AfterHash: make([]byte, 32)})
	require.NoError(t, err)
	require.Equal(t, []uint64{1, 2, 3}, numbers(entries), "the tail ends at the requested target")

	other := make([]byte, 32)
	other[0] = 1
	_, err = served.FetchJournal(context.Background(), shardnode.JournalFetchRequest{TargetHash: other, AfterHash: make([]byte, 32)})
	require.ErrorContains(t, err, "missing certified entry", "a target the journal does not hold is refused, not an empty tail")

	entries, err = served.FetchJournal(context.Background(), shardnode.JournalFetchRequest{TargetHash: target, AfterHash: chain.Blocks[2].Hash.Bytes()})
	require.NoError(t, err)
	require.Equal(t, []uint64{3, 4, 5}, numbers(entries), "an exact ancestor is unchanged")

	_, err = served.FetchJournal(context.Background(), shardnode.JournalFetchRequest{TargetHash: target, AfterHash: other})
	require.ErrorContains(t, err, "missing certified entry", "an ancestor that is not retained is still refused (only the zero ancestor asks for the tail)")
}

// TestJournalProviderCapsItsTailAt256: a journal that retains more than one suffix's worth (the default --journal-candidates is 256)
// serves the newest 256 as its tail, where an exact suffix that long is refused.
func TestJournalProviderCapsItsTailAt256(t *testing.T) {
	const n = 260
	store, chain, journalCtx, limits := tailFixture(t, n)
	served := JournalProvider{Store: store, Context: journalCtx, Limits: limits}
	entries, err := served.FetchJournal(context.Background(), shardnode.JournalFetchRequest{TargetHash: chain.Blocks[n].Hash.Bytes(), AfterHash: make([]byte, 32)})
	require.NoError(t, err)
	require.Len(t, entries, 256)
	require.EqualValues(t, n-255, entries[0].Block.Number, "the newest 256")
	require.EqualValues(t, n, entries[255].Block.Number)
	_, err = served.FetchJournal(context.Background(), shardnode.JournalFetchRequest{TargetHash: chain.Blocks[n].Hash.Bytes(), AfterHash: chain.Blocks[0].Hash.Bytes()})
	require.ErrorContains(t, err, "suffix exceeds 256 blocks", "an exact suffix keeps its cap")
}

func numbers(entries []shardnode.JournalFetchEntry) []uint64 {
	var out []uint64
	for _, e := range entries {
		out = append(out, e.Block.Number)
	}
	return out
}

// tailFixture is a journal retaining n certified blocks after its bootstrap certificate.
func tailFixture(t *testing.T, n int) (*configuredprogress.Store, *certifiedchain.Chain, configuredprogress.Context, configuredprogress.JournalLimits) {
	t.Helper()
	chain, _, journalCtx, _ := adapterFixtureBlocks(t, n)
	limits := configuredprogress.JournalLimits{Candidates: n + 8, Observations: n + 8, Bytes: 64 << 20}
	store, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/journal.db", configuredprogress.Settings{Retain: 8})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	_, _, err = store.Initialize(context.Background(), journalCtx)
	require.NoError(t, err)
	require.NoError(t, store.EnableJournal(context.Background(), journalCtx, limits))
	boot, bootTR := journalBootstrap(t, chain)
	admitPeerObservation(t, store, journalCtx, boot, bootTR)
	uc, tr := []*types.UnicityCertificate{boot}, []*certification.TechnicalRecord{bootTR}
	for i := 1; i <= n; i++ {
		u, r := signPeerBlock(t, chain, i)
		uc, tr = append(uc, u), append(tr, r)
		b, prev := chain.Blocks[i], chain.Blocks[i-1]
		require.NoError(t, store.PutJournalCandidate(context.Background(), journalCtx, limits, configuredprogress.JournalCandidate{Round: b.Round, Number: b.Number,
			ParentNumber: prev.Number, Hash: b.Hash.Bytes(), StateRoot: b.StateRoot.Bytes(), ParentHash: prev.Hash.Bytes(), ParentState: prev.StateRoot.Bytes(),
			Raw: []byte{byte(i)}, AuthorizingUC: uc[i-1], AuthorizingTR: tr[i-1]}))
		admitPeerObservation(t, store, journalCtx, u, r)
	}
	return store, chain, journalCtx, limits
}
