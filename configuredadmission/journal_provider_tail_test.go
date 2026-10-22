package configuredadmission

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// TestJournalProviderServesItsTailForAZeroAncestor: a zero ancestor asks for the certified chain ending at the target as far back as the
// journal retains it (#769: the newest blocks of a long catch-up, not yet archived), while an exact ancestor keeps its exact meaning.
func TestJournalProviderServesItsTailForAZeroAncestor(t *testing.T) {
	chain, _, journalCtx, _ := adapterFixtureBlocks(t, 5)
	limits := configuredprogress.JournalLimits{Candidates: 16, Observations: 16, Bytes: 16 << 20}
	store, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/journal.db", configuredprogress.Settings{Retain: 8})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	_, _, err = store.Initialize(context.Background(), journalCtx)
	require.NoError(t, err)
	require.NoError(t, store.EnableJournal(context.Background(), journalCtx, limits))
	boot, bootTR := journalBootstrap(t, chain)
	admitPeerObservation(t, store, journalCtx, boot, bootTR)
	uc, tr := []*types.UnicityCertificate{boot}, []*certification.TechnicalRecord{bootTR}
	for i := 1; i <= 5; i++ {
		u, r := signPeerBlock(t, chain, i)
		uc, tr = append(uc, u), append(tr, r)
		b, prev := chain.Blocks[i], chain.Blocks[i-1]
		require.NoError(t, store.PutJournalCandidate(context.Background(), journalCtx, limits, configuredprogress.JournalCandidate{Round: b.Round, Number: b.Number,
			ParentNumber: prev.Number, Hash: b.Hash.Bytes(), StateRoot: b.StateRoot.Bytes(), ParentHash: prev.Hash.Bytes(), ParentState: prev.StateRoot.Bytes(),
			Raw: []byte{byte(i)}, AuthorizingUC: uc[i-1], AuthorizingTR: tr[i-1]}))
		admitPeerObservation(t, store, journalCtx, u, r)
	}
	served := JournalProvider{Store: store, Context: journalCtx, Limits: limits}
	numbers := func(entries []shardnode.JournalFetchEntry) []uint64 {
		var out []uint64
		for _, e := range entries {
			out = append(out, e.Block.Number)
		}
		return out
	}
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
