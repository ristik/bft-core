package configuredadmission

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

func signStallCertificate(t *testing.T, c *certifiedchain.Chain, ir *types.InputRecord, next, rootRound uint64) (*types.UnicityCertificate, *certification.TechnicalRecord) {
	t.Helper()
	tr := certifiedchain.Technical(next - 1)
	tr.Round = next
	uc := c.Certify(c.Signer, ir, tr, rootRound)
	uc.UnicitySeal.NetworkID = 3
	uc.UnicitySeal.Signatures = nil
	v, err := c.Signer.Verifier()
	require.NoError(t, err)
	pk, err := v.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(t, err)
	require.NoError(t, uc.UnicitySeal.Sign(id.String(), c.Signer))
	return uc, tr
}

// bft-core#1019 (review of #1021): a node that went through a long stall at one height holds, below the journal bounds, dead proposals for
// that height and repeat certificates of its parent. When it returns as its peers certify the height, the catch-up checks for room before it
// inserts anything, so no at-bound eviction can run, and the frontier cannot pass the stall's height without the blocks being fetched. The
// room check must first free the superseded history against durable progress.
func TestCatchUpRoomFreesStallHistoryBelowTheBounds(t *testing.T) {
	ctx := context.Background()
	chain, _, jc, _ := adapterFixtureBlocks(t, 1)
	limits := configuredprogress.JournalLimits{Candidates: 16, Observations: 24, Bytes: 64 << 20} // catch-up headroom 4
	store, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/journal.db", configuredprogress.Settings{Retain: 8})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	_, _, err = store.Initialize(ctx, jc)
	require.NoError(t, err)
	require.NoError(t, store.EnableJournal(ctx, jc, limits))
	boot, bootTR := journalBootstrap(t, chain)
	admitPeerObservation(t, store, jc, boot, bootTR)
	b1, b0 := chain.Blocks[1], chain.Blocks[0]
	require.NoError(t, store.PutJournalCandidate(ctx, jc, limits, configuredprogress.JournalCandidate{Round: b1.Round, Number: 1, ParentNumber: 0, Hash: b1.Hash.Bytes(),
		StateRoot: b1.StateRoot.Bytes(), ParentHash: b0.Hash.Bytes(), ParentState: b0.StateRoot.Bytes(), Raw: []byte{1}, AuthorizingUC: boot, AuthorizingTR: bootTR}))
	uc1, tr1 := signPeerBlock(t, chain, 1)
	admitPeerObservation(t, store, jc, uc1, tr1)

	// The stall at height 2: every round's proposal fails and the root repeats block 1's certificate.
	type pair struct {
		uc *types.UnicityCertificate
		tr *certification.TechnicalRecord
	}
	auths := map[uint64]pair{tr1.Round: {uc1, tr1}}
	dead := func(round uint64, tag byte) configuredprogress.JournalCandidate {
		a := auths[round]
		return configuredprogress.JournalCandidate{Round: round, Number: 2, ParentNumber: 1, Hash: bytes.Repeat([]byte{tag}, 32), StateRoot: bytes.Repeat([]byte{tag ^ 0xff}, 32),
			ParentHash: b1.Hash.Bytes(), ParentState: b1.StateRoot.Bytes(), Raw: []byte{tag}, AuthorizingUC: a.uc, AuthorizingTR: a.tr}
	}
	round, rootRound := tr1.Round, uc1.GetRootRoundNumber()+1
	for i := 0; i < 18; i++ {
		require.NoError(t, store.PutJournalCandidate(ctx, jc, limits, dead(round, byte(0x20+i))))
		u, r := signStallCertificate(t, chain, uc1.InputRecord, round+1, rootRound)
		admitPeerObservation(t, store, jc, u, r)
		round++
		rootRound++
		auths[round] = pair{u, r}
	}
	// Late copies of earlier rounds' proposals (as a node restarted from a journal written before #1019 holds them).
	for r := tr1.Round; r < tr1.Round+12; r++ {
		require.NoError(t, store.PutJournalCandidate(ctx, jc, limits, dead(r, byte(0x80+r))))
	}
	image, err := store.LoadJournal(ctx, jc, limits)
	require.NoError(t, err)
	require.Len(t, image.Candidates, 13, "block 1 and 12 dead proposals, all below the candidate bound")
	require.Len(t, image.Observations, 20, "bootstrap, block 1 and 18 repeats, all below the observation bound")

	r := &ExecutionRecovery{Store: store, Context: jc, JournalLimits: limits}
	room, err := r.catchUpRoom(ctx, 1)
	require.NoError(t, err)
	require.True(t, room, "the catch-up gets room once the stall's superseded history is freed")
	image, err = store.LoadJournal(ctx, jc, limits)
	require.NoError(t, err)
	require.Len(t, image.Candidates, 1, "only the certified block 1 is left")
	require.True(t, image.Candidates[0].Certified)
	require.Len(t, image.Observations, 3, "bootstrap, block 1's association and the newest repeat")
	require.Equal(t, rootRound-1, image.Observations[2].UC.GetRootRoundNumber())

	// The node then admits the certificate of height 2 that its peers produced.
	b2 := chain.Executed(b1, round, rootRound)
	require.NoError(t, store.PutJournalCandidate(ctx, jc, limits, configuredprogress.JournalCandidate{Round: round, Number: 2, ParentNumber: 1, Hash: b2.Hash.Bytes(),
		StateRoot: b2.StateRoot.Bytes(), ParentHash: b1.Hash.Bytes(), ParentState: b1.StateRoot.Bytes(), Raw: []byte{2}, AuthorizingUC: auths[round].uc, AuthorizingTR: auths[round].tr}))
	u2, r2 := signStallCertificate(t, chain, &types.InputRecord{Version: 1, RoundNumber: round, Hash: b2.StateRoot.Bytes(), PreviousHash: b1.StateRoot.Bytes(), SummaryValue: []byte{},
		Timestamp: 1_700_000_000 + round, BlockHash: b2.Hash.Bytes()}, round+1, rootRound)
	admitPeerObservation(t, store, jc, u2, r2)
	_, err = store.LoadJournal(ctx, jc, limits)
	require.NoError(t, err)
}
