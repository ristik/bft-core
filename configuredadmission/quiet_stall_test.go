package configuredadmission

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// bft-core#1019, quiet tail: a shard certifies B1..B3, then a quiet round, and then stalls for many more root timeouts than its observation
// bound. Every timeout is one more repeat of the quiet input record. The journal must admit all of them, and the history it keeps must still
// answer its readers: its own recovery finds B3 as the anchor of the quiet tail, and a returning peer holding only the newest repeat catches up
// to B3 through this journal's provider (which matches the held quiet interval and walks back to its nearest certified block).
func TestQuietTailStallBeyondObservationBoundStaysServable(t *testing.T) {
	chain, origin, journalCtx, id := adapterFixtureBlocks(t, 3)
	limits := configuredprogress.JournalLimits{Candidates: 16, Observations: 8, Bytes: 16 << 20}
	open := func() *configuredprogress.Store {
		s, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/journal.db", configuredprogress.Settings{Retain: 8})
		require.NoError(t, err)
		_, _, err = s.Initialize(context.Background(), journalCtx)
		require.NoError(t, err)
		require.NoError(t, s.EnableJournal(context.Background(), journalCtx, limits))
		t.Cleanup(func() { require.NoError(t, s.Close()) })
		return s
	}
	sign := func(ir *types.InputRecord, next, rootRound uint64) (*types.UnicityCertificate, *certification.TechnicalRecord) {
		tr := certifiedchain.Technical(next - 1)
		tr.Round = next
		uc := chain.Certify(chain.Signer, ir, tr, rootRound)
		uc.UnicitySeal.NetworkID = 3
		uc.UnicitySeal.Signatures = nil
		v, err := chain.Signer.Verifier()
		require.NoError(t, err)
		pk, err := v.MarshalPublicKey()
		require.NoError(t, err)
		nodeID, err := network.NodeIDFromPublicKeyBytes(pk)
		require.NoError(t, err)
		require.NoError(t, uc.UnicitySeal.Sign(nodeID.String(), chain.Signer))
		return uc, tr
	}

	provider := open()
	boot, bootTR := journalBootstrap(t, chain)
	admitPeerObservation(t, provider, journalCtx, boot, bootTR)
	uc := []*types.UnicityCertificate{boot}
	tr := []*certification.TechnicalRecord{bootTR}
	var b1 configuredprogress.JournalCandidate
	for i := 1; i <= 3; i++ {
		u, r := signPeerBlock(t, chain, i)
		uc, tr = append(uc, u), append(tr, r)
		b, prev := chain.Blocks[i], chain.Blocks[i-1]
		candidate := configuredprogress.JournalCandidate{Round: b.Round, Number: b.Number, ParentNumber: prev.Number, Hash: b.Hash.Bytes(), StateRoot: b.StateRoot.Bytes(), ParentHash: prev.Hash.Bytes(), ParentState: prev.StateRoot.Bytes(), Raw: []byte{byte(i)}, AuthorizingUC: uc[i-1], AuthorizingTR: tr[i-1]}
		if i == 1 {
			b1 = candidate
		}
		require.NoError(t, provider.PutJournalCandidate(context.Background(), journalCtx, limits, candidate))
		admitPeerObservation(t, provider, journalCtx, uc[i], tr[i])
	}
	b3 := chain.Blocks[3]
	quietIR := &types.InputRecord{Version: 1, RoundNumber: 4, PreviousHash: b3.StateRoot.Bytes(), Hash: b3.StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_004}
	quiet, quietTR := sign(quietIR, 5, 8)
	admitPeerObservation(t, provider, journalCtx, quiet, quietTR)
	// The stall: three times the observation bound of repeats of the quiet input record.
	for i := uint64(0); i < 3*uint64(limits.Observations); i++ {
		quiet, quietTR = sign(quietIR, 6+i, 9+i)
		admitPeerObservation(t, provider, journalCtx, quiet, quietTR)
	}
	image, err := provider.LoadJournal(context.Background(), journalCtx, limits)
	require.NoError(t, err)
	require.LessOrEqual(t, len(image.Observations), limits.Observations)

	refs := make([]shardnode.BlockRef, 4)
	for i, b := range chain.Blocks {
		refs[i] = shardnode.BlockRef{Number: b.Number, Hash: b.Hash.Bytes(), StateRoot: b.StateRoot.Bytes()}
	}
	// The provider's own recovery still finds B3 behind the quiet tail.
	providerChain, err := (&ExecutionRecovery{Store: provider, Context: journalCtx, JournalLimits: limits, Genesis: refs[0]}).chainFromImage(image)
	require.NoError(t, err)
	require.Equal(t, refs[3], providerChain.anchor)

	// A returning peer holds B1 and learns the newest quiet repeat from the root; it catches up to B3 through the provider.
	served := JournalProvider{Store: provider, Context: journalCtx, Limits: limits}
	returning := open()
	admitPeerObservation(t, returning, journalCtx, boot, bootTR)
	require.NoError(t, returning.PutJournalCandidate(context.Background(), journalCtx, limits, b1))
	admitPeerObservation(t, returning, journalCtx, uc[1], tr[1])
	exec := &replayExecutor{head: refs[1], finalized: refs[1], refs: refs, known: map[string]bool{string(refs[0].Hash): true, string(refs[1].Hash): true}}
	owner := &ExecutionRecovery{Store: returning, Context: journalCtx, JournalLimits: limits, Executor: exec, Gate: shardnode.NewFinalityGate(), Genesis: refs[0], Limits: RecoveryLimits{Blocks: 8, Bytes: 1024, Deadline: 3 * time.Second, Retries: 0}, Providers: []peer.ID{"provider"}}
	owner.fetch = func(ctx context.Context, _ peer.ID, req shardnode.JournalFetchRequest) ([]shardnode.JournalFetchEntry, error) {
		return served.FetchJournal(ctx, req)
	}
	admission, err := (JournalFactory{Store: returning, Origin: origin, Limits: limits, CatchUp: owner.AcquireForCertificate}).Start(context.Background(), id, adapterGate{}, shardnode.AdmissionCallbacks{AuthenticatedFeed: func(*types.UnicityCertificate, *certification.TechnicalRecord) {}, DeliverDurable: func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error { return nil }})
	require.NoError(t, err)
	defer admission.Close()
	require.NoError(t, admission.Submit(context.Background(), quiet, quietTR))
	head, err := owner.Recover(context.Background(), quiet)
	require.NoError(t, err)
	require.Equal(t, refs[3], head)
}
