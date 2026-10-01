package configuredadmission

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// An EVM validator that never admitted a certificate after genesis (it missed its first handshake, as in the H3 lane
// run3: height 1 onward) must catch up from its peers and reach the live head. It holds only the genesis certificate when
// the first certificate it sees is B3's.
func TestPeerCatchUpFromGenesisWhenEveryCertifiedBlockWasMissed(t *testing.T) {
	lateJoinerCatchUp(t, 3)
}

func lateJoinerCatchUp(t *testing.T, blocks int) {
	chain, origin, journalCtx, id := adapterFixtureBlocks(t, blocks)
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
	provider, late := open(), open()
	boot, bootTR := journalBootstrap(t, chain)
	admitPeerObservation(t, provider, journalCtx, boot, bootTR)
	admitPeerObservation(t, late, journalCtx, boot, bootTR) // the only certificate the late validator ever saw
	uc := []*types.UnicityCertificate{boot}
	tr := []*certification.TechnicalRecord{bootTR}
	for i := 1; i <= blocks; i++ {
		u, r := signPeerBlock(t, chain, i)
		uc, tr = append(uc, u), append(tr, r)
	}
	for i := 1; i <= blocks; i++ {
		b, prev := chain.Blocks[i], chain.Blocks[i-1]
		candidate := configuredprogress.JournalCandidate{Round: b.Round, Number: b.Number, ParentNumber: prev.Number, Hash: b.Hash.Bytes(), StateRoot: b.StateRoot.Bytes(), ParentHash: prev.Hash.Bytes(), ParentState: prev.StateRoot.Bytes(), Raw: []byte{byte(i)}, AuthorizingUC: uc[i-1], AuthorizingTR: tr[i-1]}
		require.NoError(t, provider.PutJournalCandidate(context.Background(), journalCtx, limits, candidate))
		admitPeerObservation(t, provider, journalCtx, uc[i], tr[i])
	}
	refs := make([]shardnode.BlockRef, blocks+1)
	for i, b := range chain.Blocks {
		refs[i] = shardnode.BlockRef{Number: b.Number, Hash: b.Hash.Bytes(), StateRoot: b.StateRoot.Bytes()}
	}
	exec := &replayExecutor{head: refs[0], finalized: refs[0], refs: refs, known: map[string]bool{string(refs[0].Hash): true}}
	owner := &ExecutionRecovery{Store: late, Context: journalCtx, JournalLimits: limits, Executor: exec, Gate: shardnode.NewFinalityGate(), Log: slog.New(slog.DiscardHandler), Genesis: refs[0], Limits: RecoveryLimits{Blocks: 8, Bytes: 1024, Deadline: 3 * time.Second, Retries: 0}, Providers: []peer.ID{"provider"}}
	served := JournalProvider{Store: provider, Context: journalCtx, Limits: limits}
	owner.fetch = func(ctx context.Context, _ peer.ID, req shardnode.JournalFetchRequest) ([]shardnode.JournalFetchEntry, error) {
		return served.FetchJournal(ctx, req)
	}
	delivered := 0
	admission, err := (JournalFactory{Store: late, Origin: origin, Limits: limits, CatchUp: owner.AcquireForCertificate}).Start(context.Background(), id, adapterGate{}, shardnode.AdmissionCallbacks{AuthenticatedFeed: func(*types.UnicityCertificate, *certification.TechnicalRecord) {}, DeliverDurable: func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error {
		delivered++
		return nil
	}})
	require.NoError(t, err)
	defer admission.Close()
	require.NoError(t, admission.Submit(context.Background(), uc[blocks], tr[blocks]), "a validator that missed every certified block catches up from its peers")
	require.Equal(t, 1, delivered)
	head, err := owner.Recover(context.Background(), uc[blocks])
	require.NoError(t, err)
	require.Equal(t, refs[blocks], head)
}
