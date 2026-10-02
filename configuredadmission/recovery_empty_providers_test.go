package configuredadmission

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// After an assignment shrinks the set to {self} there are no hot-journal peers, but an authenticated archive may still hold the missing
// body: Recover must reach it. Retired peers are never asked in its place.
func TestRecoverReachesTheArchiveWhenTheActiveSetIsEmpty(t *testing.T) {
	chain, _, journalCtx, _ := adapterFixtureBlocks(t, 3)
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
	provider := open()
	boot, bootTR := journalBootstrap(t, chain)
	admitPeerObservation(t, provider, journalCtx, boot, bootTR)
	uc := []*types.UnicityCertificate{boot}
	tr := []*certification.TechnicalRecord{bootTR}
	for i := 1; i <= 3; i++ {
		u, r := signPeerBlock(t, chain, i)
		uc = append(uc, u)
		tr = append(tr, r)
	}
	for i := 1; i <= 3; i++ {
		b, prev := chain.Blocks[i], chain.Blocks[i-1]
		candidate := configuredprogress.JournalCandidate{Round: b.Round, Number: b.Number, ParentNumber: prev.Number, Hash: b.Hash.Bytes(), StateRoot: b.StateRoot.Bytes(), ParentHash: prev.Hash.Bytes(), ParentState: prev.StateRoot.Bytes(), Raw: []byte{byte(i)}, AuthorizingUC: uc[i-1], AuthorizingTR: tr[i-1]}
		require.NoError(t, provider.PutJournalCandidate(context.Background(), journalCtx, limits, candidate))
		admitPeerObservation(t, provider, journalCtx, uc[i], tr[i])
	}
	refs := make([]shardnode.BlockRef, 4)
	for i, b := range chain.Blocks {
		refs[i] = shardnode.BlockRef{Number: b.Number, Hash: b.Hash.Bytes(), StateRoot: b.StateRoot.Bytes()}
	}
	served := JournalProvider{Store: provider, Context: journalCtx, Limits: limits}

	// a recovery whose local journal holds an authenticated terminal observation but not its body
	build := func(t *testing.T) (*ExecutionRecovery, *int, *int) {
		local := open()
		admitPeerObservation(t, local, journalCtx, boot, bootTR)
		b, prev := chain.Blocks[1], chain.Blocks[0]
		candidate := configuredprogress.JournalCandidate{Round: b.Round, Number: b.Number, ParentNumber: prev.Number, Hash: b.Hash.Bytes(), StateRoot: b.StateRoot.Bytes(), ParentHash: prev.Hash.Bytes(), ParentState: prev.StateRoot.Bytes(), Raw: []byte{1}, AuthorizingUC: boot, AuthorizingTR: bootTR}
		require.NoError(t, local.PutJournalCandidate(context.Background(), journalCtx, limits, candidate))
		admitPeerObservation(t, local, journalCtx, uc[1], tr[1])
		admitPeerObservation(t, local, journalCtx, uc[3], tr[3])
		exec := &replayExecutor{head: refs[1], finalized: refs[1], refs: refs, known: map[string]bool{string(refs[0].Hash): true, string(refs[1].Hash): true}}
		r := &ExecutionRecovery{Store: local, Context: journalCtx, JournalLimits: limits, Executor: exec, Gate: shardnode.NewFinalityGate(), Genesis: refs[0],
			Limits: RecoveryLimits{Blocks: 8, Bytes: 1024, Deadline: 3 * time.Second, Retries: 0}}
		peerCalls, archiveCalls := new(int), new(int)
		r.fetch = func(context.Context, peer.ID, shardnode.JournalFetchRequest) ([]shardnode.JournalFetchEntry, error) {
			*peerCalls++
			return nil, ErrRecoveryUnavailable
		}
		r.FetchArchive = func(ctx context.Context, after shardnode.BlockRef, target []byte) ([]shardnode.JournalFetchEntry, error) {
			*archiveCalls++
			return served.FetchJournal(ctx, shardnode.JournalFetchRequest{TargetHash: target, AfterHash: after.Hash})
		}
		_, err := r.load(context.Background())
		require.ErrorIs(t, err, ErrRecoveryUnavailable, "the body is missing")
		return r, peerCalls, archiveCalls
	}
	emptyActiveSet := func(t *testing.T) shardnode.PeerLister {
		self, retired := newPeerIDForTest(t), newPeerIDForTest(t)
		active, err := shardnode.NewActivePeers(self, []*types.NodeInfo{{NodeID: self.String()}, {NodeID: retired.String()}})
		require.NoError(t, err)
		require.NoError(t, active.Install(1, []*types.NodeInfo{{NodeID: self.String()}}))
		require.Empty(t, active.Peers())
		return active
	}

	t.Run("an empty active set still reaches the archive, and no retired peer is asked", func(t *testing.T) {
		r, peerCalls, archiveCalls := build(t)
		r.Providers = []peer.ID{"retired"} // the fixed list a deployment without assignments would hold: must not be used
		r.ProviderSource = emptyActiveSet(t)
		got, err := r.Recover(context.Background(), uc[3])
		require.NoError(t, err)
		require.Equal(t, refs[3], got)
		require.Positive(t, *archiveCalls)
		require.Zero(t, *peerCalls, "never a fallback to retired peers")
	})
	t.Run("an archive-only recovery (no transport, no peers) reaches the archive", func(t *testing.T) {
		r, _, archiveCalls := build(t)
		r.fetch = nil // no transport at all
		got, err := r.Recover(context.Background(), uc[3])
		require.NoError(t, err)
		require.Equal(t, refs[3], got)
		require.Positive(t, *archiveCalls)
	})
	t.Run("with no peers and no archive there is nothing to ask", func(t *testing.T) {
		r, peerCalls, archiveCalls := build(t)
		r.FetchArchive = nil
		r.ProviderSource = emptyActiveSet(t)
		_, err := r.Recover(context.Background(), uc[3])
		require.ErrorIs(t, err, ErrRecoveryUnavailable)
		require.Zero(t, *peerCalls)
		require.Zero(t, *archiveCalls)
	})
	t.Run("a fixed list of peers is unchanged", func(t *testing.T) {
		r, peerCalls, archiveCalls := build(t)
		r.Providers = []peer.ID{"p"}
		got, err := r.Recover(context.Background(), uc[3])
		require.NoError(t, err, "the peer fails, the archive recovers")
		require.Equal(t, refs[3], got)
		require.Positive(t, *peerCalls)
		require.Positive(t, *archiveCalls)
	})
}

func newPeerIDForTest(t *testing.T) peer.ID {
	t.Helper()
	return testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)).ID()
}
