package configuredadmission

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

func admitPeerObservation(t *testing.T, s *configuredprogress.Store, c configuredprogress.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) {
	t.Helper()
	ctx := context.Background()
	o, err := rootinput.AuthenticateObservationV2(ctx, c.Observation, uc, tr)
	require.NoError(t, err)
	p, _, err := s.PrepareObservation(ctx, c, o)
	require.NoError(t, err)
	_, _, err = s.CommitObservation(p)
	require.NoError(t, err)
}

func signPeerBlock(t *testing.T, c *certifiedchain.Chain, i int) (*types.UnicityCertificate, *certification.TechnicalRecord) {
	t.Helper()
	b, prev := c.Blocks[i], c.Blocks[i-1]
	ir := &types.InputRecord{Version: 1, RoundNumber: b.Round, Hash: b.StateRoot.Bytes(), PreviousHash: prev.StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_000 + b.Round, BlockHash: b.Hash.Bytes()}
	if i == 1 {
		ir.PreviousHash = nil
	}
	tr := certifiedchain.Technical(uint64(i))
	tr.Round = b.Round + 1
	uc := c.Certify(c.Signer, ir, tr, uint64(4+i))
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

func TestPeerCatchUpBackfillsMissingCertifiedMiddle(t *testing.T) {
	chain, origin, journalCtx, id := adapterFixtureBlocks(t, 3)
	limits := configuredprogress.JournalLimits{Candidates: 8, Observations: 8, Bytes: 16 << 20}
	open := func() *configuredprogress.Store {
		s, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/journal.db", configuredprogress.Settings{Retain: 8})
		require.NoError(t, err)
		_, _, err = s.Initialize(context.Background(), journalCtx)
		require.NoError(t, err)
		require.NoError(t, s.EnableJournal(context.Background(), journalCtx, limits))
		t.Cleanup(func() { require.NoError(t, s.Close()) })
		return s
	}
	provider, returning := open(), open()
	boot, bootTR := journalBootstrap(t, chain)
	admitPeerObservation(t, provider, journalCtx, boot, bootTR)
	admitPeerObservation(t, returning, journalCtx, boot, bootTR)
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
		if i == 1 {
			require.NoError(t, returning.PutJournalCandidate(context.Background(), journalCtx, limits, candidate))
			admitPeerObservation(t, returning, journalCtx, uc[i], tr[i])
		}
	}
	// The returning node learns B3 from root after missing B2. Admission
	// detects the state gap and invokes peer catch-up before advancing B3.
	refs := make([]shardnode.BlockRef, 4)
	known := map[string]bool{}
	for i, b := range chain.Blocks {
		refs[i] = shardnode.BlockRef{Number: b.Number, Hash: b.Hash.Bytes(), StateRoot: b.StateRoot.Bytes()}
		if i <= 1 {
			known[string(refs[i].Hash)] = true
		}
	}
	exec := &replayExecutor{head: refs[1], finalized: refs[1], refs: refs, known: known}
	var recoveryLogs bytes.Buffer
	owner := &ExecutionRecovery{Store: returning, Context: journalCtx, JournalLimits: limits, Executor: exec, Gate: shardnode.NewFinalityGate(), Log: slog.New(slog.NewTextHandler(&recoveryLogs, nil)), Genesis: refs[0], Limits: RecoveryLimits{Blocks: 8, Bytes: 1024, Deadline: 3 * time.Second, Retries: 0}, Providers: []peer.ID{"bad", "provider"}}
	served := JournalProvider{Store: provider, Context: journalCtx, Limits: limits}
	badRequests := 0
	owner.fetch = func(ctx context.Context, peerID peer.ID, req shardnode.JournalFetchRequest) ([]shardnode.JournalFetchEntry, error) {
		entries, err := served.FetchJournal(ctx, req)
		if err == nil && peerID == "bad" {
			badRequests++
			entries[0].Block.ParentHash = bytes.Repeat([]byte{0xff}, 32)
		}
		return entries, err
	}
	delivered := 0
	admission, err := (JournalFactory{Store: returning, Origin: origin, Limits: limits, CatchUp: owner.AcquireForCertificate}).Start(context.Background(), id, adapterGate{}, shardnode.AdmissionCallbacks{AuthenticatedFeed: func(*types.UnicityCertificate, *certification.TechnicalRecord) {}, DeliverDurable: func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error {
		delivered++
		return nil
	}})
	require.NoError(t, err)
	defer admission.Close()
	require.NoError(t, admission.Submit(context.Background(), uc[3], tr[3]))
	require.Equal(t, 1, badRequests, "a malformed peer suffix must be rejected before the valid peer is tried")
	require.Equal(t, 1, delivered)
	head, err := owner.Recover(context.Background(), uc[3])
	require.NoError(t, err)
	require.Equal(t, refs[3], head)
	require.Equal(t, []uint64{2, 3}, exec.verify)
	for i := 2; i <= 3; i++ {
		line := fmt.Sprintf("source=peer_recovery block=%x height=%d round=%d rootRound=%d", refs[i].Hash, i, uc[i].GetRoundNumber(), uc[i].GetRootRoundNumber())
		require.True(t, strings.Contains(recoveryLogs.String(), line), "missing durable association log %s in %s", line, recoveryLogs.String())
	}
	// With all hot-journal peers unavailable, the same authenticated suffix
	// can be supplied by the archive source and goes through the same admission.
	archiveOnly := open()
	admitPeerObservation(t, archiveOnly, journalCtx, boot, bootTR)
	imageForArchive, err := returning.LoadJournal(context.Background(), journalCtx, limits)
	require.NoError(t, err)
	var firstCandidate configuredprogress.JournalCandidate
	for _, item := range imageForArchive.Candidates {
		if item.Candidate.Number == 1 {
			firstCandidate = item.Candidate
			break
		}
	}
	require.NotEmpty(t, firstCandidate.Hash)
	require.NoError(t, archiveOnly.PutJournalCandidate(context.Background(), journalCtx, limits, firstCandidate))
	admitPeerObservation(t, archiveOnly, journalCtx, uc[1], tr[1])
	archiveExec := &replayExecutor{head: refs[1], finalized: refs[1], refs: refs, known: map[string]bool{string(refs[0].Hash): true, string(refs[1].Hash): true}}
	archiveCalls := 0
	archiveOwner := &ExecutionRecovery{Store: archiveOnly, Context: journalCtx, JournalLimits: limits, Executor: archiveExec, Gate: shardnode.NewFinalityGate(), Genesis: refs[0], Limits: RecoveryLimits{Blocks: 8, Bytes: 1024, Deadline: 3 * time.Second, Retries: 0}}
	archiveOwner.FetchArchive = func(ctx context.Context, after shardnode.BlockRef, target []byte) ([]shardnode.JournalFetchEntry, error) {
		archiveCalls++
		return served.FetchJournal(ctx, shardnode.JournalFetchRequest{TargetHash: target, AfterHash: after.Hash})
	}
	archiveAdmission, archiveErr := (JournalFactory{Store: archiveOnly, Origin: origin, Limits: limits, CatchUp: archiveOwner.AcquireForCertificate}).Start(context.Background(), id, adapterGate{}, shardnode.AdmissionCallbacks{AuthenticatedFeed: func(*types.UnicityCertificate, *certification.TechnicalRecord) {}, DeliverDurable: func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error { return nil }})
	require.NoError(t, archiveErr)
	defer archiveAdmission.Close()
	require.NoError(t, archiveAdmission.Submit(context.Background(), uc[3], tr[3]))
	archiveHead, archiveErr := archiveOwner.Recover(context.Background(), uc[3])
	require.NoError(t, archiveErr)
	require.Equal(t, refs[3], archiveHead)
	require.Positive(t, archiveCalls)
	require.Equal(t, []uint64{2, 3}, archiveExec.verify)
	var budgetLogs bytes.Buffer
	archiveOwner.Log = slog.New(slog.NewTextHandler(&budgetLogs, nil))
	archiveOwner.Limits.Bytes = 1
	archiveOwner.Providers = []peer.ID{"offline"}
	archiveOwner.fetch = func(context.Context, peer.ID, shardnode.JournalFetchRequest) ([]shardnode.JournalFetchEntry, error) {
		return nil, ErrRecoveryUnavailable
	}
	budgetErr := archiveOwner.fetchFromPeers(context.Background(), refs[1], refs[3].Hash, false, nil)
	require.ErrorIs(t, budgetErr, ErrRecoveryUnavailable)
	require.False(t, archiveOwner.Terminal(budgetErr), "an archive byte-budget overrun must be retried")
	require.Contains(t, budgetLogs.String(), "archive recovery deferred")

	archiveOwner.FetchArchive = func(context.Context, shardnode.BlockRef, []byte) ([]shardnode.JournalFetchEntry, error) {
		return nil, fmt.Errorf("%w: tampered archived record", ErrRecoveryInvalid)
	}
	beforeRefusal, err := archiveOnly.LoadJournal(context.Background(), journalCtx, limits)
	require.NoError(t, err)
	refusal := archiveOwner.fetchFromPeers(context.Background(), refs[1], refs[2].Hash, false, nil)
	require.ErrorIs(t, refusal, ErrRecoveryInvalid)
	afterRefusal, err := archiveOnly.LoadJournal(context.Background(), journalCtx, limits)
	require.NoError(t, err)
	require.Len(t, afterRefusal.Observations, len(beforeRefusal.Observations), "invalid archive bytes must not partially admit a suffix")
	owner.Providers = []peer.ID{"provider"}
	for _, tc := range []struct {
		bindingErr error
		class      string
	}{
		{fmt.Errorf("%w: witness RPC down", shardnode.ErrBlockBindingUnavailable), ErrRecoveryUnavailable.Error()},
		{errors.New("raw header mismatch"), ErrRecoveryInvalid.Error()},
	} {
		exec.bindingErr = tc.bindingErr
		bindingErr := owner.fetchFromPeers(context.Background(), refs[1], refs[2].Hash, false, nil)
		require.ErrorContains(t, bindingErr, tc.class)
		require.False(t, owner.Terminal(bindingErr), "peer failure must not stop local recovery")
	}
	exec.bindingErr = nil
	image, err := returning.LoadJournal(context.Background(), journalCtx, limits)
	require.NoError(t, err)
	require.Len(t, image.Observations, 4)
	require.False(t, image.Observations[3].Unresolved)
	for _, entry := range image.Candidates {
		require.True(t, entry.Certified)
	}
	// Raw-hash binding does not cover envelope metadata. A malicious peer can
	// offer the same certified hash with conflicting metadata; that peer must
	// be rejected without converting its store conflict into a process stop.
	metadataOwner := &ExecutionRecovery{Store: returning, Context: journalCtx, JournalLimits: limits, Executor: exec, Gate: shardnode.NewFinalityGate(), Genesis: refs[0], Limits: RecoveryLimits{Blocks: 8, Bytes: 1024, Deadline: 3 * time.Second, Retries: 0}, Providers: []peer.ID{"bad-metadata"}}
	metadataOwner.fetch = func(ctx context.Context, _ peer.ID, req shardnode.JournalFetchRequest) ([]shardnode.JournalFetchEntry, error) {
		entries, err := served.FetchJournal(ctx, req)
		if err == nil {
			entries[0].Block.BlockSize++
		}
		return entries, err
	}
	metadataErr := metadataOwner.fetchFromPeers(context.Background(), refs[0], refs[1].Hash, false, nil)
	require.ErrorIs(t, metadataErr, ErrRecoveryUnavailable)
	require.False(t, metadataOwner.Terminal(metadataErr))
	// A shard restart can lose journal B2/B3 while ureth still has them
	// finalized. Fetch their authenticated bytes without rewinding finality.
	aheadStore := open()
	admitPeerObservation(t, aheadStore, journalCtx, boot, bootTR)
	var b1ForAhead configuredprogress.JournalCandidate
	for _, entry := range image.Candidates {
		if entry.Candidate.Number == 1 {
			b1ForAhead = entry.Candidate
			break
		}
	}
	require.NoError(t, aheadStore.PutJournalCandidate(context.Background(), journalCtx, limits, b1ForAhead))
	admitPeerObservation(t, aheadStore, journalCtx, uc[1], tr[1])
	aheadKnown := map[string]bool{}
	for _, ref := range refs {
		aheadKnown[string(ref.Hash)] = true
	}
	aheadExec := &replayExecutor{head: refs[3], finalized: refs[3], refs: refs, known: aheadKnown}
	aheadOwner := &ExecutionRecovery{Store: aheadStore, Context: journalCtx, JournalLimits: limits, Executor: aheadExec, Gate: shardnode.NewFinalityGate(), Genesis: refs[0], Limits: RecoveryLimits{Blocks: 8, Bytes: 1024, Deadline: 3 * time.Second, Retries: 0}, Providers: []peer.ID{"provider"}, fetch: owner.fetch}
	aheadAdmission, aheadErr := (JournalFactory{Store: aheadStore, Origin: origin, Limits: limits, CatchUp: aheadOwner.AcquireForCertificate}).Start(context.Background(), id, adapterGate{}, shardnode.AdmissionCallbacks{AuthenticatedFeed: func(*types.UnicityCertificate, *certification.TechnicalRecord) {}, DeliverDurable: func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error { return nil }})
	require.NoError(t, aheadErr)
	defer aheadAdmission.Close()
	require.NoError(t, aheadAdmission.Submit(context.Background(), uc[3], tr[3]))
	_, aheadErr = aheadOwner.Recover(context.Background(), uc[3])
	require.NoError(t, aheadErr)
	require.Equal(t, refs[3], aheadExec.finalized)
	require.Empty(t, aheadExec.forkchoice, "backfill must not move forkchoice below finalized")

	// A quiet certificate names only B3's state. The separate suffix request
	// binds the held quiet IR and fetches the last non-quiet source B3.
	quietIR := &types.InputRecord{Version: 1, RoundNumber: 4, PreviousHash: chain.Blocks[3].StateRoot.Bytes(), Hash: chain.Blocks[3].StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_004}
	quietTR := certifiedchain.Technical(4)
	quietTR.Round = 5
	quiet := chain.Certify(chain.Signer, quietIR, quietTR, 8)
	quiet.UnicitySeal.NetworkID = 3
	quiet.UnicitySeal.Signatures = nil
	v, verifyErr := chain.Signer.Verifier()
	require.NoError(t, verifyErr)
	pk, verifyErr := v.MarshalPublicKey()
	require.NoError(t, verifyErr)
	idForSeal, verifyErr := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(t, verifyErr)
	require.NoError(t, quiet.UnicitySeal.Sign(idForSeal.String(), chain.Signer))
	admitPeerObservation(t, provider, journalCtx, quiet, quietTR)
	quietReturning := open()
	admitPeerObservation(t, quietReturning, journalCtx, boot, bootTR)
	var b1 configuredprogress.JournalCandidate
	for _, entry := range image.Candidates {
		if entry.Candidate.Number == 1 {
			b1 = entry.Candidate
			break
		}
	}
	require.NoError(t, quietReturning.PutJournalCandidate(context.Background(), journalCtx, limits, b1))
	admitPeerObservation(t, quietReturning, journalCtx, uc[1], tr[1])
	quietExec := &replayExecutor{head: refs[1], finalized: refs[1], refs: refs, known: map[string]bool{string(refs[0].Hash): true, string(refs[1].Hash): true}}
	quietOwner := &ExecutionRecovery{Store: quietReturning, Context: journalCtx, JournalLimits: limits, Executor: quietExec, Gate: shardnode.NewFinalityGate(), Genesis: refs[0], Limits: RecoveryLimits{Blocks: 8, Bytes: 1024, Deadline: 3 * time.Second, Retries: 0}, Providers: []peer.ID{"provider"}}
	quietOwner.fetch = owner.fetch
	quietAdmission, verifyErr := (JournalFactory{Store: quietReturning, Origin: origin, Limits: limits, CatchUp: quietOwner.AcquireForCertificate}).Start(context.Background(), id, adapterGate{}, shardnode.AdmissionCallbacks{AuthenticatedFeed: func(*types.UnicityCertificate, *certification.TechnicalRecord) {}, DeliverDurable: func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error { return nil }})
	require.NoError(t, verifyErr)
	defer quietAdmission.Close()
	require.NoError(t, quietAdmission.Submit(context.Background(), quiet, quietTR))
	quietHead, verifyErr := quietOwner.Recover(context.Background(), quiet)
	require.NoError(t, verifyErr)
	require.Equal(t, refs[3], quietHead)

	// If every peer is unavailable, the newer certificate cannot silently
	// disappear behind a health status for the older retained anchor.
	blocked := open()
	admitPeerObservation(t, blocked, journalCtx, boot, bootTR)
	require.NoError(t, blocked.PutJournalCandidate(context.Background(), journalCtx, limits, b1))
	admitPeerObservation(t, blocked, journalCtx, uc[1], tr[1])
	var stopped error
	blockedAdmission, verifyErr := (JournalFactory{Store: blocked, Origin: origin, Limits: limits,
		CatchUp: func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error {
			return ErrRecoveryUnavailable
		},
		OnStop: func(err error) { stopped = err },
	}).Start(context.Background(), id, adapterGate{}, shardnode.AdmissionCallbacks{AuthenticatedFeed: func(*types.UnicityCertificate, *certification.TechnicalRecord) {}, DeliverDurable: func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error { return nil }})
	require.NoError(t, verifyErr)
	defer blockedAdmission.Close()
	require.ErrorIs(t, blockedAdmission.Submit(context.Background(), uc[3], tr[3]), ErrRecoveryUnavailable)
	require.NoError(t, stopped, "peer unavailability must remain retryable")
	require.True(t, blockedAdmission.(interface{ Pending() bool }).Pending(), "the authenticated target must be retried without another root delivery")
	blockedImage, err := blocked.LoadJournal(context.Background(), journalCtx, limits)
	require.NoError(t, err)
	require.Len(t, blockedImage.Observations, 3, "only the authenticated held certificate should remain pending")
	require.True(t, blockedImage.Observations[2].Unresolved)
	require.Len(t, blockedImage.Candidates, 1, "an unavailable source must not partially admit any suffix bodies")
}

func TestPeerCatchUpReusesLocallyBuiltCandidateAfterLeaderRestart(t *testing.T) {
	chain, origin, journalCtx, id := adapterFixtureBlocks(t, 3)
	limits := configuredprogress.JournalLimits{Candidates: 8, Observations: 8, Bytes: 16 << 20}
	open := func() *configuredprogress.Store {
		s, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/journal.db", configuredprogress.Settings{Retain: 8})
		require.NoError(t, err)
		_, _, err = s.Initialize(context.Background(), journalCtx)
		require.NoError(t, err)
		require.NoError(t, s.EnableJournal(context.Background(), journalCtx, limits))
		t.Cleanup(func() { require.NoError(t, s.Close()) })
		return s
	}
	provider, returning := open(), open()
	boot, bootTR := journalBootstrap(t, chain)
	uc := []*types.UnicityCertificate{boot}
	tr := []*certification.TechnicalRecord{bootTR}
	admitPeerObservation(t, provider, journalCtx, boot, bootTR)
	admitPeerObservation(t, returning, journalCtx, boot, bootTR)
	for i := 1; i <= 3; i++ {
		u, r := signPeerBlock(t, chain, i)
		uc, tr = append(uc, u), append(tr, r)
		b, prev := chain.Blocks[i], chain.Blocks[i-1]
		candidate := configuredprogress.JournalCandidate{Round: b.Round, Number: b.Number, ParentNumber: prev.Number, Hash: b.Hash.Bytes(), StateRoot: b.StateRoot.Bytes(), ParentHash: prev.Hash.Bytes(), ParentState: prev.StateRoot.Bytes(), Raw: []byte{byte(i)}, AuthorizingUC: uc[i-1], AuthorizingTR: tr[i-1]}
		require.NoError(t, provider.PutJournalCandidate(context.Background(), journalCtx, limits, candidate))
		admitPeerObservation(t, provider, journalCtx, u, r)
		if i == 1 {
			require.NoError(t, returning.PutJournalCandidate(context.Background(), journalCtx, limits, candidate))
			admitPeerObservation(t, returning, journalCtx, u, r)
		}
		if i == 2 {
			// The killed leader durably retained this exact body before B2 was
			// certified, then restarted with only B1 in durable progress.
			candidate.LocallyBuilt = true
			require.NoError(t, returning.PutJournalCandidate(context.Background(), journalCtx, limits, candidate))
		}
	}
	refs := make([]shardnode.BlockRef, 4)
	for i, b := range chain.Blocks {
		refs[i] = shardnode.BlockRef{Number: b.Number, Hash: b.Hash.Bytes(), StateRoot: b.StateRoot.Bytes()}
	}
	exec := &replayExecutor{head: refs[1], finalized: refs[1], refs: refs, known: map[string]bool{string(refs[0].Hash): true, string(refs[1].Hash): true}}
	owner := &ExecutionRecovery{Store: returning, Context: journalCtx, JournalLimits: limits, Executor: exec, Gate: shardnode.NewFinalityGate(), Genesis: refs[0], Limits: RecoveryLimits{Blocks: 8, Bytes: 1024, Deadline: 3 * time.Second}, Providers: []peer.ID{"provider"}}
	served := JournalProvider{Store: provider, Context: journalCtx, Limits: limits}
	owner.fetch = func(ctx context.Context, _ peer.ID, req shardnode.JournalFetchRequest) ([]shardnode.JournalFetchEntry, error) {
		return served.FetchJournal(ctx, req)
	}
	admission, err := (JournalFactory{Store: returning, Origin: origin, Limits: limits, CatchUp: owner.AcquireForCertificate}).Start(context.Background(), id, adapterGate{}, shardnode.AdmissionCallbacks{AuthenticatedFeed: func(*types.UnicityCertificate, *certification.TechnicalRecord) {}, DeliverDurable: func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error { return nil }})
	require.NoError(t, err)
	defer admission.Close()
	require.NoError(t, admission.Submit(context.Background(), uc[3], tr[3]))
	head, err := owner.Recover(context.Background(), uc[3])
	require.NoError(t, err)
	require.Equal(t, refs[3], head)
	image, err := returning.LoadJournal(context.Background(), journalCtx, limits)
	require.NoError(t, err)
	for _, e := range image.Candidates {
		if e.Candidate.Number == 2 {
			require.True(t, e.Candidate.LocallyBuilt)
			require.True(t, e.Certified)
			return
		}
	}
	t.Fatal("missing recovered locally built candidate")
}
