package recordwiring_test

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/recordwiring"
	"github.com/unicitynetwork/bft-core/shardnode"
)

/*
W3b-2: the capturer publishes a record for a block that anchor recovery applied, and the existing
store refusals answer the case where both a recovery commit and an ordinary commit report the same
block. The capturer cannot tell a recovery commit from an ordinary one, which is the contract: the
round hands it the certificate that certified the block, which across a quiet tail is the source,
never the quiet certificate in hand.
*/

// recoveryCommit is what Round.applyVerifiedAnchor reports for a recovered block: the SOURCE
// certificate that certified the block and its bound technical record, with the certified block hash.
func recoveryCommit(h *captureHarness, i int) shardnode.CertifiedCommit {
	uc, tr := h.c.Certificate(i)
	return shardnode.CertifiedCommit{Certificate: uc, Technical: tr, BlockHash: h.c.Blocks[i].Hash.Bytes()}
}

// childAfter builds a quiet certificate the source's technical record assigns: the child the
// readiness gate of §9 must find readiness for. The bound technical record is returned with it, so
// the test observes the exact pair the chain signed.
func childAfter(t *testing.T, c *certifiedchain.Chain, source *types.UnicityCertificate, sourceTR *certification.TechnicalRecord) (*types.UnicityCertificate, *certification.TechnicalRecord) {
	t.Helper()
	state := bytes.Clone(source.InputRecord.Hash)
	childTR := &certification.TechnicalRecord{Round: sourceTR.Round + 1, Epoch: sourceTR.Epoch, Leader: "leader",
		StatHash: bytes.Repeat([]byte{0xa1}, 32), FeeHash: bytes.Repeat([]byte{0xa2}, 32)}
	childIR := &types.InputRecord{Version: 1, RoundNumber: sourceTR.Round, Epoch: source.InputRecord.Epoch,
		PreviousHash: state, Hash: state, SummaryValue: []byte{}, Timestamp: source.InputRecord.Timestamp + 1}
	return c.Certify(c.Signer, childIR, childTR, source.GetRootRoundNumber()+1), childTR
}

// recoveringNode is the common setup for the end-to-end recovery tests: a returning node behind the
// certified block, wired to the real recovery stack, the real capturer and the real readiness gate.
// The certificate observer is the ONLY feed into the observation history, so a later Prepare that
// succeeds is proof the recovery chain reached it rather than something the test supplied by hand.
//
// The node is the leader, so after the anchor is installed it also exercises the gate; while the
// captured record has not caught up it declines to lead, which is the gate doing its job and not a
// processing error.
type recoveringNode struct {
	c         *certifiedchain.Chain
	d         recordwiring.Deployment
	store     *certifiedstore.Store
	exec      *lifecycleExecutor
	obs       *recordwiring.Observations
	readiness *recordwiring.Readiness
	round     *shardnode.Round
	published recordwiring.CaptureResult
	sourceUC  *types.UnicityCertificate
	sourceTR  *certification.TechnicalRecord
	childUC   *types.UnicityCertificate
	childTR   *certification.TechnicalRecord
}

func newRecoveringNode(t *testing.T) *recoveringNode {
	t.Helper()
	ctx := context.Background()
	c := certifiedchain.New(t, 3, 3)
	d := mustDeployment(t, c)
	store, err := recordwiring.OpenStore(filepath.Join(t.TempDir(), "certified.db"), 8)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	rpc := newWitnessRPC(c)
	gate := shardnode.NewFinalityGate()
	exec := newLifecycleExecutor(ref(c.Blocks[0]))
	for i := 1; i < len(c.Blocks); i++ {
		exec.blocks[string(c.Blocks[i].Hash.Bytes())] = ref(c.Blocks[i])
	}
	sourceUC, sourceTR := c.Certificate(2)
	childUC, childTR := childAfter(t, c, sourceUC, sourceTR)
	grandchildUC, grandchildTR := childAfter(t, c, childUC, childTR)
	bundle := shardnode.AnchorEvidence{Source: sourceUC, SourceTechnical: sourceTR,
		Tail: []shardnode.EvidenceLink{{UC: childUC, Technical: childTR}}}

	sc := d.StoreContext()
	req, err := shardnode.NewEvidenceRequester(shardnode.RecoveryConfig{
		PartitionID: sc.PartitionID, ShardID: sc.ShardID, ShardConfHash: sc.FullShardConfHash,
		TrustBases: sc.TrustBases, Fetcher: staticFetcher{ev: bundle}, Providers: staticProviders{"peer"},
		Limits: shardnode.DefaultAnchorEvidenceLimits, Budget: shardnode.DefaultRecoveryBudget,
	})
	require.NoError(t, err)
	t.Cleanup(req.Close)
	applier, err := shardnode.NewTargetApplier(shardnode.ApplyConfig{
		Executor: exec, Source: req, Budget: shardnode.DefaultApplyBudget, Gate: gate})
	require.NoError(t, err)
	stack := &shardnode.RecoveryStack{Requester: req, Applier: applier, Gate: gate}

	obs, err := recordwiring.NewObservations(recordwiring.DefaultObservationLimits)
	require.NoError(t, err)
	readiness, err := recordwiring.NewReadiness(d, store, exec, obs)
	require.NoError(t, err)

	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	r := shardnode.NewRound("leader", sc.PartitionID, sc.ShardID, exec, shardnode.NewLoopbackDisseminator(), signer, &recordingSubmitter{}, nil)
	r.SetAwaitTimeout(50 * time.Millisecond)
	r.SetRecovery(stack)
	r.SetHealth(shardnode.NewHealth())
	r.SetChildReadiness(recordwiring.NewChildReadiness(readiness))
	r.SetCertificateObserver(recordwiring.NewCertificateObserver(obs))

	results := make(chan recordwiring.CaptureResult, 64)
	capturer, err := recordwiring.NewCapturer(recordwiring.CaptureConfig{
		Deployment: d, Store: store, RPC: rpc, Executor: exec, Finality: gate, AcquireTimeout: 20 * time.Second,
		OnResult: func(res recordwiring.CaptureResult) { results <- res },
	})
	require.NoError(t, err)
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); _ = capturer.Run(runCtx) }()
	t.Cleanup(func() { stop(); <-done })
	r.SetCommitObserver(capturer)

	// The first quiet certificate starts the fetch; the second applies the retained evidence, which
	// commits block 2 and feeds its authenticated chain to the observation history.
	require.Error(t, r.HandleCertificate(ctx, childUC, childTR), "the node cannot name the recovered block yet")
	waitRecoveryReady(t, req)
	require.NoError(t, r.HandleCertificate(ctx, grandchildUC, grandchildTR),
		"the leader declines on readiness while the record has not caught up, which is not a processing error")

	var published recordwiring.CaptureResult
	select {
	case published = <-results:
		require.Equal(t, recordwiring.CapturePublished, published.Outcome, "%v", published.Err)
	case <-time.After(30 * time.Second):
		t.Fatal("the recovery commit was never captured")
	}
	return &recoveringNode{c: c, d: d, store: store, exec: exec, obs: obs, readiness: readiness, round: r,
		published: published, sourceUC: sourceUC, sourceTR: sourceTR, childUC: childUC, childTR: childTR}
}

// TestRecoveryCapturePublishesARecord: the capturer publishes a record for a recovery-applied block,
// and the gate of §9 then finds readiness for its child. Nothing is observed by hand: the round fed
// the authenticated chain to the history at the point it installed the anchor.
func TestRecoveryCapturePublishesARecord(t *testing.T) {
	n := newRecoveringNode(t)
	require.Equal(t, n.c.Blocks[2].Hash, n.published.Attempt.BlockHash)
	loaded, err := n.store.Load(context.Background(), n.d.StoreContext())
	require.NoError(t, err)
	require.Equal(t, n.c.Blocks[2].Hash, loaded.BlockHash())

	source, err := loaded.Certificate()
	require.NoError(t, err)
	sourceTR, err := loaded.Technical()
	require.NoError(t, err)
	require.Equal(t, n.c.Blocks[2].Hash.Bytes(), []byte(source.InputRecord.BlockHash),
		"the durable record names the block the source certificate certified")
	require.Equal(t, n.sourceTR, sourceTR)

	p, err := n.readiness.Prepare(context.Background(), n.childUC)
	require.NoError(t, err, "the record from a recovery-applied block is the source's own certificate")
	require.True(t, p.Valid())
	require.NoError(t, n.readiness.Revalidate(context.Background(), p, n.childUC))
}

// TestGateBecomesReadyAfterRecoveryAndCapture: end to end with no certificate observed by hand. The
// node recovers across a quiet tail, the capturer publishes the recovered block, and the readiness
// gate connects the durable record to the recovered block's child out of the history the recovery
// itself supplied.
func TestGateBecomesReadyAfterRecoveryAndCapture(t *testing.T) {
	n := newRecoveringNode(t)

	// No obs.Observe call appears in this test. The source and the tail were authenticated by
	// VerifyAnchorEvidence and fed by Round.observeRecoveryChain; if that feed did not happen the
	// history would contain neither the source nor the chain from it, and Prepare would refuse.
	p, err := n.readiness.Prepare(context.Background(), n.childUC)
	require.NoError(t, err)
	require.True(t, p.Valid())
	head, err := n.exec.Head(context.Background())
	require.NoError(t, err)
	require.Equal(t, n.c.Blocks[2].Hash.Bytes(), []byte(head.Hash), "the executor is at the durable record's block")
}

// TestRecoveryAndOrdinaryCommitForTheSameBlock: both a recovery commit and an ordinary commit for
// the same block are reported. The block is already durable after the first, so the existing
// duplicate refusal answers the second: no publication starts and no record is damaged. The store's
// own stale refusal is the other half of the same answer and is covered by
// TestCaptureFailuresKeepThePriorRecord's "a later record is already durable".
func TestRecoveryAndOrdinaryCommitForTheSameBlock(t *testing.T) {
	h := newCaptureHarness(t, 2)
	h.publish(0)
	b := h.c.Blocks[1]
	h.exec.set(b)

	h.cap.ObserveCommit(recoveryCommit(h, 1))
	require.Equal(t, recordwiring.CapturePublished, h.next().Outcome)
	prior, keys := h.head(), h.keys()

	// The ordinary commit reports the same block, re-certified at a later root round: the same input
	// record, so the same partition round and block, but a different signed certificate.
	source, sourceTR := storedHeadPair(t, h)
	repeatIR := *source.InputRecord
	repeat := h.c.Certify(h.c.Signer, &repeatIR, sourceTR, source.GetRootRoundNumber()+1)
	h.cap.ObserveCommit(shardnode.CertifiedCommit{Certificate: repeat, Technical: sourceTR, BlockHash: b.Hash.Bytes()})

	dup := h.next()
	require.Equal(t, recordwiring.CaptureDuplicate, dup.Outcome)
	require.ErrorIs(t, dup.Err, recordwiring.ErrDuplicateCapture)
	require.Equal(t, prior, h.head(), "the durable record is not damaged")
	require.Equal(t, keys, h.keys(), "nothing is written or deleted")
}
