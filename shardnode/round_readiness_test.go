package shardnode_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/shardnode/executortest"
)

// fakeTicket is the minimal opaque ticket: only Valid matters to the round.
type fakeTicket struct{ valid bool }

func (t fakeTicket) Valid() bool { return t.valid }

type countingRoundSigner struct {
	signer abcrypto.Signer
	calls  int
}

func (s *countingRoundSigner) Sign(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord, req *certification.BlockCertificationRequest) (*certification.BlockCertificationRequest, error) {
	s.calls++
	return shardnode.LocalKeySigner(s.signer).Sign(ctx, uc, tr, req)
}

type toggleJournalRecovery struct {
	ready, terminal bool
	head            shardnode.BlockRef
	calls           int
}

func (r *toggleJournalRecovery) Recover(context.Context, *types.UnicityCertificate) (shardnode.BlockRef, error) {
	r.calls++
	if !r.ready {
		return shardnode.BlockRef{}, errors.New("certified executor head is not ready")
	}
	return r.head, nil
}

func (r *toggleJournalRecovery) Terminal(error) bool { return r.terminal }

type refusedBuildExecutor struct {
	shardnode.Executor
	builds int
}

func (e *refusedBuildExecutor) Build(context.Context, shardnode.RoundParams) (shardnode.BuildID, error) {
	e.builds++
	return "", shardnode.ErrBuildUnavailable
}

func TestRoundBuildJobRefusalAbstainsWithoutSigning(t *testing.T) {
	exec := &refusedBuildExecutor{Executor: executortest.New()}
	sub := &recordingSubmitter{}
	r, nodeID := newTestRound(t, exec, sub)
	spy := &journalSignerSpy{}
	r.SetCertificationSigner(spy)
	health := shardnode.NewHealth()
	r.SetHealth(health)
	require.NoError(t, r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, nodeID)))
	require.Equal(t, 1, exec.builds)
	require.Zero(t, spy.calls)
	require.Empty(t, sub.got)
	require.Equal(t, "unready", health.Snapshot().ExecutionRecovery)
}

func TestJournalRecoveryBlocksRoundBuildAndSignUntilReady(t *testing.T) {
	fake := executortest.New()
	fake.AddEntries([]byte("payload"))
	genesis, err := fake.GenesisBlock(context.Background())
	require.NoError(t, err)
	builds := &buildRecordingExecutor{Executor: fake}
	sub := &recordingSubmitter{}
	r, nodeID := newTestRound(t, builds, sub)
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	spy := &countingRoundSigner{signer: signer}
	r.SetCertificationSigner(spy)
	r.SetHealth(shardnode.NewHealth())
	r.SetFinalityGate(shardnode.NewFinalityGate())
	recovery := &toggleJournalRecovery{head: genesis}
	r.SetJournalRecovery(recovery)
	err = r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, nodeID))
	require.ErrorContains(t, err, "certified executor head is not ready")
	require.Empty(t, builds.parents, "the real Round must refuse Build before recovery readiness")
	require.Zero(t, spy.calls, "the real Round must refuse Sign before recovery readiness")
	require.Empty(t, sub.got)
	recovery.ready = true
	require.NoError(t, r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, nodeID)))
	require.Len(t, builds.parents, 1, "the same Round must Build once when recovery becomes ready")
	require.Equal(t, 1, spy.calls, "the same Round must Sign once when recovery becomes ready")
	require.Len(t, sub.got, 1)
}

func TestJournalRecoveryStoppedLatchBlocksBuildAndSign(t *testing.T) {
	fake := executortest.New()
	genesis, err := fake.GenesisBlock(context.Background())
	require.NoError(t, err)
	builds := &buildRecordingExecutor{Executor: fake}
	sub := &recordingSubmitter{}
	r, nodeID := newTestRound(t, builds, sub)
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	spy := &countingRoundSigner{signer: signer}
	r.SetCertificationSigner(spy)
	health := shardnode.NewHealth()
	r.SetHealth(health)
	recovery := &toggleJournalRecovery{head: genesis, terminal: true}
	r.SetJournalRecovery(recovery)
	require.ErrorContains(t, r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, nodeID)), "certified executor head is not ready")
	require.Equal(t, "stopped", health.Snapshot().ExecutionRecovery)
	recovery.ready = true
	require.ErrorContains(t, r.HandleCertificate(context.Background(), genesisUC(1000), tr(1, 0, nodeID)), "execution journal stopped")
	require.Equal(t, 1, recovery.calls, "a stopped journal cannot be retried into readiness")
	require.Empty(t, builds.parents)
	require.Zero(t, spy.calls)
	require.Empty(t, sub.got)
}

// staticReadiness is a scripted ChildReadiness for the cases that need one verdict only.
type staticReadiness struct {
	ticket        shardnode.ReadinessTicket
	prepareErr    error
	revalidateErr error
}

func (s *staticReadiness) Prepare(context.Context, *types.UnicityCertificate) (shardnode.ReadinessTicket, error) {
	return s.ticket, s.prepareErr
}

func (s *staticReadiness) Revalidate(context.Context, shardnode.ReadinessTicket, *types.UnicityCertificate) error {
	return s.revalidateErr
}

// voteRefusingReadiness lets Build's revalidation pass and refuses the vote's, so a test can show
// that the block is still produced and pending recorded while only the signature is withheld.
type voteRefusingReadiness struct {
	mu             sync.Mutex
	failVote       bool
	callsThisRound int
}

func (v *voteRefusingReadiness) Prepare(context.Context, *types.UnicityCertificate) (shardnode.ReadinessTicket, error) {
	v.mu.Lock()
	v.callsThisRound = 0
	v.mu.Unlock()
	return fakeTicket{valid: true}, nil
}

func (v *voteRefusingReadiness) Revalidate(context.Context, shardnode.ReadinessTicket, *types.UnicityCertificate) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.callsThisRound++
	if v.failVote && v.callsThisRound == 2 {
		return errors.New("readiness revoked before the vote")
	}
	return nil
}

// countingReadiness is for the case that asserts Prepare is not called at all.
type countingReadiness struct {
	mu           sync.Mutex
	prepareCalls int
}

func (c *countingReadiness) Prepare(context.Context, *types.UnicityCertificate) (shardnode.ReadinessTicket, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prepareCalls++
	return fakeTicket{valid: true}, nil
}

func (c *countingReadiness) Revalidate(context.Context, shardnode.ReadinessTicket, *types.UnicityCertificate) error {
	return nil
}

func (c *countingReadiness) prepareCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.prepareCalls
}

// gateCheckingReadiness records whether the finality gate was held at each Revalidate.
type gateCheckingReadiness struct {
	gate *shardnode.FinalityGate
	mu   sync.Mutex
	held []bool
}

func (g *gateCheckingReadiness) Prepare(context.Context, *types.UnicityCertificate) (shardnode.ReadinessTicket, error) {
	return fakeTicket{valid: true}, nil
}

func (g *gateCheckingReadiness) Revalidate(context.Context, shardnode.ReadinessTicket, *types.UnicityCertificate) error {
	_, _, held := g.gate.Holder()
	g.mu.Lock()
	g.held = append(g.held, held)
	g.mu.Unlock()
	return nil
}

func (g *gateCheckingReadiness) holdStates() []bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]bool(nil), g.held...)
}

// failingObserver refuses every observation, standing in for a history bounded out or otherwise
// unable to retain the pair.
type failingObserver struct{}

func (failingObserver) ObserveCertificate(*types.UnicityCertificate, *certification.TechnicalRecord) error {
	return errors.New("observation refused")
}

// gateObservingSigner records whether the gate was held when the signer was called.
type gateObservingSigner struct {
	gate   *shardnode.FinalityGate
	signer abcrypto.Signer
	mu     sync.Mutex
	held   []bool
}

func (s *gateObservingSigner) Sign(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord, req *certification.BlockCertificationRequest) (*certification.BlockCertificationRequest, error) {
	_, _, held := s.gate.Holder()
	s.mu.Lock()
	s.held = append(s.held, held)
	s.mu.Unlock()
	return shardnode.LocalKeySigner(s.signer).Sign(ctx, uc, tr, req)
}

func (s *gateObservingSigner) signedWhileHeld() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.held {
		if h {
			return true
		}
	}
	return false
}

// sealingExecutor remembers every block it seals so a test can name the round it built without a
// submission to read it from.
type sealingExecutor struct {
	shardnode.Executor
	mu     sync.Mutex
	sealed []shardnode.Block
}

func (e *sealingExecutor) Seal(ctx context.Context, id shardnode.BuildID) (shardnode.Block, error) {
	b, err := e.Executor.Seal(ctx, id)
	if err == nil {
		e.mu.Lock()
		e.sealed = append(e.sealed, b)
		e.mu.Unlock()
	}
	return b, err
}

func (e *sealingExecutor) lastSealed(t *testing.T) shardnode.Block {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	require.NotEmpty(t, e.sealed, "no block was sealed")
	return e.sealed[len(e.sealed)-1]
}

// reasonMetrics wires a manual reader so a test can read the reason attributes of the IR-divergence
// counter that the record gate records.
func reasonMetrics(t *testing.T) (*shardnode.Metrics, func() []string) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	m, err := shardnode.NewMetrics(provider.Meter("round-readiness-test"))
	require.NoError(t, err)
	return m, func() []string {
		var data metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(context.Background(), &data))
		var out []string
		for _, scope := range data.ScopeMetrics {
			for _, metric := range scope.Metrics {
				if metric.Name != "shardnode.ir.divergences" {
					continue
				}
				sum, ok := metric.Data.(metricdata.Sum[int64])
				if !ok {
					continue
				}
				for _, dp := range sum.DataPoints {
					for _, kv := range dp.Attributes.ToSlice() {
						if kv.Key == "reason" {
							out = append(out, kv.Value.AsString())
						}
					}
				}
			}
		}
		return out
	}
}

// TestUngatedRoundNeverTakesTheFinalityGate: a round with no ChildReadiness must reach no gate at
// all. With the gate held for the whole round, an ungated follower round completes and signs while
// the holder is still inside it. The assertion is deliberate rather than incidental: the round is a
// follower round that commits nothing, so neither buildFinal nor commitFinal is reached and the
// only place that could take the gate is the vote's revalidation. A guard that merely held the gate
// briefly would still block here, which is the regression the guard fixes: the recovery applier
// takes the gate with tryAcquire and reports being turned away rather than waiting, so a no-op
// acquisition on every round can cost a recovery attempt the round it was made in.
func TestUngatedRoundNeverTakesTheFinalityGate(t *testing.T) {
	ctx := context.Background()
	const nodeID = "follower-node"
	const leader = "other-leader"

	// A follower round needs a block to verify. Build one on a second Fake that shares genesis, so the
	// follower recomputes the same roots and Verify returns VALID without any commit.
	leaderExec := executortest.New()
	head, err := leaderExec.Head(ctx)
	require.NoError(t, err)
	leaderExec.AddEntries([]byte("a block the follower verifies"))
	id, err := leaderExec.Build(ctx, shardnode.RoundParams{Round: 1, Parent: head})
	require.NoError(t, err)
	block, err := leaderExec.Seal(ctx, id)
	require.NoError(t, err)

	disseminator := newBroadcastDisseminator()
	require.NoError(t, disseminator.Publish(ctx, 1, block))
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	sub := &recordingSubmitter{}
	r := shardnode.NewRound(nodeID, types.PartitionID(8), types.ShardID{}, executortest.New(), disseminator, signer, sub, nil)

	gate := shardnode.NewFinalityGate()
	r.SetFinalityGate(gate)
	// No SetChildReadiness call: this is exactly the ungated configuration the guard protects.

	release, err := gate.Hold(ctx, "recovery-apply")
	require.NoError(t, err)
	defer release()

	done := make(chan error, 1)
	go func() { done <- r.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, leader)) }()

	select {
	case err := <-done:
		require.NoError(t, err, "an ungated round must complete without the finality gate")
	case <-time.After(5 * time.Second):
		t.Fatal("HandleCertificate blocked while the finality gate was held: an ungated round took the gate")
	}

	require.Len(t, sub.got, 1, "the round still signs while the gate is held")
	_, _, held := gate.Holder()
	require.True(t, held, "the gate was held throughout, so the round never acquired it")
}

// TestReadyRoundIsUnchanged: when the gate is ready it must be invisible. Two rounds with the same
// node identity and signer process the same certificate, one gated and one not, and produce
// byte-identical signed requests. The secp256k1 signer is deterministic (RFC 6979), so byte equality
// covers the signature as well as the input record.
func TestReadyRoundIsUnchanged(t *testing.T) {
	ctx := context.Background()
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	const nodeID = "ready-node"

	newRound := func(withGate bool) (*shardnode.Round, *recordingSubmitter) {
		exec := executortest.New()
		sub := &recordingSubmitter{}
		r := shardnode.NewRound(nodeID, types.PartitionID(8), types.ShardID{}, exec, shardnode.NewLoopbackDisseminator(), signer, sub, nil)
		if withGate {
			r.SetChildReadiness(&staticReadiness{ticket: fakeTicket{valid: true}})
		}
		return r, sub
	}
	plain, plainSub := newRound(false)
	ready, readySub := newRound(true)

	for _, r := range []*shardnode.Round{plain, ready} {
		require.NoError(t, r.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID)))
	}
	plainBytes, err := types.Cbor.Marshal(plainSub.last(t))
	require.NoError(t, err)
	readyBytes, err := types.Cbor.Marshal(readySub.last(t))
	require.NoError(t, err)
	require.True(t, bytes.Equal(plainBytes, readyBytes), "a ready gate must not change the signed request bytes")
}

// TestNotReadyDeclinesLeadership: a leader whose Prepare refuses does not build and does not sign.
// Building would move the executor's forkchoice (and finalize the parent) on a head the record
// cannot support, so the refusal lands before produceBlock, not at the signature.
func TestNotReadyDeclinesLeadership(t *testing.T) {
	ctx := context.Background()
	fake := executortest.New()
	builds := &buildRecordingExecutor{Executor: fake}
	sub := &recordingSubmitter{}
	r, nodeID := newTestRound(t, builds, sub)
	health := shardnode.NewHealth()
	r.SetHealth(health)
	metrics, reasons := reasonMetrics(t)
	r.SetMetrics(metrics)
	r.SetChildReadiness(&staticReadiness{prepareErr: errors.New("no durable record yet")})

	require.NoError(t, r.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID)),
		"declining to lead is not a processing error")
	require.Empty(t, sub.got, "nothing is signed")
	require.Empty(t, builds.parents, "Build is never called")
	snap := health.Snapshot()
	require.False(t, snap.Voting)
	require.Equal(t, "not-ready", snap.CertifiedRecordReadiness)
	require.Contains(t, snap.CertifiedRecordReadinessDetail, "no durable record yet")
	require.Contains(t, snap.NonVotingReason, "certified-record readiness")
	require.Contains(t, reasons(), "record_readiness_declined_leadership")
}

// TestReadinessRevokedInsideTheFinalityGate: a ticket that was valid at Prepare but fails Revalidate
// inside buildFinal's gate must not reach executor.Build. The round abstains and returns nil rather
// than failing the certificate, so the delivery layer sees an abstention, not an application error.
func TestReadinessRevokedInsideTheFinalityGate(t *testing.T) {
	ctx := context.Background()
	fake := executortest.New()
	builds := &buildRecordingExecutor{Executor: fake}
	sub := &recordingSubmitter{}
	r, nodeID := newTestRound(t, builds, sub)
	health := shardnode.NewHealth()
	r.SetHealth(health)
	metrics, reasons := reasonMetrics(t)
	r.SetMetrics(metrics)
	r.SetChildReadiness(&staticReadiness{ticket: fakeTicket{valid: true}, revalidateErr: errors.New("head moved")})
	gate := shardnode.NewFinalityGate()
	r.SetFinalityGate(gate)

	require.NoError(t, r.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID)))
	require.Empty(t, builds.parents, "Build is never reached once the ticket is revoked")
	require.Empty(t, sub.got, "and nothing is signed")
	snap := health.Snapshot()
	require.Equal(t, "revoked", snap.CertifiedRecordReadiness)
	require.Contains(t, snap.CertifiedRecordReadinessDetail, "head moved")
	require.Contains(t, reasons(), "record_readiness_abstained")
	_, _, held := gate.Holder()
	require.False(t, held, "the gate is released after the refusal")
}

// TestNotReadyAbstainsFromTheVote: the vote's Revalidate refuses after Build succeeded. The block is
// still built and r.pending is recorded, nothing is signed, and the next certificate still commits
// what the node proposed. Withholding the signature is the whole of it, which is what keeps a
// not-ready node a warm follower rather than one that falls off the chain.
func TestNotReadyAbstainsFromTheVote(t *testing.T) {
	ctx := context.Background()
	fake := executortest.New()
	exec := &sealingExecutor{Executor: fake}
	sub := &recordingSubmitter{}
	r, nodeID := newTestRound(t, exec, sub)
	health := shardnode.NewHealth()
	r.SetHealth(health)
	readiness := &voteRefusingReadiness{}
	r.SetChildReadiness(readiness)

	require.NoError(t, r.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID)))
	req1 := sub.last(t)
	require.Len(t, sub.got, 1)

	fake.AddEntries([]byte("block B"))
	readiness.mu.Lock()
	readiness.failVote = true
	readiness.mu.Unlock()
	require.NoError(t, r.HandleCertificate(ctx, certifyFrom(req1, 2, 1000), tr(2, 0, nodeID)))
	require.Len(t, sub.got, 1, "the vote revalidation refused, so nothing was signed")
	require.False(t, health.Snapshot().Voting)

	// The certificate the shard would issue for the block the node built, reconstructed from the
	// sealed block because no signed request exists to copy it from.
	built := exec.lastSealed(t)
	exp := shardnode.Expectation{Round: 2, Epoch: 0, PreviousHash: req1.InputRecord.Hash, Timestamp: 1000}
	ir, err := shardnode.BuildInputRecord(exp, built.StateRoot, built.Hash, false)
	require.NoError(t, err)
	uc2 := &types.UnicityCertificate{
		Version:     1,
		InputRecord: ir,
		UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: 3, Timestamp: 1000},
	}
	require.NoError(t, r.HandleCertificate(ctx, uc2, tr(3, 0, nodeID)),
		"the next certificate still commits the round the node built")
	head, err := fake.Head(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte(built.Hash), []byte(head.Hash),
		"r.pending was recorded, so commitPrevious applied the certified block")
}

// TestVoteRevalidationHoldsTheFinalityGate: the vote's Revalidate runs with the finality gate held
// and the gate is released before the signer is called. That ordering is what excludes every commit
// and build in this process at the moment the readiness verdict is read, and keeps a slow signer
// outside the gate.
func TestVoteRevalidationHoldsTheFinalityGate(t *testing.T) {
	ctx := context.Background()
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	gate := shardnode.NewFinalityGate()
	readiness := &gateCheckingReadiness{gate: gate}
	fake := executortest.New()
	sub := &recordingSubmitter{}
	const nodeID = "gated-vote-node"
	r := shardnode.NewRound(nodeID, types.PartitionID(8), types.ShardID{}, fake, shardnode.NewLoopbackDisseminator(), signer, sub, nil)
	r.SetChildReadiness(readiness)
	r.SetFinalityGate(gate)
	gateSigner := &gateObservingSigner{gate: gate, signer: signer}
	r.SetCertificationSigner(gateSigner)

	require.NoError(t, r.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID)))
	require.Len(t, sub.got, 1)

	held := readiness.holdStates()
	require.GreaterOrEqual(t, len(held), 2, "the build and the vote each revalidate on a leader round")
	for i, h := range held {
		require.Truef(t, h, "revalidation %d must run under the finality gate", i)
	}
	require.False(t, gateSigner.signedWhileHeld(), "the gate is released before the signer is called")
}

// TestPrepareIsSkippedWhenIdentityAlreadyRefuses: a round that already abstains on P-id must not do
// the gate's store, witness or trust work. Prepare is the expensive half, so skipping it is the
// point of placing the gate after the identity check.
func TestPrepareIsSkippedWhenIdentityAlreadyRefuses(t *testing.T) {
	ctx, _, exec, round, _, nodeID, quiet := identityFixture(t)
	readiness := &countingReadiness{}
	round.SetChildReadiness(readiness)

	head, err := exec.Head(ctx)
	require.NoError(t, err)
	head.Hash = make([]byte, 32)
	head.Hash[0] = 0xff
	exec.rewindTo(head)

	require.NoError(t, round.HandleCertificate(ctx, quiet, tr(4, 0, nodeID)))
	require.Zero(t, readiness.prepareCount(),
		"P-id already refuses, so the record gate does no store, witness or trust work")
}

// TestCertificateObserverRefusalDoesNotFailTheRound: an observer that cannot retain an
// authenticated pair is logged, not escalated. Being observed authorizes nothing, so failing to
// retain must not stop the node building and signing.
func TestCertificateObserverRefusalDoesNotFailTheRound(t *testing.T) {
	ctx := context.Background()
	fake := executortest.New()
	sub := &recordingSubmitter{}
	r, nodeID := newTestRound(t, fake, sub)
	r.SetCertificateObserver(failingObserver{})

	require.NoError(t, r.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID)),
		"a refused observation is logged, not escalated")
	require.Len(t, sub.got, 1, "the round proceeds and signs")
}
