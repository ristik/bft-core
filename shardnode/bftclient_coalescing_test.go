package shardnode

import (
	"context"
	"crypto"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// authorizationQueueDriver models the round boundary for the deterministic four-validator
// regression below. v1 never publishes its round-953 proposal; a survivor that handles that
// authorization therefore spends one T2 waiting for it. Under the live round-953 assignment,
// repeats also consume that same wait. The root's newest authorization moves round 954 to v3,
// which publishes and lets the other two survivors complete the quorum.
type authorizationQueueDriver struct {
	nodeID       string
	proposal     chan struct{}
	proposalOnce *sync.Once
	latest       chan<- string
	stalled      chan<- string
	firstTimeout <-chan struct{}
	stallOnce    *sync.Once
	t2           time.Duration
}

func (d *authorizationQueueDriver) HandleCertificate(ctx context.Context, _ *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	if tr.Round == 953 && tr.Leader == "v1" {
		first := false
		d.stallOnce.Do(func() {
			first = true
			d.stalled <- d.nodeID
		})
		if first {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-d.firstTimeout:
				// The test releases exactly one round-953 timeout after the repeat UCs are queued.
				return errors.New("round 953 proposal from v1 timed out")
			}
		}
		// Any retry of that same stale assignment costs another complete T2 in the old
		// synchronous path. The coalescer must skip directly to the queued newer authorization.
		timer := time.NewTimer(d.t2)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return errors.New("round 953 proposal from v1 timed out")
		}
	}
	if tr.Round != 954 || tr.Leader != "v3" {
		return nil
	}
	if d.nodeID == "v3" {
		d.proposalOnce.Do(func() { close(d.proposal) })
	} else {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-d.proposal:
		}
	}
	if d.nodeID == "v2" || d.nodeID == "v3" || d.nodeID == "v4" {
		d.latest <- d.nodeID
	}
	return nil
}

// TestFourValidatorNewestAuthorizationBeforeNextT2 is the deterministic repro for the devnet
// liveness failure. It gives all four validators a buffered feed containing duplicate round-953
// responses ahead of two repeat authorizations. v1's round-953 proposal is stalled. The three
// survivors must act on the root's newest authorization (round 954, leader v3) and reach quorum
// before another T2 elapses. The old synchronous receive loop replays failed duplicate responses
// one at a time, so this test fails until Run coalesces authenticated repeats before processing.
func TestFourValidatorNewestAuthorizationBeforeNextT2(t *testing.T) {
	const t2 = 500 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	f := newConfBindingFixture(t)
	zero := make([]byte, 32)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID, T2Timeout: 2500000000}
	confHash, err := pdr.Hash(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, f.confMine, confHash)

	input := &types.InputRecord{
		Version: 1, RoundNumber: 952, PreviousHash: zero, Hash: []byte("state-952"),
		BlockHash: []byte("block-952"), SummaryValue: []byte{}, Timestamp: 1,
	}
	response := func(rootRound, nextRound uint64, leader string) *certification.CertificationResponse {
		t.Helper()
		tr := &certification.TechnicalRecord{Round: nextRound, Epoch: 0, Leader: leader, StatHash: zero, FeeHash: zero}
		trHash, hashErr := tr.Hash()
		require.NoError(t, hashErr)
		ir := *input
		ir.PreviousHash = append([]byte(nil), input.PreviousHash...)
		ir.Hash = append([]byte(nil), input.Hash...)
		ir.BlockHash = append([]byte(nil), input.BlockHash...)
		ir.SummaryValue = []byte{}
		uc := testcertificates.CreateUnicityCertificate(t, f.signer, &ir, pdr, rootRound, zero, trHash)
		require.NoError(t, uc.Verify(f.tb, crypto.SHA256, authPartitionID, types.ShardID{}, confHash))
		return &certification.CertificationResponse{Partition: authPartitionID, Shard: types.ShardID{}, Technical: *tr, UC: *uc}
	}

	seed := response(952, 953, "v1")
	stale := response(953, 953, "v1")
	repeat954 := response(954, 953, "v1")
	repeat955 := response(955, 953, "v1")
	newest := response(956, 954, "v3")
	// The repeated UCs certify the same input record and differ only in root authorization. The
	// transport duplicates are intentionally ahead of the newest assignment in each feed.
	for _, resp := range []*certification.CertificationResponse{stale, repeat954, repeat955, newest} {
		require.NoError(t, resp.IsValid())
	}

	proposal := make(chan struct{})
	proposalOnce := &sync.Once{}
	latest := make(chan string, 3)
	stalled := make(chan string, 4)
	firstTimeout := make(chan struct{})
	stallOnce := map[string]*sync.Once{}
	nets := make([]*admissionTestNet, 0, 4)
	var done []<-chan error
	for _, nodeID := range []string{"v1", "v2", "v3", "v4"} {
		net := &admissionTestNet{received: make(chan any, 8)}
		net.received <- stale
		nets = append(nets, net)
		stallOnce[nodeID] = &sync.Once{}
		driver := &authorizationQueueDriver{
			nodeID: nodeID, proposal: proposal, proposalOnce: proposalOnce, latest: latest,
			stalled: stalled, firstTimeout: firstTimeout, stallOnce: stallOnce[nodeID], t2: t2,
		}
		client, createErr := NewBFTClient(
			testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)), net, f.signer,
			authPartitionID, types.ShardID{}, confHash, stubTrustBaseStore{tb: f.tb}, driver, nil,
			BFTClientOptions{HandshakeNodes: 1, CertNodes: 1, HeartbeatInterval: time.Hour, InactivityTimeout: 24 * time.Hour},
		)
		require.NoError(t, createErr)
		require.NoError(t, client.SeedLUC(&seed.UC))
		runDone := make(chan error, 1)
		go func() { runDone <- client.Run(ctx) }()
		done = append(done, runDone)
	}
	t.Cleanup(func() {
		cancel()
		for _, ch := range done {
			select {
			case <-ch:
			case <-time.After(time.Second):
				t.Errorf("validator Run did not stop after cancellation")
			}
		}
	})

	started := map[string]bool{}
	startDeadline := time.NewTimer(time.Second)
	defer startDeadline.Stop()
	for len(started) < 4 {
		select {
		case nodeID := <-stalled:
			started[nodeID] = true
		case <-startDeadline.C:
			t.Fatalf("not all four validators entered the stalled round-953 proposal: %v", started)
		}
	}
	for _, net := range nets {
		for _, resp := range []*certification.CertificationResponse{stale, stale, repeat954, repeat955, newest} {
			net.received <- resp
		}
	}
	close(firstTimeout)

	got := map[string]bool{}
	deadline := time.NewTimer(100 * time.Millisecond)
	defer deadline.Stop()
	for len(got) < 3 {
		select {
		case nodeID := <-latest:
			got[nodeID] = true
		case <-deadline.C:
			t.Fatalf("survivors did not reach quorum before another T2; newest authorization reached %v", got)
		}
	}
}

func TestStaleCertificationResponseIsDroppedAfterNewest(t *testing.T) {
	ctx := context.Background()
	f := newConfBindingFixture(t)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID, T2Timeout: 2500000000}
	zero := make([]byte, 32)
	trHash, err := f.technical.Hash()
	require.NoError(t, err)
	response := func(rootRound uint64) *certification.CertificationResponse {
		t.Helper()
		uc := testcertificates.CreateUnicityCertificate(t, f.signer, f.ucMine.InputRecord, pdr, rootRound, zero, trHash)
		require.NoError(t, uc.Verify(f.tb, crypto.SHA256, authPartitionID, types.ShardID{}, f.confMine))
		return &certification.CertificationResponse{
			Partition: authPartitionID, Shard: types.ShardID{}, Technical: *f.technical, UC: *uc,
		}
	}
	older, newest := response(51), response(52)
	client, driver := f.client(f.confMine)
	forgedNewest := *newest
	forgedUC := forgedNewest.UC
	forgedSeal := *forgedUC.UnicitySeal
	forgedSeal.Signatures = types.SignatureMap{"not-a-root-validator": []byte("invalid")}
	forgedUC.UnicitySeal = &forgedSeal
	forgedNewest.UC = forgedUC
	queuedForged := make(chan any, 1)
	queuedForged <- &forgedNewest
	verifiedBatch, closed := client.coalesceBufferedCertificationResponses(ctx, older, queuedForged)
	require.False(t, closed)
	require.Len(t, verifiedBatch, 2, "an unauthenticated larger round must not supersede a valid UC")
	require.Same(t, older, verifiedBatch[0])
	require.Same(t, &forgedNewest, verifiedBatch[1])

	// This is the queue behavior used by Run: authenticate both responses, retain the newest root
	// authorization for the same signed InputRecord, and remove the stale one before the driver.
	queued := make(chan any, 1)
	queued <- newest
	batch, closed := client.coalesceBufferedCertificationResponses(ctx, older, queued)
	require.False(t, closed)
	require.Len(t, batch, 1)
	require.Same(t, newest, batch[0], "the stale response must be dropped before processing")

	require.NoError(t, client.handleCertificationResponse(ctx, newest))
	require.Equal(t, []uint64{f.ucMine.GetRoundNumber()}, driver.rounds(), "the newest authorization is processed")
	before := client.luc
	err = client.handleCertificationResponse(ctx, older)
	require.NoError(t, err, "an out-of-order older response is routine stale input")
	require.NotErrorIs(t, err, ErrEquivocatingUC)
	require.Same(t, before, client.luc, "the older response cannot replace the newer UC")
	require.Equal(t, []uint64{f.ucMine.GetRoundNumber()}, driver.rounds(), "the older response never reaches the driver")

	conflictedIR := *f.ucMine.InputRecord
	conflictedIR.Hash = []byte("conflicting-state")
	conflictedIR.BlockHash = []byte("conflicting-block")
	conflictedUC := testcertificates.CreateUnicityCertificate(t, f.signer, &conflictedIR, pdr, 53, zero, trHash)
	conflicted := &certification.CertificationResponse{
		Partition: authPartitionID, Shard: types.ShardID{}, Technical: *f.technical, UC: *conflictedUC,
	}
	err = client.handleCertificationResponse(ctx, conflicted)
	require.ErrorIs(t, err, ErrEquivocatingUC, "same-round conflicts retain their safety classification")
	require.Same(t, before, client.luc, "a conflicting UC cannot replace the newer accepted certificate")
	require.Equal(t, []uint64{f.ucMine.GetRoundNumber()}, driver.rounds())
}
