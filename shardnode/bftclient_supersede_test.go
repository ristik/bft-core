package shardnode

import (
	"context"
	"crypto"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

func auth(input string, epoch, round uint64) *certificationAuthorization {
	return &certificationAuthorization{inputRecord: input, rootEpoch: epoch, rootRound: round}
}

func heldUC(t *testing.T, root uint64, epoch uint64, round uint64) *types.UnicityCertificate {
	t.Helper()
	return &types.UnicityCertificate{
		Version:     1,
		InputRecord: &types.InputRecord{Version: 1, RoundNumber: round, PreviousHash: []byte{1}, Hash: []byte{2}, BlockHash: []byte{3}, SummaryValue: []byte{}, Timestamp: 1},
		UnicitySeal: &types.UnicitySeal{Version: 1, RootChainRoundNumber: root, Epoch: epoch},
	}
}

func inputOf(t *testing.T, uc *types.UnicityCertificate) string {
	t.Helper()
	b, err := uc.InputRecord.Bytes()
	require.NoError(t, err)
	return string(b)
}

// counter is a cancel func that counts its calls.
type counter struct {
	mu sync.Mutex
	n  int
}

func (c *counter) cancel() { c.mu.Lock(); c.n++; c.mu.Unlock() }
func (c *counter) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// bft-core#728: only a repeat of the certificate being waited on supersedes it.
func TestSupersessionCancelsOnlyOnAStrictlyGreaterRootRoundOfTheSameRecordAndEpoch(t *testing.T) {
	held := heldUC(t, 10, 1, 500)
	input := inputOf(t, held)
	other := inputOf(t, heldUC(t, 10, 1, 501))
	for name, tc := range map[string]struct {
		observed *certificationAuthorization
		cancels  bool
	}{
		"a greater root round of the same record":                    {auth(input, 1, 11), true},
		"a much greater root round":                                  {auth(input, 1, 900), true},
		"a duplicate (the same root round)":                          {auth(input, 1, 10), false},
		"an older root round":                                        {auth(input, 1, 9), false},
		"a greater root round of a different certified record":       {auth(other, 1, 11), false},
		"a greater root round in a different root epoch":             {auth(input, 2, 11), false},
		"a greater root round in an earlier root epoch is no repeat": {auth(input, 0, 99), false},
	} {
		t.Run(name, func(t *testing.T) {
			var s supersession
			c := &counter{}
			unregister := s.register(held, c.cancel)
			defer unregister()
			s.observe(tc.observed)
			if tc.cancels {
				require.Equal(t, 1, c.calls())
			} else {
				require.Zero(t, c.calls())
			}
		})
	}
}

// Arrival before registration: the repeat is already known when the wait starts, so registering cancels at once, exactly once.
func TestSupersessionRegistrationAfterTheRepeatCancelsAtOnce(t *testing.T) {
	held := heldUC(t, 10, 1, 500)
	var s supersession
	s.observe(auth(inputOf(t, held), 1, 12))
	c := &counter{}
	s.register(held, c.cancel)
	require.Equal(t, 1, c.calls())

	// a repeat seen only in a later root epoch is no repeat of a wait armed in an earlier one
	var other supersession
	other.observe(auth(inputOf(t, held), 2, 12))
	elsewhere := &counter{}
	other.register(held, elsewhere.cancel)
	require.Zero(t, elsewhere.calls())

	dup := &counter{}
	var s2 supersession
	s2.observe(auth(inputOf(t, held), 1, 10)) // a duplicate seen first is no repeat
	s2.register(held, dup.cancel)
	require.Zero(t, dup.calls())
}

// A wait that ended (unregistered) is not cancelled by a later repeat, and one repeat cancels each registered wait once.
func TestSupersessionUnregisterAndOnce(t *testing.T) {
	held := heldUC(t, 10, 1, 500)
	input := inputOf(t, held)
	var s supersession
	ended, live := &counter{}, &counter{}
	s.register(held, ended.cancel)()
	s.register(held, live.cancel)
	s.observe(auth(input, 1, 11))
	s.observe(auth(input, 1, 12))
	require.Zero(t, ended.calls())
	require.Equal(t, 1, live.calls(), "a wait is cancelled once")
}

// The cancel runs outside the registry lock: a cancel that registers again must not deadlock.
func TestSupersessionCancelRunsOutsideTheLock(t *testing.T) {
	held := heldUC(t, 10, 1, 500)
	var s supersession
	done := make(chan struct{})
	s.register(held, func() {
		s.register(held, func() {})
		close(done)
	})
	go s.observe(auth(inputOf(t, held), 1, 11))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the cancel deadlocked on the registry lock")
	}
}

func TestSupersessionMarkerIsBounded(t *testing.T) {
	var s supersession
	for i := 0; i < 3*maxSupersessionInputs; i++ {
		s.observe(auth(string(rune('a'+i)), 1, 5))
	}
	require.LessOrEqual(t, len(s.latest), maxSupersessionInputs)
	require.LessOrEqual(t, len(s.order), maxSupersessionInputs)
}

// waitDriver stands in for a follower inside Round.produceBlock: it arms the same registration and waits for the leader's block, which never comes.
type waitDriver struct {
	client *BFTClient
	mu     sync.Mutex
	got    []uint64 // root rounds in delivery order
	ended  map[uint64]string
	inWait chan uint64
	budget time.Duration
}

func (d *waitDriver) HandleCertificate(ctx context.Context, uc *types.UnicityCertificate, _ *certification.TechnicalRecord) error {
	root := uc.GetRootRoundNumber()
	d.mu.Lock()
	d.got = append(d.got, root)
	d.mu.Unlock()
	if d.ended == nil {
		return nil
	}
	waitCtx, cut := context.WithCancelCause(ctx)
	defer cut(nil)
	defer d.client.WatchSupersession(uc, func() { cut(errAwaitSuperseded) })()
	select {
	case d.inWait <- root:
	default:
	}
	timer := time.NewTimer(d.budget)
	defer timer.Stop()
	how := "timeout"
	select {
	case <-waitCtx.Done():
		how = "cancelled"
	case <-timer.C:
	}
	d.mu.Lock()
	d.ended[root] = how
	d.mu.Unlock()
	return nil
}

func (d *waitDriver) snapshot() ([]uint64, map[uint64]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ended := map[uint64]string{}
	for k, v := range d.ended {
		ended[k] = v
	}
	return append([]uint64(nil), d.got...), ended
}

// A repeat UC arriving while the delivery loop is inside the driver is seen by the reader at once, cancels that wait, and is delivered next; duplicates, an invalid response
// and an equal-round conflict seen during the wait do not cancel it.
func TestRunACertificateArrivingDuringTheDriversWaitSupersedesItButNotDuplicatesOrInvalidOnes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f := newConfBindingFixture(t)
	zero := make([]byte, 32)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID, T2Timeout: 2500000000}
	confHash, err := pdr.Hash(crypto.SHA256)
	require.NoError(t, err)
	input := &types.InputRecord{Version: 1, RoundNumber: 952, PreviousHash: zero, Hash: []byte("state-952"), BlockHash: []byte("block-952"), SummaryValue: []byte{}, Timestamp: 1}
	response := func(rootRound, nextRound uint64, leader string) *certification.CertificationResponse {
		t.Helper()
		trec := &certification.TechnicalRecord{Round: nextRound, Epoch: 0, Leader: leader, StatHash: zero, FeeHash: zero}
		trHash, hashErr := trec.Hash()
		require.NoError(t, hashErr)
		ir := *input
		ir.SummaryValue = []byte{}
		uc := testcertificates.CreateUnicityCertificate(t, f.signer, &ir, pdr, rootRound, zero, trHash)
		return &certification.CertificationResponse{Partition: authPartitionID, Shard: types.ShardID{}, Technical: *trec, UC: *uc}
	}
	seed := response(952, 953, "v1")
	first := response(953, 953, "v1")
	duplicate := response(953, 953, "v1")
	conflict := response(953, 953, "v2") // the same root round, a different technical record
	wrongShard := response(960, 953, "v1")
	wrongShard.Partition = authPartitionID + 1
	repeat := response(954, 953, "v1")

	net := &admissionTestNet{received: make(chan any, 16)}
	driver := &waitDriver{ended: map[uint64]string{}, inWait: make(chan uint64, 4), budget: 5 * time.Second}
	client, err := NewBFTClient(testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)), net, f.signer, authPartitionID, types.ShardID{}, confHash, stubTrustBaseStore{tb: f.tb}, driver, nil,
		BFTClientOptions{HandshakeNodes: 1, CertNodes: 1, HeartbeatInterval: time.Hour, InactivityTimeout: 24 * time.Hour})
	require.NoError(t, err)
	driver.client = client
	require.NoError(t, client.SeedLUC(&seed.UC))
	runDone := make(chan error, 1)
	go func() { runDone <- client.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(time.Second):
			t.Error("Run did not stop")
		}
	})

	net.received <- first
	select {
	case root := <-driver.inWait:
		require.Equal(t, uint64(953), root)
	case <-time.After(2 * time.Second):
		t.Fatal("the driver never started waiting")
	}
	for _, resp := range []*certification.CertificationResponse{duplicate, conflict, wrongShard} {
		net.received <- resp
	}
	time.Sleep(300 * time.Millisecond)
	_, ended := driver.snapshot()
	require.Empty(t, ended, "a duplicate, an equal-round conflict and an invalid response must not end the wait")

	sent := time.Now()
	net.received <- repeat
	require.Eventually(t, func() bool { _, e := driver.snapshot(); return e[953] != "" }, time.Second, 5*time.Millisecond)
	_, ended = driver.snapshot()
	require.Equal(t, "cancelled", ended[953])
	require.Less(t, time.Since(sent), time.Second, "the wait ended on the repeat's arrival, not on its 5 s budget")

	require.Eventually(t, func() bool { got, _ := driver.snapshot(); return len(got) > 0 && got[len(got)-1] == 954 }, 2*time.Second, 5*time.Millisecond)
	got, _ := driver.snapshot()
	require.Equal(t, uint64(953), got[0])
	require.Contains(t, got, uint64(954), "and the repeat itself was delivered next")
}

// The configured-admission route: the delivery (DeliverDurable, which is also what the journal's retry calls) is inside the driver's wait on a worker other than the receive loop.
// The repeat UC arrives on the network, the reader cancels the wait, the delivery counts as applied, and a redelivery of that obsolete certificate does not call the driver again.
func TestConfiguredAdmissionDeliveryWaitIsSupersededByARepeatUCAndNotRetried(t *testing.T) {
	net := &admissionTestNet{}
	driver := &waitDriver{ended: map[uint64]string{}, inWait: make(chan uint64, 4), budget: 5 * time.Second}
	c, f := newAdmissionTestClient(t, driver, net)
	driver.client = c
	factory := &admissionTestFactory{}
	cancel, done := startAdmissionClient(t, c, factory, driver)
	defer func() { cancel(); require.ErrorIs(t, <-done, context.Canceled) }()

	response := f.respond(f.ucMine)
	mine := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID, T2Timeout: 2500000000}
	zero := make([]byte, 32)
	trHash, err := f.technical.Hash()
	require.NoError(t, err)
	repeat := f.respond(testcertificates.CreateUnicityCertificate(t, f.signer, f.ucMine.InputRecord, mine, f.ucMine.GetRootRoundNumber()+1, zero, trHash))

	factory.mu.Lock()
	deliver := factory.callbacks.DeliverDurable
	factory.mu.Unlock()
	delivered := make(chan error, 1)
	go func() { delivered <- deliver(context.Background(), &response.UC, &response.Technical) }()
	select {
	case <-driver.inWait:
	case <-time.After(2 * time.Second):
		t.Fatal("the delivery never reached the driver's wait")
	}
	sent := time.Now()
	net.received <- repeat
	select {
	case err := <-delivered:
		require.NoError(t, err, "the abandoned wait is a success for the admission layer, so the journal does not retry it")
	case <-time.After(2 * time.Second):
		t.Fatal("the delivery was not released by the repeat UC")
	}
	require.Less(t, time.Since(sent), time.Second)
	got, ended := driver.snapshot()
	require.Equal(t, "cancelled", ended[f.ucMine.GetRootRoundNumber()])
	require.Len(t, got, 1)

	require.NoError(t, deliver(context.Background(), &response.UC, &response.Technical), "a redelivery of the obsolete certificate")
	got, _ = driver.snapshot()
	require.Len(t, got, 1, "does not reach the driver again")
}
