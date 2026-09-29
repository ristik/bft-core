package shardnode

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/network/protocol/handshake"
	"github.com/unicitynetwork/bft-go-base/types"
)

type admissionTestGate struct{}

func (admissionTestGate) Hold(context.Context, string) (func(), error) { return func() {}, nil }

type admissionTestFactory struct {
	mu        sync.Mutex
	callbacks AdmissionCallbacks
	identity  AdmissionIdentity
	session   *admissionTestSession
	startErr  error
	started   chan struct{}
	startUC   *types.UnicityCertificate
	startTR   *certification.TechnicalRecord
}

func (f *admissionTestFactory) Start(_ context.Context, id AdmissionIdentity, _ FinalityBoundary, callbacks AdmissionCallbacks) (CertificateAdmission, error) {
	if f.startErr != nil {
		return nil, f.startErr
	}
	f.mu.Lock()
	f.identity, f.callbacks = id, callbacks
	if f.session == nil {
		f.session = &admissionTestSession{epoch: 1, closed: make(chan struct{})}
	}
	f.session.callbacks = callbacks
	s := f.session
	startUC, startTR := f.startUC, f.startTR
	f.mu.Unlock()
	if startUC != nil {
		if err := callbacks.DeliverDurable(context.Background(), startUC, startTR); err != nil {
			return nil, err
		}
	}
	if f.started != nil {
		close(f.started)
	}
	return s, nil
}

type admissionEpochTrustStore struct {
	tb     *types.RootTrustBaseV1
	epochs chan uint64
}

type v2AdmissionTrustStore struct{ stubTrustBaseStore }

func (v2AdmissionTrustStore) IsV2Epoch(epoch uint64) bool { return epoch == 1 }

func (s admissionEpochTrustStore) GetByEpoch(_ context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	s.epochs <- epoch
	return s.tb, nil
}

type admissionTestSession struct {
	callbacks AdmissionCallbacks
	epoch     uint64
	submitErr error
	closed    chan struct{}
	once      sync.Once
}

func (s *admissionTestSession) Submit(_ context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	s.callbacks.AuthenticatedFeed(uc, tr)
	return s.submitErr
}
func (s *admissionTestSession) RootEpoch() uint64 { return s.epoch }
func (s *admissionTestSession) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

type admissionTestNet struct {
	mu       sync.Mutex
	received chan any
	sent     []any
	sendErr  error
}

func (n *admissionTestNet) Send(context.Context, any, ...peer.ID) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.sendErr != nil {
		return n.sendErr
	}
	n.sent = append(n.sent, handshake.Handshake{})
	return nil
}
func (n *admissionTestNet) ReceivedChannel() <-chan any { return n.received }
func (n *admissionTestNet) handshakes() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.sent)
}

type admissionSink struct {
	mu     sync.Mutex
	calls  int
	errors []error
	mutate bool
}

func (s *admissionSink) HandleCertificate(_ context.Context, uc *types.UnicityCertificate, _ *certification.TechnicalRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.mutate {
		uc.InputRecord.Hash = []byte{0xff}
	}
	if len(s.errors) == 0 {
		return nil
	}
	err := s.errors[0]
	s.errors = s.errors[1:]
	return err
}
func (s *admissionSink) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.calls }

func newAdmissionTestClient(t *testing.T, sink RoundDriver, net *admissionTestNet) (*BFTClient, *confBindingFixture) {
	t.Helper()
	f := newConfBindingFixture(t)
	if net.received == nil {
		net.received = make(chan any)
	}
	c, err := NewBFTClient(testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)), net, f.signer, authPartitionID, types.ShardID{}, f.confMine, stubTrustBaseStore{tb: f.tb}, &recordingDriver{}, nil, DefaultBFTClientOptions)
	require.NoError(t, err)
	require.NotNil(t, sink)
	return c, f
}

func startAdmissionClient(t *testing.T, c *BFTClient, factory *admissionTestFactory, sink RoundDriver) (context.CancelFunc, <-chan error) {
	t.Helper()
	require.NoError(t, c.SetCertificateAdmission(factory, admissionTestGate{}, sink))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	require.Eventually(t, func() bool {
		factory.mu.Lock()
		defer factory.mu.Unlock()
		return factory.callbacks.DeliverDurable != nil
	}, 2*time.Second, time.Millisecond)
	return cancel, done
}

func TestConfiguredAdmissionPersistsBeforeLUCAndOwnsDriverEvidence(t *testing.T) {
	net := &admissionTestNet{}
	sink := &admissionSink{mutate: true}
	c, f := newAdmissionTestClient(t, sink, net)
	factory := &admissionTestFactory{}
	cancel, done := startAdmissionClient(t, c, factory, sink)
	defer func() { cancel(); require.ErrorIs(t, <-done, context.Canceled) }()

	response := f.respond(f.ucMine)
	require.NoError(t, c.handleCertificationResponse(context.Background(), response))
	require.Nil(t, c.luc, "authenticated feed progress is not LUC adoption")
	require.Zero(t, sink.count())

	factory.mu.Lock()
	deliver := factory.callbacks.DeliverDurable
	factory.mu.Unlock()
	require.NoError(t, deliver(context.Background(), &response.UC, &response.Technical))
	require.Equal(t, 1, sink.count())
	require.NotNil(t, c.luc)
	require.NotEqual(t, []byte{0xff}, c.luc.InputRecord.Hash, "driver mutation cannot change retained LUC")
}

func TestConfiguredAdmissionReceivesVerifiedV2Epoch(t *testing.T) {
	net := &admissionTestNet{}
	sink := &admissionSink{}
	c, fixture := newAdmissionTestClient(t, sink, net)
	c.trustBaseStore = v2AdmissionTrustStore{stubTrustBaseStore{tb: fixture.tb}}
	response := fixture.respond(fixture.ucMine)
	require.ErrorIs(t, c.handleCertificationResponse(context.Background(), response), ErrProfile2Unready,
		"without proof-aware admission, the v2 certificate remains closed")
	factory := &admissionTestFactory{}
	cancel, done := startAdmissionClient(t, c, factory, sink)
	defer func() { cancel(); require.ErrorIs(t, <-done, context.Canceled) }()
	require.NoError(t, c.handleCertificationResponse(context.Background(), response),
		"configured admission owns v2 verification and durability")
	require.Nil(t, c.luc, "feed observation alone is not durable admission")
}

func TestConfiguredAdmissionDropsRetiredEpochAfterInstalledHandoff(t *testing.T) {
	c, fixture := newAdmissionTestClient(t, &admissionSink{}, &admissionTestNet{})
	stale := fixture.respond(fixture.ucMine)
	require.Equal(t, uint64(1), stale.UC.GetRootEpoch())
	c.profile2 = &Profile2Consumer{verified: &evmroot.VerifiedHandoff{Epoch: 1}}
	forwarded := errors.New("current epoch forwarded")
	c.admission = &admissionTestSession{submitErr: forwarded, callbacks: AdmissionCallbacks{
		AuthenticatedFeed: func(*types.UnicityCertificate, *certification.TechnicalRecord) {},
	}}
	require.NoError(t, c.handleCertificationResponse(context.Background(), stale),
		"a delayed old-committee response cannot reach admission or the driver")
	current := fixture.respond(fixture.ucMine)
	current.UC.UnicitySeal.Epoch = 2
	require.ErrorIs(t, c.handleCertificationResponse(context.Background(), current), forwarded,
		"the installed epoch still reaches configured admission")
}

func TestConfiguredAdmissionFeedRenewalSurvivesPersistenceFailure(t *testing.T) {
	net := &admissionTestNet{}
	sink := &admissionSink{}
	c, f := newAdmissionTestClient(t, sink, net)
	factory := &admissionTestFactory{session: &admissionTestSession{epoch: 1, submitErr: errors.New("disk unavailable"), closed: make(chan struct{})}}
	cancel, done := startAdmissionClient(t, c, factory, sink)
	defer func() { cancel(); require.ErrorIs(t, <-done, context.Canceled) }()
	require.Eventually(t, func() bool { return net.handshakes() == 1 }, 2*time.Second, time.Millisecond)
	require.ErrorContains(t, c.handleCertificationResponse(context.Background(), f.respond(f.ucMine)), "disk unavailable")
	require.Nil(t, c.luc)
	require.Eventually(t, func() bool { return net.handshakes() == 2 }, 2*time.Second, time.Millisecond)
	require.Zero(t, sink.count())
}

func TestConfiguredAdmissionCoalescedFeedConsumesOnlyOneSubmissionCredit(t *testing.T) {
	net := &admissionTestNet{}
	c, f := newAdmissionTestClient(t, &admissionSink{}, net)
	c.submittedSinceHandshake = true
	response := f.respond(f.ucMine)
	latest := &response.UC
	for i := uint64(0); i < 3; i++ {
		uc, _, err := ownConfiguredPair(&response.UC, &response.Technical)
		require.NoError(t, err)
		uc.UnicitySeal.RootChainRoundNumber += i
		c.observeConfiguredFeed(uc, &response.Technical)
		latest = uc
	}
	c.mu.Lock()
	require.Equal(t, uint8(3), c.feedPendingCount)
	pending := c.feedPending
	count := c.feedPendingCount
	c.feedPending, c.feedPendingCount = nil, 0
	c.mu.Unlock()
	require.Equal(t, latest.GetRootRoundNumber(), pending.GetRootRoundNumber())
	c.renewSubscriptionIfIdle(context.Background(), pending, true, count)
	require.Equal(t, 1, net.handshakes(), "three coalesced responses exhaust more than one submission credit")
	c.observeConfiguredFeed(latest, &response.Technical)
	c.mu.Lock()
	require.Zero(t, c.feedPendingCount, "an exact duplicate does not spend another feed response")
	c.mu.Unlock()
}

func TestConfiguredAdmissionDeliveryRetryDedupAndSubmissionFailure(t *testing.T) {
	for _, tc := range []struct {
		name       string
		firstError error
		wantCalls  int
	}{
		{name: "application failure retries", firstError: errors.New("executor unavailable"), wantCalls: 2},
		{name: "submission failure is applied", firstError: ErrSubmissionFailed, wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			net := &admissionTestNet{}
			sink := &admissionSink{errors: []error{tc.firstError}}
			c, f := newAdmissionTestClient(t, sink, net)
			factory := &admissionTestFactory{}
			cancel, done := startAdmissionClient(t, c, factory, sink)
			defer func() { cancel(); require.ErrorIs(t, <-done, context.Canceled) }()
			response := f.respond(f.ucMine)
			factory.mu.Lock()
			deliver := factory.callbacks.DeliverDurable
			factory.mu.Unlock()
			first := deliver(context.Background(), &response.UC, &response.Technical)
			if errors.Is(tc.firstError, ErrSubmissionFailed) {
				require.NoError(t, first)
			} else {
				require.Error(t, first)
			}
			require.NoError(t, deliver(context.Background(), &response.UC, &response.Technical))
			require.Equal(t, tc.wantCalls, sink.count())
		})
	}
}

func TestConfiguredAdmissionFullTRConflictAndLifecycle(t *testing.T) {
	net := &admissionTestNet{}
	sink := &admissionSink{}
	c, f := newAdmissionTestClient(t, sink, net)
	factory := &admissionTestFactory{}
	cancel, done := startAdmissionClient(t, c, factory, sink)
	response := f.respond(f.ucMine)
	factory.mu.Lock()
	deliver := factory.callbacks.DeliverDurable
	factory.mu.Unlock()
	require.NoError(t, deliver(context.Background(), &response.UC, &response.Technical))
	otherTR := response.Technical
	otherTR.Leader = "other"
	require.ErrorIs(t, deliver(context.Background(), &response.UC, &otherTR), ErrAdmissionMode)
	require.Equal(t, 1, sink.count())
	require.ErrorIs(t, c.SeedLUC(&response.UC), ErrClientRunning)
	require.ErrorIs(t, c.SetDriver(&recordingDriver{}), ErrClientRunning)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	require.ErrorIs(t, c.SeedLUC(&response.UC), ErrAdmissionMode)
	require.ErrorIs(t, c.SetDriver(&recordingDriver{}), ErrAdmissionMode)
	require.ErrorIs(t, c.Run(context.Background()), ErrAdmissionMode, "configured Run is single-use")
}

func TestConfiguredAdmissionRejectsNilAndCanceledDelivery(t *testing.T) {
	net := &admissionTestNet{}
	sink := &admissionSink{}
	c, f := newAdmissionTestClient(t, sink, net)
	factory := &admissionTestFactory{}
	cancelRun, done := startAdmissionClient(t, c, factory, sink)
	defer func() { cancelRun(); require.ErrorIs(t, <-done, context.Canceled) }()
	require.Error(t, c.handleCertificationResponse(context.Background(), nil))

	response := f.respond(f.ucMine)
	factory.mu.Lock()
	deliver := factory.callbacks.DeliverDurable
	factory.mu.Unlock()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, deliver(canceled, &response.UC, &response.Technical), context.Canceled)
	require.Nil(t, c.luc)
	require.Zero(t, sink.count())
}

func TestConfiguredAdmissionStartAndHandshakeFailureCloseLifecycle(t *testing.T) {
	t.Run("start failure is before handshake", func(t *testing.T) {
		net := &admissionTestNet{}
		c, _ := newAdmissionTestClient(t, &admissionSink{}, net)
		factory := &admissionTestFactory{startErr: errors.New("bad configured context")}
		require.NoError(t, c.SetCertificateAdmission(factory, admissionTestGate{}, &admissionSink{}))
		require.ErrorContains(t, c.Run(context.Background()), "bad configured context")
		require.Zero(t, net.handshakes())
	})
	t.Run("initial handshake failure drains admission", func(t *testing.T) {
		net := &admissionTestNet{sendErr: errors.New("network down")}
		c, _ := newAdmissionTestClient(t, &admissionSink{}, net)
		factory := &admissionTestFactory{}
		require.NoError(t, c.SetCertificateAdmission(factory, admissionTestGate{}, &admissionSink{}))
		require.ErrorContains(t, c.Run(context.Background()), "initial handshake")
		select {
		case <-factory.session.closed:
		case <-time.After(2 * time.Second):
			t.Fatal("admission was not closed on handshake failure")
		}
	})
}

func TestConfiguredAdmissionUsesTrustedEpochAndCanDeliverDuringStart(t *testing.T) {
	net := &admissionTestNet{}
	sink := &admissionSink{}
	c, f := newAdmissionTestClient(t, sink, net)
	epochs := make(chan uint64, 1)
	c.trustBaseStore = admissionEpochTrustStore{tb: f.tb, epochs: epochs}
	response := f.respond(f.ucMine)
	factory := &admissionTestFactory{
		session: &admissionTestSession{epoch: 7, closed: make(chan struct{})},
		startUC: &response.UC,
		startTR: &response.Technical,
	}
	cancel, done := startAdmissionClient(t, c, factory, sink)
	defer func() { cancel(); require.ErrorIs(t, <-done, context.Canceled) }()
	require.Equal(t, uint64(7), <-epochs)
	require.Equal(t, 1, sink.count())
	require.NotNil(t, c.luc, "the durable callback is initialized before Start returns")
}

func TestConfiguredAdmissionHandshakeReadsCurrentEpoch(t *testing.T) {
	net := &admissionTestNet{}
	c, f := newAdmissionTestClient(t, &admissionSink{}, net)
	epochs := make(chan uint64, 1)
	c.trustBaseStore = admissionEpochTrustStore{tb: f.tb, epochs: epochs}
	c.admission = &admissionTestSession{epoch: 3}
	c.admissionEpoch = 1
	c.admissionEpochSet = true
	require.NoError(t, c.sendHandshake(context.Background()))
	require.EqualValues(t, 3, <-epochs)
}
