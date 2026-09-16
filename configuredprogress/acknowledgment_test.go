package configuredprogress

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

type blockedAdmissionGate struct {
	entered chan struct{}
	release chan struct{}
}

func (g *blockedAdmissionGate) WithinFinality(ctx context.Context, f func() error) error {
	select {
	case g.entered <- struct{}{}:
	default:
	}
	select {
	case <-g.release:
		return f()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestAcknowledgePairRetainsBeforeBlockedGateAndCallerCancellation(t *testing.T) {
	f := newFixture(t, 2)
	s, _ := f.open(2)
	gate := &blockedAdmissionGate{entered: make(chan struct{}, 1), release: make(chan struct{})}
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	c, err := newAdmissionCoordinator(ctx, AdmissionConfig{Store: s, Context: f.ctx, Gate: gate, Invalidate: func() {}, Deliver: func(context.Context, rootinput.VerifiedObservationV2) error { return nil }}, wallAdmissionClock{}, admissionPolicy{attempts: 1, duration: 5 * time.Second, cooldown: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() {
		cancel()
		close(gate.release)
		require.NoError(t, c.Close())
	})
	u, tr := f.sign(f.c.InputRecord(1), 2, 5)
	retained, err := c.AcknowledgePair(u, tr)
	require.True(t, retained)
	require.NoError(t, err)
	cancel()
	status := c.Status()
	require.True(t, status.BootstrapInvalidated)
	require.True(t, status.PendingFirst)
	require.True(t, status.PendingLatest)
	require.NotEmpty(t, status.FirstOrdinaryPair)
	require.Equal(t, status.FirstOrdinaryPair, status.LatestOrdinaryPair)
	status.FirstOrdinaryPair[0] ^= 0xff
	require.NotEqual(t, status.FirstOrdinaryPair, c.Status().FirstOrdinaryPair)
}

func TestAcknowledgePairDoesNotWaitForSubmitFinalityGate(t *testing.T) {
	f := newFixture(t, 2)
	s, _ := f.open(2)
	gate := &blockedAdmissionGate{entered: make(chan struct{}, 1), release: make(chan struct{})}
	var releaseGate sync.Once
	release := func() { releaseGate.Do(func() { close(gate.release) }) }
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	c, err := newAdmissionCoordinator(context.Background(), AdmissionConfig{Store: s, Context: f.ctx, Gate: gate, Invalidate: func() {}, Deliver: func(context.Context, rootinput.VerifiedObservationV2) error { return nil }}, wallAdmissionClock{}, admissionPolicy{attempts: 1, duration: 5 * time.Second, cooldown: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() {
		release()
		require.NoError(t, c.Close())
	})
	u, tr := f.sign(f.c.InputRecord(1), 2, 5)
	submitDone := make(chan error, 1)
	go func() {
		_, submitErr := c.Submit(context.Background(), u, tr)
		submitDone <- submitErr
	}()
	select {
	case <-gate.entered:
	case <-time.After(time.Second):
		t.Fatal("Submit did not enter finality gate")
	}

	ackDone := make(chan error, 1)
	go func() {
		retained, ackErr := c.AcknowledgePair(u, tr)
		if !retained && ackErr == nil {
			ackErr = errors.New("pair was not retained")
		}
		ackDone <- ackErr
	}()
	select {
	case ackErr := <-ackDone:
		require.NoError(t, ackErr)
	case <-time.After(time.Second):
		t.Fatal("AcknowledgePair waited for Submit's finality gate")
	}
	require.False(t, c.BootstrapState().Allowed())
	release()
	require.NoError(t, <-submitDone)
}

func TestBootstrapStateReflectsStoredOrdinaryAndClose(t *testing.T) {
	f := newFixture(t, 2)
	s, _ := f.open(2)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	u, tr := f.sign(f.c.InputRecord(1), 2, 5)
	c := newTestAdmission(t, f, s, &admissionGate{}, wallAdmissionClock{}, admissionPolicy{attempts: 3, duration: time.Second, spacing: 0, cooldown: time.Hour}, func() {}, func(context.Context, rootinput.VerifiedObservationV2) error { return nil })
	retained, err := c.AcknowledgePair(u, tr)
	require.True(t, retained)
	require.NoError(t, err)
	waitAdmission(t, func() bool {
		st, _, loadErr := s.Load(context.Background(), f.ctx)
		return loadErr == nil && st.Ordinary()
	})
	require.NoError(t, c.Close())
	state := c.BootstrapState()
	require.True(t, state.BootstrapInvalidated)
	require.True(t, state.Closed)
	require.True(t, state.ProcessStopped)
	require.False(t, state.Allowed())

	reopened := newTestAdmission(t, f, s, &admissionGate{}, wallAdmissionClock{}, admissionPolicy{attempts: 1, duration: time.Second, cooldown: time.Hour}, func() {}, func(context.Context, rootinput.VerifiedObservationV2) error { return nil })
	require.False(t, reopened.BootstrapState().Allowed())
}

func TestAcknowledgePairRejectsForeignContextWithoutRetention(t *testing.T) {
	f := newFixture(t, 2)
	s, _ := f.open(2)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	c := newTestAdmission(t, f, s, &admissionGate{}, wallAdmissionClock{}, admissionPolicy{attempts: 1, duration: time.Second, cooldown: time.Hour}, func() {}, func(context.Context, rootinput.VerifiedObservationV2) error { return nil })
	u, tr := f.sign(f.c.InputRecord(1), 2, 5)
	u.UnicitySeal.NetworkID++
	retained, err := c.AcknowledgePair(u, tr)
	require.False(t, retained)
	require.Error(t, err)
	status := c.Status()
	require.False(t, status.BootstrapInvalidated)
	require.Empty(t, status.FirstOrdinaryPair)
}

func TestAcknowledgePairUnsupportedRetainsOwnedDiagnostic(t *testing.T) {
	f := newFixture(t, 1)
	s, _ := f.open(2)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	c := newTestAdmission(t, f, s, &admissionGate{}, wallAdmissionClock{}, admissionPolicy{attempts: 1, duration: time.Second, cooldown: time.Hour}, func() {}, func(context.Context, rootinput.VerifiedObservationV2) error { return nil })
	u, tr := f.sign(&types.InputRecord{Version: 1, SumOfEarnedFees: 1}, 2, 5)
	retained, err := c.AcknowledgePair(u, tr)
	require.True(t, retained)
	require.Error(t, err)
	require.True(t, rootinput.IsUnsupportedObservationV2(err))
	status := c.Status()
	require.True(t, status.BootstrapInvalidated)
	require.True(t, status.UnsupportedSeen)
	require.NotEmpty(t, status.FirstUnsupportedPair)
	require.False(t, status.PendingFirst)
	require.False(t, status.PendingLatest)
}

func TestAcknowledgePairAuthenticChangedRootEpochIsUnsupported(t *testing.T) {
	f := newFixture(t, 1)
	s, _ := f.open(2)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	c := newTestAdmission(t, f, s, &admissionGate{}, wallAdmissionClock{}, admissionPolicy{attempts: 1, duration: time.Second, cooldown: time.Hour}, func() {}, func(context.Context, rootinput.VerifiedObservationV2) error { return nil })
	u, tr := f.sign(&types.InputRecord{Version: 1, SumOfEarnedFees: 1}, 2, 5)
	var author string
	for signer := range u.UnicitySeal.Signatures {
		author = signer
	}
	u.UnicitySeal.Epoch = 2
	u.UnicitySeal.Signatures = nil
	require.NoError(t, u.UnicitySeal.Sign(author, f.c.Signer))
	encoded, err := types.Cbor.Marshal(u)
	require.NoError(t, err)
	var forged types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(encoded, &forged))
	for signer, signature := range forged.UnicitySeal.Signatures {
		signature[0] ^= 0xff
		forged.UnicitySeal.Signatures[signer] = signature
		break
	}
	retained, err := c.AcknowledgePair(&forged, tr)
	require.False(t, retained)
	require.Error(t, err)
	require.True(t, c.BootstrapState().Allowed(), "forged epoch claim must not invalidate bootstrap")

	retained, err = c.AcknowledgePair(u, tr)
	require.True(t, retained)
	require.Error(t, err)
	require.True(t, rootinput.IsUnsupportedObservationV2(err))
	status := c.Status()
	require.True(t, status.BootstrapInvalidated)
	require.True(t, status.UnsupportedSeen)
	require.NotEmpty(t, status.FirstUnsupportedPair)
}

func TestAcknowledgePairProfileBindingIsFixed(t *testing.T) {
	f := newFixture(t, 1)
	s, _ := f.open(2)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	c := newTestAdmission(t, f, s, &admissionGate{}, wallAdmissionClock{}, admissionPolicy{attempts: 1, duration: time.Second, cooldown: time.Hour}, func() {}, func(context.Context, rootinput.VerifiedObservationV2) error { return nil })
	want, err := rootinput.AdmissionProfileBindingV2(f.ctx.Observation, f.c.TrustBase, f.origin.Identity().Bytes())
	require.NoError(t, err)
	require.Equal(t, want, c.EvidenceProfileBinding())
	f.c.TrustBase.QuorumThreshold++
	require.Equal(t, want, c.EvidenceProfileBinding())
}

func TestAcknowledgePairStoreFailureDoesNotEraseRetention(t *testing.T) {
	f := newFixture(t, 2)
	s, _ := f.open(2)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	s.checkpoint = func(string) error { return errors.New("disk failed") }
	c := newTestAdmission(t, f, s, &admissionGate{}, wallAdmissionClock{}, admissionPolicy{attempts: 2, duration: time.Second, spacing: 0, cooldown: time.Hour}, func() {}, func(context.Context, rootinput.VerifiedObservationV2) error { return nil })
	u, tr := f.sign(f.c.InputRecord(1), 2, 5)
	retained, err := c.AcknowledgePair(u, tr)
	require.True(t, retained)
	require.NoError(t, err)
	waitAdmission(t, func() bool { return c.Status().LastError != nil })
	status := c.Status()
	require.True(t, status.BootstrapInvalidated)
	require.NotEmpty(t, status.FirstOrdinaryPair)
	require.NotEmpty(t, status.LatestOrdinaryPair)
}
