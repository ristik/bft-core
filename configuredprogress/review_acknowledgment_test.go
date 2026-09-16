package configuredprogress

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootinput"
)

func TestReviewAcknowledgmentDoesNotWaitForAnotherSubmissionsGate(t *testing.T) {
	f := newFixture(t, 2)
	s, _ := f.open(2)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	gate := &blockedAdmissionGate{entered: make(chan struct{}, 2), release: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(gate.release) }) }
	c, err := NewAdmissionCoordinator(context.Background(), AdmissionConfig{
		Store: s, Context: f.ctx, Gate: gate, Invalidate: func() {},
		Deliver: func(context.Context, rootinput.VerifiedObservationV2) error { return nil },
	})
	require.NoError(t, err)
	u, tr := f.sign(f.c.InputRecord(1), 2, 5)
	submitted, acknowledged := make(chan error, 1), make(chan bool, 1)
	t.Cleanup(func() {
		release()
		require.NoError(t, c.Close())
	})
	go func() { _, e := c.Submit(context.Background(), u, tr); submitted <- e }()
	select {
	case <-gate.entered:
	case <-time.After(time.Second):
		t.Fatal("normal submission did not reach the held finality gate")
	}
	go func() { retained, _ := c.AcknowledgePair(u, tr); acknowledged <- retained }()
	select {
	case retained := <-acknowledged:
		require.True(t, retained)
		require.NotEmpty(t, c.Status().FirstOrdinaryPair)
	case <-time.After(time.Second):
		t.Error("acknowledgment waited for another submission's finality gate")
	}
	release()
	select {
	case e := <-submitted:
		require.NoError(t, e)
	case <-time.After(time.Second):
		t.Fatal("submission did not finish after gate release")
	}
}

func TestReviewAdmissionValidatesContextBeforeTrustLookup(t *testing.T) {
	f := newFixture(t, 1)
	s, _ := f.open(2)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	bad := f.ctx
	bad.Observation.TrustBases = nil
	require.NotPanics(t, func() {
		c, err := NewAdmissionCoordinator(context.Background(), AdmissionConfig{
			Store: s, Context: bad, Gate: &admissionGate{}, Invalidate: func() {},
			Deliver: func(context.Context, rootinput.VerifiedObservationV2) error { return nil },
		})
		if c != nil {
			require.NoError(t, c.Close())
		}
		require.Error(t, err)
	})
}
