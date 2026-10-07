package q3delivery

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3active"
)

type fakeProvider struct {
	bundle q3active.Bundle
	err    error
	asked  []uint64
}

func (p *fakeProvider) Q3Bundle(_ context.Context, epoch uint64) (q3active.Bundle, error) {
	p.asked = append(p.asked, epoch)
	return p.bundle, p.err
}

// serveOnce runs one Serve against a client exchange over an in-memory duplex and returns the client's result.
func serveOnce(t *testing.T, s *Server, epoch uint64) (q3active.Bundle, error) {
	t.Helper()
	cr, sw := io.Pipe()
	sr, cw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := s.Serve(context.Background(), struct {
			io.Reader
			io.Writer
		}{sr, sw})
		_ = sw.Close()
		done <- err
	}()
	b, err := exchange(struct {
		io.Reader
		io.Writer
	}{cr, cw}, epoch)
	_ = cw.Close()
	<-done
	return b, err
}

func TestAnActivationBundleIsServedAndFetchedByteForByte(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{Assignment: true})
	bundle := q3active.Bundle{Envelope: f.EnvelopeBytes, Snapshot: f.Snapshot, Candidate: f.Candidate}
	p := &fakeProvider{bundle: bundle}
	s, err := NewServer(p)
	require.NoError(t, err)

	got, err := serveOnce(t, s, f.Claim.Epoch)
	require.NoError(t, err)
	want, err := q3active.EncodeBundle(bundle)
	require.NoError(t, err)
	have, err := q3active.EncodeBundle(got)
	require.NoError(t, err)
	require.Equal(t, want, have)
	require.Equal(t, []uint64{f.Claim.Epoch}, p.asked)
}

func TestTheExchangeRefusesEachWrongThingAndAsksNoProviderForABadEpoch(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	good := q3active.Bundle{Envelope: f.EnvelopeBytes, Snapshot: f.Snapshot}

	p := &fakeProvider{bundle: good}
	s, _ := NewServer(p)
	_, err := serveOnce(t, s, 1)
	require.ErrorIs(t, err, ErrBundle, "epoch 1 is not a successor")
	require.Empty(t, p.asked, "an invalid epoch never reaches the provider")

	_, err = serveOnce(t, s, f.Claim.Epoch+1)
	require.ErrorIs(t, err, ErrBundle, "a provider that serves another epoch's bundle")

	p = &fakeProvider{err: errors.New("not committed here")}
	s, _ = NewServer(p)
	_, err = serveOnce(t, s, f.Claim.Epoch)
	require.ErrorIs(t, err, ErrBundle)
	require.Contains(t, err.Error(), "activation unavailable")

	p = &fakeProvider{bundle: q3active.Bundle{Envelope: []byte("garbage"), Snapshot: f.Snapshot}}
	s, _ = NewServer(p)
	_, err = serveOnce(t, s, f.Claim.Epoch)
	require.ErrorIs(t, err, ErrBundle, "a bundle that does not decode is never served")

	_, err = NewServer(nil)
	require.Error(t, err)
}
