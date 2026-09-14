package inputcarrier_test

// The two reproductions from review 5196428126, kept as regressions. The first is adapted by one line:
// the receiver now admits deliveries only for rounds the caller declared with Expect, which is the
// repair for the future-round saturation half of the same finding, so the test declares round 5 before
// serving. Everything else is as published.

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	lp "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/inputcarrier"
)

func TestReview154RejectedFirstDeliveryDoesNotPoisonRound(t *testing.T) {
	s := newScenario(t)
	_, err := inputcarrier.Verify(context.Background(), s.ctx, s.env, s.header)
	require.NoError(t, err)
	r := newReceiver(t, inputcarrier.DefaultTransportLimits)
	require.NoError(t, r.Expect(s.env.ShardRound, inputcarrier.Expectation{BlockHash: s.env.BlockHash})) // the one added line
	bad := s.env
	bad.Certificate = []byte{0x80}
	require.NoError(t, r.Serve(bytes.NewReader(frame(t, bad)), "attacker"))
	got, err := r.Await(context.Background(), s.env.ShardRound)
	require.NoError(t, err)
	_, err = inputcarrier.Verify(context.Background(), s.ctx, got, s.header)
	require.Error(t, err)
	require.NoError(t, r.Serve(bytes.NewReader(frame(t, s.env)), "honest-proposer"), "a rejected unauthenticated candidate must not permanently exclude the valid witness")
}

type reviewStream struct {
	lp.Stream
	c net.Conn
}

func (s *reviewStream) Write(b []byte) (int, error)   { return s.c.Write(b) }
func (s *reviewStream) SetDeadline(d time.Time) error { return s.c.SetDeadline(d) }
func (s *reviewStream) Reset() error                  { return s.c.Close() }
func (s *reviewStream) Close() error                  { return s.c.Close() }
func (s *reviewStream) CloseWrite() error             { return nil }

type reviewHost struct{ stream lp.Stream }

func (h reviewHost) RegisterProtocolHandler(string, lp.StreamHandler) {}
func (h reviewHost) CreateStream(context.Context, peer.ID, string) (lp.Stream, error) {
	return h.stream, nil
}

func TestReview154SendHonorsCallerDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	l := inputcarrier.DefaultTransportLimits
	l.Deadline = 600 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := inputcarrier.Send(ctx, reviewHost{&reviewStream{c: a}}, peer.ID("peer"), sampleEnvelope(), l)
	require.Error(t, err)
	require.Less(t, time.Since(start), 250*time.Millisecond, "blocked write must stop at the caller budget")
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
