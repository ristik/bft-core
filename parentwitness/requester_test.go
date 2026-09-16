package parentwitness

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

type testRequesterOpener struct{}

func (*testRequesterOpener) CreateStream(context.Context, peer.ID, string) (libp2pnetwork.Stream, error) {
	return nil, errors.New("unused")
}

type countingRequesterOpener struct{ calls int }

func (o *countingRequesterOpener) CreateStream(context.Context, peer.ID, string) (libp2pnetwork.Stream, error) {
	o.calls++
	return nil, errors.New("unavailable")
}

type pipeLibp2pStream struct {
	libp2pnetwork.Stream
	conn      net.Conn
	resetOnce sync.Once
}

func (s *pipeLibp2pStream) Read(p []byte) (int, error)  { return s.conn.Read(p) }
func (s *pipeLibp2pStream) Write(p []byte) (int, error) { return s.conn.Write(p) }

func (s *pipeLibp2pStream) CloseWrite() error             { return nil }
func (s *pipeLibp2pStream) CloseRead() error              { return nil }
func (s *pipeLibp2pStream) Conn() libp2pnetwork.Conn      { return nil }
func (s *pipeLibp2pStream) Reset() error                  { s.resetOnce.Do(func() { _ = s.conn.Close() }); return nil }
func (s *pipeLibp2pStream) SetDeadline(t time.Time) error { return s.conn.SetDeadline(t) }
func (s *pipeLibp2pStream) Close() error                  { return s.conn.Close() }

type scriptedOpener struct {
	target    Target
	responses []Response
	mu        sync.Mutex
	calls     int
}

func (o *scriptedOpener) CreateStream(_ context.Context, _ peer.ID, _ string) (libp2pnetwork.Stream, error) {
	a, b := net.Pipe()
	o.mu.Lock()
	i := o.calls
	o.calls++
	o.mu.Unlock()
	go func() {
		defer b.Close()
		_, err := ReadRequestFrame(b)
		if err != nil {
			return
		}
		o.mu.Lock()
		resp := o.responses[i%len(o.responses)]
		o.mu.Unlock()
		_ = WriteResponseFrame(b, resp)
	}()
	return &pipeLibp2pStream{conn: a}, nil
}

func TestRequesterRejectsProviderListBeyondBudgetBeforeCopy(t *testing.T) {
	_, err := NewRequester(context.Background(), RequesterConfig{
		Opener: &testRequesterOpener{}, Providers: []peer.ID{"a", "b"},
		Budget: RequesterBudget{MaxAttempts: 2, MaxProviders: 1, Overall: time.Second, PerAttempt: time.Second, MaxDownloadedBytes: 10, Backoff: time.Second},
	})
	require.Error(t, err)
}

func TestBudgetedFrameCountsPrefixAndPartialBody(t *testing.T) {
	// 0x03 declares a three-byte body; a two-byte budget must fail after consuming
	// the prefix and the first body byte, without consuming the remaining body.
	var used int64
	_, err := readFrameBudgeted(bytes.NewReader([]byte{3, 1, 2, 3}), MaxResponseBytes, &used, 2)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDownloadedBytes))
	require.EqualValues(t, 2, used)
}

func TestRequesterCountsEveryProviderAndAppliesBackoff(t *testing.T) {
	o := &countingRequesterOpener{}
	_, target := fixtureTarget(t)
	r, err := NewRequester(context.Background(), RequesterConfig{Opener: o, Providers: []peer.ID{"a", "b"}, Budget: RequesterBudget{MaxAttempts: 2, MaxProviders: 2, Overall: time.Second, PerAttempt: time.Second, MaxDownloadedBytes: 100, Backoff: time.Second}})
	require.NoError(t, err)
	t.Cleanup(r.Close)
	got, err := r.Request(context.Background(), target)
	require.NoError(t, err)
	require.Equal(t, RequesterInvalid, got.Outcome)
	require.Equal(t, 2, got.Attempts)
	require.Equal(t, 2, o.calls)
	_, err = r.Request(context.Background(), target)
	require.ErrorIs(t, err, ErrRequesterBackoff)
}

func TestRequesterVerifiedProofAndInvalidThenValid(t *testing.T) {
	c, target := fixtureTarget(t)
	bad := c.Blocks[1].Evidence
	bad.Header = append([]byte(nil), bad.Header...)
	bad.Header[0] ^= 1
	responses := []Response{{Request: target.Request(), Outcome: OutcomeFound, Evidence: bad}, {Request: target.Request(), Outcome: OutcomeFound, Evidence: c.Blocks[1].Evidence}}
	o := &scriptedOpener{target: target, responses: responses}
	r, err := NewRequester(context.Background(), RequesterConfig{Opener: o, Providers: []peer.ID{"a", "b"}, Budget: RequesterBudget{MaxAttempts: 2, MaxProviders: 2, Overall: time.Second, PerAttempt: time.Second, MaxDownloadedBytes: MaxResponseBytes * 2, Backoff: time.Second}})
	require.NoError(t, err)
	t.Cleanup(r.Close)
	got, err := r.Request(context.Background(), target)
	require.NoError(t, err)
	require.Equal(t, RequesterVerified, got.Outcome)
	require.True(t, got.Response.Found())
	require.Equal(t, 2, o.calls)
}
