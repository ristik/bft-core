package frontiertransport

import (
	"bytes"
	"encoding/binary"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type reviewCountReader struct {
	r           io.Reader
	read        int
	afterPrefix func()
}

func (r *reviewCountReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.read += n
	if r.read == 4 && r.afterPrefix != nil {
		f := r.afterPrefix
		r.afterPrefix = nil
		f()
	}
	return n, err
}

func reviewFrame(declared uint32, payload []byte) []byte {
	raw := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(raw, declared)
	return append(raw, payload...)
}

func TestReviewReceiveBudgetPrecedesReads(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit uint64
		read  int
	}{
		{"inside prefix", 3, 3},
		{"before body", 5, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := NewReceiveBudget(tc.limit)
			require.NoError(t, err)
			r := &reviewCountReader{r: bytes.NewReader(reviewFrame(2, []byte{8, 9}))}
			body, _, err := readBudgetedFrame(r, b)
			require.ErrorIs(t, err, ErrBudget)
			require.Nil(t, body)
			require.Equal(t, tc.read, r.read, "budget must refuse before the next network read")
			require.EqualValues(t, tc.read, b.Snapshot().Consumed)
		})
	}
}

func TestReviewPartialReservationIsNotRefundedOrReportedAsConsumed(t *testing.T) {
	b, err := NewReceiveBudget(20)
	require.NoError(t, err)
	body, partial, err := readBudgetedFrame(bytes.NewReader(reviewFrame(8, []byte{1, 2, 3})), b)
	require.Error(t, err)
	require.Nil(t, body)
	require.Equal(t, []byte{1, 2, 3}, partial)
	require.EqualValues(t, 12, b.Snapshot().Committed)
	require.EqualValues(t, 7, b.Snapshot().Consumed)
	body, _, err = readBudgetedFrame(bytes.NewReader(reviewFrame(4, []byte{4, 5, 6, 7})), b)
	require.NoError(t, err)
	require.Equal(t, []byte{4, 5, 6, 7}, body)
	require.EqualValues(t, 20, b.Snapshot().Committed)
	require.EqualValues(t, 15, b.Snapshot().Consumed)
	r := &reviewCountReader{r: bytes.NewReader(reviewFrame(1, []byte{9}))}
	_, _, err = readBudgetedFrame(r, b)
	require.ErrorIs(t, err, ErrBudget)
	require.Zero(t, r.read)
	require.EqualValues(t, 15, b.Snapshot().Consumed)
}

func TestReviewConcurrentReadersReserveFromOneCap(t *testing.T) {
	b, err := NewReceiveBudget(13) // two prefixes plus exactly one five-byte body
	require.NoError(t, err)
	gate := make(chan struct{})
	var release sync.Once
	open := func() { release.Do(func() { close(gate) }) }
	t.Cleanup(open)
	ready := make(chan struct{}, 2)
	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 2)
	readers := []*reviewCountReader{
		{r: bytes.NewReader(reviewFrame(5, []byte{1, 2, 3, 4, 5}))},
		{r: bytes.NewReader(reviewFrame(5, []byte{6, 7, 8, 9, 10}))},
	}
	for _, r := range readers {
		r.afterPrefix = func() { ready <- struct{}{}; <-gate }
		go func(r *reviewCountReader) {
			body, _, err := readBudgetedFrame(r, b)
			done <- result{body, err}
		}(r)
	}
	for range 2 {
		select {
		case <-ready:
		case <-time.After(time.Second):
			t.Fatal("readers did not reach the reserved prefix boundary")
		}
	}
	open()
	succeeded := 0
	for range 2 {
		select {
		case res := <-done:
			if res.err == nil {
				succeeded++
				require.Len(t, res.body, 5)
			} else {
				require.ErrorIs(t, res.err, ErrBudget)
				require.Nil(t, res.body)
			}
		case <-time.After(time.Second):
			t.Fatal("reader did not finish")
		}
	}
	require.Equal(t, 1, succeeded)
	require.Equal(t, 13, readers[0].read+readers[1].read)
	require.EqualValues(t, 13, b.Snapshot().Committed)
	require.EqualValues(t, 13, b.Snapshot().Consumed)
}

func TestReviewExchangeSlotsAreConcurrentRatherThanLifetime(t *testing.T) {
	b, err := NewReceiveBudget(100)
	require.NoError(t, err)
	for range MaxExchanges {
		require.NoError(t, b.begin())
	}
	require.Error(t, b.begin())
	b.end()
	require.NoError(t, b.begin(), "a completed exchange releases capacity for the later cut request")
	for range MaxExchanges {
		b.end()
	}
	require.Zero(t, b.Snapshot().Active)
	var zero ReceiveBudget
	require.Error(t, zero.begin(), "the zero budget must not authorize a dial")
	require.NoError(t, b.reserve(100))
	require.ErrorIs(t, b.begin(), ErrBudget)
}
