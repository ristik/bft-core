package inputcarrier

// Review 5196862602's reproduction, kept as a regression and adapted. As published it declared a round
// with no sender restriction and required 1,000 distinct senders' deliveries to be admitted, which is
// exactly the open admission the review asked to replace. Since the repair every round pins a finite
// eligible sender set, so the adaptation is:
//
//   - TestReview154RejectionAccountingIsBounded runs the published loop unchanged except that the round
//     pins one eligible sender, and each of the 1,000 distinct senders' deliveries must now be refused
//     rather than admitted. Its closing assertion is the published one, and the retained state is
//     logged as published.
//   - TestReview154EligibleSendersCannotGrowAccounting is the same loop with every delivery coming from
//     the eligible set, which is the only way to reach Reject now, so the published bound is checked
//     against state that rejection actually produced.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

func TestReview154RejectionAccountingIsBounded(t *testing.T) {
	limits := DefaultTransportLimits
	r, err := NewReceiver(limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	e := Envelope{Version: Version, ShardRound: 5, BlockHash: bytes.Repeat([]byte{1}, 32), Certificate: []byte{0x80}, TechnicalRecord: []byte{0x80}}
	if err := r.Expect(5, Expectation{BlockHash: e.BlockHash, Senders: []string{"proposer"}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		e.Certificate = []byte(fmt.Sprintf("invalid-%d", i))
		body, err := Encode(e, limits.Envelope)
		if err != nil {
			t.Fatal(err)
		}
		f := append(binary.AppendUvarint(nil, uint64(len(body))), body...)
		if err := r.Serve(bytes.NewReader(f), fmt.Sprintf("peer-%d", i)); !errors.Is(err, ErrUnexpectedSender) {
			t.Fatalf("delivery %d from a sender outside the pinned set: got %v, want %v", i, err, ErrUnexpectedSender)
		}
		if err := r.Reject(5, e); !errors.Is(err, ErrNoSuchCandidate) {
			t.Fatalf("reject %d: got %v, want %v", i, err, ErrNoSuchCandidate)
		}
	}
	rs := r.rounds[5]
	t.Logf("pending=%d rejectedDigests=%d retainedPeerCounters=%d activeStreams=%d", len(rs.pending), len(rs.rejected), len(rs.rejectsByPeer), r.admTotal)
	if len(rs.rejectsByPeer) > limits.MaxRejectedPerRound {
		t.Fatalf("per-round rejection memory grows past the configured history bound: %d peer counters, %d digest limit", len(rs.rejectsByPeer), limits.MaxRejectedPerRound)
	}
	if len(rs.rejectsByPeer) != 0 || len(rs.pending) != 0 || len(rs.rejected) != 0 {
		t.Fatalf("senders outside the set retained state: %d counters, %d pending, %d digests", len(rs.rejectsByPeer), len(rs.pending), len(rs.rejected))
	}
}

func TestReview154EligibleSendersCannotGrowAccounting(t *testing.T) {
	limits := DefaultTransportLimits
	r, err := NewReceiver(limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	eligible := []string{"s0", "s1", "s2", "s3"}
	e := Envelope{Version: Version, ShardRound: 5, BlockHash: bytes.Repeat([]byte{1}, 32), Certificate: []byte{0x80}, TechnicalRecord: []byte{0x80}}
	if err := r.Expect(5, Expectation{BlockHash: e.BlockHash, Senders: eligible}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		e.Certificate = []byte(fmt.Sprintf("invalid-%d", i))
		body, err := Encode(e, limits.Envelope)
		if err != nil {
			t.Fatal(err)
		}
		f := append(binary.AppendUvarint(nil, uint64(len(body))), body...)
		err = r.Serve(bytes.NewReader(f), eligible[i%len(eligible)])
		if errors.Is(err, ErrPeerExhausted) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Reject(5, e); err != nil {
			t.Fatal(err)
		}
	}
	rs := r.rounds[5]
	t.Logf("pending=%d rejectedDigests=%d retainedPeerCounters=%d activeStreams=%d", len(rs.pending), len(rs.rejected), len(rs.rejectsByPeer), r.admTotal)
	if len(rs.rejectsByPeer) > limits.MaxRejectedPerRound || len(rs.rejectsByPeer) > limits.MaxSendersPerRound {
		t.Fatalf("per-round rejection memory grows past its bounds: %d peer counters", len(rs.rejectsByPeer))
	}
	if len(rs.rejected) > limits.MaxRejectedPerRound {
		t.Fatalf("rejected digests past their bound: %d", len(rs.rejected))
	}
}
