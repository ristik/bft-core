package evmroot

import (
	"math"
	"strconv"
	"testing"
)

func TestD5_QueueSequenceBoundariesRefundAndRevoke(t *testing.T) {
	for _, seq := range []uint64{uint64(math.MaxInt64), uint64(math.MaxInt64) + 1} {
		t.Run("seq_"+strconv.FormatUint(seq, 10), func(t *testing.T) {
			esc := NewCreditEscrow()
			if r := esc.ApplyDeposit(CertifiedDeposit{DepositID: "d", Owner: "a", Amount: 1, Certified: true}); !r.Applied {
				t.Fatalf("deposit failed: %s", r.Reason)
			}
			q := NewForcedInbox(esc, AdmissionLimits{MaxEncodedBytes: 4096, GFI: 300_000, PerSenderQueue: 4, GlobalQueue: 16})
			q.nextSeq = seq

			admitted, _ := q.Admit("a", "c", 100, 100_000, rep(1, 32), true, 1, true, true, true)
			if !admitted.Admitted || admitted.Seq != seq {
				t.Fatalf("admission at sequence %d failed: %+v", seq, admitted)
			}
			credit := esc.credits["c"]
			if !credit.consumed || credit.consumedBy != seq {
				t.Fatalf("credit binding lost full-width sequence: consumed=%v seq=%d, want %d", credit.consumed, credit.consumedBy, seq)
			}

			refund := esc.ReconcileUnusedCredit(RefundStatement{CreditID: "c", Owner: "a", RootCertifiedUnused: true}, q)
			if !refund.Applied {
				t.Fatalf("pending entry was not refunded: %s", refund.Reason)
			}
			if len(q.live) != 0 || esc.available["a"] != 1 {
				t.Fatalf("refund did not revoke the pending entry atomically: live=%d available=%d", len(q.live), esc.available["a"])
			}
			for _, outcome := range q.ProcessDuePrefix(nil) {
				if outcome.Seq == seq && outcome.Executed {
					t.Fatalf("refunded sequence %d remained executable", seq)
				}
			}
		})
	}
}

func TestD5_QueueMaxUint64SequenceDoesNotWrapOrRefundLiveEntry(t *testing.T) {
	esc := NewCreditEscrow()
	if r := esc.ApplyDeposit(CertifiedDeposit{DepositID: "d", Owner: "a", Amount: 2, Certified: true}); !r.Applied {
		t.Fatalf("deposit failed: %s", r.Reason)
	}
	q := NewForcedInbox(esc, AdmissionLimits{MaxEncodedBytes: 4096, GFI: 300_000, PerSenderQueue: 4, GlobalQueue: 16})
	q.nextSeq = math.MaxUint64

	maxEntry, _ := q.Admit("a", "c-max", 100, 100_000, rep(1, 32), true, 1, true, true, true)
	if !maxEntry.Admitted || maxEntry.Seq != math.MaxUint64 || !q.seqExhausted {
		t.Fatalf("MaxUint64 sequence admission/exhaustion failed: result=%+v exhausted=%v", maxEntry, q.seqExhausted)
	}
	if !esc.ReconcileUnusedCredit(RefundStatement{CreditID: "c-max", Owner: "a", RootCertifiedUnused: true}, q).Applied {
		t.Fatal("MaxUint64 pending entry could not be refunded and revoked")
	}
	if len(q.live) != 0 || esc.available["a"] != 2 {
		t.Fatalf("MaxUint64 refund left a live entry or lost credit: live=%d available=%d", len(q.live), esc.available["a"])
	}

	wrapped, _ := q.Admit("a", "c-next", 100, 100_000, rep(2, 32), true, 2, true, true, true)
	if wrapped.Admitted || wrapped.Code != "sequence_exhausted" {
		t.Fatalf("sequence counter wrapped after MaxUint64: %+v", wrapped)
	}
	if esc.available["a"] != 2 || len(q.live) != 0 {
		t.Fatalf("exhausted admission mutated credit or queue: available=%d live=%d", esc.available["a"], len(q.live))
	}
}
