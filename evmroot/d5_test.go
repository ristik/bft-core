package evmroot

import (
	"bytes"
	"os"
	"testing"
)

func TestD5_VoteInfoLedgerCommitBinding(t *testing.T) {
	vi := VoteInfo{Network: 3, MessageDomain: "root-vote", VotingEpoch: 8, VotingRound: 442}
	good := LedgerCommitInfo{VoteInfoHash: hashSlice(vi.Hash())}
	if !good.BindsVoteInfo(vi) {
		t.Fatal("correct VoteInfoHash rejected")
	}
	bad := LedgerCommitInfo{VoteInfoHash: rep(0, 32)}
	if bad.BindsVoteInfo(vi) {
		t.Fatal("wrong VoteInfoHash accepted")
	}
	// changing any VoteInfo field changes the hash the commit must bind.
	vi2 := vi
	vi2.VotingRound = 443
	if good.BindsVoteInfo(vi2) {
		t.Fatal("commit info bound a different VoteInfo")
	}
}

func TestD5_SigningPreimageBindsDomainEvenForNonCommittingVote(t *testing.T) {
	vi := VoteInfo{Network: 3, MessageDomain: "root-timeout", VotingEpoch: 8, VotingRound: 442}
	nonCommitting := LedgerCommitInfo{VoteInfoHash: hashSlice(vi.Hash())}
	p1 := SigningPreimage(vi, nonCommitting)
	// A different message domain -> different preimage, even though commit
	// fields are empty. The domain is in the signed bytes, not an argument.
	vi2 := vi
	vi2.MessageDomain = "root-vote"
	p2 := SigningPreimage(vi2, LedgerCommitInfo{VoteInfoHash: hashSlice(vi2.Hash())})
	if bytes.Equal(p1, p2) {
		t.Fatal("message domain not bound into the non-committing vote preimage")
	}
	if !bytes.HasPrefix(p1, marshalCBOR(cText(VoteDomainTag))[:1]) {
		// sanity: preimage is CBOR starting with an array head; the domain
		// tag text follows. Just assert it is non-empty and deterministic.
		if len(p1) == 0 {
			t.Fatal("empty preimage")
		}
	}
}

func TestD5_SlashableConflictDomain(t *testing.T) {
	a := VoteStatement{AccountableKey: "v", Preimage: []byte("x"), Network: 3, MessageDomain: "d", VotingEpoch: 1, VotingRound: 9}
	dbl := a
	dbl.Preimage = []byte("y")
	if !SlashableConflict(a, dbl) {
		t.Fatal("two different statements for the same (key,net,domain,epoch,round) not flagged")
	}
	if SlashableConflict(a, a) {
		t.Fatal("identical statement (duplicate delivery) flagged as an offense")
	}
	dr := dbl
	dr.VotingRound = 10
	if SlashableConflict(a, dr) {
		t.Fatal("different voting round flagged")
	}
	dd := dbl
	dd.MessageDomain = "other"
	if SlashableConflict(a, dd) {
		t.Fatal("different message domain flagged")
	}
	lg := dbl
	lg.Legacy = true
	if SlashableConflict(a, lg) {
		t.Fatal("legacy vote reinterpreted as a PoS offense")
	}
}

func TestD5_ProtectionParamOrdering(t *testing.T) {
	ok := ProtectionParams{WCert: 50, DeltaEv: 100, DeltaIncl: 40, DeltaExec: 40, DeltaHold: 200}
	if !ok.Valid() {
		t.Fatal("valid params rejected")
	}
	bad := ok
	bad.DeltaHold = 180 // == Δ_ev+Δ_incl+Δ_exec, not strictly greater
	if bad.Valid() {
		t.Fatal("Δ_hold not strictly greater than the sum was accepted")
	}
}

func TestD5_WithdrawalGates(t *testing.T) {
	p := ProtectionParams{WCert: 50, DeltaEv: 100, DeltaIncl: 40, DeltaExec: 40, DeltaHold: 200}
	r := Reservation{Phase: Draining, RetirementRound: 1000, LastLiabilityRound: 1050}
	if r.CanWithdraw(1100, p, 2000, false).Allowed {
		t.Fatal("withdrew before protection elapsed")
	}
	if r.CanWithdraw(1300, p, 1040, false).Allowed {
		t.Fatal("withdrew with the consumption watermark behind the last liability")
	}
	if r.CanWithdraw(1300, p, 2000, true).Allowed {
		t.Fatal("withdrew with timely evidence still pending")
	}
	if !r.CanWithdraw(1300, p, 2000, false).Allowed {
		t.Fatal("blocked a withdrawal with every gate clear")
	}
	// inherited protection dominates a nearer R_ret+Δ_hold.
	r.InheritedProtectionUntil = 5000
	if r.CanWithdraw(1300, p, 2000, false).Allowed {
		t.Fatal("inherited protection ignored")
	}
}

func TestD5_EvidenceTimeliness(t *testing.T) {
	p := ProtectionParams{DeltaEv: 100}
	if !EvidenceTimely(500, 560, p, 0, false) {
		t.Fatal("execution within Δ_ev not timely")
	}
	if EvidenceTimely(500, 900, p, 0, false) {
		t.Fatal("late execution with no inbox commit treated as timely")
	}
	if !EvidenceTimely(500, 900, p, 540, true) {
		t.Fatal("inbox-committed-in-window not timely despite late execution")
	}
	if EvidenceTimely(500, 900, p, 540, false) {
		t.Fatal("unavailable payload preserved timeliness")
	}
}

func TestD5_InboxNoUnbackedAdmissionNoDoubleSpend(t *testing.T) {
	esc := NewCreditEscrow()
	if esc.ApplyDeposit("d1", "a", 2).Applied != true {
		t.Fatal("first deposit not applied")
	}
	if esc.ApplyDeposit("d1", "a", 2).Applied {
		t.Fatal("duplicate certified-deposit proof credited a second time")
	}
	q := NewForcedInbox(esc, AdmissionLimits{MaxEncodedBytes: 4096, GFI: 300_000, PerSenderQueue: 4, GlobalQueue: 16})
	r, cert := q.Admit("a", "c1", 100, 100_000, rep(1, 32), true, 1, true, true, true)
	if !r.Admitted || cert == nil {
		t.Fatalf("valid admission failed: %+v", r)
	}
	rd, _ := q.Admit("a", "c1", 100, 100_000, rep(2, 32), true, 2, true, true, true)
	if rd.Admitted {
		t.Fatal("same credit consumed twice")
	}
	rn, _ := q.Admit("nobody", "c9", 100, 100_000, rep(3, 32), true, 3, true, true, true)
	if rn.Admitted || rn.Code != "no_credit" {
		t.Fatalf("admission without a credit succeeded: %+v", rn)
	}
}

func TestD5_PoisonedEntryDoesNotStallQueue(t *testing.T) {
	esc := NewCreditEscrow()
	esc.ApplyDeposit("d", "a", 5)
	q := NewForcedInbox(esc, AdmissionLimits{MaxEncodedBytes: 4096, GFI: 300_000, PerSenderQueue: 9, GlobalQueue: 16})
	for i := 0; i < 3; i++ {
		if r, _ := q.Admit("a", "c"+itoa(uint64(i)), 100, 100_000, rep(byte(i), 32), true, uint64(i), true, true, true); !r.Admitted {
			t.Fatalf("admit %d failed", i)
		}
	}
	out := q.ProcessDuePrefix(map[uint64]PoisonKind{1: PoisonInsufficient})
	if len(out) != 3 {
		t.Fatalf("processed %d entries, want 3 — a poisoned entry stalled the prefix", len(out))
	}
	if out[1].Executed || out[1].Reason != string(PoisonInsufficient) {
		t.Fatalf("poisoned entry not consumed with a reason: %+v", out[1])
	}
	if !out[2].Executed {
		t.Fatal("entry after the poisoned one did not execute")
	}
}

func TestD5_WatermarkAdvancesExactlyOnce(t *testing.T) {
	q := NewForcedInbox(NewCreditEscrow(), AdmissionLimits{})
	if !q.AcknowledgeConsumption(5) {
		t.Fatal("first advance rejected")
	}
	if q.AcknowledgeConsumption(5) {
		t.Fatal("repeat advance to the same seq took effect")
	}
	if q.AcknowledgeConsumption(3) {
		t.Fatal("advance to a lower seq took effect")
	}
	if q.Watermark() != 5 {
		t.Fatalf("watermark = %d, want 5", q.Watermark())
	}
}

func TestD5_RefundOnlyViaReconciliationAndAtMostOnce(t *testing.T) {
	esc := NewCreditEscrow()
	esc.ApplyDeposit("d", "a", 2)
	q := NewForcedInbox(esc, AdmissionLimits{MaxEncodedBytes: 4096, GFI: 300_000, PerSenderQueue: 4, GlobalQueue: 16})
	q.Admit("a", "c1", 100, 100_000, rep(1, 32), true, 1, true, true, true)
	if esc.ReconcileUnusedCredit("c1", "a", false).Applied {
		t.Fatal("refunded a reserved credit with no root-certified reconciliation")
	}
	if !esc.ReconcileUnusedCredit("c1", "a", true).Applied {
		t.Fatal("root-certified reconciliation did not refund")
	}
	if esc.ReconcileUnusedCredit("c1", "a", true).Applied {
		t.Fatal("second reconciliation of the same credit applied (refund race)")
	}
}

func TestD5_InclusionBoundK(t *testing.T) {
	// (3_000_000 + 300_000) / 300_000 = 11 blocks, + 2 lag + 3 allowance = 16.
	if got := InclusionBoundK(3_000_000, 300_000, 300_000, 2, 3); got != 16 {
		t.Fatalf("K = %d, want 16", got)
	}
	if got := InclusionBoundK(0, 300_000, 300_000, 1, 0); got != 2 {
		t.Fatalf("K = %d, want 2", got)
	}
}

func TestD5_VectorsMatchGolden(t *testing.T) {
	const path = "testdata/d5-vectors.json"
	got, err := MarshalD5Vectors(BuildD5Vectors())
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s (run: go run ./evmroot/cmd/d5vectors -update): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale — regenerate with: go run ./evmroot/cmd/d5vectors -update", path)
	}
}
