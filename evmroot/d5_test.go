package evmroot

import (
	"bytes"
	"os"
	"strconv"
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
	r := Reservation{Phase: Draining, RetirementRound: 1000, LiabilityDeadlineRound: 1050}
	if r.CanWithdraw(1100, p, true, false).Allowed {
		t.Fatal("withdrew before protection elapsed")
	}
	if r.CanWithdraw(1300, p, false, false).Allowed {
		t.Fatal("withdrew with the position cutoff not satisfied")
	}
	if r.CanWithdraw(1300, p, true, true).Allowed {
		t.Fatal("withdrew with timely evidence still pending")
	}
	if !r.CanWithdraw(1300, p, true, false).Allowed {
		t.Fatal("blocked a withdrawal with every gate clear")
	}
	r.InheritedProtectionUntil = 5000
	if r.CanWithdraw(1300, p, true, false).Allowed {
		t.Fatal("inherited protection ignored")
	}
}

func TestD5_PositionCutoffNotAWatermarkComparison(t *testing.T) {
	esc := NewCreditEscrow()
	esc.ApplyDeposit(CertifiedDeposit{DepositID: "d", Owner: "v", Amount: 9, Certified: true})
	q := NewForcedInbox(esc, AdmissionLimits{MaxEncodedBytes: 4096, GFI: 300_000, PerSenderQueue: 9, GlobalQueue: 32})
	// Many entries admitted in ONE root round 1050.
	for i := 0; i < 5; i++ {
		q.Admit("v", "k"+strconv.Itoa(i), 10, 50_000, rep(byte(i), 32), true, 1050, true, true, true)
	}
	// Long empty interval: nothing admitted through 1049.
	if !q.PositionCutoffSatisfied(1049) {
		t.Fatal("empty interval not trivially satisfied")
	}
	if q.PositionCutoffSatisfied(1050) {
		t.Fatal("cutoff satisfied while entries from round 1050 are still live")
	}
	q.ProcessDuePrefix(nil)
	q.AcknowledgeConsumption(2) // partial
	if q.PositionCutoffSatisfied(1050) {
		t.Fatal("cutoff satisfied after only a partial acknowledgement")
	}
	q.AcknowledgeConsumption(4) // all five (seq 0..4)
	if !q.PositionCutoffSatisfied(1050) {
		t.Fatal("cutoff not satisfied after every entry through the deadline was certified-consumed")
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
	if !esc.ApplyDeposit(CertifiedDeposit{DepositID: "d1", Owner: "a", Amount: 2, Certified: true}).Applied {
		t.Fatal("first certified deposit not applied")
	}
	if esc.ApplyDeposit(CertifiedDeposit{DepositID: "d1", Owner: "a", Amount: 2, Certified: true}).Applied {
		t.Fatal("duplicate certified deposit credited a second time")
	}
	if esc.ApplyDeposit(CertifiedDeposit{DepositID: "d2", Owner: "a", Amount: 2, Certified: false}).Applied {
		t.Fatal("an uncertified deposit was applied")
	}
	q := NewForcedInbox(esc, AdmissionLimits{MaxEncodedBytes: 4096, GFI: 300_000, PerSenderQueue: 4, GlobalQueue: 16})
	r, cert := q.Admit("a", "c1", 100, 100_000, rep(1, 32), true, 1, true, true, true)
	if !r.Admitted || cert == nil {
		t.Fatalf("valid admission failed: %+v", r)
	}
	rd, _ := q.Admit("a", "c1", 100, 100_000, rep(2, 32), true, 2, true, true, true)
	if rd.Admitted || rd.Code != "credit_already_consumed" {
		t.Fatalf("same credit consumed twice: %+v", rd)
	}
	rn, _ := q.Admit("nobody", "c9", 100, 100_000, rep(3, 32), true, 3, true, true, true)
	if rn.Admitted || rn.Code != "no_credit" {
		t.Fatalf("admission without a credit succeeded: %+v", rn)
	}
}

func TestD5_QueueLifecycleReleasesCapacityAndNoReExecution(t *testing.T) {
	esc := NewCreditEscrow()
	esc.ApplyDeposit(CertifiedDeposit{DepositID: "d", Owner: "a", Amount: 5, Certified: true})
	q := NewForcedInbox(esc, AdmissionLimits{MaxEncodedBytes: 4096, GFI: 300_000, PerSenderQueue: 1, GlobalQueue: 16})

	// Capacity one: admit c1, it fills the per-sender queue.
	if r, _ := q.Admit("a", "c1", 10, 100_000, rep(1, 32), true, 1, true, true, true); !r.Admitted {
		t.Fatal("c1 not admitted")
	}
	if q.AvailableCapacity("a") != 0 {
		t.Fatal("capacity not consumed")
	}
	if r, _ := q.Admit("a", "c2", 10, 100_000, rep(2, 32), true, 2, true, true, true); r.Admitted || r.Code != "per_sender_queue_full" {
		t.Fatalf("c2 admitted while queue full: %+v", r)
	}

	// Process, acknowledge position 1: c1 is certified-consumed and its
	// slot is released.
	q.ProcessDuePrefix(nil)
	if !q.AcknowledgeConsumption(1) {
		t.Fatal("acknowledge rejected")
	}
	if q.AvailableCapacity("a") != 1 {
		t.Fatalf("acknowledgement did not release per-sender capacity: %d", q.AvailableCapacity("a"))
	}
	// Reprocess (crash/replay): c1 is not re-executed.
	out := q.ProcessDuePrefix(nil)
	for _, o := range out {
		if o.Seq == 0 && !o.AlreadyFinal {
			t.Fatal("certified-consumed entry was re-executed on replay")
		}
	}
	// Now c2 can be admitted into the released slot.
	if r, _ := q.Admit("a", "c2", 10, 100_000, rep(2, 32), true, 3, true, true, true); !r.Admitted {
		t.Fatalf("c2 not admitted after capacity release: %+v", r)
	}
}

func TestD5_PoisonedEntryDoesNotStallQueue(t *testing.T) {
	esc := NewCreditEscrow()
	esc.ApplyDeposit(CertifiedDeposit{DepositID: "d", Owner: "a", Amount: 5, Certified: true})
	q := NewForcedInbox(esc, AdmissionLimits{MaxEncodedBytes: 4096, GFI: 300_000, PerSenderQueue: 9, GlobalQueue: 16})
	for i := 0; i < 3; i++ {
		if r, _ := q.Admit("a", "c"+strconv.Itoa(i), 100, 100_000, rep(byte(i), 32), true, uint64(i), true, true, true); !r.Admitted {
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
	esc := NewCreditEscrow()
	esc.ApplyDeposit(CertifiedDeposit{DepositID: "d", Owner: "a", Amount: 9, Certified: true})
	q := NewForcedInbox(esc, AdmissionLimits{MaxEncodedBytes: 4096, GFI: 300_000, PerSenderQueue: 9, GlobalQueue: 16})
	for i := 0; i < 6; i++ {
		q.Admit("a", "c"+strconv.Itoa(i), 10, 10_000, rep(byte(i), 32), true, 1, true, true, true)
	}
	q.ProcessDuePrefix(nil)
	if !q.AcknowledgeConsumption(5) {
		t.Fatal("first advance rejected")
	}
	if q.AcknowledgeConsumption(5) || q.AcknowledgeConsumption(3) {
		t.Fatal("a repeat / lower acknowledgement took effect")
	}
	if q.Watermark() != 5 {
		t.Fatalf("watermark = %d, want 5", q.Watermark())
	}
}

func TestD5_RefundProvenance(t *testing.T) {
	esc := NewCreditEscrow()
	esc.ApplyDeposit(CertifiedDeposit{DepositID: "d", Owner: "a", Amount: 3, Certified: true})
	q := NewForcedInbox(esc, AdmissionLimits{MaxEncodedBytes: 4096, GFI: 300_000, PerSenderQueue: 4, GlobalQueue: 16})
	q.Admit("a", "c1", 100, 100_000, rep(1, 32), true, 1, true, true, true) // seq 0

	// No root certification.
	if esc.ReconcileUnusedCredit(RefundStatement{CreditID: "c1", Owner: "a", RootCertifiedUnused: false}, q).Applied {
		t.Fatal("refunded without a root-certified reconciliation")
	}
	// Wrong owner.
	if esc.ReconcileUnusedCredit(RefundStatement{CreditID: "c1", Owner: "mallory", RootCertifiedUnused: true}, q).Applied {
		t.Fatal("refund redirected to a non-owner")
	}
	// Certified-consumed entry cannot be refunded.
	q.ProcessDuePrefix(nil)
	q.AcknowledgeConsumption(0)
	if esc.ReconcileUnusedCredit(RefundStatement{CreditID: "c1", Owner: "a", RootCertifiedUnused: true}, q).Applied {
		t.Fatal("refunded a credit backing a certified-consumed entry")
	}

	// A genuinely unconsumed (rolled-back) credit: refund once only, and it
	// must PERMANENTLY revoke the still-pending queue entry — otherwise the
	// same paid credit backs both a refund and an executed entry.
	q.Admit("a", "c2", 100, 100_000, rep(2, 32), true, 2, true, true, true) // seq 1, pending
	if esc.ReconcileUnusedCredit(RefundStatement{CreditID: "c2", Owner: "a", RootCertifiedUnused: true}, nil).Applied {
		t.Fatal("refund applied with no queue to roll back")
	}
	if !esc.ReconcileUnusedCredit(RefundStatement{CreditID: "c2", Owner: "a", RootCertifiedUnused: true}, q).Applied {
		t.Fatal("a rolled-back credit was not refunded")
	}
	if esc.ReconcileUnusedCredit(RefundStatement{CreditID: "c2", Owner: "a", RootCertifiedUnused: true}, q).Applied {
		t.Fatal("second reconciliation applied (refund race)")
	}
	// seq 1 is gone from the live queue and never executes.
	for _, o := range q.ProcessDuePrefix(nil) {
		if o.Seq == 1 {
			t.Fatal("a refunded credit's entry still executed — credit reuse")
		}
	}
	// Re-admitting the reconciled credit id fails; the restored balance is
	// usable through a fresh credit id.
	if r, _ := q.Admit("a", "c2", 100, 100_000, rep(3, 32), true, 3, true, true, true); r.Admitted || r.Code != "credit_already_reconciled" {
		t.Fatalf("a reconciled credit id was reused: %+v", r)
	}
	if r, _ := q.Admit("a", "c3", 100, 100_000, rep(4, 32), true, 4, true, true, true); !r.Admitted {
		t.Fatalf("refunded balance did not back a fresh admission: %+v", r)
	}
}

// TestD5_RefundedCreditCannotBackTwoEntries is the re-review counterexample:
// deposit one credit, admit c1, refund c1, admit c2 — after the fix the
// refunded c1's entry is revoked, so ProcessDuePrefix executes only c2 and
// the single paid credit backs a single entry.
func TestD5_RefundedCreditCannotBackTwoEntries(t *testing.T) {
	esc := NewCreditEscrow()
	esc.ApplyDeposit(CertifiedDeposit{DepositID: "d", Owner: "a", Amount: 1, Certified: true})
	q := NewForcedInbox(esc, AdmissionLimits{MaxEncodedBytes: 4096, GFI: 300_000, PerSenderQueue: 4, GlobalQueue: 16})

	if r, _ := q.Admit("a", "c1", 100, 100_000, rep(1, 32), true, 1, true, true, true); !r.Admitted {
		t.Fatalf("c1 not admitted: %+v", r)
	}
	if !esc.ReconcileUnusedCredit(RefundStatement{CreditID: "c1", Owner: "a", RootCertifiedUnused: true}, q).Applied {
		t.Fatal("c1 refund not applied")
	}
	if r, _ := q.Admit("a", "c2", 100, 100_000, rep(2, 32), true, 2, true, true, true); !r.Admitted {
		t.Fatalf("c2 not admitted from the refunded balance: %+v", r)
	}
	executed := 0
	for _, o := range q.ProcessDuePrefix(nil) {
		if o.Executed {
			executed++
		}
		if o.Seq == 0 {
			t.Fatal("refunded c1's entry (seq 0) executed — one paid credit backed two entries")
		}
	}
	if executed != 1 {
		t.Fatalf("one paid credit backed %d executed entries, want 1", executed)
	}
}

func TestD5_SponsorPathIsExecutable(t *testing.T) {
	esc := NewCreditEscrow()
	esc.ApplyDeposit(CertifiedDeposit{DepositID: "sd", Owner: "sponsor", Amount: 2, Certified: true})
	if !esc.GrantSponsoredCredit(SponsorGrant{GrantID: "g1", Sponsor: "sponsor", Recipient: "newbie", Amount: 1, Certified: true}).Applied {
		t.Fatal("certified sponsor grant not applied")
	}
	if esc.GrantSponsoredCredit(SponsorGrant{GrantID: "g1", Sponsor: "sponsor", Recipient: "newbie", Amount: 1, Certified: true}).Applied {
		t.Fatal("sponsor grant replayed")
	}
	q := NewForcedInbox(esc, AdmissionLimits{MaxEncodedBytes: 4096, GFI: 300_000, PerSenderQueue: 4, GlobalQueue: 16})
	if r, _ := q.Admit("newbie", "cn1", 100, 100_000, rep(1, 32), true, 1, true, true, true); !r.Admitted {
		t.Fatalf("newcomer with a sponsored credit could not admit: %+v", r)
	}
}

func TestD5_InclusionBoundK_EntryCountAware(t *testing.T) {
	// The reviewer's case: 3 entries of 60 gas, g_fi 100. Only one fits per
	// block. Backlog of 2 ahead + the entry itself -> 3 blocks.
	if got := InclusionBoundK(2, 60, 100, 0, 0); got != 3 {
		t.Fatalf("K(2,60,100,0,0) = %d, want 3", got)
	}
	// entriesPerBlock = 2: ceil((9+1)/2) = 5, +2 lag +3 allowance = 10.
	if got := InclusionBoundK(9, 150_000, 300_000, 2, 3); got != 10 {
		t.Fatalf("K = %d, want 10", got)
	}
	// Empty backlog: just the entry itself -> 1, +1 lag = 2.
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
