package evmroot

import "encoding/json"

// D5 vector set: slashable vote domain, retirement/withdrawal gating, and
// forced-inbox credit accounting. Same builder feeds the golden test and
// cmd/d5vectors.

type D5VectorSet struct {
	VoteBinding    D5VoteBinding    `json:"vote_binding"`
	SlashConflicts []D5ConflictCase `json:"slashable_conflicts"`
	Protection     D5ProtectionCase `json:"protection_params"`
	Withdrawal     []D5WithdrawCase `json:"withdrawal_gates"`
	EvidenceTimely []D5EvidenceCase `json:"evidence_timeliness"`
	Inbox          D5InboxCase      `json:"forced_inbox"`
	KDerivation    []D5KCase        `json:"inclusion_bound_k"`
}

type D5VoteBinding struct {
	Note               string `json:"note"`
	VoteInfoHash       string `json:"vote_info_hash"`
	CommitBindsVote    bool   `json:"commit_binds_vote"`
	TamperedRejected   bool   `json:"tampered_commit_rejected"`
	NonCommittingBinds bool   `json:"non_committing_vote_still_binds_domain"`
	PreimageHex        string `json:"non_committing_preimage_hex"`
}

type D5ConflictCase struct {
	Name     string `json:"name"`
	Conflict bool   `json:"conflict"`
	Note     string `json:"note"`
}

type D5ProtectionCase struct {
	Params ProtectionParams `json:"params"`
	Valid  bool             `json:"valid"`
	Note   string           `json:"note"`
}

type D5WithdrawCase struct {
	Name                    string `json:"name"`
	Now                     uint64 `json:"now"`
	PositionCutoffSatisfied bool   `json:"position_cutoff_satisfied"`
	TimelyEvidence          bool   `json:"timely_evidence_pending"`
	Allowed                 bool   `json:"allowed"`
	Reason                  string `json:"reason,omitempty"`
}

type D5EvidenceCase struct {
	Name             string `json:"name"`
	OffenseRound     uint64 `json:"offense_round"`
	ExecRound        uint64 `json:"exec_round"`
	InboxCommitRound uint64 `json:"inbox_commit_round"`
	PayloadAvailable bool   `json:"payload_available"`
	Timely           bool   `json:"timely"`
}

type D5InboxCase struct {
	Note                        string         `json:"note"`
	DuplicateDepositRejected    bool           `json:"duplicate_certified_deposit_rejected"`
	AdmitWithoutCreditRejected  bool           `json:"admit_without_credit_rejected"`
	DoubleSpendRejected         bool           `json:"double_spend_of_credit_rejected"`
	HTTPAckIsNotEnqueue         bool           `json:"http_ack_is_not_an_enqueue_certificate"`
	Outcomes                    []EntryOutcome `json:"due_prefix_outcomes"`
	PoisonDoesNotStall          bool           `json:"poisoned_entry_does_not_stall_queue"`
	AckReleasesCapacity         bool           `json:"acknowledgement_releases_per_sender_capacity"`
	NoReExecutionAfterAck       bool           `json:"reprocess_after_ack_does_not_re_execute"`
	WatermarkAdvance            []bool         `json:"watermark_advance_results"` // first true, repeats false
	RefundWrongOwnerRejected    bool           `json:"refund_to_wrong_owner_rejected"`
	RefundConsumedEntryRejected bool           `json:"refund_of_certified_consumed_entry_rejected"`
	RefundReservedRejected      bool           `json:"refund_without_root_certification_rejected"`
	RefundRaceAppliedOnce       bool           `json:"refund_race_applied_at_most_once"`
	AdmitAfterRefundRejected    bool           `json:"admit_reusing_a_reconciled_credit_rejected"`
	RefundRevokesQueueEntry     bool           `json:"refund_permanently_revokes_the_pending_queue_entry"`
	RefundedBalanceBacksOne     bool           `json:"refunded_balance_backs_exactly_one_fresh_admission"`
	RefundNilQueueRejected      bool           `json:"refund_with_no_queue_rejected"`
	SponsorPathAdmits           bool           `json:"certified_sponsor_grant_lets_a_newcomer_admit"`
}

type D5KCase struct {
	Name                     string `json:"name"`
	MaxBacklogEntries        uint64 `json:"max_backlog_entries"`
	DeclaredGasLimit         uint64 `json:"declared_gas_limit"`
	GFI                      uint64 `json:"g_fi"`
	EntriesPerBlock          uint64 `json:"entries_per_block"`
	OriginObservationLag     uint64 `json:"origin_observation_lag_blocks"`
	RootRoundAllowanceBlocks uint64 `json:"root_round_allowance_blocks"`
	K                        uint64 `json:"k_produced_evm_blocks"`
	Note                     string `json:"note,omitempty"`
}

func BuildD5Vectors() D5VectorSet {
	var vs D5VectorSet

	// --- vote binding ---------------------------------------------------
	vi := VoteInfo{Network: 3, MessageDomain: "root-vote", VotingEpoch: 8, VotingRound: 442, ParentRound: 441, ExecStateHash: rep(0xEE, 32)}
	commit := LedgerCommitInfo{VoteInfoHash: hashSlice(vi.Hash()), CommitStateHash: rep(0xCC, 32), CommitRound: 300}
	tampered := LedgerCommitInfo{VoteInfoHash: rep(0x00, 32), CommitStateHash: rep(0xCC, 32), CommitRound: 300}
	nonCommitting := LedgerCommitInfo{VoteInfoHash: hashSlice(vi.Hash())} // empty commit fields
	vs.VoteBinding = D5VoteBinding{
		Note:               "LedgerCommitInfo binds VoteInfo iff its VoteInfoHash == H(CBOR(VoteInfo)); the signed preimage opens with the domain tag + network and binds the message domain even when commit fields are empty.",
		VoteInfoHash:       hx(hashSlice(vi.Hash())),
		CommitBindsVote:    commit.BindsVoteInfo(vi),
		TamperedRejected:   !tampered.BindsVoteInfo(vi),
		NonCommittingBinds: nonCommitting.BindsVoteInfo(vi),
		PreimageHex:        hx(SigningPreimage(vi, nonCommitting)),
	}

	// --- slashable conflicts -----------------------------------------------
	base := VoteStatement{AccountableKey: "val-7", Preimage: []byte("A"), Network: 3, MessageDomain: "root-vote", VotingEpoch: 8, VotingRound: 442}
	mk := func(f func(*VoteStatement)) VoteStatement { s := base; f(&s); return s }
	vs.SlashConflicts = []D5ConflictCase{
		{"double_sign_same_round", SlashableConflict(base, mk(func(s *VoteStatement) { s.Preimage = []byte("B") })),
			"same key/network/domain/epoch/round, different signed statements: the offense"},
		{"duplicate_delivery", SlashableConflict(base, mk(func(s *VoteStatement) {})),
			"identical preimage delivered twice: not two votes"},
		{"different_round", SlashableConflict(base, mk(func(s *VoteStatement) { s.Preimage = []byte("B"); s.VotingRound = 443 })),
			"different voting round: not this offense"},
		{"different_domain", SlashableConflict(base, mk(func(s *VoteStatement) { s.Preimage = []byte("B"); s.MessageDomain = "root-timeout" })),
			"different message domain: not this offense"},
		{"legacy_vote", SlashableConflict(base, mk(func(s *VoteStatement) { s.Preimage = []byte("B"); s.Legacy = true })),
			"legacy votes use their explicit legacy rules; never reinterpreted"},
	}

	// --- protection params ------------------------------------------------
	p := ProtectionParams{WCert: 50, DeltaEv: 100, DeltaIncl: 40, DeltaExec: 40, DeltaHold: 200}
	vs.Protection = D5ProtectionCase{Params: p, Valid: p.Valid(),
		Note: "W_cert <= Δ_ev < Δ_hold and Δ_hold > Δ_ev + Δ_incl + Δ_exec (200 > 100+40+40=180)"}

	// --- withdrawal gates ----------------------------------------------
	// LiabilityDeadlineRound is a root round; the linkage to inbox positions
	// is ForcedInbox.PositionCutoffSatisfied, exercised below and passed in
	// here as a bool so the two units never get compared directly.
	res := Reservation{Phase: Draining, RetirementRound: 1_000, LiabilityDeadlineRound: 1_050}
	mkW := func(name string, now uint64, cutoff, ev bool) D5WithdrawCase {
		wb := res.CanWithdraw(now, p, cutoff, ev)
		return D5WithdrawCase{Name: name, Now: now, PositionCutoffSatisfied: cutoff, TimelyEvidence: ev, Allowed: wb.Allowed, Reason: wb.Reason}
	}
	vs.Withdrawal = []D5WithdrawCase{
		mkW("protection_not_elapsed", 1_100, true, false), // < 1000+200
		mkW("position_cutoff_not_satisfied", 1_300, false, false),
		mkW("timely_evidence_pending", 1_300, true, true),
		mkW("all_gates_clear", 1_300, true, false),
	}

	// A concrete position-cutoff evaluation: two entries admitted in the
	// same root round 1_050, one still live -> cutoff not satisfied; after
	// both are certified-consumed -> satisfied. An earlier deadline with no
	// admitted entries -> trivially satisfied.
	cesc := NewCreditEscrow()
	cesc.ApplyDeposit(CertifiedDeposit{DepositID: "cd", Owner: "v", Amount: 5, Certified: true})
	cq := NewForcedInbox(cesc, AdmissionLimits{MaxEncodedBytes: 4096, GFI: 300_000, PerSenderQueue: 9, GlobalQueue: 16})
	cq.Admit("v", "k1", 10, 100_000, rep(1, 32), true, 1_050, true, true, true)
	cq.Admit("v", "k2", 10, 100_000, rep(2, 32), true, 1_050, true, true, true)
	cutoffBefore := cq.PositionCutoffSatisfied(1_050)
	emptyIntervalOK := cq.PositionCutoffSatisfied(1_049)
	cq.ProcessDuePrefix(nil)
	cq.AcknowledgeConsumption(0) // seq 0 only
	cutoffMid := cq.PositionCutoffSatisfied(1_050)
	cq.AcknowledgeConsumption(1) // seq 1 too
	cutoffAfter := cq.PositionCutoffSatisfied(1_050)
	vs.Withdrawal = append(vs.Withdrawal,
		D5WithdrawCase{Name: "cutoff_many_entries_one_root_round_before", PositionCutoffSatisfied: cutoffBefore},
		D5WithdrawCase{Name: "cutoff_empty_interval_trivially_ok", PositionCutoffSatisfied: emptyIntervalOK},
		D5WithdrawCase{Name: "cutoff_partial_ack_still_not_satisfied", PositionCutoffSatisfied: cutoffMid},
		D5WithdrawCase{Name: "cutoff_all_consumed_satisfied", PositionCutoffSatisfied: cutoffAfter},
	)

	// --- evidence timeliness -------------------------------------------
	vs.EvidenceTimely = []D5EvidenceCase{
		{"executed_in_window", 500, 560, 0, false, EvidenceTimely(500, 560, p, 0, false)},
		{"executed_late_no_inbox", 500, 900, 0, false, EvidenceTimely(500, 900, p, 0, false)},
		{"inbox_committed_in_window_then_late_exec", 500, 900, 540, true, EvidenceTimely(500, 900, p, 540, true)},
		{"inbox_hash_unavailable", 500, 900, 540, false, EvidenceTimely(500, 900, p, 540, false)},
	}

	// --- forced inbox --------------------------------------------------
	esc := NewCreditEscrow()
	esc.ApplyDeposit(CertifiedDeposit{DepositID: "dep-1", Owner: "alice", Amount: 3, Certified: true})
	dupDep := esc.ApplyDeposit(CertifiedDeposit{DepositID: "dep-1", Owner: "alice", Amount: 3, Certified: true})
	esc.ApplyDeposit(CertifiedDeposit{DepositID: "dep-2", Owner: "bob", Amount: 1, Certified: true})
	limits := AdmissionLimits{MaxEncodedBytes: 4096, GFI: 300_000, PerSenderQueue: 2, GlobalQueue: 16}
	q := NewForcedInbox(esc, limits)
	r1, cert1 := q.Admit("alice", "cr-a1", 1000, 100_000, rep(0xA1, 32), true, 10, true, true, true) // seq 0
	rDup, _ := q.Admit("alice", "cr-a1", 1000, 100_000, rep(0xA2, 32), true, 11, true, true, true)   // reuse credit id
	rNoCredit, _ := q.Admit("charlie", "cr-c1", 1000, 100_000, rep(0xC1, 32), true, 12, true, true, true)
	q.Admit("alice", "cr-a2", 1000, 100_000, rep(0xA3, 32), true, 13, true, true, true)             // seq 1 -> alice at PerSenderQueue=2
	rFull, _ := q.Admit("alice", "cr-a3", 1000, 100_000, rep(0xA4, 32), true, 14, true, true, true) // per_sender_queue_full
	q.Admit("bob", "cr-b1", 1000, 100_000, rep(0xB1, 32), true, 15, true, true, true)               // seq 2

	// process due prefix with entry seq 1 poisoned (nonce already used)
	outcomes := q.ProcessDuePrefix(map[uint64]PoisonKind{1: PoisonNonceUsed})
	poisonDoesNotStall := len(outcomes) == 3 && outcomes[1].Reason == string(PoisonNonceUsed) && outcomes[2].Executed

	// acknowledge seq 0..1: alice's live-queue occupancy drops from 2 to 0.
	capBeforeAck := q.AvailableCapacity("alice") // 0 (at PerSenderQueue)
	wm1 := q.AcknowledgeConsumption(1)
	capAfterAck := q.AvailableCapacity("alice") // 2 again — capacity released
	// reprocess after ack: seq 0 and 1 are certified-consumed -> AlreadyFinal, never re-executed.
	reOut := q.ProcessDuePrefix(nil)
	noReExec := true
	for _, o := range reOut {
		if (o.Seq == 0 || o.Seq == 1) && !o.AlreadyFinal {
			noReExec = false
		}
	}
	wmResults := []bool{wm1, q.AcknowledgeConsumption(1), q.AcknowledgeConsumption(0)}

	// refund provenance. cr-a2 (seq 1) was certified-consumed -> refund of it
	// is rejected. A fresh unconsumed-then-rolled-back credit is the refundable
	// case: admit cr-x, then a root-certified reconciliation before it is
	// acknowledged.
	esc.ApplyDeposit(CertifiedDeposit{DepositID: "dep-x", Owner: "alice", Amount: 1, Certified: true})
	q.Admit("alice", "cr-x", 1000, 100_000, rep(0xAA, 32), true, 20, true, true, true) // seq 3, not acknowledged
	refundWrongOwner := esc.ReconcileUnusedCredit(RefundStatement{CreditID: "cr-x", Owner: "mallory", RootCertifiedUnused: true}, q)
	refundNoCert := esc.ReconcileUnusedCredit(RefundStatement{CreditID: "cr-x", Owner: "alice", RootCertifiedUnused: false}, q)
	refundConsumed := esc.ReconcileUnusedCredit(RefundStatement{CreditID: "cr-a2", Owner: "alice", RootCertifiedUnused: true}, q)
	refund1 := esc.ReconcileUnusedCredit(RefundStatement{CreditID: "cr-x", Owner: "alice", RootCertifiedUnused: true}, q)
	refund2 := esc.ReconcileUnusedCredit(RefundStatement{CreditID: "cr-x", Owner: "alice", RootCertifiedUnused: true}, q)
	admitAfterRefund, _ := q.Admit("alice", "cr-x", 1000, 100_000, rep(0xAB, 32), true, 21, true, true, true)

	// The refund and the admission rollback are one transition: cr-x's
	// pending entry (seq 3) is permanently revoked, so a later
	// ProcessDuePrefix never executes it. The restored balance backs
	// exactly one fresh admission (cr-x2), not a second copy of seq 3.
	revokedGone := true
	for _, e := range q.live {
		if e.CreditID == "cr-x" {
			revokedGone = false
		}
	}
	freshAdmit, _ := q.Admit("alice", "cr-x2", 1000, 100_000, rep(0xAC, 32), true, 22, true, true, true)
	reAfterRefund := q.ProcessDuePrefix(nil)
	revokedNeverExecutes := true
	for _, o := range reAfterRefund {
		if o.Seq == 3 {
			revokedNeverExecutes = false
		}
	}
	// A reconciliation with no queue to roll back is refused outright.
	refundNilQueue := esc.ReconcileUnusedCredit(RefundStatement{CreditID: "cr-x2", Owner: "alice", RootCertifiedUnused: true}, nil)

	// sponsor path: a newcomer with no credits is funded by a certified grant.
	sesc := NewCreditEscrow()
	sesc.ApplyDeposit(CertifiedDeposit{DepositID: "sd", Owner: "sponsor", Amount: 2, Certified: true})
	sesc.GrantSponsoredCredit(SponsorGrant{GrantID: "g1", Sponsor: "sponsor", Recipient: "newbie", Amount: 1, Certified: true})
	sq := NewForcedInbox(sesc, limits)
	sponsorAdmit, _ := sq.Admit("newbie", "cr-n1", 100, 100_000, rep(0x4E, 32), true, 30, true, true, true)

	vs.Inbox = D5InboxCase{
		Note:                        "Authenticated certified deposits (dedup on certified DepositID); unique credit minted+consumed per admission; a three-state entry lifecycle (pending -> tentatively executed -> certified-consumed+archived) that releases queue capacity; a refund is the certified admission rollback and the credit return as ONE transition — it needs the queue, permanently revokes the still-pending entry (matched on seq AND creditID), and returns the credit at most once; a tentatively-executed or certified-consumed entry is not refundable.",
		DuplicateDepositRejected:    !dupDep.Applied,
		AdmitWithoutCreditRejected:  rNoCredit.Code == "no_credit",
		DoubleSpendRejected:         rDup.Code == "credit_already_consumed",
		HTTPAckIsNotEnqueue:         r1.Admitted && cert1 != nil && rFull.Code == "per_sender_queue_full",
		Outcomes:                    outcomes,
		PoisonDoesNotStall:          poisonDoesNotStall,
		AckReleasesCapacity:         capBeforeAck == 0 && capAfterAck == 2,
		NoReExecutionAfterAck:       noReExec,
		WatermarkAdvance:            wmResults,
		RefundWrongOwnerRejected:    !refundWrongOwner.Applied,
		RefundConsumedEntryRejected: !refundConsumed.Applied,
		RefundReservedRejected:      !refundNoCert.Applied,
		RefundRaceAppliedOnce:       refund1.Applied && !refund2.Applied,
		AdmitAfterRefundRejected:    admitAfterRefund.Code == "credit_already_reconciled",
		RefundRevokesQueueEntry:     revokedGone && revokedNeverExecutes,
		RefundedBalanceBacksOne:     freshAdmit.Admitted,
		RefundNilQueueRejected:      !refundNilQueue.Applied,
		SponsorPathAdmits:           sponsorAdmit.Admitted && SponsorPathAvailable(),
	}

	// --- K derivation (entry-count / fragmentation aware) ----------------
	for _, k := range []D5KCase{
		{Name: "adversarial_indivisible_packing", MaxBacklogEntries: 2, DeclaredGasLimit: 60, GFI: 100, OriginObservationLag: 0, RootRoundAllowanceBlocks: 0,
			Note: "3 entries of 60 gas, g_fi 100: only one fits per block -> K = ceil((2+1)/1) = 3"},
		{Name: "half_target_two_per_block", MaxBacklogEntries: 9, DeclaredGasLimit: 150_000, GFI: 300_000, OriginObservationLag: 2, RootRoundAllowanceBlocks: 3,
			Note: "entriesPerBlock = 2 -> ceil(10/2) = 5, +2 lag +3 allowance = 10"},
		{Name: "empty_backlog", MaxBacklogEntries: 0, DeclaredGasLimit: 300_000, GFI: 300_000, OriginObservationLag: 1, RootRoundAllowanceBlocks: 0,
			Note: "just the entry itself -> 1, +1 lag = 2"},
	} {
		epb := k.GFI / k.DeclaredGasLimit
		if epb == 0 {
			epb = 1
		}
		k.EntriesPerBlock = epb
		k.K = InclusionBoundK(k.MaxBacklogEntries, k.DeclaredGasLimit, k.GFI, k.OriginObservationLag, k.RootRoundAllowanceBlocks)
		vs.KDerivation = append(vs.KDerivation, k)
	}

	return vs
}

func MarshalD5Vectors(vs D5VectorSet) ([]byte, error) {
	b, err := json.MarshalIndent(vs, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
