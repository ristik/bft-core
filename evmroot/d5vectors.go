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
	Name           string `json:"name"`
	Now            uint64 `json:"now"`
	InboxWatermark uint64 `json:"inbox_watermark"`
	TimelyEvidence bool   `json:"timely_evidence_pending"`
	Allowed        bool   `json:"allowed"`
	Reason         string `json:"reason,omitempty"`
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
	Note                       string         `json:"note"`
	DuplicateDepositRejected   bool           `json:"duplicate_deposit_rejected"`
	AdmitWithoutCreditRejected bool           `json:"admit_without_credit_rejected"`
	DoubleSpendRejected        bool           `json:"double_spend_of_credit_rejected"`
	HTTPAckIsNotEnqueue        bool           `json:"http_ack_is_not_an_enqueue_certificate"`
	Outcomes                   []EntryOutcome `json:"due_prefix_outcomes"`
	PoisonDoesNotStall         bool           `json:"poisoned_entry_does_not_stall_queue"`
	WatermarkAdvance           []bool         `json:"watermark_advance_results"` // first true, repeats false
	RefundReservedRejected     bool           `json:"refund_of_reserved_credit_rejected"`
	RefundRaceAppliedOnce      bool           `json:"refund_race_applied_at_most_once"`
}

type D5KCase struct {
	MaxBacklogGas            uint64 `json:"max_backlog_gas"`
	DeclaredGasLimit         uint64 `json:"declared_gas_limit"`
	GFI                      uint64 `json:"g_fi"`
	OriginObservationLag     uint64 `json:"origin_observation_lag_blocks"`
	RootRoundAllowanceBlocks uint64 `json:"root_round_allowance_blocks"`
	K                        uint64 `json:"k"`
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
	res := Reservation{Phase: Draining, RetirementRound: 1_000, LastLiabilityRound: 1_050}
	mkW := func(name string, now, wm uint64, ev bool) D5WithdrawCase {
		wb := res.CanWithdraw(now, p, wm, ev)
		return D5WithdrawCase{Name: name, Now: now, InboxWatermark: wm, TimelyEvidence: ev, Allowed: wb.Allowed, Reason: wb.Reason}
	}
	vs.Withdrawal = []D5WithdrawCase{
		mkW("protection_not_elapsed", 1_100, 2_000, false),     // < 1000+200
		mkW("watermark_behind_liability", 1_300, 1_040, false), // wm 1040 < 1050
		mkW("timely_evidence_pending", 1_300, 2_000, true),
		mkW("all_gates_clear", 1_300, 2_000, false),
	}

	// --- evidence timeliness -------------------------------------------
	vs.EvidenceTimely = []D5EvidenceCase{
		{"executed_in_window", 500, 560, 0, false, EvidenceTimely(500, 560, p, 0, false)},
		{"executed_late_no_inbox", 500, 900, 0, false, EvidenceTimely(500, 900, p, 0, false)},
		{"inbox_committed_in_window_then_late_exec", 500, 900, 540, true, EvidenceTimely(500, 900, p, 540, true)},
		{"inbox_hash_unavailable", 500, 900, 540, false, EvidenceTimely(500, 900, p, 540, false)},
	}

	// --- forced inbox --------------------------------------------------
	esc := NewCreditEscrow()
	esc.ApplyDeposit("dep-1", "alice", 3)
	dupDep := esc.ApplyDeposit("dep-1", "alice", 3)
	esc.ApplyDeposit("dep-2", "bob", 1)
	limits := AdmissionLimits{MaxEncodedBytes: 4096, GFI: 300_000, PerSenderQueue: 4, GlobalQueue: 16}
	q := NewForcedInbox(esc, limits)
	r1, cert1 := q.Admit("alice", "cr-a1", 1000, 100_000, rep(0xA1, 32), true, 10, true, true, true)
	// double spend: reuse cr-a1
	rDup, _ := q.Admit("alice", "cr-a1", 1000, 100_000, rep(0xA2, 32), true, 11, true, true, true)
	// no credit: charlie never deposited
	rNoCredit, _ := q.Admit("charlie", "cr-c1", 1000, 100_000, rep(0xC1, 32), true, 12, true, true, true)
	q.Admit("alice", "cr-a2", 1000, 100_000, rep(0xA3, 32), true, 13, true, true, true)
	q.Admit("bob", "cr-b1", 1000, 100_000, rep(0xB1, 32), true, 14, true, true, true)
	// process due prefix with entry seq 1 poisoned (nonce already used)
	outcomes := q.ProcessDuePrefix(map[uint64]PoisonKind{1: PoisonNonceUsed})
	poisonDoesNotStall := len(outcomes) == 3 && outcomes[1].Reason == string(PoisonNonceUsed) && outcomes[2].Executed
	// watermark advance
	wmResults := []bool{q.AcknowledgeConsumption(3), q.AcknowledgeConsumption(3), q.AcknowledgeConsumption(2)}
	// refund of a reserved (consumed) credit without root-certified reconciliation
	refundReserved := esc.ReconcileUnusedCredit("cr-a1", "alice", false)
	// refund race: two reconciliations of the same credit, only the first applies
	refund1 := esc.ReconcileUnusedCredit("cr-a2", "alice", true)
	refund2 := esc.ReconcileUnusedCredit("cr-a2", "alice", true)

	vs.Inbox = D5InboxCase{
		Note:                       "Prepaid UCT credits in an immutable escrow; unique credit consumed in root consensus; refunds only via root-certified reconciliation of unused credits.",
		DuplicateDepositRejected:   !dupDep.Applied,
		AdmitWithoutCreditRejected: rNoCredit.Code == "no_credit",
		DoubleSpendRejected:        rDup.Code == "credit_already_consumed" || rDup.Code == "credit_already_reserved",
		HTTPAckIsNotEnqueue:        r1.Admitted && cert1 != nil, // only Admit yields an EnqueueCertificate; an HTTP ack carries none
		Outcomes:                   outcomes,
		PoisonDoesNotStall:         poisonDoesNotStall,
		WatermarkAdvance:           wmResults,
		RefundReservedRejected:     !refundReserved.Applied,
		RefundRaceAppliedOnce:      refund1.Applied && !refund2.Applied,
	}

	// --- K derivation --------------------------------------------------
	for _, k := range []D5KCase{
		{MaxBacklogGas: 3_000_000, DeclaredGasLimit: 300_000, GFI: 300_000, OriginObservationLag: 2, RootRoundAllowanceBlocks: 3},
		{MaxBacklogGas: 0, DeclaredGasLimit: 300_000, GFI: 300_000, OriginObservationLag: 1, RootRoundAllowanceBlocks: 0},
	} {
		k.K = InclusionBoundK(k.MaxBacklogGas, k.DeclaredGasLimit, k.GFI, k.OriginObservationLag, k.RootRoundAllowanceBlocks)
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
