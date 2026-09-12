package evmroot

import (
	"bytes"
	"os"
	"testing"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

func TestD2_GasBudgetInvariant(t *testing.T) {
	cfg := DefaultExecConfig()
	// g_sys + g_fi + ordinary_capacity == g_max, exactly.
	if cfg.GSys+cfg.GFI+cfg.OrdinaryCapacity() != cfg.GMax {
		t.Fatalf("budget split does not close: %d + %d + %d != %d",
			cfg.GSys, cfg.GFI, cfg.OrdinaryCapacity(), cfg.GMax)
	}
}

func TestD2_HeaderGasUsedIsTheSum(t *testing.T) {
	w := BlockWork{System: 1_800_000, Forced: 500_000, Ordinary: 12_000_000}
	if w.HeaderGasUsed() != 14_300_000 {
		t.Fatalf("HeaderGasUsed = %d, want 14300000", w.HeaderGasUsed())
	}
}

func TestD2_BaseFeeUpdateExcludesSystemAndForcedGas(t *testing.T) {
	cfg := DefaultExecConfig()
	tgt := cfg.OrdinaryTarget()
	// Two blocks with identical ordinary gas (== target) but very
	// different system/forced gas must yield the same next base fee:
	// system and forced gas are outside the feedback loop.
	a := cfg.NextBaseFee(1_000_000_000, BlockWork{System: 100_000, Forced: 0, Ordinary: tgt})
	b := cfg.NextBaseFee(1_000_000_000, BlockWork{System: cfg.GSys, Forced: 0, Ordinary: tgt})
	if a != b || a != 1_000_000_000 {
		t.Fatalf("base fee depends on system/forced gas: a=%d b=%d", a, b)
	}
}

func TestD2_BaseFeeClampsToPositiveFloor(t *testing.T) {
	cfg := DefaultExecConfig()
	got := cfg.NextBaseFee(8, BlockWork{System: cfg.GSys, Ordinary: 0})
	if got < cfg.BaseFeeFloor {
		t.Fatalf("base fee %d dropped below floor %d", got, cfg.BaseFeeFloor)
	}
}

func TestD2_BaseFeeRisesWhenOrdinaryDemandExceedsTarget(t *testing.T) {
	cfg := DefaultExecConfig()
	tgt := cfg.OrdinaryTarget()
	got := cfg.NextBaseFee(1_000_000_000, BlockWork{System: cfg.GSys, Ordinary: tgt + tgt/2})
	if got <= 1_000_000_000 {
		t.Fatalf("base fee did not rise on over-target ordinary demand: %d", got)
	}
}

func TestD2_ImportValidation(t *testing.T) {
	for _, v := range BuildD2Vectors().ImportChecks {
		if !v.Matches {
			t.Errorf("%s: got (ok=%v code=%q), want (ok=%v code=%q)", v.Name, v.GotOK, v.GotCode, v.WantOK, v.WantCode)
		}
	}
}

func TestD2_SystemCallMustBeFirstAndValid(t *testing.T) {
	cfg := DefaultExecConfig()
	b, _ := validSealBlock(cfg)
	if r := ValidateImport(b, cfg); !r.OK {
		t.Fatalf("baseline block rejected: %s (%s)", r.Code, r.Reason)
	}
	// A forged ordinary sender for the privileged op is rejected before
	// the payload's own execution result is considered.
	b.SystemCall.From = [20]byte{0: 0x01}
	if r := ValidateImport(b, cfg); r.OK || r.Code != "system_origin_forged" {
		t.Fatalf("forged system sender not rejected as expected: %+v", r)
	}
}

func TestD2_FinalizerGasBoundToBudget(t *testing.T) {
	cfg := DefaultExecConfig()

	// The reviewer's reproduction: bump the finalizer gas without touching
	// Work — import must now reject (Work.System no longer equals the sum
	// of the two privileged steps).
	b, _ := validSealBlock(cfg)
	b.Finalize.GasUsed = cfg.GSys + 1
	if r := ValidateImport(b, cfg); r.OK || r.Code != "gas_split_unreconciled" {
		t.Fatalf("a finalizer alone over the whole system budget was accepted: %+v", r)
	}

	// Even if Work.System is bumped to match the (open + finalize) sum, the
	// COMBINED cap still bites.
	b, _ = validSealBlock(cfg)
	b.SystemCall.GasUsed = cfg.GSys - 100
	b.Finalize = finalizeFor(b) // recompute commitment for the new open gas
	b.Finalize.GasUsed = 200    // sum = GSys + 100 > GSys
	b.SealRegistryStateValue = b.Finalize.Committed
	b.Work.System = cfg.GSys + 100
	if r := ValidateImport(b, cfg); r.OK || r.Code != "gas_budget" {
		t.Fatalf("combined system gas over g_sys was accepted: %+v", r)
	}

	// Work.Forced cannot be supplied independently of the turn-rejected set.
	b, _ = validSealBlock(cfg)
	b.Work.Forced = 9_000 // baseline has no forced prefix -> derived Forced is 0
	if r := ValidateImport(b, cfg); r.OK || r.Code != "gas_split_unreconciled" {
		t.Fatalf("an independently supplied Work.Forced was accepted: %+v", r)
	}

	// A block WITH a forced prefix: Work.System / Work.Forced must reconcile.
	fc := cfg
	fc.GFI = 2_000_000
	b, _ = validSealBlock(fc)
	b.ForcedTxCount = 1
	b.DiscretionaryGasUsed = 10_000_000
	b.ForcedStartBalance = map[string]int64{"a": 100}
	b.ForcedPrefix = []ForcedEntry{
		{Sender: "a", ValueDelta: -100, DeclaredGas: 400_000, ExecGas: 0, Reason: ""}, // valid at turn, no EVM gas recorded
		{Sender: "a", ValueDelta: -50, Reason: "insufficient_balance_at_turn"},        // 1 rejected
	}
	b.RejectedConsumptionGas = 21_000
	b.SystemCall.GasUsed = 1_500_000
	b.Finalize = finalizeFor(b)
	b.Finalize.GasUsed = 30_000
	b.SealRegistryStateValue = b.Finalize.Committed
	b.Work = BlockWork{System: 1_530_000, Forced: 21_000, Ordinary: 10_000_000}
	if r := ValidateImport(b, fc); !r.OK {
		t.Fatalf("a well-formed forced-prefix block was rejected: %s (%s)", r.Code, r.Reason)
	}
	// header gas includes BOTH privileged steps + the rejected-entry charge.
	if b.Work.HeaderGasUsed() != 1_530_000+21_000+10_000_000 {
		t.Fatalf("header gas does not include both g_sys steps + forced charge: %d", b.Work.HeaderGasUsed())
	}
	rec, ok := RecoverOrdinaryGas(b.Work.HeaderGasUsed(), b.SystemCall.GasUsed+b.Finalize.GasUsed, b.Work.Forced)
	if !ok || rec != b.Work.Ordinary {
		t.Fatalf("ordinary-gas recovery does not net out both g_sys steps: rec=%d ok=%v", rec, ok)
	}
	// Now hide the finalizer charge from Work.System -> rejected.
	b.Work.System = 1_500_000
	if r := ValidateImport(b, fc); r.OK || r.Code != "gas_split_unreconciled" {
		t.Fatalf("hidden finalizer charge accepted on a forced-prefix block: %+v", r)
	}
}

// TestReview6SuccessfulForcedPrefixUsesReservedCapacity is the sixth-review
// reproduction, carried onto the DeclaredGas / ExecGas / DiscretionaryGasUsed
// fields the review asked for (a forced entry now declares the reserved g_fi
// capacity it consumed). A valid forced tx of 9M gas under a 20M g_fi, with
// zero discretionary demand and only 8M ordinary capacity, must import.
func TestReview6SuccessfulForcedPrefixUsesReservedCapacity(t *testing.T) {
	cfg := DefaultExecConfig()
	cfg.GFI = 20_000_000
	if err := cfg.Valid(); err != nil {
		t.Fatal(err)
	}
	b, _ := validSealBlock(cfg)
	b.OrdinaryTxCount, b.ForcedTxCount = 0, 1
	b.DiscretionaryGasUsed = 0
	b.ForcedPrefix = []ForcedEntry{{Sender: "alice", ValueDelta: -1, DeclaredGas: 9_000_000, ExecGas: 9_000_000, Digest: rep(0x31, 32)}}
	b.ForcedStartBalance = map[string]int64{"alice": 1}
	b.Finalize = finalizeFor(b)
	b.SealRegistryStateValue = b.Finalize.Committed
	b.Work = BlockWork{System: b.SystemCall.GasUsed + b.Finalize.GasUsed, Forced: 9_000_000, Ordinary: 0}
	if got := ValidateImport(b, cfg); !got.OK {
		t.Fatalf("reserved forced capacity unusable: %+v", got)
	}
}

// TestD2_ForcedPrefixGasUsesReservedBudget pins the sixth-review accounting:
// a valid forced tx's execution gas (success or EVM-revert) is charged to
// g_forced_actual against the reserved g_fi budget, never ordinary capacity;
// it does not move the base fee; charging it to the discretionary bucket or
// exceeding g_fi is rejected.
func TestD2_ForcedPrefixGasUsesReservedBudget(t *testing.T) {
	cfg := DefaultExecConfig()
	cfg.GFI = 20_000_000 // ordinary capacity is now 8M
	base := func() SealBlock {
		b, _ := validSealBlock(cfg)
		b.OrdinaryTxCount, b.ForcedTxCount = 0, 1
		b.DiscretionaryGasUsed = 0
		b.ForcedStartBalance = map[string]int64{"a": 100}
		b.ForcedPrefix = []ForcedEntry{{Sender: "a", ValueDelta: -1, DeclaredGas: 9_000_000, ExecGas: 9_000_000}}
		b.SystemCall.GasUsed = 1_500_000
		b.Finalize = finalizeFor(b)
		b.Finalize.GasUsed = 30_000
		b.SealRegistryStateValue = b.Finalize.Committed
		b.Work = BlockWork{System: 1_530_000, Forced: 9_000_000, Ordinary: 0}
		return b
	}

	// 9M forced tx fits despite ordinary capacity being only 8M.
	b := base()
	if r := ValidateImport(b, cfg); !r.OK {
		t.Fatalf("9M forced tx did not fit despite 20M reserved g_fi: %s (%s)", r.Code, r.Reason)
	}
	w, reason := reconcileWork(b)
	if reason != "" || w.Forced != 9_000_000 || w.Ordinary != 0 {
		t.Fatalf("forced gas not charged to the reserved budget: work=%+v reason=%q", w, reason)
	}
	if w.HeaderGasUsed() != 1_530_000+9_000_000+0 {
		t.Fatalf("header gas wrong: %d", w.HeaderGasUsed())
	}

	// The 9M does not enter the EIP-1559 feedback loop.
	withForced := cfg.NextBaseFee(1_000_000_000, w)
	control := cfg.NextBaseFee(1_000_000_000, BlockWork{System: w.System, Ordinary: w.Ordinary})
	if withForced != control {
		t.Fatalf("forced-tx gas moved the base fee: %d vs %d", withForced, control)
	}

	// A valid forced tx that EVM-reverts still consumes reserved capacity.
	rv := base()
	rv.ForcedPrefix[0] = ForcedEntry{Sender: "a", ValueDelta: -1, DeclaredGas: 9_000_000, ExecGas: 8_400_000, Reverted: true}
	rv.Finalize = finalizeFor(rv)
	rv.SealRegistryStateValue = rv.Finalize.Committed
	rv.Work.Forced = 8_400_000
	if r := ValidateImport(rv, cfg); !r.OK {
		t.Fatalf("a reverted forced tx did not draw on reserved capacity: %s (%s)", r.Code, r.Reason)
	}

	// Charging that gas to the discretionary bucket is rejected.
	bad := base()
	bad.DiscretionaryGasUsed = 9_000_000
	bad.Work = BlockWork{System: 1_530_000, Forced: 0, Ordinary: 9_000_000}
	if r := ValidateImport(bad, cfg); r.OK || r.Code != "gas_split_unreconciled" {
		t.Fatalf("forced-tx gas charged to the discretionary bucket was accepted: %+v", r)
	}

	// A forced prefix whose executed gas exceeds g_fi is rejected.
	over := base()
	over.ForcedPrefix[0].DeclaredGas = 20_000_000
	over.ForcedPrefix[0].ExecGas = 20_000_001
	over.Finalize = finalizeFor(over)
	over.SealRegistryStateValue = over.Finalize.Committed
	over.Work.Forced = 20_000_001
	if r := ValidateImport(over, cfg); r.OK || (r.Code != "gas_budget" && r.Code != "gas_split_unreconciled") {
		t.Fatalf("an over-g_fi forced prefix was accepted: %+v", r)
	}
}

// TestD2_ForcedTxCountMustMatchTurnValidSet: a builder cannot drop an
// admitted forced tx from the receipt trie, nor claim extra ones.
func TestD2_ForcedTxCountMustMatchTurnValidSet(t *testing.T) {
	cfg := DefaultExecConfig()
	cfg.GFI = 2_000_000
	b, _ := validSealBlock(cfg)
	b.DiscretionaryGasUsed = 10_000_000
	b.ForcedStartBalance = map[string]int64{"a": 100}
	b.ForcedPrefix = []ForcedEntry{
		{Sender: "a", ValueDelta: -100, DeclaredGas: 500_000, ExecGas: 400_000},
		{Sender: "a", ValueDelta: -50, Reason: "insufficient_balance_at_turn"},
	}
	b.RejectedConsumptionGas = 21_000
	b.SystemCall.GasUsed = 1_500_000
	b.Finalize = finalizeFor(b)
	b.Finalize.GasUsed = 30_000
	b.SealRegistryStateValue = b.Finalize.Committed
	b.Work = BlockWork{System: 1_530_000, Forced: 421_000, Ordinary: 10_000_000}
	b.ForcedTxCount = 1
	if r := ValidateImport(b, cfg); !r.OK {
		t.Fatalf("well-formed forced-prefix block rejected: %s (%s)", r.Code, r.Reason)
	}
	b.ForcedTxCount = 0
	if r := ValidateImport(b, cfg); r.OK || r.Code != "forced_tx_count_mismatch" {
		t.Fatalf("a dropped admitted forced tx was accepted: %+v", r)
	}
	b.ForcedTxCount = 2
	if r := ValidateImport(b, cfg); r.OK || r.Code != "forced_tx_count_mismatch" {
		t.Fatalf("an inflated forced-tx count was accepted: %+v", r)
	}
}

func TestD2_MissingCompanionDataIsFatal(t *testing.T) {
	cfg := DefaultExecConfig()
	b, _ := validSealBlock(cfg)
	b.Companion.Present = false
	if r := ValidateImport(b, cfg); r.OK || r.Code != "companion_missing" {
		t.Fatalf("a block whose payload executes but has no companion data must be rejected: %+v", r)
	}
}

func TestD2_AuthenticationBoundary(t *testing.T) {
	cfg := DefaultExecConfig()

	// The consumed VerifiedCert is not verified against the trust base.
	b, _ := validSealBlock(cfg)
	b.Companion.Witness.UC.Cert.SignaturesValid = false
	if r := ValidateImport(b, cfg); r.OK || r.Code != "companion_unauthenticated" {
		t.Fatalf("an unverified certificate authenticated the block: %+v", r)
	}

	// The verified cert is for a different O_-.
	b, _ = validSealBlock(cfg)
	b.Companion.Witness.UC.Cert.OriginID = Hash32{9}
	if r := ValidateImport(b, cfg); r.OK || r.Code != "companion_unauthenticated" {
		t.Fatalf("cert for a different O_- accepted: %+v", r)
	}

	// The cert authorizes a different shard round.
	b, _ = validSealBlock(cfg)
	b.Companion.Witness.UC.Cert.AuthorizedRound = 99
	if r := ValidateImport(b, cfg); r.OK || r.Code != "companion_unauthenticated" {
		t.Fatalf("cert authorizing the wrong round accepted: %+v", r)
	}

	// A stale certificate (root round behind the verifier's seal-registry
	// cursor) is rejected.
	b, _ = validSealBlock(cfg)
	b.LastAppliedRootRound = b.Companion.Witness.UC.Cert.RootRound + 5
	if r := ValidateImport(b, cfg); r.OK || r.Code != "companion_unauthenticated" {
		t.Fatalf("stale bound certificate accepted: %+v", r)
	}

	// A swapped technical record: TE no longer hashes to Origin.TRHash.
	b, _ = validSealBlock(cfg)
	b.Companion.RootInput.TE.Leader = "someone-else"
	if r := ValidateImport(b, cfg); r.OK || r.Code != "companion_unauthenticated" {
		t.Fatalf("TE not bound to the certified TRHash: %+v", r)
	}

	// FINDING: transition contents must be authenticated, not just counted.
	// Append an arbitrary committed body; the authenticated expected
	// sequence does not contain it.
	b, _ = validSealBlock(cfg)
	b.Companion.RootInput.Transitions = append(b.Companion.RootInput.Transitions, []byte{0x81, 0x01})
	if r := ValidateImport(b, cfg); r.OK || r.Code != "companion_unauthenticated" {
		t.Fatalf("an inserted committed body was accepted: %+v", r)
	}
	// Same-length substitution of the one expected body is also rejected.
	b, _ = validSealBlock(cfg)
	b.Companion.Witness.ExpectedTransitions = [][]byte{{0x01, 0x02}}
	b.Companion.RootInput.Transitions = [][]byte{{0xFF, 0xFF}}
	if r := ValidateImport(b, cfg); r.OK || r.Code != "companion_unauthenticated" {
		t.Fatalf("a substituted committed body was accepted: %+v", r)
	}
	// A reorder of two expected bodies is rejected.
	b, _ = validSealBlock(cfg)
	b.Companion.Witness.ExpectedTransitions = [][]byte{{0x0A}, {0x0B}}
	b.Companion.RootInput.Transitions = [][]byte{{0x0B}, {0x0A}}
	if r := ValidateImport(b, cfg); r.OK || r.Code != "companion_unauthenticated" {
		t.Fatalf("a reordered committed body sequence was accepted: %+v", r)
	}

	// Structurally invalid rootInput (after a passing witness): only
	// AuthorizedEpoch is bumped, so the TE still hashes to Origin.TRHash and
	// the witness authenticates; RootInput.Validate then fails on
	// TE.Epoch != AuthorizedEpoch.
	b, _ = validSealBlock(cfg)
	b.Companion.RootInput.AuthorizedEpoch = 9
	if r := ValidateImport(b, cfg); r.OK || r.Code != "rootinput_invalid" {
		t.Fatalf("structurally invalid rootInput accepted: %+v", r)
	}

	// A rootInput for a DIFFERENT block: the cert OriginID no longer matches.
	b, _ = validSealBlock(cfg)
	other := d2RootInput()
	other.Round, other.TE.Round = 99, 99
	b.Companion.RootInput = other
	if r := ValidateImport(b, cfg); r.OK {
		t.Fatal("a rootInput for a different block was accepted")
	}
}

// TestD2_CertificateBoundaryFixtures establishes the mapping the reviewer
// asked for: a real types.UnicityCertificate verified through bft-go-base's
// UnicitySeal.Verify against a real trust base, projected to RootOrigin,
// yields the VerifiedCert that D2's authentication boundary consumes —
// positive (quorum subset) and negative (sub-quorum subset).
func TestD2_CertificateBoundaryFixtures(t *testing.T) {
	ids := []string{"r1", "r2", "r3", "r4", "r5"}
	signers := map[string]abcrypto.Signer{}
	pubs := map[string][]byte{}
	for _, id := range ids {
		s, p := newSigner(t)
		signers[id], pubs[id] = s, p
	}
	tb := fixtureTrustBase(t, ids, pubs) // equal stake, quorum 4

	// Positive: a 4-of-5 subset reaches quorum.
	ucOK, trOK := fixtureCertificate(t, []string{"r1", "r2", "r3", "r4"}, signers)
	sigValidOK := ucOK.UnicitySeal.Verify(tb) == nil
	if !sigValidOK {
		t.Fatal("4-of-5 subset did not verify to quorum")
	}
	oOK, err := RootOriginFromCertificate(ucOK, trOK)
	if err != nil {
		t.Fatal(err)
	}
	certOK := verifiedCertFromOrigin(oOK, trOK.Round, sigValidOK)

	// Negative: a 1-of-5 subset does not reach quorum.
	ucBad, trBad := fixtureCertificate(t, []string{"r1"}, signers)
	sigValidBad := ucBad.UnicitySeal.Verify(tb) == nil
	if sigValidBad {
		t.Fatal("1-of-5 subset unexpectedly verified to quorum")
	}
	oBad, err := RootOriginFromCertificate(ucBad, trBad)
	if err != nil {
		t.Fatal(err)
	}
	certBad := verifiedCertFromOrigin(oBad, trBad.Round, sigValidBad)

	// Build a rootInput around the fixture O_- and feed the boundary.
	ri := RootInput{
		Version: ProfileVersion, NetworkID: oOK.NetworkID, PartitionID: 0x45564d00, ShardID: []byte{},
		Round: trOK.Round, CertifiedEpoch: oOK.IR.Epoch, AuthorizedEpoch: trOK.Epoch,
		ParentHash: rep(0xEE, 32), Origin: oOK, TE: TechnicalRecord{
			Round: trOK.Round, Epoch: trOK.Epoch, Leader: trOK.Leader,
			StatHash: trOK.StatHash, FeeHash: trOK.FeeHash,
		},
	}
	if !bytes.Equal(teHash(ri.TE), ri.Origin.TRHash) {
		t.Fatal("fixture TE does not hash to the projected O_-.TRHash")
	}
	wOK := CompanionWitness{UC: UCWitness{Cert: certOK}}
	if a := VerifyCompanionWitnesses(wOK, ri, 0); !a.OK {
		t.Fatalf("quorum-verified certificate rejected at the boundary: %s", a.Reason)
	}
	wBad := CompanionWitness{UC: UCWitness{Cert: certBad}}
	if a := VerifyCompanionWitnesses(wBad, ri, 0); a.OK {
		t.Fatal("a sub-quorum certificate authenticated at the boundary")
	}
}

// TestD2_ForcedPrefixOutcomesDeterminedAtTurn is the third-review fixture:
// a preceding valid forced tx changes whether the next entry is valid, so
// the rejection set — and the commitment over it — cannot be known before
// the prefix runs.
func TestD2_ForcedPrefixOutcomesDeterminedAtTurn(t *testing.T) {
	cfg := DefaultExecConfig()
	cfg.GFI = 2_000_000

	b, _ := validSealBlock(cfg)
	b.DiscretionaryGasUsed = 10_000_000
	b.ForcedStartBalance = map[string]int64{"alice": 100}
	b.ForcedPrefix = []ForcedEntry{
		{Sender: "alice", ValueDelta: -100, DeclaredGas: 900_000, ExecGas: 700_000, Reason: ""},
		{Sender: "alice", ValueDelta: -50, Reason: "insufficient_balance_at_turn"},
	}
	b.RejectedConsumptionGas = 21_000
	b.ForcedTxCount = 1
	b.SystemCall.GasUsed = 1_500_000
	b.Work = BlockWork{System: 1_530_000, Forced: 721_000, Ordinary: 10_000_000}
	b.Finalize = finalizeFor(b)
	b.SealRegistryStateValue = b.Finalize.Committed

	// entry 2 is valid at admission (100 >= 50) but invalid at its turn.
	turns := evalForcedPrefix(b.ForcedPrefix, b.ForcedStartBalance)
	if !turns[0] || turns[1] {
		t.Fatalf("prefix turn evaluation wrong: %v", turns)
	}
	outs := DerivedSealOutcomes(b)
	if len(outs) != 2 || outs[1].Kind != OutcomeForcedRejected || outs[1].Reason == "" {
		t.Fatalf("rejection record not derived from the turn outcome: %+v", outs)
	}
	if r := ValidateImport(b, cfg); !r.OK {
		t.Fatalf("valid sequential-prefix block rejected: %s (%s)", r.Code, r.Reason)
	}
	// The first system call cannot carry the outcome: moving the write into
	// it (no post-prefix finalization) is rejected.
	nf := b
	nf.Finalize.AfterForcedPrefix = false
	if r := ValidateImport(nf, cfg); r.OK || r.Code != "seal_finalize_missing" {
		t.Fatalf("commitment written before the prefix accepted: %+v", r)
	}
	// A commitment that reflects the ADMISSION-time set (both entries valid,
	// no rejection record) does not match the turn-determined outcomes.
	wrong := b
	wrong.Finalize.Committed = SealRegistryCommitment([]SealOutcome{outs[0]})
	wrong.SealRegistryStateValue = wrong.Finalize.Committed
	if r := ValidateImport(wrong, cfg); r.OK || r.Code != "seal_registry_commitment_mismatch" {
		t.Fatalf("admission-time commitment accepted: %+v", r)
	}
}

func TestD2_SealOutcomeListSeparateFromTxList(t *testing.T) {
	v := BuildD2Vectors().SealOutcomes
	if !v.ImportOK {
		t.Fatal("the sequential-forced-prefix block did not import")
	}
	if v.SystemOrRejectedInTrie {
		t.Fatal("the system op or a rejection record is in a transaction/receipt trie")
	}
	if !v.SuccessfulForcedInTxReceipt {
		t.Fatal("a successful forced tx is not exported through the ordinary tx/receipt trie")
	}
	if !v.CommitmentInContractState {
		t.Fatal("the seal-registry commitment is claimed as a header field, not contract state")
	}
	if !v.PoisonNotAReverT {
		t.Fatal("the rejected entry is not a rejection record with an authenticated reason")
	}
	// Entry 2 is valid at admission but not at its turn — so the rejection
	// set is only determinable after the prefix runs.
	if !v.Entry1ValidAtTurn || v.Entry2ValidAtTurn || !v.Entry2ValidAtAdmission ||
		!v.OutcomeDeterminedAtTurn || !v.CommitmentWrittenPostPrefix {
		t.Fatalf("forced-prefix turn semantics not demonstrated: %+v", v)
	}
	if v.HeaderGasUsed != v.SystemGas+v.ForcedExecGas+v.RejectedConsumptionGas+v.RecoveredOrdinary {
		t.Fatalf("gas does not close: header %d != %d + %d + %d + %d",
			v.HeaderGasUsed, v.SystemGas, v.ForcedExecGas, v.RejectedConsumptionGas, v.RecoveredOrdinary)
	}
	// The valid forced entry's ExecGas is charged to g_fi, not ordinary.
	if v.ForcedExecGas == 0 {
		t.Fatal("the valid forced entry recorded no execution gas against the reserved budget")
	}
}

func TestD2_NextBaseFeeNoOverflow(t *testing.T) {
	cfg := DefaultExecConfig()
	// The reviewer's case: parent 1e13, ordinary at 2x target -> +parent/8.
	tgt := cfg.OrdinaryTarget()
	got := cfg.NextBaseFee(10_000_000_000_000, BlockWork{System: cfg.GSys, Ordinary: 2 * tgt})
	if got != 11_250_000_000_000 {
		t.Fatalf("NextBaseFee overflowed or is wrong: got %d, want 11250000000000", got)
	}
	// Cross-check the whole oracle table.
	for _, o := range BuildD2Vectors().BaseFeeOracle {
		if !o.Match {
			t.Errorf("base-fee oracle mismatch: parent=%d used=%d model=%d oracle=%d",
				o.ParentBaseFee, o.OrdinaryUsed, o.Model, o.BigIntOracle)
		}
	}
}

func TestD2_ConfigValidation(t *testing.T) {
	if err := DefaultExecConfig().Valid(); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
	for _, bad := range []ExecConfig{
		{GMax: 30_000_000, GSys: 2_000_000, BaseFeeFloor: 7, ElasticityDenom: 0, BaseFeeChangeDenom: 8},
		{GMax: 30_000_000, GSys: 2_000_000, BaseFeeFloor: 7, ElasticityDenom: 2, BaseFeeChangeDenom: 0},
		{GMax: 30_000_000, GSys: 2_000_000, BaseFeeFloor: 0, ElasticityDenom: 2, BaseFeeChangeDenom: 8},
		{GMax: 30_000_000, GSys: 30_000_000, BaseFeeFloor: 7, ElasticityDenom: 2, BaseFeeChangeDenom: 8},
	} {
		if bad.Valid() == nil {
			t.Errorf("invalid config accepted: %+v", bad)
		}
		if r := ValidateImport(SealBlock{}, bad); r.OK || r.Code != "bad_config" {
			t.Errorf("ValidateImport did not reject bad config: %+v", r)
		}
	}
}

func TestD2_RecoverOrdinaryGas(t *testing.T) {
	if g, ok := RecoverOrdinaryGas(20_000_000, 2_000_000, 3_000_000); !ok || g != 15_000_000 {
		t.Fatalf("recovered %d, ok=%v; want 15000000,true", g, ok)
	}
	if _, ok := RecoverOrdinaryGas(1_000_000, 2_000_000, 0); ok {
		t.Fatal("receipts exceeding the header total were accepted")
	}
}

func TestD2_VectorsMatchGolden(t *testing.T) {
	const path = "testdata/d2-vectors.json"
	got, err := MarshalD2Vectors(BuildD2Vectors())
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s (run: go run ./evmroot/cmd/d2vectors -update): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale — regenerate with: go run ./evmroot/cmd/d2vectors -update", path)
	}
}
