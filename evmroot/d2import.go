package evmroot

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/bits"
)

// D2 import-validation model: the ordered predicate set an execution client
// (builder, follower, devp2p import, re-execution) applies to a sealed
// enshrined-EVM block before it can be certified.
//
// Third-review revision — minimal client divergence:
//
//   - A SUCCESSFUL forced-inclusion transaction IS an ordinary Ethereum
//     transaction. It sits in `transactionsRoot` / `receiptsRoot` with a
//     standard receipt (logs, bloom, cumulative gas), so its events export
//     through the normal receipt proof. No divergence.
//   - Only two things cannot be ordinary transactions: the privileged seal
//     call (no fee payer, no signature) and a REJECTED forced-inbox entry
//     (an authenticated rejection record — not an EVM transaction, so it
//     has no receipt). These are committed by a value the system call
//     writes into the seal-registry contract's storage — the
//     `sealRegistryCommitment` — which is already covered by the block's
//     `stateRoot` and provable via `eth_getProof`. There is NO new header
//     field. `extraData` (D1) hashes only the rootInput and never claimed
//     to cover these.
//   - `header.gasUsed` is the standard cumulative gas over the transaction
//     list (now including successful forced txs) PLUS the seal call's
//     `g_sys` work. It is NOT "entirely unchanged"; it includes the
//     system-call gas, which is bounded by `g_sys` and recoverable.
//
// Normative source: docs/design/d2-reth-system-call-fee-profile.md §3.

// Fixed protocol addresses (illustrative values; a deployment pins them in
// ExecConfig-adjacent partition configuration). No private key can
// originate the system operation from a_sys.
var (
	SystemOrigin   = [20]byte{0: 0xff, 19: 0x01} // a_sys — the privileged origin
	SystemRegistry = [20]byte{0: 0xff, 19: 0x02} // a_sr  — the seal-registry destination
)

// SystemCall describes the single privileged operation that runs FIRST on
// every successful block. It is PRESENCE-ONLY: it opens the seal-registry
// commitment slot and binds the rootInput, and carries NO forced-outcome
// input — those are not yet determined. The commitment value is written
// later by the post-prefix FinalizeStep.
type SystemCall struct {
	From       [20]byte
	To         [20]byte
	Value      uint64 // must be 0
	HasSig     bool   // must be false — no EOA signature
	HasNonce   bool   // must be false — no account nonce
	FromTxPool bool   // must be false — cannot enter through the transaction pool
	GasUsed    uint64 // g_sys work of the open step
	Succeeded  bool   // false => whole block invalid
}

// FinalizeStep is the narrowly-scoped SECOND privileged operation. It runs
// AFTER the forced-inclusion prefix, once every forced entry's outcome AT
// ITS TURN is determined, and writes `sealRegistryCommitment` into the
// seal-registry contract's storage. Its gas is charged explicitly against
// the g_sys sub-budget. This is why the first call cannot — and must not —
// take a forced-outcome argument.
type FinalizeStep struct {
	Present           bool
	AfterForcedPrefix bool     // ordering: it must run after the whole forced prefix
	Committed         [32]byte // the value written to seal-registry storage
	GasUsed           uint64   // g_sys sub-budget for the finalization
}

// ForcedEntry is one forced-inclusion entry in the block's FIFO prefix.
// Whether it is valid is decided AT ITS TURN, against the running pre-state
// the earlier prefix entries left — never at admission.
type ForcedEntry struct {
	Sender     string
	ValueDelta int64  // net balance effect if it executes (negative = a spend)
	Reason     string // the rejection reason it carries if invalid at its turn
	Digest     []byte // 32-byte canonical-payload digest
}

// evalForcedPrefix walks the FIFO prefix against starting balances and
// returns, per entry, whether it was valid AT ITS TURN. A spend an earlier
// entry made unaffordable is rejected at its turn even though it looked
// fine at admission — which is exactly why the outcome set cannot be known
// before the prefix runs.
func evalForcedPrefix(entries []ForcedEntry, start map[string]int64) []bool {
	bal := map[string]int64{}
	for k, v := range start {
		bal[k] = v
	}
	out := make([]bool, len(entries))
	for i, e := range entries {
		nb := bal[e.Sender] + e.ValueDelta
		if nb < 0 {
			out[i] = false
			continue
		}
		bal[e.Sender] = nb
		out[i] = true
	}
	return out
}

// SealOutcomeKind classifies one entry committed by the seal-registry
// contract-state commitment.
type SealOutcomeKind string

const (
	OutcomeSystem         SealOutcomeKind = "system"          // the privileged seal call — index 0, always
	OutcomeForcedRejected SealOutcomeKind = "forced_rejected" // a forced-inbox entry invalid at its turn — consumed with an authenticated reason, NEVER executed, NOT an EVM revert
)

// SealOutcome is one record committed by SealRegistryCommitment — the
// system call and the authenticated rejection records for forced-inbox
// entries invalid at their turn. It is NOT an RLP receipt and NOT a
// transaction. A SUCCESSFUL forced transaction is not here: it is an
// ordinary transaction in transactionsRoot / receiptsRoot with a standard
// receipt (logs, bloom, cumulative gas).
type SealOutcome struct {
	Kind    SealOutcomeKind
	GasUsed uint64 // g_sys work (system) or the g_fi consumption charge for a rejected entry; never a fee payer
	Status  uint8  // system: 1 (0 ⇒ block invalid). forced_rejected: always 0, with a Reason
	Reason  string // authenticated rejection reason for OutcomeForcedRejected, else ""
	Digest  []byte // 32-byte digest of the rejected entry's canonical payload, or the rootInput commitment (system)
}

func (o SealOutcome) canonical() cArray {
	return cArray{cText(string(o.Kind)), cUint(o.GasUsed), cUint(uint64(o.Status)), cText(o.Reason), optBytes(o.Digest)}
}

// SealRegistryCommitment is SHA-256(CBOR([outcome_0, outcome_1, …])) over
// the ordered list. outcome_0 is always the system call; the rest are
// rejection records. The system call writes this value into the
// seal-registry contract's storage, so it is authenticated by the block's
// stateRoot (provable via eth_getProof) — NOT by a header field.
func SealRegistryCommitment(outcomes []SealOutcome) [32]byte {
	arr := make(cArray, len(outcomes))
	for i, o := range outcomes {
		arr[i] = o.canonical()
	}
	return sha256.Sum256(marshalCBOR(arr))
}

// --- verified inputs the authentication boundary consumes ---------------
//
// D2 does NOT re-verify root signatures and does NOT invent a new
// root-quorum message. Two things are VERIFIED UPSTREAM and consumed here
// as typed inputs — the boundary is explicit, tested, and cannot become a
// new signing obligation by accident:
//
//  1. VerifiedCert (D1) — the real types.UnicityCertificate for this O_-
//     has been verified against the trust base for its epoch: the
//     UnicitySeal signatures + quorum (bft-go-base UnicitySeal.Verify),
//     the shard-tree / unicity-tree inclusion paths, and TR.Hash. Its
//     SignaturesValid field IS that verdict. VerifyCompanionWitnesses
//     consumes it via D1's ValidateBoundCertificate; the certificate ->
//     VerifiedCert mapping is exercised through bft-go-base's real
//     verifier in TestD2_CertificateBoundaryFixtures.
//  2. ExpectedTransitions — the authenticated, ordered committed
//     trust-base bodies the verifier expects THIS block to carry, from its
//     own committed cursor. Produced by whoever verified the committed-body
//     chain (D3 / seal registry). ri.Transitions must equal it byte-for-
//     byte, position by position.

// UCWitness carries the verified certificate for the block's O_-.
type UCWitness struct {
	Cert VerifiedCert
}

// CompanionWitness carries the authentication evidence for a block's
// rootInput. The verdict is produced by VerifyCompanionWitnesses; there is
// no free-standing `Authenticated bool`.
type CompanionWitness struct {
	UC                  UCWitness
	ExpectedTransitions [][]byte // the verifier's authenticated committed-body sequence for this block
}

// CompanionData is the block's required out-of-payload transport: the
// STRUCTURED rootInput, the authentication witness, and provenance. The
// seal-registry records are DERIVED from the forced prefix at import
// (DerivedSealOutcomes), not transported — the first system call cannot
// know them.
type CompanionData struct {
	Present    bool
	RootInput  RootInput
	Witness    CompanionWitness
	Provenance string // "build" | "newPayload" | "devp2p" | "reexec"
}

// CompanionAuth is the outcome of VerifyCompanionWitnesses.
type CompanionAuth struct {
	OK     bool
	Reason string
}

// teHash is H(CBOR(TE_-)) in the same field order the canonical root input
// commits — the value O_-.TRHash must equal.
func teHash(te TechnicalRecord) []byte {
	h := sha256Slice(marshalCBOR(cArray{
		cUint(te.Round), cUint(te.Epoch), cText(te.Leader), cBytes(te.StatHash), cBytes(te.FeeHash),
	}))
	return h
}

// VerifyCompanionWitnesses is the AUTHENTICATION BOUNDARY. It consumes the
// two verified inputs above and checks their bindings:
//
//   - D1's ValidateBoundCertificate accepts the VerifiedCert for this O_-:
//     cert.SignaturesValid (the real UnicitySeal.Verify verdict, quorum
//     included), the O_- / TRHash / root-round binding, the authorized
//     round == this shard round, and a non-stale seal-registry cursor;
//   - the carried technical record hashes to the certified TRHash
//     (H(CBOR(TE_-)) == Origin.TRHash) — a swapped TE is rejected;
//   - every committed body equals the authenticated ExpectedTransitions
//     body at its position — substitution, reordering, omission and replay
//     all fail (a byte-count check is NOT enough).
//
// WHO runs it: the shard node / Engine-API adapter, which produced the
// VerifiedCert and the ExpectedTransitions from authenticated state. Over
// the JWT-authenticated Engine API the execution client trusts that
// verdict; a devp2p importer and an offline re-executor re-derive the same
// two verified inputs and re-run this function. The verdict is never an
// untrusted companion assertion, and this function is the CHECK — not the
// source of trust.
func VerifyCompanionWitnesses(w CompanionWitness, ri RootInput, lastAppliedRootRound uint64) CompanionAuth {
	ref, err := RefFromOrigin(ri.Origin)
	if err != nil {
		return CompanionAuth{Reason: "rootInput O_- has no valid authorizing ref: " + err.Error()}
	}
	if sel := ValidateBoundCertificate(ref, w.UC.Cert, ri.Round, lastAppliedRootRound); !sel.Accept {
		return CompanionAuth{Reason: "bound certificate: " + sel.Reason}
	}
	if len(ri.Origin.TRHash) != 32 || !bytes.Equal(teHash(ri.TE), ri.Origin.TRHash) {
		return CompanionAuth{Reason: "carried technical record is not bound to the certified TRHash"}
	}
	if len(ri.Transitions) != len(w.ExpectedTransitions) {
		return CompanionAuth{Reason: fmt.Sprintf("companion carries %d committed bodies; the authenticated sequence has %d", len(ri.Transitions), len(w.ExpectedTransitions))}
	}
	for i := range ri.Transitions {
		if !bytes.Equal(ri.Transitions[i], w.ExpectedTransitions[i]) {
			return CompanionAuth{Reason: "committed body at index " + itoaSmall(i) + " is not the authenticated body at that position (substitution / reorder / omission / replay)"}
		}
	}
	return CompanionAuth{OK: true}
}

// forcedDigest is a deterministic canonical-payload digest for a rejected
// forced entry (position-bound so reorders change it).
func forcedDigest(pos int, e ForcedEntry) []byte {
	if len(e.Digest) == 32 {
		return e.Digest
	}
	return sha256Slice(marshalCBOR(cArray{cText("UNICITY_FORCED_ENTRY"), cUint(uint64(pos)), cText(e.Sender), cUint(uint64(e.ValueDelta)), cText(e.Reason)}))
}

// DerivedSealOutcomes is the seal-registry record list the FinalizeStep
// writes: the system op (index 0), then a forced_rejected record for every
// prefix entry invalid AT ITS TURN. It is computed AFTER the forced prefix
// runs — it cannot be produced by the first system call.
func DerivedSealOutcomes(b SealBlock) []SealOutcome {
	outs := []SealOutcome{{Kind: OutcomeSystem, GasUsed: b.SystemCall.GasUsed, Status: 1, Digest: b.ExtraData[:]}}
	for i, ok := range evalForcedPrefix(b.ForcedPrefix, b.ForcedStartBalance) {
		if !ok {
			e := b.ForcedPrefix[i]
			outs = append(outs, SealOutcome{
				Kind: OutcomeForcedRejected, GasUsed: b.RejectedConsumptionGas, Status: 0,
				Reason: e.Reason, Digest: forcedDigest(i, e),
			})
		}
	}
	return outs
}

func itoaSmall(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}

// BlockContext is the block-header context the decoded rootInput must agree
// with.
type BlockContext struct {
	NetworkID   uint64
	PartitionID uint64
	ShardID     []byte
	Round       uint64
	ParentHash  []byte
}

// SealBlock is the subset of a sealed block D2 import validation inspects.
type SealBlock struct {
	ExtraData   [32]byte
	Context     BlockContext
	BaseFee     uint64
	Withdrawals int
	BlobTxCount int
	// Discretionary transactions and SUCCESSFUL forced transactions are both
	// ordinary entries in transactionsRoot / receiptsRoot. Split only for
	// reporting; neither ever includes the system call or a rejection record.
	OrdinaryTxCount int
	ForcedTxCount   int

	// The forced-inclusion prefix, its starting balances, and the g_fi
	// consumption charge per rejected entry. Outcomes are determined AT EACH
	// ENTRY'S TURN by evalForcedPrefix.
	ForcedPrefix           []ForcedEntry
	ForcedStartBalance     map[string]int64
	RejectedConsumptionGas uint64

	SystemCall SystemCall   // the presence-only open step (first)
	Finalize   FinalizeStep // the post-prefix commitment write

	// The value in the seal-registry contract's storage — authenticated by
	// the block's stateRoot (eth_getProof), not a header field.
	SealRegistryStateValue [32]byte

	Work      BlockWork
	Companion CompanionData

	// The verifier's own committed seal-registry cursor (last-applied root
	// round). Not part of the block; from authenticated local state.
	LastAppliedRootRound uint64
}

// ImportResult is the outcome of ValidateImport.
type ImportResult struct {
	OK     bool
	Code   string
	Reason string
}

func reject(code, reason string) ImportResult { return ImportResult{Code: code, Reason: reason} }

// ValidateImport runs the D2 predicates in a fixed order.
func ValidateImport(b SealBlock, cfg ExecConfig) ImportResult {
	if err := cfg.Valid(); err != nil {
		return reject("bad_config", err.Error())
	}
	if !b.Companion.Present {
		return reject("companion_missing", "block has no companion data")
	}

	// Authentication boundary: consume the verified certificate + the
	// authenticated expected-transition sequence. Executing the payload
	// authenticates nothing.
	auth := VerifyCompanionWitnesses(b.Companion.Witness, b.Companion.RootInput, b.LastAppliedRootRound)
	if !auth.OK {
		return reject("companion_unauthenticated", auth.Reason)
	}

	ri := b.Companion.RootInput
	if err := ri.Validate(); err != nil {
		return reject("rootinput_invalid", "companion rootInput fails D1 validation: "+err.Error())
	}

	ctx := b.Context
	switch {
	case ri.NetworkID != ctx.NetworkID || ri.PartitionID != ctx.PartitionID || !bytes.Equal(ri.ShardID, ctx.ShardID):
		return reject("context_mismatch", "rootInput network/partition/shard does not match the block context")
	case ri.Round != ctx.Round:
		return reject("context_mismatch", "rootInput authorized round does not match the block context")
	case !bytes.Equal(ri.ParentHash, ctx.ParentHash):
		return reject("context_mismatch", "rootInput parent hash does not match the header parent")
	}

	if want := ri.ExtraData(); !bytes.Equal(b.ExtraData[:], want[:]) {
		return reject("extradata_mismatch", "header extraData != SHA-256(CBOR(canonical rootInput))")
	}

	if b.OrdinaryTxCount < 0 || b.ForcedTxCount < 0 {
		return reject("tx_list_shape", "negative transaction count")
	}

	// The first system call is presence-only.
	sc := b.SystemCall
	switch {
	case sc.From != SystemOrigin:
		return reject("system_origin_forged", "system operation not from a_sys — a forged ordinary sender is rejected")
	case sc.To != SystemRegistry:
		return reject("system_destination", "system operation destination is not a_sr")
	case sc.Value != 0:
		return reject("system_value_nonzero", "system operation carries non-zero value")
	case sc.HasSig || sc.HasNonce:
		return reject("system_eoa_like", "system operation has an EOA signature or nonce")
	case sc.FromTxPool:
		return reject("system_from_pool", "system operation entered through the transaction pool")
	case !sc.Succeeded:
		return reject("system_failed", "system operation failed — the whole block is invalid")
	}

	// The seal-registry commitment is written by a post-forced-prefix
	// FinalizeStep — because a valid prefix entry can change whether a later
	// entry is valid at its turn, the first system call cannot determine it.
	derived := DerivedSealOutcomes(b)
	if !b.Finalize.Present || !b.Finalize.AfterForcedPrefix {
		return reject("seal_finalize_missing", "sealRegistryCommitment must be written by a post-forced-prefix finalization step, not the first system call")
	}
	if b.Finalize.GasUsed == 0 && len(b.ForcedPrefix) > 0 {
		return reject("seal_finalize_unmetered", "the finalization step consumed no gas — its work must be charged against g_sys")
	}
	want := SealRegistryCommitment(derived)
	if b.Finalize.Committed != want {
		return reject("seal_registry_commitment_mismatch", "finalization wrote a commitment that does not match the outcomes determined at each forced entry's turn")
	}
	if b.SealRegistryStateValue != want {
		return reject("seal_registry_commitment_mismatch", "seal-registry storage value != the finalized commitment (eth_getProof against stateRoot)")
	}
	if derived[0].Status != 1 {
		return reject("system_failed", "system operation record has non-1 status")
	}

	if b.BaseFee < cfg.BaseFeeFloor {
		return reject("base_fee_below_floor", "base fee below the positive floor f_base^min")
	}
	if b.Withdrawals != 0 {
		return reject("withdrawals_nonempty", "protocol withdrawal list must be empty")
	}
	if b.BlobTxCount != 0 {
		return reject("blob_tx_present", "blob transactions are disabled in the initial profile")
	}
	// Gas: the system split is DERIVED from the two executed privileged
	// steps and the turn-determined rejection set, not taken from a
	// caller-supplied total. An independently supplied Work.System /
	// Work.Forced cannot defeat the g_sys / g_fi split.
	work, wreason := reconcileWork(b)
	if wreason != "" {
		return reject("gas_split_unreconciled", wreason)
	}
	if gc := cfg.CheckGas(work); !gc.BudgetOK {
		return reject("gas_budget", gc.Reason)
	}
	return ImportResult{OK: true}
}

// reconcileWork derives the system and forced gas from the block's actual
// steps and checks that the caller-supplied Work.System / Work.Forced match
// them, with overflow-safe arithmetic:
//
//	System = SystemCall.GasUsed + Finalize.GasUsed   (both privileged steps)
//	Forced = (# entries invalid at their turn) * RejectedConsumptionGas
//	Ordinary = Work.Ordinary   (the standard transaction-list cumulative
//	           gas, incl. successful forced txs — a re-executor reproduces it)
//
// Returns the derived BlockWork and "" on success, or a non-empty reason.
func reconcileWork(b SealBlock) (BlockWork, string) {
	sysGas, carry := bits.Add64(b.SystemCall.GasUsed, b.Finalize.GasUsed, 0)
	if carry != 0 {
		return BlockWork{}, "system + finalize gas overflows uint64"
	}
	rejected := uint64(0)
	for _, valid := range evalForcedPrefix(b.ForcedPrefix, b.ForcedStartBalance) {
		if !valid {
			rejected++
		}
	}
	fHi, forcedGas := bits.Mul64(rejected, b.RejectedConsumptionGas)
	if fHi != 0 {
		return BlockWork{}, "rejected-entry consumption charge overflows uint64"
	}
	derived := BlockWork{System: sysGas, Forced: forcedGas, Ordinary: b.Work.Ordinary}
	if b.Work.System != sysGas {
		return derived, fmt.Sprintf("Work.System %d != SystemCall.GasUsed %d + Finalize.GasUsed %d",
			b.Work.System, b.SystemCall.GasUsed, b.Finalize.GasUsed)
	}
	if b.Work.Forced != forcedGas {
		return derived, fmt.Sprintf("Work.Forced %d != %d turn-rejected entries * %d consumption charge",
			b.Work.Forced, rejected, b.RejectedConsumptionGas)
	}
	return derived, ""
}
