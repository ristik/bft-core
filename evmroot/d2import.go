package evmroot

import (
	"bytes"
	"crypto/sha256"
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

// SystemCall describes the single privileged operation that must be the
// first entry of the seal-outcome list of every successful block.
type SystemCall struct {
	From       [20]byte
	To         [20]byte
	Value      uint64 // must be 0
	HasSig     bool   // must be false — no EOA signature
	HasNonce   bool   // must be false — no account nonce
	FromTxPool bool   // must be false — cannot enter through the transaction pool
	Succeeded  bool   // false => whole block invalid
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

// The D2-local root-assignment view (NodeID + weight + consensus key) and
// its derived threshold live in d2seal.go as D2TrustBase. D3 owns the full
// weighted-consensus model; D2 and D3 are independent tracks off D1, so D2
// carries this minimal copy rather than depending on D3.

// UCWitness is the verified-UC evidence a companion carries: the O_-
// identity the UC certifies, the claimed seal signer node-ids, and the
// actual secp256k1 signatures over D2SealWitnessStatement(OriginID,
// Origin.TRHash). VerifyCompanionWitnesses checks the signatures against
// the verifier's OWN authenticated assignment — a name is not evidence.
type UCWitness struct {
	OriginID    Hash32
	SealSigners []string          // claimed signers (informational; only signed ones count)
	Signatures  map[string][]byte // NodeID -> signature over the seal-witness statement
}

// CompanionWitness carries the authentication evidence for a block's
// rootInput. There is no free-standing `Authenticated bool`: the verdict is
// produced by VerifyCompanionWitnesses, whose trusted boundary and
// obligations are stated there.
type CompanionWitness struct {
	UC               UCWitness
	TransitionProofs [][]byte // one per rootInput.Transitions entry (authenticates D, not re-hashed)
}

// CompanionData is the block's required out-of-payload transport: the
// STRUCTURED rootInput, the authentication witness, the seal-outcome list,
// and provenance.
type CompanionData struct {
	Present      bool
	RootInput    RootInput
	Witness      CompanionWitness
	SealOutcomes []SealOutcome
	Provenance   string // "build" | "newPayload" | "devp2p" | "reexec"
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

// VerifyCompanionWitnesses is the AUTHENTICATION BOUNDARY. Its only trusted
// input is the verifier's OWN authenticated assignment `tb` (from
// authenticated seal-registry state, never from the companion). It checks
// PROOF BINDINGS, not assertions:
//
//   - the witness UC certifies exactly this rootInput's O_- (OriginID ==
//     Origin.Identity());
//   - the carried technical record is bound to the certified TRHash
//     (H(CBOR(TE_-)) == Origin.TRHash) — a swapped TE is rejected;
//   - the threshold is DERIVED here as tb.RootQuorumThreshold(); a
//     companion-supplied threshold is not consulted and cannot exist;
//   - the seal signatures VERIFY: each is checked with secp256k1 against
//     the named member's consensus key over
//     D2SealWitnessStatement(OriginID, Origin.TRHash), and only verified
//     signers' weight counts toward the quorum. Signer names alone are
//     worth nothing;
//   - there is one transition proof per rootInput.Transitions entry.
//
// WHO runs it: the shard node / Engine-API adapter, which holds the
// assignment. Over the JWT-authenticated Engine API the execution client
// trusts that verdict; a devp2p importer and an offline re-executor re-run
// this function against their OWN assignment using the same witnesses. The
// verdict is never an untrusted companion assertion.
func VerifyCompanionWitnesses(w CompanionWitness, ri RootInput, tb D2TrustBase) CompanionAuth {
	if w.UC.OriginID != ri.Origin.Identity() {
		return CompanionAuth{Reason: "witness UC certifies a different O_- than the companion rootInput"}
	}
	if len(ri.Origin.TRHash) != 32 || !bytesEqualD2(teHash(ri.TE), ri.Origin.TRHash) {
		return CompanionAuth{Reason: "carried technical record is not bound to the certified TRHash"}
	}
	if tb.TotalWeight() == 0 {
		return CompanionAuth{Reason: "verifier trust base is empty"}
	}
	threshold := tb.RootQuorumThreshold()
	stmt := D2SealWitnessStatement(w.UC.OriginID, ri.Origin.TRHash)
	sw, ok := tb.VerifiedSignerWeight(stmt, w.UC.Signatures)
	if !ok {
		return CompanionAuth{Reason: "seal witness carries no verifying signature (unknown/duplicate/bad signature)"}
	}
	if sw < threshold {
		return CompanionAuth{Reason: "verified seal signer weight is below the derived root quorum threshold"}
	}
	if len(w.TransitionProofs) != len(ri.Transitions) {
		return CompanionAuth{Reason: "transition-proof count does not match rootInput.Transitions"}
	}
	for i, p := range w.TransitionProofs {
		if len(p) == 0 {
			return CompanionAuth{Reason: "empty transition proof at index " + itoaSmall(i)}
		}
	}
	return CompanionAuth{OK: true}
}

func bytesEqualD2(a, b []byte) bool { return string(a) == string(b) }

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
	// The value the system call wrote into the seal-registry contract's
	// storage — authenticated by the block's stateRoot, not a header field.
	SealRegistryStateValue [32]byte
	SystemCall             SystemCall
	Work                   BlockWork
	Companion              CompanionData

	// The importer's OWN authenticated root assignment (from authenticated
	// seal-registry state). Not part of the block. The quorum threshold is
	// derived from it, never carried.
	TrustBase D2TrustBase
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

	// Authentication boundary: verify the witness against the caller's own
	// trust base. Executing the payload authenticates nothing.
	auth := VerifyCompanionWitnesses(b.Companion.Witness, b.Companion.RootInput, b.TrustBase)
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

	// Seal-registry commitment: the system call (index 0) plus authenticated
	// rejection records, committed by a value in the seal-registry
	// contract's storage — authenticated by stateRoot, NOT a header field.
	// A successful forced transaction is an ordinary tx and is NOT here.
	outs := b.Companion.SealOutcomes
	if len(outs) == 0 || outs[0].Kind != OutcomeSystem {
		return reject("seal_outcomes_shape", "seal-outcome list is empty or does not start with the system call")
	}
	for i, o := range outs[1:] {
		if o.Kind != OutcomeForcedRejected {
			return reject("seal_outcomes_shape", "seal-outcome index "+itoaSmall(i+1)+" is not a forced-rejection record (successful forced txs are ordinary txs)")
		}
	}
	if got := SealRegistryCommitment(outs); got != b.SealRegistryStateValue {
		return reject("seal_registry_commitment_mismatch", "seal-registry storage value != SHA-256(CBOR(system + rejection records)) — check via eth_getProof against stateRoot")
	}
	if b.OrdinaryTxCount < 0 || b.ForcedTxCount < 0 {
		return reject("tx_list_shape", "negative transaction count")
	}

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
	case !sc.Succeeded || outs[0].Status != 1:
		return reject("system_failed", "system operation failed — the whole block is invalid")
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
	if gc := cfg.CheckGas(b.Work); !gc.BudgetOK {
		return reject("gas_budget", gc.Reason)
	}
	return ImportResult{OK: true}
}
