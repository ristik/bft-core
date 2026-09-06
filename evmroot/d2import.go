package evmroot

import (
	"bytes"
	"crypto/sha256"
)

// D2 import-validation model: the ordered predicate set an execution client
// (builder, follower, devp2p import, re-execution) applies to a sealed
// enshrined-EVM block before it can be certified.
//
// The protocol operations (the privileged seal call and the
// forced-inclusion prefix) live in a SEPARATE committed structure — the
// seal-outcome list — NOT in the Ethereum transaction list. Ordinary
// transactions keep standard `transactionsRoot` / `receiptsRoot` semantics
// unchanged; an intrinsically invalid forced entry is consumed with a
// seal-outcome rejection record, never as an EVM revert.
//
// Normative source: docs/design/d2-reth-system-call-fee-profile.md.

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

// SealOutcomeKind classifies one entry of the seal-outcome list.
type SealOutcomeKind string

const (
	OutcomeSystem         SealOutcomeKind = "system"          // the privileged seal call — index 0, always
	OutcomeForced         SealOutcomeKind = "forced"          // an executed forced-inclusion entry (may have reverted)
	OutcomeForcedRejected SealOutcomeKind = "forced_rejected" // an entry invalid at its turn — consumed, NOT executed
)

// SealOutcome is one record in the seal-outcome list. It is NOT an RLP
// receipt: there is no corresponding entry in the transaction list, no
// transactionsRoot slot, and no receiptsRoot slot. Its only proof surface
// is the sealOutcomeRoot committed in companion data.
type SealOutcome struct {
	Kind    SealOutcomeKind
	GasUsed uint64 // charged against g_sys (system) or g_fi (forced); never a fee payer
	Status  uint8  // 1 executed OK, 0 executed-and-reverted; a rejected entry has status 0 with a Reason
	Reason  string // authenticated rejection reason for OutcomeForcedRejected, else ""
	Digest  []byte // 32-byte digest of the entry's canonical payload (forced) or the rootInput commitment (system)
}

func (o SealOutcome) canonical() cArray {
	return cArray{cText(string(o.Kind)), cUint(o.GasUsed), cUint(uint64(o.Status)), cText(o.Reason), optBytes(o.Digest)}
}

// SealOutcomeRoot is SHA-256(CBOR([outcome_0, outcome_1, …])) over the
// ordered list. outcome_0 is always the system call.
func SealOutcomeRoot(outcomes []SealOutcome) [32]byte {
	arr := make(cArray, len(outcomes))
	for i, o := range outcomes {
		arr[i] = o.canonical()
	}
	return sha256.Sum256(marshalCBOR(arr))
}

// SignerAssignment is the D2-local view of the root assignment: NodeID ->
// effective weight. D3 owns the full weighted-consensus model; D2 needs
// only "sum the unique authorised signers' weight and compare a threshold",
// so it carries a minimal copy rather than depending on D3 (D2 and D3 are
// independent tracks off D1).
type SignerAssignment map[string]uint64

// TotalWeight sums all members' weight.
func (a SignerAssignment) TotalWeight() uint64 {
	var w uint64
	for _, v := range a {
		w += v
	}
	return w
}

// RootQuorumThreshold is ⌊2W/3⌋+1 over the assignment — recomputed here,
// never accepted from the companion.
func (a SignerAssignment) RootQuorumThreshold() uint64 { return (2*a.TotalWeight())/3 + 1 }

// SignerWeight sums the unique authorised signers' weight. ok is false on an
// unknown or duplicate signer.
func (a SignerAssignment) SignerWeight(signers []string) (weight uint64, ok bool) {
	seen := make(map[string]struct{}, len(signers))
	for _, s := range signers {
		if _, dup := seen[s]; dup {
			return 0, false
		}
		seen[s] = struct{}{}
		w, known := a[s]
		if !known {
			return 0, false
		}
		weight += w
	}
	return weight, true
}

// UCWitness is the verified-UC evidence a companion carries: the O_-
// identity the UC certifies and the seal's signer node-ids. The seal
// signatures themselves are verified by whoever holds the trust base (the
// shard node / adapter); see VerifyCompanionWitnesses for the boundary.
type UCWitness struct {
	OriginID    Hash32
	SealSigners []string // NodeIDs whose signatures are on the seal
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

// VerifyCompanionWitnesses is the AUTHENTICATION BOUNDARY. Trusted inputs:
// the caller's own trust-base view (`tb`, `threshold`) — from D3, obtained
// from authenticated seal-registry state, never from the companion. It
// checks:
//
//   - the witness UC certifies exactly this rootInput's O_- (OriginID);
//   - the seal's unique authorised signer weight meets the threshold
//     (reusing D3's weighted-quorum rule over the caller's assignment);
//   - there is one transition proof per rootInput.Transitions entry.
//
// WHO runs it: the shard node / Engine-API adapter, which holds the trust
// base. Over the JWT-authenticated Engine API the execution client trusts
// that verdict; a devp2p importer and an offline re-executor re-run this
// function against their OWN trust base using the same companion witnesses.
// The verdict is never an untrusted companion assertion.
func VerifyCompanionWitnesses(w CompanionWitness, ri RootInput, tb SignerAssignment, threshold uint64) CompanionAuth {
	if w.UC.OriginID != ri.Origin.Identity() {
		return CompanionAuth{Reason: "witness UC certifies a different O_- than the companion rootInput"}
	}
	if threshold == 0 {
		return CompanionAuth{Reason: "trust-base threshold is zero"}
	}
	sw, ok := tb.SignerWeight(w.UC.SealSigners)
	if !ok {
		return CompanionAuth{Reason: "seal signer set is malformed (unknown/duplicate signer)"}
	}
	if sw < threshold {
		return CompanionAuth{Reason: "seal signer weight is below the root quorum threshold"}
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
	NetworkID       uint64
	PartitionID     uint64
	ShardID         []byte
	Round           uint64
	ParentHash      []byte
	SealOutcomeRoot [32]byte // header sibling field committing the seal-outcome list
}

// SealBlock is the subset of a sealed block D2 import validation inspects.
type SealBlock struct {
	ExtraData       [32]byte
	Context         BlockContext
	BaseFee         uint64
	Withdrawals     int
	BlobTxCount     int
	OrdinaryTxCount int // entries in the Ethereum transaction list — never includes system/forced
	SystemCall      SystemCall
	Work            BlockWork
	Companion       CompanionData

	// Trust-base view the importer holds (from D3, via authenticated
	// seal-registry state). Not part of the block; supplied by the caller.
	TrustBase          SignerAssignment
	TrustBaseThreshold uint64
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
	auth := VerifyCompanionWitnesses(b.Companion.Witness, b.Companion.RootInput, b.TrustBase, b.TrustBaseThreshold)
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

	// Seal-outcome list: committed by its own root, distinct from the tx
	// list. outcome_0 is the system call; the rest are forced outcomes.
	outs := b.Companion.SealOutcomes
	if len(outs) == 0 || outs[0].Kind != OutcomeSystem {
		return reject("seal_outcomes_shape", "seal-outcome list is empty or does not start with the system call")
	}
	for i, o := range outs[1:] {
		if o.Kind != OutcomeForced && o.Kind != OutcomeForcedRejected {
			return reject("seal_outcomes_shape", "non-forced entry at seal-outcome index "+itoaSmall(i+1))
		}
	}
	if got := SealOutcomeRoot(outs); got != ctx.SealOutcomeRoot {
		return reject("seal_outcome_root_mismatch", "header sealOutcomeRoot != SHA-256(CBOR(seal-outcome list))")
	}
	// The ordinary transaction list must NOT include the system op or any
	// forced entry — its count is exactly the discretionary transactions.
	if b.OrdinaryTxCount < 0 {
		return reject("tx_list_shape", "negative ordinary transaction count")
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
