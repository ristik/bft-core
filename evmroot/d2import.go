package evmroot

import "bytes"

// D2 import-validation model: the ordered predicate set an execution client
// (builder, follower, devp2p import, re-execution) applies to a sealed
// enshrined-EVM block before it can be certified. "Its Ethereum payload
// executes" is necessary but not sufficient — a block that omits the
// companion data, whose companion input is not authenticated, whose
// decoded input does not match the block context, that carries a forged
// system sender, drops below the base-fee floor, includes a blob
// transaction, or whose privileged operation failed is invalid regardless.
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
// first entry in every successful block.
type SystemCall struct {
	From       [20]byte
	To         [20]byte
	Value      uint64 // must be 0
	HasSig     bool   // must be false — no EOA signature
	HasNonce   bool   // must be false — no account nonce
	FromTxPool bool   // must be false — cannot enter through the transaction pool
	Succeeded  bool   // false => whole block invalid
}

// CompanionData is the block's required out-of-payload transport. It
// carries the STRUCTURED rootInput this block imports (not an opaque blob:
// arbitrary bytes with a matching self-hash prove nothing) plus the
// authentication witnesses, and the caller's authentication verdict.
//
//   - RootInput is the decoded structure; ValidateImport re-encodes it
//     canonically and checks the header commitment against that.
//   - Authenticated records that the caller has already verified Witnesses
//     against committed certification/transition state (D1's
//     ValidateBoundCertificate + D3 signature verification + transition
//     proofs). A companion that is Present but not Authenticated fails
//     import — "the payload executes" never substitutes for authentication.
//   - Provenance names how it was obtained, for diagnostics and the
//     sync-path retention rule.
type CompanionData struct {
	Present       bool
	Authenticated bool
	RootInput     RootInput
	Witnesses     [][]byte
	Provenance    string // "build" | "newPayload" | "devp2p" | "reexec" | ""
}

// BlockContext is the block-header context the decoded rootInput must
// agree with, so a syntactically valid rootInput for a *different* block
// cannot be spliced in.
type BlockContext struct {
	NetworkID   uint64
	PartitionID uint64
	ShardID     []byte
	Round       uint64 // authorized shard round (n)
	ParentHash  []byte // header's parent EVM block hash
}

// SealBlock is the subset of a sealed block D2 import validation inspects.
type SealBlock struct {
	ExtraData   [32]byte // header extraData — must equal SHA-256(CBOR(canonical rootInput))
	Context     BlockContext
	BaseFee     uint64
	Withdrawals int // count; must be 0
	BlobTxCount int // must be 0 — blob transactions disabled in the initial profile
	SystemCall  SystemCall
	Work        BlockWork
	Companion   CompanionData
}

// ImportResult is the outcome of ValidateImport: OK plus, on failure, the
// first predicate that rejected and a stable code for it.
type ImportResult struct {
	OK     bool
	Code   string
	Reason string
}

func reject(code, reason string) ImportResult { return ImportResult{Code: code, Reason: reason} }

// ValidateImport runs the D2 predicates in the order a client applies them.
// The order is fixed so that two implementations reject an invalid block
// for the same stated reason.
func ValidateImport(b SealBlock, cfg ExecConfig) ImportResult {
	// 0. The configuration itself must be one the arithmetic is safe on.
	if err := cfg.Valid(); err != nil {
		return reject("bad_config", err.Error())
	}

	// 1. Companion data must be present.
	if !b.Companion.Present {
		return reject("companion_missing", "block has no companion data (rootInput + witnesses)")
	}

	// 2. The companion input must be authenticated — witnesses verified
	//    against committed certification/transition state. Executing the
	//    payload does not authenticate anything.
	if !b.Companion.Authenticated || len(b.Companion.Witnesses) == 0 {
		return reject("companion_unauthenticated", "companion rootInput is not authenticated against committed certificate/transition state")
	}

	// 3. The decoded rootInput must itself be structurally valid (D1).
	if err := b.Companion.RootInput.Validate(); err != nil {
		return reject("rootinput_invalid", "companion rootInput fails D1 validation: "+err.Error())
	}

	// 4. The decoded rootInput must match this block's header context — a
	//    valid rootInput for a different block cannot be spliced in.
	ri := b.Companion.RootInput
	ctx := b.Context
	switch {
	case ri.NetworkID != ctx.NetworkID || ri.PartitionID != ctx.PartitionID || !bytes.Equal(ri.ShardID, ctx.ShardID):
		return reject("context_mismatch", "rootInput network/partition/shard does not match the block context")
	case ri.Round != ctx.Round:
		return reject("context_mismatch", "rootInput authorized round does not match the block context")
	case !bytes.Equal(ri.ParentHash, ctx.ParentHash):
		return reject("context_mismatch", "rootInput parent hash does not match the header parent")
	}

	// 5. Header commitment binds the canonical re-encoding of that input.
	want := ri.ExtraData()
	if !bytes.Equal(b.ExtraData[:], want[:]) {
		return reject("extradata_mismatch", "header extraData != SHA-256(CBOR(canonical rootInput))")
	}

	// 6. Privileged system operation: first, exactly once, fixed
	//    origin/destination, zero value, no key/nonce, not from the pool.
	sc := b.SystemCall
	switch {
	case sc.From != SystemOrigin:
		return reject("system_origin_forged", "system operation not from a_sys — a forged ordinary sender is rejected")
	case sc.To != SystemRegistry:
		return reject("system_destination", "system operation destination is not a_sr")
	case sc.Value != 0:
		return reject("system_value_nonzero", "system operation carries non-zero value — it cannot mint or move value")
	case sc.HasSig || sc.HasNonce:
		return reject("system_eoa_like", "system operation has an EOA signature or nonce — it has neither")
	case sc.FromTxPool:
		return reject("system_from_pool", "system operation entered through the transaction pool")
	case !sc.Succeeded:
		return reject("system_failed", "system operation failed — the whole block is invalid, not the call skipped")
	}

	// 7. Fee and payload-shape validity rules.
	if b.BaseFee < cfg.BaseFeeFloor {
		return reject("base_fee_below_floor", "base fee below the positive floor f_base^min")
	}
	if b.Withdrawals != 0 {
		return reject("withdrawals_nonempty", "protocol withdrawal list must be empty")
	}
	if b.BlobTxCount != 0 {
		return reject("blob_tx_present", "blob transactions are disabled in the initial profile")
	}

	// 8. Gas budget and accounting.
	if gc := cfg.CheckGas(b.Work); !gc.BudgetOK {
		return reject("gas_budget", gc.Reason)
	}

	return ImportResult{OK: true}
}
