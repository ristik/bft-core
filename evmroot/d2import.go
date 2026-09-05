package evmroot

import (
	"bytes"
	"crypto/sha256"
)

// D2 import-validation model: the ordered predicate set an execution client
// (builder, follower, devp2p import, re-execution) applies to a sealed
// enshrined-EVM block before it can be certified. "Its Ethereum payload
// executes" is necessary but not sufficient — a block that omits the
// companion data, carries a forged system sender, drops below the base-fee
// floor, includes a blob transaction, or whose privileged operation failed
// is invalid regardless.
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

// CompanionData is the block's required out-of-payload transport. Stock
// Engine API V3 payload attributes cannot carry it; the profile defines an
// explicit extension (see the design doc §"Engine API extension").
type CompanionData struct {
	Present   bool
	RootInput []byte   // canonical CBOR of the rootInput this block imports
	Witnesses [][]byte // UC + tree paths + transition proofs; authenticate RootInput / D, never re-hashed into it
}

// SealBlock is the subset of a sealed block D2 import validation inspects.
type SealBlock struct {
	ExtraData   [32]byte // header extraData — must equal SHA-256(CBOR(rootInput))
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
	// 1. Companion data must be present before anything else — a block
	//    whose payload executes but that carries no input/witness cannot be
	//    certified.
	if !b.Companion.Present || len(b.Companion.RootInput) == 0 {
		return reject("companion_missing", "block has no companion data (rootInput + witnesses)")
	}

	// 2. Header commitment binds the companion input.
	want := sha256.Sum256(b.Companion.RootInput)
	if !bytes.Equal(b.ExtraData[:], want[:]) {
		return reject("extradata_mismatch", "header extraData != SHA-256(CBOR(rootInput)) from companion data")
	}

	// 3. Privileged system operation: first, exactly once, fixed
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

	// 4. Fee and payload-shape validity rules.
	if b.BaseFee < cfg.BaseFeeFloor {
		return reject("base_fee_below_floor", "base fee below the positive floor f_base^min")
	}
	if b.Withdrawals != 0 {
		return reject("withdrawals_nonempty", "protocol withdrawal list must be empty")
	}
	if b.BlobTxCount != 0 {
		return reject("blob_tx_present", "blob transactions are disabled in the initial profile")
	}

	// 5. Gas budget and accounting.
	if gc := cfg.CheckGas(b.Work); !gc.BudgetOK {
		return reject("gas_budget", gc.Reason)
	}

	return ImportResult{OK: true}
}
