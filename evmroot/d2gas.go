package evmroot

import "math/bits"

// D2 gas / header / fee model. Reference for the reth system-call and fee
// profile: how the privileged system operation and the forced-inclusion
// prefix consume a reserved budget without a fee payer, how the header's
// gasUsed is formed, and how the EIP-1559 base fee updates when part of the
// block's gas is protocol-mandated rather than demand-driven.
//
// Normative source: docs/design/d2-reth-system-call-fee-profile.md,
// docs/adr/0004-reth-system-call-fee-profile.md. Issue:
// https://github.com/ristik/bft-core/issues/4

// ExecConfig is the versioned execution configuration fields D2 pins. A
// builder cannot override any of them; every validator checks them
// independently of builder preferences.
type ExecConfig struct {
	GMax               uint64 // g_max — total block work budget (the header gas limit)
	GSys               uint64 // g_sys — reserved system-operation budget
	GFI                uint64 // g_fi  — reserved forced-inclusion budget (0 until the inbox is enabled)
	BaseFeeFloor       uint64 // f_base^min — positive; validated on every block
	ElasticityDenom    uint64 // EIP-1559 elasticity divisor applied to the *ordinary* capacity (London: 2)
	BaseFeeChangeDenom uint64 // EIP-1559 max base-fee change denominator (London: 8)
}

// DefaultExecConfig is an illustrative pinned profile used by the D2
// vectors. A deployment publishes its own values before activation; the
// invariants below hold for any valid choice.
func DefaultExecConfig() ExecConfig {
	return ExecConfig{
		GMax:               30_000_000,
		GSys:               2_000_000,
		GFI:                0,
		BaseFeeFloor:       7, // wei; positive floor
		ElasticityDenom:    2,
		BaseFeeChangeDenom: 8,
	}
}

// MaxBaseFee is the execution-compatible upper bound for a base fee in this
// model. Real clients carry the EIP-1559 base fee as a 256-bit value; the
// model keeps it in uint64 and rejects a configuration or parent value that
// could carry it past this bound, so every arithmetic step stays exact in a
// checked 128-bit intermediate.
const MaxBaseFee uint64 = 1 << 62

// Valid rejects a configuration the fee/gas arithmetic cannot be trusted
// on: zero or degenerate denominators, a reserved budget that leaves no
// ordinary capacity, or a non-positive base-fee floor.
func (c ExecConfig) Valid() error {
	switch {
	case c.ElasticityDenom == 0:
		return errBadConfig("elasticity denominator is zero")
	case c.BaseFeeChangeDenom == 0:
		return errBadConfig("base-fee change denominator is zero")
	case c.BaseFeeFloor == 0:
		return errBadConfig("base-fee floor must be positive")
	case c.BaseFeeFloor > MaxBaseFee:
		return errBadConfig("base-fee floor exceeds MaxBaseFee")
	case c.GSys == 0:
		return errBadConfig("g_sys must be positive (the system operation always runs)")
	case c.GSys+c.GFI >= c.GMax:
		return errBadConfig("g_sys + g_fi leaves no ordinary capacity")
	case (c.GMax-c.GSys-c.GFI)/c.ElasticityDenom == 0:
		return errBadConfig("ordinary target rounds to zero")
	}
	return nil
}

type configError struct{ msg string }

func (e configError) Error() string { return "evmroot: exec config: " + e.msg }
func errBadConfig(m string) error   { return configError{m} }

// OrdinaryCapacity is g_max - g_sys - g_fi: the gas available to
// discretionary user transactions.
func (c ExecConfig) OrdinaryCapacity() uint64 { return c.GMax - c.GSys - c.GFI }

// OrdinaryTarget is the EIP-1559 gas target, taken over the *ordinary*
// capacity only. System and forced-inclusion gas are protocol-mandated and
// are deliberately excluded from the base-fee feedback loop — they are not
// a congestion signal.
func (c ExecConfig) OrdinaryTarget() uint64 { return c.OrdinaryCapacity() / c.ElasticityDenom }

// BlockWork is the gas actually consumed in one produced block, split by
// origin. Only Ordinary feeds the base-fee update.
type BlockWork struct {
	System   uint64 // actual gas of the single privileged seal operation (<= GSys)
	Forced   uint64 // g_fi consumption charge for REJECTED forced entries only (<= GFI). A successful forced tx is an ordinary tx; its gas is in Ordinary and its receipt is in receiptsRoot.
	Ordinary uint64 // discretionary + successful-forced transaction gas (<= OrdinaryCapacity), i.e. the cumulative gas of the transaction list
}

// HeaderGasUsed is the block header's gasUsed field: the standard
// cumulative gas over the transaction list (Ordinary, which now includes
// successful forced txs) PLUS the seal call's g_sys work PLUS the g_fi
// consumption charge for rejected entries. It is NOT "entirely unchanged"
// vs a vanilla block — it includes the system-call gas.
func (w BlockWork) HeaderGasUsed() uint64 { return w.System + w.Forced + w.Ordinary }

// GasCheck is the per-block gas validity result.
type GasCheck struct {
	BudgetOK      bool   // g_sys + g_fi + g_ordinary_capacity <= g_max, and each actual <= its budget
	HeaderGasUsed uint64 // System + Forced + Ordinary
	Reason        string // first failure, "" when BudgetOK
}

// CheckGas validates one block's work against the configuration.
func (c ExecConfig) CheckGas(w BlockWork) GasCheck {
	switch {
	case c.GSys+c.GFI > c.GMax:
		return GasCheck{Reason: "config: g_sys + g_fi exceeds g_max"}
	case w.System == 0:
		return GasCheck{Reason: "system operation consumed no gas — it must run on every successful block"}
	case w.System > c.GSys:
		return GasCheck{Reason: "system gas exceeds reserved g_sys — block invalid, not silently truncated"}
	case w.Forced > c.GFI:
		return GasCheck{Reason: "forced-inclusion gas exceeds reserved g_fi"}
	case w.Ordinary > c.OrdinaryCapacity():
		return GasCheck{Reason: "ordinary gas exceeds g_max - g_sys - g_fi"}
	case w.HeaderGasUsed() > c.GMax:
		return GasCheck{Reason: "total gasUsed exceeds g_max"}
	}
	return GasCheck{BudgetOK: true, HeaderGasUsed: w.HeaderGasUsed()}
}

// mulDivFloor returns floor(a * b / d) computed through a full 128-bit
// intermediate — a * b never truncates. Requires d > 0 and the quotient to
// fit in uint64 (guaranteed by NextBaseFee's caller invariants: b <= d, so
// a*b/d <= a).
func mulDivFloor(a, b, d uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	if hi >= d { // quotient would overflow uint64 — clamp defensively
		return a
	}
	q, _ := bits.Div64(hi, lo, d)
	return q
}

// NextBaseFee applies the EIP-1559 update using the *ordinary* gas used and
// the *ordinary* target, then clamps to the positive floor. Every product
// goes through a 128-bit intermediate (mulDivFloor); the earlier version
// multiplied two uint64 before dividing and overflowed for representable
// parent base fees.
//
// The London formula, with the ordinary substitutions (numerator is the
// unsigned gap, always <= target because a valid block's ordinary gas is
// bounded by OrdinaryCapacity == 2*target):
//
//	used == target      -> child = parent
//	used  > target      -> child = parent + max(1, floor(parent*(used-target)/target)/denom)
//	used  < target      -> child = parent - floor(parent*(target-used)/target)/denom
//	child               -> max(child, floor), and <= MaxBaseFee
func (c ExecConfig) NextBaseFee(parentBaseFee uint64, w BlockWork) uint64 {
	target := c.OrdinaryTarget()
	used := w.Ordinary
	if used > 2*target {
		used = 2 * target // a valid block cannot exceed this; clamp rather than trust
	}
	var child uint64
	switch {
	case target == 0 || used == target:
		child = parentBaseFee
	case used > target:
		delta := mulDivFloor(parentBaseFee, used-target, target) / c.BaseFeeChangeDenom
		if delta == 0 {
			delta = 1
		}
		child = parentBaseFee + delta
	default: // used < target
		delta := mulDivFloor(parentBaseFee, target-used, target) / c.BaseFeeChangeDenom
		if parentBaseFee > delta {
			child = parentBaseFee - delta
		}
	}
	if child < c.BaseFeeFloor {
		child = c.BaseFeeFloor
	}
	if child > MaxBaseFee {
		child = MaxBaseFee
	}
	return child
}

// RecoverOrdinaryGas reconstructs the ordinary gas used from the header and
// the system / forced-prefix receipts — the value that feeds the next base
// fee. It is authenticated, not trusted: header gasUsed and each receipt's
// cumulativeGasUsed are part of the block, and the forced-prefix boundary
// is the deterministic inbox watermark (D5). Returns (0, false) if the
// receipts do not fit inside the header total.
func RecoverOrdinaryGas(headerGasUsed, systemReceiptGas, forcedReceiptGasSum uint64) (uint64, bool) {
	if systemReceiptGas+forcedReceiptGasSum > headerGasUsed {
		return 0, false
	}
	return headerGasUsed - systemReceiptGas - forcedReceiptGasSum, true
}
