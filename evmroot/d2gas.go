package evmroot

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

// OrdinaryCapacity is g_max - g_sys - g_fi: the gas available to
// discretionary user transactions.
func (c ExecConfig) OrdinaryCapacity() uint64 { return c.GMax - c.GSys - c.GFI }

// OrdinaryTarget is the EIP-1559 gas target, taken over the *ordinary*
// capacity only. System and forced-inclusion gas are protocol-mandated and
// are deliberately excluded from the base-fee feedback loop — they are not
// a congestion signal.
func (c ExecConfig) OrdinaryTarget() uint64 { return c.OrdinaryCapacity() / c.ElasticityDenom }

// BlockWork is the gas actually consumed in one produced block, split by
// origin. All three are metered; only Ordinary feeds the base-fee update.
type BlockWork struct {
	System   uint64 // actual gas of the single privileged seal operation (<= GSys)
	Forced   uint64 // actual gas of the executed forced-inclusion prefix (<= GFI)
	Ordinary uint64 // actual gas of discretionary transactions (<= OrdinaryCapacity)
}

// HeaderGasUsed is the value written to the block header's gasUsed field:
// every executed unit, system + forced + ordinary. Receipts and tracing
// are consistent with this total (each system/forced entry has a receipt
// with its own cumulativeGasUsed contribution).
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

// NextBaseFee applies the EIP-1559 update using the *ordinary* gas used and
// the *ordinary* target, then clamps to the positive floor. parentBaseFee
// is the previous block's base fee.
//
// The London formula, with the ordinary substitutions:
//
//	used == target      -> child = parent
//	used  > target      -> child = parent + max(1, parent*(used-target)/target/denom)
//	used  < target      -> child = parent - parent*(target-used)/target/denom
//	child               -> max(child, floor)
func (c ExecConfig) NextBaseFee(parentBaseFee uint64, w BlockWork) uint64 {
	target := c.OrdinaryTarget()
	used := w.Ordinary
	var child uint64
	switch {
	case target == 0:
		child = parentBaseFee
	case used == target:
		child = parentBaseFee
	case used > target:
		delta := parentBaseFee * (used - target) / target / c.BaseFeeChangeDenom
		if delta == 0 {
			delta = 1
		}
		child = parentBaseFee + delta
	default: // used < target
		delta := parentBaseFee * (target - used) / target / c.BaseFeeChangeDenom
		if parentBaseFee > delta {
			child = parentBaseFee - delta
		}
	}
	if child < c.BaseFeeFloor {
		child = c.BaseFeeFloor
	}
	return child
}
