package vrschema

import (
	"errors"
	"math/big"
)

// Fee profile errors (the ureth BlockAccountingError names).
var (
	ErrFeeZero        = errors.New("ZeroParameter")
	ErrFeeNoCapacity  = errors.New("NoOrdinaryCapacity")
	ErrFeeBaseFee     = errors.New("InvalidParentBaseFee")
	ErrFeeUnsupported = errors.New("UnsupportedProfile")
	ErrFeeCollector   = errors.New("ZeroFeeCollector")
	ErrFeeOverflow    = errors.New("Overflow")
)

// Elasticity is fixed at 2 for every generation.
const Elasticity = 2

// ValidateChange is the part of FeeParams validation that needs no generation fields.
func (f FeeParams) ValidateChange() error {
	switch {
	case f.BaseFeeFloor == 0 || f.ChangeDenominator == 0:
		return ErrFeeZero
	case f.BaseFeeFloor > MaxBaseFee:
		return ErrFeeBaseFee
	case f.FeeCollector == [20]byte{}:
		return ErrFeeCollector
	}
	return nil
}

// ValidateProfile is ureth BlockProfile.validate over the generation's fixed fields (maxGas, systemGas, elasticity 2) and the new fee
// parameters, plus a nonzero collector: the queue-time check of a FeeParams change.
func ValidateProfile(maxGas, systemGas uint64, f FeeParams) error {
	if maxGas == 0 || systemGas == 0 || f.BaseFeeFloor == 0 || f.ChangeDenominator == 0 {
		return ErrFeeZero
	}
	if systemGas >= maxGas {
		return ErrFeeNoCapacity
	}
	if f.BaseFeeFloor > MaxBaseFee {
		return ErrFeeBaseFee
	}
	if (maxGas-systemGas)%Elasticity != 0 {
		return ErrFeeUnsupported
	}
	if f.FeeCollector == [20]byte{} {
		return ErrFeeCollector
	}
	return nil
}

// FeesFor is F(N): current when N >= effectiveBlock, otherwise previous, both read at N-1's post-state.
func FeesFor(n uint64, s Fees) FeeParams {
	if n >= s.EffectiveBlock {
		return s.Current
	}
	return s.Previous
}

// ApplyFeeBoundary is the Boundary transition in block bAck: previous := current, current := new, effectiveBlock := bAck + 1.
func ApplyFeeBoundary(s Fees, next FeeParams, bAck uint64) Fees {
	return Fees{Previous: s.Current, Current: next, EffectiveBlock: bAck + 1}
}

// NextBaseFee is ureth next_base_fee with the child's F(N): clamp(eip1559(parent ordinary gas, denominator), floor, MAX_BASE_FEE).
// ordinaryCapacity is maxGas - systemGas; the parent base fee must already be reconciled under F(N-1).
func NextBaseFee(parentBaseFee, ordinaryUsed, ordinaryCapacity uint64, f FeeParams) (uint64, error) {
	if f.ChangeDenominator == 0 || f.BaseFeeFloor == 0 {
		return 0, ErrFeeZero
	}
	target := ordinaryCapacity / Elasticity
	if target == 0 {
		return 0, ErrFeeNoCapacity
	}
	next := parentBaseFee
	if ordinaryUsed != target {
		var num uint64
		if ordinaryUsed > target {
			num = ordinaryUsed - target
		} else {
			num = target - ordinaryUsed
		}
		p := new(big.Int).Mul(new(big.Int).SetUint64(parentBaseFee), new(big.Int).SetUint64(num))
		p.Div(p, new(big.Int).SetUint64(target))
		p.Div(p, new(big.Int).SetUint64(f.ChangeDenominator))
		if !p.IsUint64() {
			return 0, ErrFeeOverflow
		}
		d := p.Uint64()
		if ordinaryUsed > target {
			if d == 0 {
				d = 1
			}
			if parentBaseFee > ^uint64(0)-d {
				return 0, ErrFeeOverflow
			}
			next = parentBaseFee + d
		} else if d >= parentBaseFee {
			next = 0
		} else {
			next = parentBaseFee - d
		}
	}
	if next < f.BaseFeeFloor {
		next = f.BaseFeeFloor
	}
	if next > MaxBaseFee {
		next = MaxBaseFee
	}
	return next, nil
}

// ReconcileParentBaseFee is the parent check under F(N-1): floor <= base fee <= MAX_BASE_FEE.
func ReconcileParentBaseFee(baseFee uint64, parentFees FeeParams) error {
	if baseFee < parentFees.BaseFeeFloor || baseFee > MaxBaseFee {
		return ErrFeeBaseFee
	}
	return nil
}
