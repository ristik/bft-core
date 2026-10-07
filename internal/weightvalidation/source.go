package weightvalidation

import "fmt"

// ModeSource is a trust source that knows which validation rules an epoch's data falls under. q3active's guarded trust lookup is
// the only implementation in the module: it answers ModeWeighted only for an epoch the verified history holds as an activated V3
// epoch whose installation is complete, so no consumer selects the weighted rules by a flag of its own.
type ModeSource interface {
	Mode(epoch uint64) (Mode, error)
}

// ModeFor is the validation mode for the data of a root epoch. A source that is not a ModeSource (every legacy trust store) is the
// unit-weight world and stays so; a ModeSource that cannot answer for the epoch refuses it rather than fall back to either mode.
func ModeFor(source any, epoch uint64) (Mode, error) {
	ms, ok := source.(ModeSource)
	if !ok {
		return ModeUnit, nil
	}
	m, err := ms.Mode(epoch)
	if err != nil {
		return 0, fmt.Errorf("validation mode of root epoch %d: %w", epoch, err)
	}
	if m < ModeUnit || m > ModeWeighted {
		return 0, fmt.Errorf("%w: mode %d", ErrContext, m)
	}
	return m, nil
}

// ModeOfTrustBase is the mode a verified trust base carries with it: a value that has a ValidationMode method (what the guarded
// lookup hands out for an activated epoch) says it, and a plain trust base is the unit world.
func ModeOfTrustBase(tb any) Mode {
	if v, ok := tb.(interface{ ValidationMode() Mode }); ok {
		if m := v.ValidationMode(); m >= ModeUnit && m <= ModeWeighted {
			return m
		}
	}
	return ModeUnit
}
