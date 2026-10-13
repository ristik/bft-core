package b1ref

// SetWorkHook installs the test instrumentation hook (nil removes it).
func SetWorkHook(f func(kind string)) { onWork = f }

// EvalClaims evaluates claims, each in the v1 claim encoding, as one verification-local batch: any number of claims, in any order,
// under any seals. It is the encoding-independent core of the registry-backed certificate batch, reachable from tests before the
// batch ABI exists. An unavailable registry or an infrastructure failure is returned as ErrInfrastructure, as Run would.
func EvalClaims(wires [][]byte, reg *Registry) error {
	claims := make([]claim, 0, len(wires))
	for _, w := range wires {
		tokens := 0
		r := &reader{b: w}
		c, err := parseClaim(r, &tokens)
		if err != nil {
			return err
		}
		if r.left() != 0 {
			return ErrTrailingBytes
		}
		claims = append(claims, c)
	}
	if !registryReady(reg) {
		return ErrInfrastructure
	}
	if reg.Phase == 1 {
		return ErrPhase
	}
	return newBatch(reg).eval(claims)
}
