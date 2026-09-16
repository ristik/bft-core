package parentwitness

import "fmt"

// validateCBORBounds walks the restricted wire grammar without allocating. Frame admission bounds
// total bytes; this pass additionally refuses oversized nested collections and byte strings before
// the general CBOR decoder can allocate them.
func validateCBORBounds(raw []byte) error {
	n, err := scanCBOR(raw, 0)
	if err != nil {
		return err
	}
	if n != len(raw) {
		return fmt.Errorf("%w: trailing CBOR item", ErrWire)
	}
	return nil
}

func scanCBOR(raw []byte, depth int) (int, error) {
	if depth > 16 || len(raw) == 0 {
		return 0, fmt.Errorf("%w: CBOR nesting/truncation", ErrBounds)
	}
	major, ai := raw[0]>>5, raw[0]&31
	n, head, err := cborArgument(raw, ai)
	if err != nil {
		return 0, err
	}
	switch major {
	case 0:
		return head, nil
	case 2:
		if n > 1024 {
			return 0, fmt.Errorf("%w: byte string is %d bytes", ErrBounds, n)
		}
		if n > uint64(len(raw)-head) {
			return 0, fmt.Errorf("%w: truncated byte string", ErrWire)
		}
		return head + int(n), nil
	case 3:
		if n > MaxDiagnosticBytes {
			return 0, fmt.Errorf("%w: text is %d bytes", ErrBounds, n)
		}
		if n > uint64(len(raw)-head) {
			return 0, fmt.Errorf("%w: truncated text", ErrWire)
		}
		return head + int(n), nil
	case 4:
		if n > 2048 {
			return 0, fmt.Errorf("%w: array has %d items", ErrBounds, n)
		}
		off := head
		for range n {
			used, err := scanCBOR(raw[off:], depth+1)
			if err != nil {
				return 0, err
			}
			off += used
		}
		return off, nil
	case 7:
		if ai == 22 {
			return 1, nil
		}
	}
	return 0, fmt.Errorf("%w: forbidden CBOR major type %d", ErrWire, major)
}

func cborArgument(raw []byte, ai byte) (uint64, int, error) {
	switch {
	case ai < 24:
		return uint64(ai), 1, nil
	case ai == 24:
		if len(raw) < 2 {
			break
		}
		return uint64(raw[1]), 2, nil
	case ai == 25:
		if len(raw) < 3 {
			break
		}
		return uint64(raw[1])<<8 | uint64(raw[2]), 3, nil
	case ai == 26:
		if len(raw) < 5 {
			break
		}
		return uint64(raw[1])<<24 | uint64(raw[2])<<16 | uint64(raw[3])<<8 | uint64(raw[4]), 5, nil
	case ai == 27:
		if len(raw) < 9 {
			break
		}
		var n uint64
		for _, b := range raw[1:9] {
			n = n<<8 | uint64(b)
		}
		return n, 9, nil
	}
	return 0, 0, fmt.Errorf("%w: invalid/truncated CBOR argument", ErrWire)
}
