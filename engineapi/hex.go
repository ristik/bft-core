package engineapi

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// The Engine API's JSON encoding, per the execution-apis spec, distinguishes
// two hex conventions and is strict about both:
//
//   - QUANTITY (a number): "0x" + the minimal hex digits, no leading zeros,
//     except the value zero itself, which is "0x0". "0x0f" is invalid.
//   - DATA (a byte string): "0x" + exactly two hex digits per byte, so
//     always an even-length string after the prefix. "0x0" is invalid here.
//
// hand-rolled rather than imported from go-ethereum's hexutil — see
// docs/adr/0001-executor-boundary.md decision 1.

// quantity encodes/decodes a QUANTITY field.
type quantity uint64

func (q quantity) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"0x%x"`, uint64(q))), nil
}

func (q *quantity) UnmarshalJSON(data []byte) error {
	s, err := unquote(data)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(s, "0x") {
		return fmt.Errorf("engineapi: quantity %q missing 0x prefix", s)
	}
	digits := s[2:]
	if digits == "" {
		return fmt.Errorf("engineapi: quantity %q has no digits", s)
	}
	if len(digits) > 1 && digits[0] == '0' {
		return fmt.Errorf("engineapi: quantity %q has a leading zero", s)
	}
	var v uint64
	if _, err := fmt.Sscanf(digits, "%x", &v); err != nil {
		return fmt.Errorf("engineapi: quantity %q: %w", s, err)
	}
	*q = quantity(v)
	return nil
}

// data encodes/decodes a DATA field of any length.
type data []byte

func (d data) MarshalJSON() ([]byte, error) {
	return []byte(`"0x` + hex.EncodeToString(d) + `"`), nil
}

func (d *data) UnmarshalJSON(raw []byte) error {
	s, err := unquote(raw)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(s, "0x") {
		return fmt.Errorf("engineapi: data %q missing 0x prefix", s)
	}
	digits := s[2:]
	if len(digits)%2 != 0 {
		return fmt.Errorf("engineapi: data %q has an odd number of hex digits", s)
	}
	b, err := hex.DecodeString(digits)
	if err != nil {
		return fmt.Errorf("engineapi: data %q: %w", s, err)
	}
	*d = b
	return nil
}

// data32/data20 are fixed-length DATA fields (hashes, addresses). Encoding
// is identical to data; the length is enforced on decode so a malformed
// response fails at the boundary instead of producing a silently
// short/long hash deep inside adapter logic.
type data32 [32]byte

func (d data32) MarshalJSON() ([]byte, error) { return data(d[:]).MarshalJSON() }
func (d *data32) UnmarshalJSON(raw []byte) error {
	var b data
	if err := b.UnmarshalJSON(raw); err != nil {
		return err
	}
	if len(b) != 32 {
		return fmt.Errorf("engineapi: expected 32 bytes, got %d", len(b))
	}
	copy(d[:], b)
	return nil
}

type data20 [20]byte

func (d data20) MarshalJSON() ([]byte, error) { return data(d[:]).MarshalJSON() }
func (d *data20) UnmarshalJSON(raw []byte) error {
	var b data
	if err := b.UnmarshalJSON(raw); err != nil {
		return err
	}
	if len(b) != 20 {
		return fmt.Errorf("engineapi: expected 20 bytes, got %d", len(b))
	}
	copy(d[:], b)
	return nil
}

func unquote(raw []byte) (string, error) {
	s := string(raw)
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", fmt.Errorf("engineapi: expected a JSON string, got %s", s)
	}
	return s[1 : len(s)-1], nil
}
