package bridgeprofile

// A strict, minimal RLP reader for header, account and trie-node checks. It
// rejects every non-minimal length, a single byte below 0x80 wrapped as a
// string, trailing bytes and nesting over MaxRLPDepth. It never allocates from
// a declared length before comparing it with the remaining input.

type rlpItem struct {
	list bool
	str  []byte    // payload of a string
	kids []rlpItem // items of a list
	raw  []byte    // the exact encoding of this item
}

// rlpDecode decodes exactly one item spanning all of b.
func rlpDecode(b []byte) (rlpItem, error) {
	it, n, err := rlpRead(b, 0)
	if err != nil {
		return rlpItem{}, err
	}
	if n != len(b) {
		return rlpItem{}, ErrRLP
	}
	return it, nil
}

func rlpRead(b []byte, depth int) (rlpItem, int, error) {
	if len(b) == 0 {
		return rlpItem{}, 0, ErrRLP
	}
	if depth > MaxRLPDepth {
		return rlpItem{}, 0, ErrRLP
	}
	p := b[0]
	switch {
	case p < 0x80:
		return rlpItem{str: b[:1], raw: b[:1]}, 1, nil
	case p <= 0xb7:
		n := int(p - 0x80)
		if len(b) < 1+n {
			return rlpItem{}, 0, ErrRLP
		}
		if n == 1 && b[1] < 0x80 {
			return rlpItem{}, 0, ErrRLP // a single low byte must be its own encoding
		}
		return rlpItem{str: b[1 : 1+n], raw: b[:1+n]}, 1 + n, nil
	case p <= 0xbf:
		ll := int(p - 0xb7)
		n, err := rlpLen(b[1:], ll)
		if err != nil || n < 56 || n > len(b)-1-ll {
			return rlpItem{}, 0, ErrRLP
		}
		return rlpItem{str: b[1+ll : 1+ll+n], raw: b[:1+ll+n]}, 1 + ll + n, nil
	}
	var hdr, n int
	if p <= 0xf7 {
		hdr, n = 1, int(p-0xc0)
	} else {
		ll := int(p - 0xf7)
		l, err := rlpLen(b[1:], ll)
		if err != nil || l < 56 {
			return rlpItem{}, 0, ErrRLP
		}
		hdr, n = 1+ll, l
	}
	if n > len(b)-hdr {
		return rlpItem{}, 0, ErrRLP
	}
	it := rlpItem{list: true, raw: b[:hdr+n]}
	for off := hdr; off < hdr+n; {
		kid, used, err := rlpRead(b[off:hdr+n], depth+1)
		if err != nil {
			return rlpItem{}, 0, err
		}
		it.kids = append(it.kids, kid)
		off += used
	}
	return it, hdr + n, nil
}

// rlpLen reads an ll-byte big-endian length with no leading zero.
func rlpLen(b []byte, ll int) (int, error) {
	if ll > 4 || len(b) < ll || b[0] == 0 {
		return 0, ErrRLP
	}
	n := 0
	for _, x := range b[:ll] {
		n = n<<8 | int(x)
	}
	return n, nil
}

// rlpUint reads a canonical RLP integer string: no leading zero byte, at most
// 32 bytes (the empty string is zero).
func (it rlpItem) uintBytes() ([]byte, bool) {
	if it.list || len(it.str) > 32 || (len(it.str) > 0 && it.str[0] == 0) {
		return nil, false
	}
	return it.str, true
}
