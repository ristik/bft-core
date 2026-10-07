package bridgeprofile

import "fmt"

// replaceCertificateItem preserves all unrelated encoded bytes, including the
// signed immutable justification carried by a token. Paths index scanned CBOR
// children (a tag has one child).
func replaceCertificateItem(raw, replacement []byte, path ...int) ([]byte, error) {
	root, err := scanOneNative(raw)
	if err != nil {
		return nil, err
	}
	it := root
	for _, index := range path {
		if index < 0 || index >= len(it.kids) {
			return nil, fmt.Errorf("certificate fixture path %v", path)
		}
		it = &it.kids[index]
	}
	out := append([]byte{}, raw[:it.start]...)
	out = append(out, replacement...)
	return append(out, raw[it.end:]...), nil
}

type certificateMutation struct {
	name           string
	path           []int
	replacement    []byte
	nativeAccepted bool
}

// Isolated SDK/native intersection sentinels. The native-only accepted cases
// deliberately stay accepted by B1; the bridge must reject their exact bytes.
func certificateMutations() []certificateMutation {
	return []certificateMutation{
		{"summary-null", []int{0, 1, 0, 5}, CNull, true},
		{"summary-text", []int{0, 1, 0, 5}, []byte{0x60}, false},
		{"shard-siblings-null", []int{0, 4, 0, 2}, CNull, true},
		{"shard-siblings-bytes", []int{0, 4, 0, 2}, CBytes(nil), false},
		{"unicity-steps-null", []int{0, 5, 0, 2}, CNull, true},
		{"unicity-steps-bytes", []int{0, 5, 0, 2}, CBytes(nil), false},
		{"signatures-null", []int{0, 6, 0, 7}, CNull, true},
		{"signatures-array", []int{0, 6, 0, 7}, CArr(), false},
		{"seal-network-zero", []int{0, 6, 0, 1}, CUint(0), true},
		{"seal-network-overflow", []int{0, 6, 0, 1}, CUint(65536), false},
		{"signature-not-bytes", []int{0, 6, 0, 7, 1}, CNull, false},
		{"signature-key-not-text", []int{0, 6, 0, 7, 0}, CUint(1), false},
		{"signature-key-invalid-utf8", []int{0, 6, 0, 7, 0}, []byte{0x61, 0xff}, false},
		{"partition-overflow", []int{0, 5, 0, 1}, CUint(1 << 32), false},
		{"unicity-step-key-overflow", []int{0, 5, 0, 2}, CArr(CArr(CUint(1<<32), CBytes(make([]byte, 32)))), false},
		{"unicity-step-null-hash", []int{0, 5, 0, 2}, CArr(CArr(CUint(1), CNull)), false},
		{"shard-sibling-null", []int{0, 4, 0, 2}, CArr(CNull), false},
		{"signature-recovery-two", []int{0, 6, 0, 7, 1}, CBytes(append(make([]byte, 64), 2)), false},
	}
}

func certificateWithSteps(raw []byte, n int) ([]byte, error) {
	steps := make([][]byte, n)
	for i := range steps {
		steps[i] = CArr(CUint(uint64(i)), CBytes(make([]byte, 32)))
	}
	return replaceCertificateItem(raw, CArr(steps...), 0, 5, 0, 2)
}
