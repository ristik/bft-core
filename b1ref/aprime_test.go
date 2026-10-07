package b1ref

import (
	"encoding/hex"
	"errors"
	"github.com/unicitynetwork/bft-core/b1ref/b1gen"
	"testing"
)

func TestCallerScannerAllocatesNothing(t *testing.T) {
	m := b1gen.Build("b1-oracle-v1")
	for _, id := range []string{"cert.single.ok", "cert.shared.max-8.ok", "quorum.max.all"} {
		for _, v := range m.Vectors {
			if v.ID != id {
				continue
			}
			raw, _ := hex.DecodeString(v.Request)
			if _, err := scanCertCall(raw, v.Op == "SHARED_SEAL_V1"); err != nil {
				t.Fatal(err)
			}
			if n := testing.AllocsPerRun(100, func() { scanCertCall(raw, v.Op == "SHARED_SEAL_V1") }); n != 0 {
				t.Fatalf("%s: %g allocations", id, n)
			}
		}
	}
}
func TestUnavailableRegistryAfterFullDebit(t *testing.T) {
	m := b1gen.Build("b1-oracle-v1")
	var raw []byte
	var gas uint64
	for _, v := range m.Vectors {
		if v.ID == "cert.single.ok" {
			raw, _ = hex.DecodeString(v.Request)
			gas = v.Expected.Gas
		}
	}
	if _, _, err := Run(OpUC, raw, nil, gas-1); !errors.Is(err, ErrOutOfGas) {
		t.Fatal(err)
	}
	if _, _, err := Run(OpUC, raw, nil, gas); !errors.Is(err, ErrInfrastructure) || errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
}
func TestCallerScannerRejectsSignatureShape(t *testing.T) {
	m := b1gen.Build("b1-oracle-v1")
	count := 0
	for _, v := range m.Vectors {
		if v.Expected.Sentinel != "ErrSigFormat" {
			continue
		}
		raw, _ := hex.DecodeString(v.Request)
		if _, err := scanCertCall(raw, false); !errors.Is(err, ErrSigFormat) {
			t.Fatalf("%s: %v", v.ID, err)
		}
		count++
	}
	if count < 6 {
		t.Fatal("missing signature format cases", count)
	}
}

// certFrame wraps one UC payload in a valid single-claim call frame. The UC is
// last, so slicing the frame with cap=len leaves the payload with no spare
// capacity: reads past its end panic instead of silently succeeding.
func certFrame(uc []byte) []byte {
	f := []byte{1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0x80}
	f = append(f, make([]byte, 96)...)
	f = append(f, byte(len(uc)>>24), byte(len(uc)>>16), byte(len(uc)>>8), byte(len(uc)))
	f = append(f, uc...)
	return f[:len(f):len(f)]
}

func TestCallerScannerEmptyUC(t *testing.T) {
	if _, err := scanCertCall(certFrame(nil), false); !errors.Is(err, ErrTruncated) {
		t.Fatal(err)
	}
}

func TestCallerScannerTightCapacityTruncation(t *testing.T) {
	for name, uc := range map[string][]byte{
		"bytes-inline":    {0x45, 1, 2, 3},
		"text-inline":     {0x65, 'a', 'b', 'c'},
		"bytes-no-body":   {0x58, 32},
		"text-no-body":    {0x78, 32},
		"bytes-one-short": {0x43, 1, 2},
	} {
		if _, err := scanCertCall(certFrame(uc), false); !errors.Is(err, ErrTruncated) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestCallerScannerDuplicateBeforeDecode(t *testing.T) {
	// {1:0, 2:0, 1:0}: the later duplicate key is found by the allocation-free
	// pass, before the shape reader or any decoder sees the UC.
	uc := []byte{0xa3, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00}
	if _, err := scanCertCall(certFrame(uc), false); !errors.Is(err, ErrDuplicateMapKey) {
		t.Fatal(err)
	}
}
