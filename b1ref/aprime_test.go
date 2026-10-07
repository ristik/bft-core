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
