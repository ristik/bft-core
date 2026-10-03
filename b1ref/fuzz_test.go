package b1ref_test

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/b1ref/b1gen"
)

// seedFuzz adds every committed request of the given ops as a corpus entry.
func seedFuzz(f *testing.F, ops ...string) *b1gen.PreState {
	m, _ := loadGolden(f)
	var pre *b1gen.PreState
	for _, v := range m.Vectors {
		if v.ID == "cert.single.ok" {
			pre = v.PreState
		}
		for _, o := range ops {
			if v.Op == o && len(v.Request) < 60000 { // keep the corpus light; padding vectors add nothing
				req, _ := hex.DecodeString(v.Request)
				f.Add(req)
			}
		}
	}
	return pre
}

// checkVerdict asserts the malformed-versus-false split and the bounds that
// hold for every input, whatever its content.
func checkVerdict(t *testing.T, v b1ref.Verdict, err error, in []byte, maxGas uint64, maxIn int) {
	if len(in) > maxIn {
		if !errors.Is(err, b1ref.ErrInputTooLarge) {
			t.Fatalf("%d bytes admitted: %v", len(in), err)
		}
		return
	}
	if err != nil {
		if !errors.Is(err, b1ref.ErrMalformed) || errors.Is(err, b1ref.ErrInvalid) || v.Valid {
			t.Fatalf("error outside the malformed family: %v (%+v)", err, v)
		}
		return
	}
	if v.Valid != (v.Why == nil) || (!v.Valid && !errors.Is(v.Why, b1ref.ErrInvalid)) || errors.Is(v.Why, b1ref.ErrMalformed) {
		t.Fatalf("inconsistent verdict %+v", v)
	}
	if v.Gas > maxGas || v.Gas == 0 {
		t.Fatalf("charge %d outside (0, %d]", v.Gas, maxGas)
	}
}

func FuzzCertCall(f *testing.F) {
	pre := seedFuzz(f, "UC_V1", "SHARED_SEAL_V1")
	reg := registry(f, pre)
	f.Fuzz(func(t *testing.T, in []byte) {
		v, err := b1ref.UC(in, reg)
		checkVerdict(t, v, err, in, 5_294_304, b1ref.MaxCallBytes)
		v, err = b1ref.Shared(in, reg)
		checkVerdict(t, v, err, in, 5_294_304, b1ref.MaxCallBytes)
	})
}

func FuzzMember(f *testing.F) {
	seedFuzz(f, "RSMT_MEMBER_V1")
	f.Fuzz(func(t *testing.T, in []byte) {
		v, err := b1ref.Member(in)
		checkVerdict(t, v, err, in, 264_522, b1ref.MaxRSMTInputBytes)
	})
}
