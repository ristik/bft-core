package s1ref_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/unicitynetwork/bft-core/s1ref"
)

func TestGasFormula(t *testing.T) {
	if got := s1ref.Gas(s1ref.MaxInputBytes, s1ref.MaxMembers, 4, 2); got != 389168 || s1ref.MaxGas != 389168 {
		t.Fatalf("conservative maximum %d, MaxGas %d, want 389168", got, s1ref.MaxGas)
	}
	if s1ref.MaxInputBytes != 4+4+s1ref.MaxViewBytes+2*(4+s1ref.MaxEvidenceBytes) {
		t.Fatal("MaxInputBytes is not the maximum framing")
	}
	// 2000 + 16*B + 1000*M + 6000*S + 2000*N
	if got := s1ref.Gas(1000, 4, 3, 2); got != 2000+16000+4000+18000+4000 {
		t.Fatalf("Gas(1000,4,3,2) = %d", got)
	}
}

func TestOutputLayout(t *testing.T) {
	off := &s1ref.Offence{Scheme: 2, Network: 0x0102, Epoch: 0x0304, Round: 0x0506, Kind: 1}
	off.DomainHash[0], off.SignerID[1], off.ConflictID[2], off.ContentA[3], off.ContentB[4] = 0xd0, 0xd1, 0xd2, 0xd3, 0xd4
	out := s1ref.Output(s1ref.Verdict{Valid: true, Offence: off})
	if len(out) != 384 {
		t.Fatalf("true output is %d bytes", len(out))
	}
	word := func(i int) []byte { return out[32*i : 32*i+32] }
	u := func(tail ...byte) []byte { w := make([]byte, 32); copy(w[32-len(tail):], tail); return w }
	want := map[int][]byte{0: u(1), 1: u(1), 2: u(2), 3: u(1, 2), 6: u(3, 4), 7: u(5, 6), 8: u(1)}
	for i, w := range want {
		if !bytes.Equal(word(i), w) {
			t.Errorf("word %d = %x", i, word(i))
		}
	}
	if word(4)[0] != 0xd0 || word(5)[1] != 0xd1 || word(9)[2] != 0xd2 || word(10)[3] != 0xd3 || word(11)[4] != 0xd4 {
		t.Error("hash words are not literal bytes32")
	}
	f := s1ref.Output(s1ref.Verdict{})
	if len(f) != 64 || f[31] != 1 || !allZero(f[32:]) || !allZero(f[:31]) {
		t.Errorf("false output %x", f)
	}
	if g := s1ref.Output(s1ref.Verdict{Valid: false, Offence: off}); len(g) != 64 {
		t.Error("a false verdict must never carry offence words")
	}
}

// TestClassification pins S1 caller classifications. A′ B1 no longer accepts
// a caller authority view; its authority defects fail admission instead.
func TestClassification(t *testing.T) {
	for name, e := range map[string]error{
		"unsorted view": s1ref.ErrViewOrder, "invalid point": s1ref.ErrViewKey, "empty view": s1ref.ErrViewEmpty,
		"duplicate": s1ref.ErrViewDuplicate, "weight": s1ref.ErrWeightProfile,
	} {
		if !errors.Is(e, s1ref.ErrInvalid) || errors.Is(e, s1ref.ErrMalformed) {
			t.Errorf("%s must be false in S1", name)
		}
	}
	for name, e := range map[string]error{"bad signature length": s1ref.ErrSigShape, "bad scheme": s1ref.ErrScheme, "bad kind": s1ref.ErrViewKind} {
		if !errors.Is(e, s1ref.ErrMalformed) {
			t.Errorf("%s must be malformed in S1", name)
		}
	}
	if !errors.Is(s1ref.ErrInputTooLarge, s1ref.ErrBound) || !errors.Is(s1ref.ErrBound, s1ref.ErrMalformed) {
		t.Error("bound errors are a malformed subfamily")
	}
}

// TestAbsentContextIsFalse: a nil context, an empty one and one without the
// voting epoch are authenticated absence, which is false and never an error.
func TestAbsentContextIsFalse(t *testing.T) {
	m, _ := loadGolden(t)
	for _, v := range m.Vectors {
		if v.ID != "s2.noncommitting.ok" {
			continue
		}
		for name, ctx := range map[string]*s1ref.Context{"nil": nil, "empty": {}, "no epochs": {Network: 9, OpenEpoch: 2, Epochs: map[uint64]s1ref.EpochEntry{}}} {
			got, err := s1ref.Verify(requestOf(t, v), ctx)
			if err != nil || got.Valid || !errors.Is(got.Why, s1ref.ErrUnknownEpoch) && !errors.Is(got.Why, s1ref.ErrNetwork) {
				t.Errorf("%s: %+v %v", name, got, err)
			}
			if got.Gas != v.Expected.Gas {
				t.Errorf("%s: absence must still be charged in full", name)
			}
		}
	}
}
