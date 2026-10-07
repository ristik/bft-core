package b1state

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestUpdateEncodingRefusals(t *testing.T) {
	p := fixtureProfile(5)
	u := fixtureUpdate(p)
	raw := u.Bytes()
	// Every truncated prefix is malformed, with no member or point allocation.
	for cut := 0; cut < len(raw); cut++ {
		if _, _, err := Admit(raw[:cut], p, math.MaxUint64); !errors.Is(err, ErrEncoding) {
			t.Fatalf("cut %d: %v", cut, err)
		}
	}
	for _, first := range []byte{0x8c, 0xad, 0x9f, 0xd9} {
		bad := append([]byte(nil), raw...)
		bad[0] = first
		if _, _, err := Admit(bad, p, math.MaxUint64); !errors.Is(err, ErrEncoding) {
			t.Fatalf("first %x: %v", first, err)
		}
	}
	key := u.NewEntries[0].Members[0].Key
	keyCBOR := append([]byte{0x58, 33}, key[:]...)
	for _, badKey := range [][]byte{{0xf6}, append([]byte{0x58, 32}, key[:32]...), append([]byte{0x59, 0, 33}, key[:]...)} {
		bad := bytes.Replace(raw, keyCBOR, badKey, 1)
		if _, _, err := Admit(bad, p, math.MaxUint64); !errors.Is(err, ErrEncoding) {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*Update)
		want   error
	}{
		{"execution-chain", func(u *Update) { u.ExecutionChainID ^= 1 }, ErrBinding},
		{"prior-epoch", func(u *Update) { u.PriorTipEpoch = 1 }, ErrInterval},
		{"entry-genesis", func(u *Update) { u.NewEntries[0].BodyKind = 1; u.NewEntries[0].ActivationCommitID = [32]byte{} }, ErrInterval},
		{"expired", func(u *Update) { u.NewEntries[0].Start = 10; end := uint64(15); u.NewEntries[0].End = &end }, ErrInterval},
		{"future-end", func(u *Update) { end := uint64(21); u.NewEntries[0].End = &end }, ErrInterval},
		{"closed-tail", func(u *Update) { u.OriginRound = 21; end := uint64(21); u.NewEntries[0].End = &end }, ErrInterval},
		{"empty-closure", func(u *Update) { u.NewEntries = nil; u.OriginEpoch = 0 }, ErrInterval},
		{"empty-wrong-origin", func(u *Update) { u.NewEntries = nil; u.OldTipEnd = nil }, ErrInterval},
		{"duplicate-entries", func(u *Update) { u.NewEntries = append(u.NewEntries, clone(u.NewEntries[0])) }, ErrInterval},
		{"gap", func(u *Update) {
			end := uint64(21)
			u.NewEntries[0].End = &end
			u.OriginRound = 22
			u.OriginEpoch = 3
			u.NewEntries = append(u.NewEntries, fixtureEntry(3, 22))
		}, ErrInterval},
		{"wrong-closure", func(u *Update) { end := uint64(19); u.OldTipEnd = &end }, ErrInterval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := fixtureUpdate(p)
			tc.change(&bad)
			if _, _, err := Admit(bad.Bytes(), p, math.MaxUint64); !errors.Is(err, tc.want) {
				t.Fatalf("%v", err)
			}
		})
	}
	// Empty updates still bind height/parent/origin and incur scan gas.
	u = fixtureUpdate(p)
	u.NewEntries = nil
	u.OldTipEnd = nil
	u.OriginEpoch = u.PriorTipEpoch
	if _, gas, err := Admit(u.Bytes(), p, math.MaxUint64); err != nil || gas != uint64(2000+16*len(u.Bytes())) {
		t.Fatal(gas, err)
	}
}
func TestProfilePinRefusals(t *testing.T) {
	p := fixtureProfile(1)
	for _, change := range []func(*Profile){
		func(p *Profile) { p.Network = 0 }, func(p *Profile) { p.RootGenesisID = [32]byte{} }, func(p *Profile) { p.ExecutionChainID = 0 }, func(p *Profile) { p.CompilerHash = [32]byte{} }, func(p *Profile) { p.SystemGas = p.MaxGas + 1 }, func(p *Profile) { p.ForcedGas = p.MaxGas }, func(p *Profile) { p.OtherCompanionBytes = p.CompanionBytes + 1 },
	} {
		bad := p
		change(&bad)
		if err := bad.Validate(); !errors.Is(err, ErrProfile) {
			t.Fatal(err)
		}
	}
	p.WCert = math.MaxUint64 / 1000
	p.DeltaEV = p.WCert
	p.DeltaHold = p.WCert + 1
	if _, _, _, err := p.Bounds(); !errors.Is(err, ErrOverflow) {
		t.Fatal(err)
	}
}
