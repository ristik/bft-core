package b1state

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// widthCases are hand-written CBOR unsigned-integer encodings, independent of head().
var widthCases = []struct {
	v   uint64
	enc []byte
}{
	{23, []byte{0x17}},
	{24, []byte{0x18, 0x18}},
	{255, []byte{0x18, 0xff}},
	{256, []byte{0x19, 0x01, 0x00}},
	{65535, []byte{0x19, 0xff, 0xff}},
	{65536, []byte{0x1a, 0x00, 0x01, 0x00, 0x00}},
	{math.MaxUint32, []byte{0x1a, 0xff, 0xff, 0xff, 0xff}},
	{math.MaxUint32 + 1, []byte{0x1b, 0, 0, 0, 1, 0, 0, 0, 0}},
	{math.MaxUint64, []byte{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
}

func TestUpdateCBORWidthBoundaries(t *testing.T) {
	p := fixtureProfile(5)
	for _, tc := range widthCases {
		if got := uintValue(nil, tc.v); !bytes.Equal(got, tc.enc) {
			t.Fatalf("%d: encoded %x want %x", tc.v, got, tc.enc)
		}
		// The same value as a block number and as the final member weight, which
		// ends exactly at EOF, must be admitted and round-trip.
		u := fixtureUpdate(p)
		u.BlockNumber = tc.v
		u.NewEntries[0].Members[0].Weight = tc.v
		raw := u.Bytes()
		if !bytes.HasSuffix(raw, tc.enc) {
			t.Fatalf("%d: update does not end with %x", tc.v, tc.enc)
		}
		got, _, err := Admit(raw, p, math.MaxUint64)
		if err != nil {
			t.Fatalf("%d: %v", tc.v, err)
		}
		if got.BlockNumber != tc.v || got.NewEntries[0].Members[0].Weight != tc.v {
			t.Fatalf("%d: decoded %d/%d", tc.v, got.BlockNumber, got.NewEntries[0].Members[0].Weight)
		}
	}
}

func TestUpdateNetworkMaximum(t *testing.T) {
	p := fixtureProfile(5)
	p.Network = math.MaxUint16
	u := fixtureUpdate(p)
	got, _, err := Admit(u.Bytes(), p, math.MaxUint64)
	if err != nil || got.Network != math.MaxUint16 {
		t.Fatal(got.Network, err)
	}
	// 65536 is not a network and is refused by encoding, not binding.
	raw := u.Bytes()
	old := uintValue(nil, math.MaxUint16)
	bad := bytes.Replace(raw, old, uintValue(nil, math.MaxUint16+1), 1)
	if _, _, err := Admit(bad, p, math.MaxUint64); !errors.Is(err, ErrEncoding) {
		t.Fatal(err)
	}
}

func fixtureMembers(n int) []Member {
	ms := make([]Member, n)
	for i := range ms {
		var scalar [32]byte
		scalar[30], scalar[31] = byte((i+1)>>8), byte(i+1)
		key, err := ethcrypto.ToECDSA(scalar[:])
		if err != nil {
			panic(err)
		}
		ms[i] = Member{NodeID: fmt.Sprintf("n%03d", i), Weight: 1}
		copy(ms[i].Key[:], ethcrypto.CompressPubkey(&key.PublicKey))
	}
	return ms
}

// maximalUpdate has exactly K=W+1 live entries, the last with 64 members.
func maximalUpdate(p Profile) Update {
	u := fixtureUpdate(p)
	k := p.WCert + 1
	first := uint64(p.WCert + 10)
	u.OriginRound = first + k - 1
	u.OriginEpoch = k
	old := first
	u.OldTipEnd = &old
	u.NewEntries = nil
	for i := uint64(0); i < k; i++ {
		e := fixtureEntry(i+1, first+i)
		if i+1 < k {
			end := first + i + 1
			e.End = &end
		}
		u.NewEntries = append(u.NewEntries, e)
	}
	u.NewEntries[k-1].Members = fixtureMembers(MaxMembers)
	return u
}

func TestUpdateMaximumProjectionAndMembers(t *testing.T) {
	p := fixtureProfile(5)
	u := maximalUpdate(p)
	k, _, _, _ := p.Bounds()
	if uint64(len(u.NewEntries)) != k || len(u.NewEntries[k-1].Members) != 64 {
		t.Fatal("fixture is not maximal")
	}
	got, _, err := Admit(u.Bytes(), p, math.MaxUint64)
	if err != nil {
		t.Fatal(err)
	}
	if uint64(len(got.NewEntries)) != k || len(got.NewEntries[k-1].Members) != 64 {
		t.Fatal("decoded shape differs")
	}
	// One more entry, or a 65th member, is an encoding refusal.
	tooMany := maximalUpdate(p)
	tooMany.NewEntries = append(tooMany.NewEntries, fixtureEntry(k+1, tooMany.OriginRound))
	if _, _, err := Admit(tooMany.Bytes(), p, math.MaxUint64); !errors.Is(err, ErrEncoding) {
		t.Fatal(err)
	}
	wide := maximalUpdate(p)
	wide.NewEntries[k-1].Members = fixtureMembers(MaxMembers + 1)
	if _, _, err := Admit(wide.Bytes(), p, math.MaxUint64); !errors.Is(err, ErrEncoding) {
		t.Fatal(err)
	}
}

func TestUpdateTightCapacityTruncation(t *testing.T) {
	p := fixtureProfile(5)
	richer := maximalUpdate(p)
	for i, tc := range widthCases {
		richer.NewEntries[0].Members[0].Weight = tc.v
		richer.BlockNumber = tc.v
		raw := richer.Bytes()
		step := 1
		if i > 0 {
			step = 7 // the full sweep once; later widths sample every 7th cut
		}
		for cut := 0; cut < len(raw); cut += step {
			if _, _, err := Admit(raw[:cut:cut], p, math.MaxUint64); !errors.Is(err, ErrEncoding) {
				t.Fatalf("tight cut %d: %v", cut, err)
			}
			if _, _, err := Admit(append([]byte(nil), raw[:cut]...), p, math.MaxUint64); !errors.Is(err, ErrEncoding) {
				t.Fatalf("copied cut %d: %v", cut, err)
			}
		}
	}
}

func TestUpdateNoncanonicalBeforeMemberDebit(t *testing.T) {
	p := fixtureProfile(5)
	for _, tc := range widthCases[:7] {
		if tc.v == 24 || tc.v == 256 || tc.v == 65536 {
			continue
		}
		u := fixtureUpdate(p)
		u.NewEntries[0].Members[0].Weight = tc.v
		raw := u.Bytes()
		if !bytes.HasSuffix(raw, tc.enc) {
			t.Fatal("weight is not last")
		}
		var overlong []byte
		switch len(tc.enc) {
		case 1: // 23
			overlong = []byte{0x18, byte(tc.v)}
		case 2: // 255
			overlong = []byte{0x19, 0, byte(tc.v)}
		case 3: // 65535
			overlong = []byte{0x1a, 0, 0, byte(tc.v >> 8), byte(tc.v)}
		default: // 2^32-1
			overlong = []byte{0x1b, 0, 0, 0, 0, byte(tc.v >> 24), byte(tc.v >> 16), byte(tc.v >> 8), byte(tc.v)}
		}
		bad := append(raw[:len(raw)-len(tc.enc):len(raw)-len(tc.enc)], overlong...)
		scan := uint64(2000 + 16*len(bad))
		_, gas, err := Admit(bad, p, scan) // funds the scan only, not one member
		if !errors.Is(err, ErrEncoding) || gas != scan {
			t.Fatalf("%d: err %v gas %d want %d", tc.v, err, gas, scan)
		}
	}
}
