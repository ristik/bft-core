package b1ref_test

import (
	"math/big"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/b1ref/b1gen"
)

// CheckSealSignature is the seal rule for one signature, the upstream rule (owner decision 2026-11-04): exactly 65 bytes r||s||v, 1 <= r < n,
// 1 <= s <= n/2, v in 0..3, one recovery to the member's key over SHA-256 of the seal bytes. It is the base library's recoverable verifier, with the
// reason a signature does not count. The golden corpus exercises the same rule end to end.
func TestCheckSealSignatureIsTheUpstreamRule(t *testing.T) {
	m, _ := loadGolden(t)
	val := b1gen.ValidatorForTest(m.Seed, "node00")
	other := b1gen.ValidatorForTest(m.Seed, "node01")
	msg := []byte("seal bytes")
	ver, err := nativeVerifier(val.Pub)
	if err != nil {
		t.Fatal(err)
	}
	sig65 := val.Sign(msg, true)
	sig64 := val.Sign(msg, false)
	if len(sig65) != 65 || len(sig64) != 64 {
		t.Fatalf("premise: signature lengths %d and %d", len(sig65), len(sig64))
	}
	if err := b1ref.CheckSealSignature(ver, sig65, msg); err != nil {
		t.Fatalf("the canonical 65-byte signature must count: %v", err)
	}

	refuse := func(name string, want error, sig, data []byte) {
		t.Helper()
		if err := b1ref.CheckSealSignature(ver, sig, data); err != want {
			t.Fatalf("%s: got %v, want %v", name, err, want)
		}
	}
	withV := func(v byte) []byte { return append(append([]byte{}, sig65[:64]...), v) }
	refuse("the compact 64-byte form", b1ref.ErrSigFormat, sig64, msg)
	refuse("63 bytes", b1ref.ErrSigFormat, sig64[:63], msg)
	refuse("66 bytes", b1ref.ErrSigFormat, append(append([]byte{}, sig65...), 0), msg)
	refuse("empty", b1ref.ErrSigFormat, nil, msg)
	refuse("recovery byte 4", b1ref.ErrSigFormat, withV(4), msg)
	refuse("recovery byte 27", b1ref.ErrSigFormat, withV(27), msg)
	refuse("recovery byte 255", b1ref.ErrSigFormat, withV(255), msg)
	refuse("the other parity", b1ref.ErrSigInvalid, withV(sig65[64]^1), msg)
	refuse("a legal recovery byte that does not recover the key", b1ref.ErrSigInvalid, withV(2), msg)
	refuse("another message", b1ref.ErrSigInvalid, sig65, []byte("other bytes"))
	refuse("another member's signature", b1ref.ErrSigInvalid, other.Sign(msg, true), msg)

	n := ethcrypto.S256().Params().N
	high := append([]byte{}, sig65...)
	hs := new(big.Int).Sub(n, new(big.Int).SetBytes(sig65[32:64])).FillBytes(make([]byte, 32))
	copy(high[32:64], hs)
	refuse("high s (never normalized)", b1ref.ErrSigRange, high, msg)
	refuse("s zero", b1ref.ErrSigRange, append(append([]byte{}, sig65[:32]...), append(make([]byte, 32), sig65[64])...), msg)
	refuse("r zero", b1ref.ErrSigRange, append(make([]byte, 32), sig65[32:]...), msg)

	// there is one rule: the base library's recoverable verifier agrees with CheckSealSignature on every one of these
	for _, sig := range [][]byte{sig65, sig64, sig64[:63], withV(0), withV(1), withV(2), withV(3), withV(255), high} {
		if (ver.VerifyBytes(sig, msg) == nil) != (b1ref.CheckSealSignature(ver, sig, msg) == nil) {
			t.Fatalf("the base verifier and CheckSealSignature disagree on %x", sig)
		}
	}
}
