package b1ref_test

import (
	"math/big"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/b1ref/b1gen"
)

// CheckSealSignature is the B1 rule for one seal signature, exported for the profiles that must accept what B1 accepts: 64 bytes, or 65 with a
// recovery byte 0 or 1 (ignored), compact verification, never the native recoverable rule. The golden corpus exercises the same rule end to end
// (its valid seals are 64-byte signatures, quorum.sig.v-present is the 65-byte form and quorum.sig.v-ignored swaps the recovery byte).
func TestCheckSealSignatureIsTheB1Rule(t *testing.T) {
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

	for name, sig := range map[string][]byte{
		"64 bytes":                          sig64,
		"65 bytes, recovery byte as signed": sig65,
		"65 bytes, recovery byte swapped":   append(append([]byte{}, sig65[:64]...), sig65[64]^1),
	} {
		if err := b1ref.CheckSealSignature(ver, sig, msg); err != nil {
			t.Fatalf("%s must be accepted: %v", name, err)
		}
	}

	refuse := func(name string, want error, sig, data []byte) {
		t.Helper()
		if err := b1ref.CheckSealSignature(ver, sig, data); err != want {
			t.Fatalf("%s: got %v, want %v", name, err, want)
		}
	}
	refuse("63 bytes", b1ref.ErrSigFormat, sig64[:63], msg)
	refuse("66 bytes", b1ref.ErrSigFormat, append(append([]byte{}, sig65...), 0), msg)
	refuse("recovery byte 2", b1ref.ErrSigFormat, append(append([]byte{}, sig65[:64]...), 2), msg)
	refuse("recovery byte 255", b1ref.ErrSigFormat, append(append([]byte{}, sig65[:64]...), 255), msg)
	refuse("another message", b1ref.ErrSigInvalid, sig64, []byte("other bytes"))
	refuse("another member's signature", b1ref.ErrSigInvalid, other.Sign(msg, false), msg)

	n := ethcrypto.S256().Params().N
	high := append([]byte{}, sig64...)
	hs := new(big.Int).Sub(n, new(big.Int).SetBytes(sig64[32:64])).FillBytes(make([]byte, 32))
	copy(high[32:], hs)
	refuse("high s", b1ref.ErrSigRange, high, msg)
	refuse("s zero", b1ref.ErrSigRange, append(append([]byte{}, sig64[:32]...), make([]byte, 32)...), msg)
	refuse("r zero", b1ref.ErrSigRange, append(make([]byte, 32), sig64[32:]...), msg)

	// the native rule refuses what B1 accepts: the two are different rules (see TestRecoveryByteIsPolicy)
	if ver.VerifyBytes(sig64, msg) == nil {
		t.Fatal("the native verifier must refuse the compact form that B1 accepts")
	}
}
