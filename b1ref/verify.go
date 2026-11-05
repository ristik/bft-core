package b1ref

import (
	"errors"
	"math/big"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

// Verdict is the outcome of a well-formed call. Why is nil when Valid and otherwise wraps ErrInvalid: one verdict for the whole
// batch, its reason only diagnostic metadata. Gas is the full charge, independent of where a false relation failed.
type Verdict struct {
	Valid bool
	Why   error
	Gas   uint64
}

// Cert evaluates a CERT_BATCH_V2 request (briefs/b1-any-age-contract.md sections 2 and 3) without a gas limit: the error is a
// halt (ErrMalformed) or an infrastructure failure (ErrInfrastructure); otherwise the verdict carries the full charge.
func Cert(in []byte, st State, pins Pins) (Verdict, error) { return CertWith(in, st, pins, Standard) }

// CertWith is Cert under explicit aggregate limits: the composition authenticates its anchor table under Composed, as the native
// BRIDGE_COMPOSE_V1 does.
func CertWith(in []byte, st State, pins Pins, lim Limits) (Verdict, error) {
	var pl plan
	if err := scanBatch(in, &pl, lim); err != nil {
		return Verdict{}, err
	}
	return finishCert(in, &pl, st, pins)
}

// VerifyCert returns (valid, err): err is non-nil exactly for a halt or an infrastructure failure.
func VerifyCert(in []byte, st State, pins Pins) (bool, error) {
	v, err := Cert(in, st, pins)
	return v.Valid, err
}

// finishCert is everything after the scan and the full charge: the native decode of every occurrence, then the registry and the
// relation.
func finishCert(in []byte, pl *plan, st State, pins Pins) (Verdict, error) {
	claims, err := parseClaims(in, pl.k, pl.perUCItems)
	if err != nil {
		return Verdict{}, err
	}
	if st == nil {
		return Verdict{}, ErrHost
	}
	why, err := evalBatch(pl, claims, st, pins)
	if err != nil {
		return Verdict{}, err
	}
	return Verdict{Valid: why == nil, Why: why, Gas: pl.charge}, nil
}

var curveN = ethcrypto.S256().Params().N

func checkSignature(m *member, sig, sigBytes []byte) error {
	if err := checkSignatureFormat(sig); err != nil {
		return err
	}
	return verifySealSignature(m.ver, sig, sigBytes)
}

// CheckSealSignature is the seal signature rule, the upstream rule (owner decision 2026-11-04), for one signature of a known member whose verifier
// the caller holds: nil iff the signature is exactly 65 bytes r||s||v with 1 <= r < n, 1 <= s <= n/2 and a recovery ID v in 0..3 that recovers, over
// SHA-256(sigBytes), to the member's key. Any other signature does not count: ErrSigFormat (width or recovery ID), ErrSigRange (scalar range or
// high s) or ErrSigInvalid (recovery fails or yields another key) say why, but none of them rejects a seal: a caller sums the weight of the
// signatures that return nil. It is the rule of checkSignature, without the gas.
func CheckSealSignature(ver abcrypto.Verifier, sig, sigBytes []byte) error {
	if err := checkSignatureFormat(sig); err != nil {
		return err
	}
	return verifySealSignature(ver, sig, sigBytes)
}

func checkSignatureFormat(sig []byte) error {
	if len(sig) != 65 || sig[64] > abcrypto.MaxRecoveryID {
		return ErrSigFormat
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	halfN := new(big.Int).Rsh(curveN, 1)
	if r.Sign() == 0 || r.Cmp(curveN) >= 0 || s.Sign() == 0 || s.Cmp(halfN) > 0 {
		return ErrSigRange
	}
	return nil
}

// verifySealSignature is the one recovery: the base library's recoverable verifier recovers the key from (hash, r, s, v) and compares it with the
// member's key; there is no second verification and no alternative parity.
func verifySealSignature(ver abcrypto.Verifier, sig, sigBytes []byte) error {
	if err := ver.VerifyBytes(sig, sigBytes); err != nil {
		return ErrSigInvalid
	}
	return nil
}

// pairs returns the (text key, byte value) entries of a scanned signature map
// in wire order.
func (it *item) pairs() [][2][]byte {
	out := make([][2][]byte, 0, len(it.kids)/2)
	for i := 0; i < len(it.kids); i += 2 {
		out = append(out, [2][]byte{it.kids[i].data, it.kids[i+1].data})
	}
	return out
}

// Output is the successful CERT_BATCH_V2 return data: abi.encode(uint256(2), bool(valid)).
func Output(valid bool) []byte { return output(certVersion, valid) }

// MemberOutput is the successful RSMT_MEMBER_V1 return data: abi.encode(uint256(1), bool(valid)).
func MemberOutput(valid bool) []byte { return output(memberVersion, valid) }

func output(version byte, valid bool) []byte {
	out := make([]byte, 64)
	out[31] = version
	if valid {
		out[63] = 1
	}
	return out
}

// Op selects a builtin.
type Op int

const (
	OpCertBatch Op = iota // 0x0100 CERT_BATCH_V2
	OpMember              // 0x0102 RSMT_MEMBER_V1
)

// Run is the EVM-facing wrapper of one builtin call with a gas limit, in the contract's debit order (section 5): the size cap,
// then 60,000 + 16*C, then the header and G_scan, then the full scan and grouping, then G_batch, and only then decoding and state.
// It returns output and gas, or a halt consuming all forwarded gas. An infrastructure failure returns ErrInfrastructure with no
// EVM result (used=0). st may be nil for OpMember.
func Run(op Op, in []byte, st State, pins Pins, gas uint64) (out []byte, used uint64, err error) {
	switch op {
	case OpCertBatch:
		if len(in) > MaxCallBytes {
			return nil, gas, ErrInputTooLarge
		}
		if gas < scanBaseGas+gasPerByte*uint64(len(in)) {
			return nil, gas, ErrOutOfGas
		}
		k, herr := header(in, certVersion)
		if herr != nil {
			return nil, gas, herr
		}
		if k < 1 || k > MaxClaims {
			return nil, gas, ErrCount
		}
		if gas < ScanGas(uint64(len(in)), uint64(k)) {
			return nil, gas, ErrOutOfGas
		}
		var pl plan
		if perr := scanBatch(in, &pl, Standard); perr != nil {
			return nil, gas, perr
		}
		if gas < pl.charge {
			return nil, gas, ErrOutOfGas
		}
		v, verr := finishCert(in, &pl, st, pins)
		if verr != nil {
			if errors.Is(verr, ErrInfrastructure) {
				return nil, 0, verr
			}
			return nil, gas, verr
		}
		return Output(v.Valid), v.Gas, nil
	case OpMember:
		if len(in) > MaxRSMTInputBytes {
			return nil, gas, ErrInputTooLarge
		}
		if gas < rsmtBaseGas+gasPerByte*uint64(len(in)) {
			return nil, gas, ErrOutOfGas
		}
		mc, perr := parseMember(in)
		if perr != nil {
			return nil, gas, perr
		}
		if gas < mc.gas {
			return nil, gas, ErrOutOfGas
		}
		v := evalMember(mc)
		return MemberOutput(v.Valid), v.Gas, nil
	}
	return nil, gas, errors.New("b1ref: unknown op")
}

// onWork is test instrumentation: when set, it is called immediately before each counted operation: "epoch-load" (an epoch
// entry read), "key-parse" (a member key parsed), "claim" and "fold" (a distinct claim's binding and folds), "quorum" (a distinct
// seal's signature loop), "signature" (one signature check) and "rsmt-fold". It never changes behaviour.
var onWork func(kind string)

func work(kind string) {
	if onWork != nil {
		onWork(kind)
	}
}
