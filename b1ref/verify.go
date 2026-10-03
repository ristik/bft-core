package b1ref

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// EpochEntry is the registry's five words for one epoch, minus the activation
// commit ID, which no verification reads. A zero ViewHash means the epoch is
// unknown. Start is inclusive; End is exclusive, zero meaning the open
// interval.
type EpochEntry struct {
	ViewHash [32]byte
	BodyID   [32]byte
	Start    uint64
	End      uint64
}

// Registry is the explicit registry context of one call: everything the
// builtins would read from authenticated EVM state, and nothing else. In this
// package it is an injected precondition: the caller asserts it came from
// authenticated state, and nothing here establishes that. A Registry built by
// a test is a simulation of the context, not authority.
type Registry struct {
	Network   uint16 // b1.network
	WCert     uint64 // b1.wCert
	Origin    uint64 // origin.rootEpoch
	RootRound uint64 // clock.rootRound, O
	Epochs    map[uint64]EpochEntry
}

// Verdict is the outcome of a well-formed call. Why is nil when Valid and
// otherwise wraps ErrInvalid. Gas is the full charge, independent of where a
// false relation failed.
type Verdict struct {
	Valid bool
	Why   error
	Gas   uint64
}

// UC evaluates a UC_V1 input.
func UC(in []byte, reg *Registry) (Verdict, error) { return certCallVerdict(in, reg, false) }

// Shared evaluates a SHARED_SEAL_V1 input.
func Shared(in []byte, reg *Registry) (Verdict, error) { return certCallVerdict(in, reg, true) }

// VerifyUC returns (valid, err): err is non-nil exactly for malformed input.
func VerifyUC(in []byte, reg *Registry) (bool, error) {
	v, err := UC(in, reg)
	return v.Valid, err
}

// VerifyShared returns (valid, err): err is non-nil exactly for malformed input.
func VerifyShared(in []byte, reg *Registry) (bool, error) {
	v, err := Shared(in, reg)
	return v.Valid, err
}

func certCallVerdict(in []byte, reg *Registry, shared bool) (Verdict, error) {
	call, err := parseCertCall(in, shared)
	if err != nil {
		return Verdict{}, err
	}
	return finishCertCall(call, reg)
}

// finishCertCall is everything after the structural scan: point decoding, then
// the semantic relation. Run calls it only once the full charge is reserved.
func finishCertCall(call *certCall, reg *Registry) (Verdict, error) {
	if err := call.view.decodePoints(); err != nil {
		return Verdict{}, fmt.Errorf("trust view: %w", err)
	}
	v := Verdict{Gas: call.charge}
	if v.Why = evalCertCall(call, reg); v.Why == nil {
		v.Valid = true
	}
	return v, nil
}

// evalCertCall checks every claim and the one common seal, returning the first
// reason the relation fails. It never short-circuits the signature loop.
func evalCertCall(call *certCall, reg *Registry) error {
	if err := call.view.check(); err != nil {
		return err
	}
	for i := range call.claims {
		c := &call.claims[i]
		if i > 0 && compareClaimID(&call.claims[i-1], c) == 0 {
			return ErrDuplicateClaim
		}
		if !bytes.Equal(c.sealRaw, call.claims[0].sealRaw) {
			return ErrSealMismatch
		}
	}
	for i := range call.claims {
		if err := ucFolds(&call.claims[i]); err != nil {
			return fmt.Errorf("claim %d: %w", i, err)
		}
	}
	return evalSeal(call, reg)
}

func evalSeal(call *certCall, reg *Registry) error {
	view, seal := call.view, call.claims[0].uc.UnicitySeal
	if view.network != reg.Network || uint64(seal.NetworkID) != uint64(reg.Network) {
		return ErrNetwork
	}
	if seal.Epoch != view.epoch || seal.Epoch > reg.Origin {
		return ErrSealEpoch
	}
	entry, ok := reg.Epochs[view.epoch]
	if !ok || entry.ViewHash == ([32]byte{}) {
		return ErrUnknownEpoch
	}
	if entry.ViewHash != view.hash {
		return ErrViewHash
	}
	if entry.BodyID != view.bodyID {
		return ErrBodyID
	}
	r := seal.RootChainRoundNumber
	if r < entry.Start {
		return ErrBeforeStart
	}
	if entry.End != 0 && r >= entry.End {
		return ErrAfterEnd
	}
	if entry.End == 0 && view.epoch != reg.Origin {
		return ErrOpenInterval
	}
	if r > reg.RootRound {
		return ErrFuture
	}
	if reg.RootRound-r > reg.WCert {
		return ErrStale
	}
	return verifySignatures(call)
}

var curveN = ethcrypto.S256().Params().N

// verifySignatures checks every supplied signature over SHA256(Seal.SigBytes())
// and then the quorum. Any unknown signer or bad signature fails the call even
// when the rest reach quorum; the loop does not stop at the first failure.
func verifySignatures(call *certCall) error {
	view := call.view
	sigBytes, err := call.claims[0].uc.UnicitySeal.SigBytes()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFold, err)
	}
	var first error
	good := uint64(0)
	for _, kv := range call.claims[0].sigs.pairs() {
		m := view.lookup(string(kv[0]))
		if m == nil {
			first = firstErr(first, ErrUnknownSigner)
			continue
		}
		if err := checkSignature(m, kv[1], sigBytes); err != nil {
			first = firstErr(first, err)
			continue
		}
		good++
	}
	if first != nil {
		return first
	}
	if good < view.threshold() {
		return ErrQuorum
	}
	return nil
}

func firstErr(cur, next error) error {
	if cur != nil {
		return cur
	}
	return next
}

func checkSignature(m *member, sig, sigBytes []byte) error {
	if len(sig) != 64 && len(sig) != 65 {
		return ErrSigFormat
	}
	if len(sig) == 65 && sig[64] > 1 {
		return ErrSigFormat
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	halfN := new(big.Int).Rsh(curveN, 1)
	if r.Sign() == 0 || r.Cmp(curveN) >= 0 || s.Sign() == 0 || s.Cmp(halfN) > 0 {
		return ErrSigRange
	}
	work("signature")
	if err := m.ver.VerifyBytes(sig, sigBytes); err != nil {
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

// Output is the successful EVM return data: abi.encode(uint256(1), bool(valid)).
func Output(valid bool) []byte {
	out := make([]byte, 64)
	out[31] = outputVersion
	if valid {
		out[63] = 1
	}
	return out
}

// Op selects a builtin.
type Op int

const (
	OpUC Op = iota
	OpShared
	OpMember
)

// Run is the EVM-facing wrapper of one builtin call with a gas limit: it
// returns the 64 output bytes and the gas used, or an error with all
// forwarded gas consumed. reg may be nil for OpMember.
func Run(op Op, in []byte, reg *Registry, gas uint64) (out []byte, used uint64, err error) {
	limit, base := uint64(MaxCallBytes), uint64(ucBaseGas)
	if op == OpMember {
		limit, base = MaxRSMTInputBytes, rsmtBaseGas
	}
	if uint64(len(in)) > limit {
		return nil, gas, ErrInputTooLarge
	}
	if gas < base+gasPerByte*uint64(len(in)) {
		return nil, gas, ErrOutOfGas
	}
	var v Verdict
	switch op {
	case OpUC, OpShared:
		call, perr := parseCertCall(in, op == OpShared)
		if perr != nil {
			return nil, gas, perr
		}
		// The full charge is known from the structural scan alone. It is
		// reserved here, before any point decoding, path fold or signature check.
		if gas < call.charge {
			return nil, gas, ErrOutOfGas
		}
		v, err = finishCertCall(call, reg)
	case OpMember:
		mc, perr := parseMember(in)
		if perr != nil {
			return nil, gas, perr
		}
		if gas < mc.gas {
			return nil, gas, ErrOutOfGas
		}
		v = evalMember(mc)
	default:
		return nil, gas, errors.New("b1ref: unknown op")
	}
	if err != nil {
		return nil, gas, err
	}
	return Output(v.Valid), v.Gas, nil
}

// onWork is test instrumentation: when set, it is called with "point",
// "signature", "fold" or "rsmt-fold" immediately before each such operation.
// It never changes behaviour.
var onWork func(kind string)

func work(kind string) {
	if onWork != nil {
		onWork(kind)
	}
}
