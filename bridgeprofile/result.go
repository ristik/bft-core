package bridgeprofile

import (
	"bytes"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// MaxKernelInputBytes bounds the 0x0104 input: the semantic ceiling plus the
// ABI framing words and a Cfg.
const MaxKernelInputBytes = MaxSemanticBytes + 4096

// KernelMarker is bytes32("UNICITY_TOKEN_SEMANTICS"), left aligned.
var KernelMarker = func() (m [32]byte) { copy(m[:], "UNICITY_TOKEN_SEMANTICS"); return }()

// ResultBaseBytes and ResultLeafBytes size the canonical successful output:
// 448 + 128*m bytes for m leaves (four words per leaf since SDK 3.0.1:
// sid, txHash, uint64 referenceTime, leafValue).
const (
	ResultBaseBytes = 448
	ResultLeafBytes = 128
)

var (
	kernelInArgs  = mustArgs("uint8", "bytes", "bytes")
	kernelOutArgs = mustOutArgs()
)

func mustArgs(types ...string) abi.Arguments {
	var a abi.Arguments
	for _, t := range types {
		ty, err := abi.NewType(t, "", nil)
		if err != nil {
			panic(err)
		}
		a = append(a, abi.Argument{Type: ty})
	}
	return a
}

type abiResultLeaf struct {
	Sid           [32]byte
	TxHash        [32]byte
	ReferenceTime uint64
	LeafValue     [32]byte
}

type abiResult struct {
	Cfg                [32]byte
	Nonce              *big.Int
	Amount             *big.Int
	TokenId            [32]byte
	Salt               [32]byte
	FirstPredicateHash [32]byte
	LockDigest         [32]byte
	ReleaseTo          [20]byte
	Nullifier          [32]byte
	Leaves             []abiResultLeaf
}

func mustOutArgs() abi.Arguments {
	tuple, err := abi.NewType("tuple", "", []abi.ArgumentMarshaling{
		{Name: "cfg", Type: "bytes32"}, {Name: "nonce", Type: "uint256"}, {Name: "amount", Type: "uint256"},
		{Name: "tokenId", Type: "bytes32"}, {Name: "salt", Type: "bytes32"}, {Name: "firstPredicateHash", Type: "bytes32"},
		{Name: "lockDigest", Type: "bytes32"}, {Name: "releaseTo", Type: "address"}, {Name: "nullifier", Type: "bytes32"},
		{Name: "leaves", Type: "tuple[]", Components: []abi.ArgumentMarshaling{
			{Name: "sid", Type: "bytes32"}, {Name: "txHash", Type: "bytes32"},
			{Name: "referenceTime", Type: "uint64"}, {Name: "leafValue", Type: "bytes32"}}},
	})
	if err != nil {
		panic(err)
	}
	b32, _ := abi.NewType("bytes32", "", nil)
	bl, _ := abi.NewType("bool", "", nil)
	return abi.Arguments{{Type: b32}, {Type: bl}, {Type: tuple}}
}

// EncodeKernelInput is abi.encode(uint8 operation, bytes Cfg, bytes payload).
func EncodeKernelInput(op uint8, cfg, payload []byte) ([]byte, error) {
	return kernelInArgs.Pack(op, nonNil(cfg), nonNil(payload))
}

// DecodeKernelInput decodes the kernel input and rejects noncanonical offsets,
// padding, aliases and trailing data by re-encoding.
func DecodeKernelInput(b []byte) (op uint8, cfg, payload []byte, err error) {
	if len(b) > MaxKernelInputBytes {
		return 0, nil, nil, ErrInputTooLarge
	}
	if len(b)%32 != 0 || len(b) < 3*32 {
		return 0, nil, nil, ErrABIFraming
	}
	vals, uerr := kernelInArgs.Unpack(b)
	if uerr != nil || len(vals) != 3 {
		return 0, nil, nil, ErrABIFraming
	}
	op, cfg, payload = vals[0].(uint8), vals[1].([]byte), vals[2].([]byte)
	if re, rerr := EncodeKernelInput(op, cfg, payload); rerr != nil || !bytes.Equal(re, b) {
		return 0, nil, nil, ErrABIFraming
	}
	return op, cfg, payload, nil
}

// EncodeResult is the canonical output
// abi.encode(bytes32("UNICITY_TOKEN_SEMANTICS"), bool valid, Result). Valid
// false carries the all-zero, empty Result.
func EncodeResult(valid bool, r *Result) ([]byte, error) {
	ar := abiResult{Nonce: new(big.Int), Amount: new(big.Int), Leaves: []abiResultLeaf{}}
	if valid {
		ar.Cfg, ar.Nonce, ar.Amount = r.Cfg, new(big.Int).SetUint64(r.Nonce), new(big.Int).Set(zeroIfNil(r.Amount))
		ar.TokenId, ar.Salt, ar.FirstPredicateHash = r.TokenID, r.Salt, r.FirstPredicateHash
		ar.LockDigest, ar.ReleaseTo, ar.Nullifier = r.LockDigest, r.ReleaseTo, r.Nullifier
		for _, l := range r.Leaves {
			ar.Leaves = append(ar.Leaves, abiResultLeaf{l.SID, l.TxHash, l.ReferenceTime, l.Value})
		}
	}
	return kernelOutArgs.Pack(KernelMarker, valid, ar)
}

func zeroIfNil(a *big.Int) *big.Int {
	if a == nil {
		return new(big.Int)
	}
	return a
}

// DecodeResult strictly decodes a kernel output: the marker, the exact length
// 448+128*m, canonical framing (re-encoding reproduces the input, which also
// forces zero high padding on every narrow word) and, for valid=false, the
// all-zero empty Result.
func DecodeResult(b []byte) (bool, *Result, error) {
	if len(b) < ResultBaseBytes || len(b) > ResultBaseBytes+ResultLeafBytes*MaxLeaves || (len(b)-ResultBaseBytes)%ResultLeafBytes != 0 {
		return false, nil, ErrResultFrame
	}
	vals, err := kernelOutArgs.Unpack(b)
	if err != nil || len(vals) != 3 {
		return false, nil, ErrResultFrame
	}
	if vals[0].([32]byte) != KernelMarker {
		return false, nil, ErrResultFrame
	}
	valid := vals[1].(bool)
	ar := abi.ConvertType(vals[2], new(abiResult)).(*abiResult)
	res := &Result{Cfg: ar.Cfg, Amount: ar.Amount, TokenID: ar.TokenId, Salt: ar.Salt, FirstPredicateHash: ar.FirstPredicateHash,
		LockDigest: ar.LockDigest, ReleaseTo: ar.ReleaseTo, Nullifier: ar.Nullifier}
	if !ar.Nonce.IsUint64() {
		return false, nil, ErrResultFrame
	}
	res.Nonce = ar.Nonce.Uint64()
	for _, l := range ar.Leaves {
		res.Leaves = append(res.Leaves, Leaf{SID: l.Sid, TxHash: l.TxHash, ReferenceTime: l.ReferenceTime, Value: l.LeafValue})
	}
	re, err := EncodeResult(valid, res)
	if err != nil || !bytes.Equal(re, b) {
		return false, nil, ErrResultFrame
	}
	if !valid {
		zero, _ := EncodeResult(false, nil)
		if !bytes.Equal(b, zero) {
			return false, nil, ErrResultFrame
		}
		return false, nil, nil
	}
	return true, res, nil
}

// Validate recomputes the cfg-derived identifiers: ty and aid from the
// unicity-native family, the zero address, and a nonzero vault.
func (c *Cfg) Validate() error {
	if c.Ty != DeriveType(c.Network, c.RootGenesis, c.ExecutionGenesis, c.ChainID) ||
		c.Aid != DeriveAsset(c.Network, c.RootGenesis, c.ExecutionGenesis, c.ChainID) ||
		c.ZeroAddress != ([20]byte{}) || c.Vault == ([20]byte{}) {
		return ErrCfgMismatch
	}
	return nil
}

// PreparePayload is the prepareLock payload C(n,b(amount),P0).
func PreparePayload(n uint64, amount *big.Int, p0 []byte) []byte {
	return CArr(CUint(n), CAmount(amount), p0)
}

func decodePreparePayload(b []byte) (uint64, *big.Int, []byte, error) {
	if len(b) > MaxSemanticBytes {
		return 0, nil, nil, ErrInputTooLarge
	}
	root, err := scanOne(b)
	if err != nil {
		return 0, nil, nil, err
	}
	if !root.isArray(3) {
		return 0, nil, nil, ErrShape
	}
	n, err := root.kids[0].uintMax(^uint64(0))
	if err != nil {
		return 0, nil, nil, err
	}
	amount, err := root.kids[1].amount()
	if err != nil {
		return 0, nil, nil, err
	}
	return n, amount, root.kids[2].raw(b), nil
}

// Kernel is the 0x0104 relation at the ABI: input
// abi.encode(operation, Cfg, payload) to the canonical output. A relation that
// does not hold yields the all-zero valid=false output; a malformed or
// over-budget input is an exceptional halt (an error and no output). The
// split is the oracle's provisional classification, to be fixed with the
// native kernel.
func Kernel(in []byte) ([]byte, error) {
	op, cfgBytes, payload, err := DecodeKernelInput(in)
	if err != nil {
		return nil, err
	}
	cfg, err := DecodeCfg(cfgBytes)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return EncodeResult(false, nil)
	}
	var res *Result
	switch op {
	case OpPrepareLock:
		n, amount, p0, perr := decodePreparePayload(payload)
		if perr != nil {
			return nil, perr
		}
		res, err = PrepareLock(cfg, n, amount, p0)
	case OpMint:
		res, err = VerifyMint(cfg, payload)
	case OpReturn:
		res, err = VerifyReturn(cfg, payload)
	default:
		return nil, ErrBadOperation
	}
	switch {
	case err == nil:
		return EncodeResult(true, res)
	case errors.Is(err, ErrMalformed) || errors.Is(err, ErrBudget):
		return nil, err
	}
	return EncodeResult(false, nil)
}
