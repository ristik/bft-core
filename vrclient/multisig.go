package vrclient

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/unicitynetwork/bft-core/vrschema"
)

// The Foundation's side (design 3.5.5, 3.5.6): the FoundationMultisig (3-of-5, VR's governor) approves one call under an EIP-712 digest;
// the call is VR.queue(kind, payload) or VR.cancel(id). Anyone executes the approved call, and anyone executes the queued change once both
// governance delays have passed.

// MultisigABI is FoundationMultisig's external ABI (unicity-pos-contracts src/vr/FoundationMultisig.sol): the approval and the views.
var MultisigABI = mustABI(`[
 {"type":"function","name":"execute","stateMutability":"nonpayable","inputs":[{"name":"target","type":"address"},{"name":"data","type":"bytes"},{"name":"sigs","type":"bytes[]"}],"outputs":[]},
 {"type":"function","name":"callDigest","stateMutability":"view","inputs":[{"name":"target","type":"address"},{"name":"data","type":"bytes"},{"name":"nonce_","type":"uint64"}],"outputs":[{"name":"","type":"bytes32"}]},
 {"type":"function","name":"nonce","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"uint64"}]},
 {"type":"function","name":"signers","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"address[5]"}]},
 {"type":"function","name":"nextSigners","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"address[5]"}]},
 {"type":"function","name":"isSigner","stateMutability":"view","inputs":[{"name":"a","type":"address"}],"outputs":[{"name":"","type":"bool"}]},
 {"type":"function","name":"domainSeparator","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"bytes32"}]},
 {"type":"function","name":"signersPending","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"bool"}]},
 {"type":"function","name":"nextNotBeforeProgress","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"uint64"}]},
 {"type":"function","name":"nextNotBeforeTime","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"uint64"}]},
 {"type":"function","name":"applySigners","stateMutability":"nonpayable","inputs":[],"outputs":[]},
 {"type":"error","name":"NotSelf","inputs":[]},
 {"type":"error","name":"BadSigners","inputs":[]},
 {"type":"error","name":"BadSignatures","inputs":[]},
 {"type":"error","name":"CallFailed","inputs":[]},
 {"type":"error","name":"NoPendingSigners","inputs":[]},
 {"type":"error","name":"SignersPending","inputs":[]}]`)

// MultisigThreshold is the number of distinct signer approvals an execution needs.
const MultisigThreshold = 3

// Change kinds the Foundation queues (src/vr/VRConstants.sol K_*).
const (
	KindSetModule          uint8 = 1
	KindSetGovernor        uint8 = 3
	KindCommitteeLimits    uint8 = 4
	KindFeeParams          uint8 = 5
	KindReplaceAggregator  uint8 = 6
	KindAddPartition       uint8 = 7
	KindUpdatePartition    uint8 = 8
	KindScheduleActivation uint8 = 9
	KindForceRemove        uint8 = 10
)

// Change states (src/vr/VRConstants.sol CH_*).
const (
	ChangeQueued    uint8 = 1
	ChangeScheduled uint8 = 2
	ChangeBound     uint8 = 3
	ChangeActive    uint8 = 4
	ChangeRejected  uint8 = 5
	ChangeCancelled uint8 = 6
)

var (
	domainTypeHash = ethcrypto.Keccak256Hash([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))
	callTypeHash   = ethcrypto.Keccak256Hash([]byte("Call(address target,bytes data,uint64 nonce)"))
	nameHash       = ethcrypto.Keccak256Hash([]byte("UnicityFoundationMultisig"))
	versionHash    = ethcrypto.Keccak256Hash([]byte("1"))
)

func word(b []byte) []byte {
	var w [32]byte
	copy(w[32-len(b):], b)
	return w[:]
}

// CallDigest is FoundationMultisig.callDigest(target, data, nonce) computed locally (the EIP-712 digest the signers sign), so a signer
// needs no endpoint: the chain id and the multisig's address are part of it.
func CallDigest(chainID *big.Int, multisig, target ethcommon.Address, data []byte, nonce uint64) ([32]byte, error) {
	if chainID == nil || chainID.Sign() < 0 || chainID.BitLen() > 256 {
		return [32]byte{}, fmt.Errorf("%w: chain id", ErrVR)
	}
	var cid [32]byte
	chainID.FillBytes(cid[:])
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], nonce)
	dom := ethcrypto.Keccak256(domainTypeHash[:], nameHash[:], versionHash[:], cid[:], word(multisig.Bytes()))
	dh := ethcrypto.Keccak256Hash(data)
	st := ethcrypto.Keccak256(callTypeHash[:], word(target.Bytes()), dh[:], word(n[:]))
	var out [32]byte
	copy(out[:], ethcrypto.Keccak256([]byte{0x19, 0x01}, dom, st))
	return out, nil
}

// SignCall signs a call digest as a multisig approval: r || s || v with v 27/28 and a low s.
func SignCall(key *ecdsa.PrivateKey, digest [32]byte) ([]byte, error) { return SignDigest(key, digest) }

// RecoverSigner is the address that signed digest (the multisig's ecrecover; low s and v 27/28 required).
func RecoverSigner(digest [32]byte, sig []byte) (ethcommon.Address, error) {
	if len(sig) != 65 || (sig[64] != 27 && sig[64] != 28) {
		return ethcommon.Address{}, fmt.Errorf("%w: a signature is 65 bytes with v 27 or 28", ErrVR)
	}
	s := new(big.Int).SetBytes(sig[32:64])
	if s.Cmp(new(big.Int).Rsh(ethcrypto.S256().Params().N, 1)) > 0 {
		return ethcommon.Address{}, fmt.Errorf("%w: the signature has a high s", ErrVR)
	}
	raw := append([]byte(nil), sig...)
	raw[64] -= 27
	pub, err := ethcrypto.SigToPub(digest[:], raw)
	if err != nil {
		return ethcommon.Address{}, fmt.Errorf("%w: recovering the signer: %v", ErrVR, err)
	}
	return ethcrypto.PubkeyToAddress(*pub), nil
}

// Approval is one signer's signature over a call digest.
type Approval struct {
	Signer    ethcommon.Address
	Signature []byte
}

// OrderApprovals checks each approval against digest (the signature recovers to its signer), refuses a duplicate signer, and returns
// the signatures ordered by strictly ascending signer address, as the multisig requires.
func OrderApprovals(digest [32]byte, as []Approval) ([]Approval, error) {
	seen := map[ethcommon.Address]bool{}
	out := make([]Approval, 0, len(as))
	for _, a := range as {
		got, err := RecoverSigner(digest, a.Signature)
		if err != nil {
			return nil, err
		}
		if got != a.Signer {
			return nil, fmt.Errorf("%w: a signature claimed for %s is by %s", ErrVR, a.Signer.Hex(), got.Hex())
		}
		if seen[got] {
			return nil, fmt.Errorf("%w: signer %s approved twice", ErrVR, got.Hex())
		}
		seen[got] = true
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return strings.Compare(string(out[i].Signer[:]), string(out[j].Signer[:])) < 0 })
	return out, nil
}

// ExecuteCalldata is FoundationMultisig.execute(target, data, sigs) with the approvals in the order OrderApprovals returns.
func ExecuteCalldata(target ethcommon.Address, data []byte, as []Approval) ([]byte, error) {
	sigs := make([][]byte, len(as))
	for i, a := range as {
		sigs[i] = a.Signature
	}
	return MultisigABI.Pack("execute", target, data, sigs)
}

// QueueCalldata is VR.queue(kind, payload); CancelCalldata is VR.cancel(id); ExecuteChangeCalldata is VR.execute(id).
func QueueCalldata(kind uint8, payload []byte) ([]byte, error) {
	return VRABI.Pack("queue", kind, payload)
}
func CancelCalldata(id uint64) ([]byte, error)        { return VRABI.Pack("cancel", id) }
func ExecuteChangeCalldata(id uint64) ([]byte, error) { return VRABI.Pack("execute", id) }

// Payload builders of the live-config changes (schema v1 section 6; vrschema.EncodeChange).

// CommitteeLimitsPayload is the kind 4 payload.
func CommitteeLimitsPayload(nMin, nTarget, nMax uint32) ([]byte, error) {
	return vrschema.EncodeChange(KindCommitteeLimits, uint64(nMin), uint64(nTarget), uint64(nMax))
}

// FeeParamsPayload is the kind 5 payload.
func FeeParamsPayload(baseFeeFloor, changeDenominator uint64, collector ethcommon.Address) ([]byte, error) {
	return vrschema.EncodeChange(KindFeeParams, baseFeeFloor, changeDenominator, [20]byte(collector))
}

// ForceRemovePayload is the kind 10 payload.
func ForceRemovePayload(id uint64) ([]byte, error) { return vrschema.EncodeChange(KindForceRemove, id) }

// DescribeChange reads a change payload for an operator: the kind's fields by name, a ModuleAction's PoA action in words. It does not
// fail on a payload it cannot read; it says so.
func DescribeChange(kind uint8, payload []byte) string {
	vals, err := vrschema.DecodeChangePayload(kind, payload)
	if err != nil {
		return fmt.Sprintf("%s: payload not readable (%v)", ChangeKind(kind), err)
	}
	names := vrschema.ChangePayloadFields[kind]
	if kind == KindModuleAction {
		if ma, ok := DecodeModuleAction(payload); ok {
			return fmt.Sprintf("ModuleAction %s identity %d on module %s", ActionName(ma.Action), ma.ID, ma.Module.Hex())
		}
		return fmt.Sprintf("ModuleAction on module %s, action not a PoA action (%x)", ethcommon.Address(vals[0].([20]byte)).Hex(), vals[1].([]byte))
	}
	parts := make([]string, 0, len(vals))
	for i, v := range vals {
		name := fmt.Sprint(i)
		if i < len(names) {
			name = names[i]
		}
		switch x := v.(type) {
		case string:
			parts = append(parts, fmt.Sprintf("%s=%q", name, Clean(x)))
		case [20]byte:
			parts = append(parts, fmt.Sprintf("%s=%s", name, ethcommon.Address(x).Hex()))
		case vrschema.Word:
			parts = append(parts, fmt.Sprintf("%s=%s", name, vrschema.Hexw(x)))
		case []byte:
			if len(x) > 32 {
				parts = append(parts, fmt.Sprintf("%s=%d bytes (keccak %s)", name, len(x), ethcrypto.Keccak256Hash(x).Hex()))
			} else {
				parts = append(parts, fmt.Sprintf("%s=0x%x", name, x))
			}
		default:
			parts = append(parts, fmt.Sprintf("%s=%v", name, v))
		}
	}
	return fmt.Sprintf("%s(%s)", ChangeKind(kind), strings.Join(parts, ", "))
}

// Clean makes text from a file or a payload safe to print on a terminal: every rune that is not printable (the C0 and C1 controls, ESC,
// CR, the line and paragraph separators, unassigned and format runes) is written as an escape, so a printed field can never move the
// cursor or repaint the lines around it.
func Clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			b.WriteString(`\ufffd`)
		case unicode.IsPrint(r):
			b.WriteRune(r)
		case r < 0x10000:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	return b.String()
}

// QueueRefusal reads a QueueRefused code (src/vr/VRChanges.sol).
func QueueRefusal(code int) string {
	switch code {
	case 1:
		return "unknown change kind"
	case 2:
		return "too many pending changes"
	case 3:
		return "payload larger than the bound"
	case 4, 5, 6, 7:
		return "the payload is not the exact abi.encode of the kind's fields"
	case 8:
		return "a value is out of range (zero address or hash, committee limits)"
	case 9:
		return "a fee parameter is zero"
	case 10:
		return "the fee profile leaves no ordinary gas capacity"
	case 11:
		return "the base fee floor is above the maximum"
	case 12:
		return "unsupported fee profile (the ordinary gas is not a multiple of the elasticity)"
	case 13:
		return "the fee collector is the zero address"
	case 14:
		return "the activation epoch is too early"
	case 15:
		return "the activation time is too soon"
	case 16:
		return "the identity is not in the committee in force"
	case 17:
		return "too many ForceRemove changes pending"
	case 18:
		return "the partition configuration is not readable"
	case 20, 21, 22:
		return "the module's code, code hash or metadata is not acceptable"
	case 23:
		return "too many activations scheduled"
	}
	return fmt.Sprintf("code %d", code)
}

// ChangeQueuedID reads the id from a receipt's ChangeQueued(id, kind, ...) log of VR.
func ChangeQueuedID(r *Receipt, registry ethcommon.Address) (id uint64, kind uint8, ok bool) {
	ev := VRABI.Events["ChangeQueued"]
	for _, l := range r.Logs {
		if l.Address == registry && len(l.Topics) == 3 && l.Topics[0] == ev.ID {
			return new(big.Int).SetBytes(l.Topics[1].Bytes()).Uint64(), uint8(new(big.Int).SetBytes(l.Topics[2].Bytes()).Uint64()), true
		}
	}
	return 0, 0, false
}

// ActionRefusal is a PoA ActionRefused event in a receipt: the module took the ModuleAction without effect.
type ActionRefusal struct {
	Action, ID uint64
	Reason     uint8
}

// String reads the refusal.
func (a ActionRefusal) String() string {
	return fmt.Sprintf("PoaElection refused %s of identity %d: %s", ActionName(a.Action), a.ID, PoaRefusal(a.Reason))
}

// PoaRefusal reads an ActionRefused reason (PoaElection REFUSED_*).
func PoaRefusal(r uint8) string {
	switch r {
	case 1:
		return "the identity is not in a state the action applies to"
	case 2:
		return "not a PoA action"
	case 3:
		return "malformed action"
	case 4:
		return "the module's admission queue is full"
	}
	return fmt.Sprintf("code %d", r)
}

// ActionRefusals lists the ActionRefused events a module emitted in a receipt.
func ActionRefusals(r *Receipt, module ethcommon.Address) []ActionRefusal {
	ev := PoaABI.Events["ActionRefused"]
	var out []ActionRefusal
	for _, l := range r.Logs {
		if l.Address != module || len(l.Topics) != 1 || l.Topics[0] != ev.ID {
			continue
		}
		vals, err := ev.Inputs.Unpack(l.Data)
		if err != nil || len(vals) != 3 {
			continue
		}
		a, _ := vals[0].(*big.Int)
		i, _ := vals[1].(*big.Int)
		rs, _ := vals[2].(uint8)
		if a != nil && i != nil {
			out = append(out, ActionRefusal{Action: a.Uint64(), ID: i.Uint64(), Reason: rs})
		}
	}
	return out
}

// ---- reads ----

func (c *Client) multisig(ctx context.Context, gov ethcommon.Address, method string, out any, args ...any) error {
	return c.call(ctx, gov, MultisigABI, method, out, args...)
}

// MultisigNonce is the governor's next approval nonce.
func (c *Client) MultisigNonce(ctx context.Context, gov ethcommon.Address) (uint64, error) {
	var n uint64
	return n, c.multisig(ctx, gov, "nonce", &n)
}

// MultisigSigners is the governor's five signers, ascending.
func (c *Client) MultisigSigners(ctx context.Context, gov ethcommon.Address) ([5]ethcommon.Address, error) {
	var s [5]ethcommon.Address
	return s, c.multisig(ctx, gov, "signers", &s)
}

// MultisigCallDigest is the governor's own callDigest, to cross-check the local computation.
func (c *Client) MultisigCallDigest(ctx context.Context, gov, target ethcommon.Address, data []byte, nonce uint64) ([32]byte, error) {
	var d [32]byte
	return d, c.multisig(ctx, gov, "callDigest", &d, target, data, nonce)
}

// MultisigPendingSigners reports a staged signer-set change and its delays.
func (c *Client) MultisigPendingSigners(ctx context.Context, gov ethcommon.Address) (pending bool, progress, ucTime uint64, err error) {
	err = errors.Join(c.multisig(ctx, gov, "signersPending", &pending), c.multisig(ctx, gov, "nextNotBeforeProgress", &progress),
		c.multisig(ctx, gov, "nextNotBeforeTime", &ucTime))
	return
}
