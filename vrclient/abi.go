// Package vrclient is the operator side of the ValidatorRegistry (VR) and its PoA module over public JSON-RPC only: the reads `ubft
// validator status` shows, the owner transactions of the validator lifecycle (design briefs/validator-registry-design-final.md section
// 3.5.6: `validator apply` = VR.register + PoaElection.submitApplication, requestExit, rejoin, and VR.proposeBinding for a key rotation),
// their registration proofs of possession (section 3.1), and decoding of calldata and revert data for previews.
//
// The ABIs in abi/ are the compiled interfaces of unicity-pos-contracts (src/vr: IVR with VRShared's events and errors, and PoaElection's
// owner and view functions), taken from the forge artifacts. Nothing here holds consensus state; every value is read from the chain.
package vrclient

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

var (
	//go:embed abi/vr.json
	vrJSON []byte
	//go:embed abi/poa.json
	poaJSON []byte

	// VRABI is the ValidatorRegistry's external ABI (core and facets) without the system-only hooks, with VR's events and errors.
	VRABI abi.ABI
	// PoaABI is PoaElection's owner functions, views, events and errors.
	PoaABI abi.ABI

	// ErrVR is returned for a VR or module answer this client cannot use.
	ErrVR = errors.New("validator registry")
)

func init() {
	var err error
	if VRABI, err = abi.JSON(bytes.NewReader(vrJSON)); err != nil {
		panic(fmt.Sprintf("vrclient: VR ABI: %v", err))
	}
	if PoaABI, err = abi.JSON(bytes.NewReader(poaJSON)); err != nil {
		panic(fmt.Sprintf("vrclient: PoA ABI: %v", err))
	}
}

// Call is decoded calldata: the contract it is for, the method and its named arguments in order.
type Call struct {
	Contract string // "ValidatorRegistry", "PoaElection" or "FoundationMultisig"
	Method   string
	Args     []NamedValue
}

// NamedValue is one decoded argument.
type NamedValue struct {
	Name  string
	Value any
}

// DecodeCall decodes calldata of a VR or PoaElection method (VR first: the PoA module has no selector in common with VR's write methods).
func DecodeCall(data []byte) (Call, error) {
	if len(data) < 4 {
		return Call{}, fmt.Errorf("%w: calldata shorter than a selector", ErrVR)
	}
	for _, c := range []struct {
		name string
		a    *abi.ABI
	}{{"ValidatorRegistry", &VRABI}, {"PoaElection", &PoaABI}, {"FoundationMultisig", &MultisigABI}, {"StakeCustody", &CustodyABI}, {"StakeCustody", &CustodyTermsABI}, {"ElectionPolicy", &PosElectionABI}, {"ElectionPolicy", &PosPublishABI}} {
		m, err := c.a.MethodById(data[:4])
		if err != nil {
			continue
		}
		vals, err := m.Inputs.Unpack(data[4:])
		if err != nil {
			return Call{}, fmt.Errorf("%w: %s.%s calldata: %v", ErrVR, c.name, m.Name, err)
		}
		out := Call{Contract: c.name, Method: m.Name}
		for i, in := range m.Inputs {
			out.Args = append(out.Args, NamedValue{Name: in.Name, Value: vals[i]})
		}
		return out, nil
	}
	return Call{}, fmt.Errorf("%w: unknown selector %x", ErrVR, data[:4])
}

// String renders the call on several lines, one argument per line, byte strings in hex and tuples field by field.
func (c Call) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s.%s(", c.Contract, c.Method)
	if len(c.Args) == 0 {
		b.WriteString(")")
		return b.String()
	}
	b.WriteString("\n")
	for _, a := range c.Args {
		fmt.Fprintf(&b, "    %s: %s\n", a.Name, render(a.Value, "    "))
	}
	b.WriteString(")")
	return b.String()
}

func render(v any, indent string) string {
	switch x := v.(type) {
	case []byte:
		if len(x) == 0 {
			return "0x (empty)"
		}
		return fmt.Sprintf("%s (%d bytes)", hexutil.Encode(x), len(x))
	case [32]byte:
		return hexutil.Encode(x[:])
	case [][]byte:
		parts := make([]string, len(x))
		for i, b := range x {
			parts[i] = hexutil.Encode(b)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case ethcommon.Address:
		return x.Hex()
	case string:
		return fmt.Sprintf("%q", x)
	case *big.Int:
		return x.String()
	}
	// a tuple: the ABI decoder's anonymous struct
	s := fmt.Sprintf("%+v", v)
	if fields, ok := structFields(v); ok {
		var b strings.Builder
		b.WriteString("{\n")
		for _, f := range fields {
			fmt.Fprintf(&b, "%s    %s: %s\n", indent, f.Name, render(f.Value, indent+"    "))
		}
		b.WriteString(indent + "}")
		return b.String()
	}
	return s
}

// RevertError is a decoded VR or module revert: the error's name and its arguments, with a plain-language reading where the code is
// known.
type RevertError struct {
	Name   string
	Args   []any
	Reason string
}

func (e *RevertError) Error() string {
	s := e.Name
	if len(e.Args) > 0 {
		parts := make([]string, len(e.Args))
		for i, a := range e.Args {
			parts[i] = fmt.Sprint(a)
		}
		s += "(" + strings.Join(parts, ", ") + ")"
	}
	if e.Reason != "" {
		s += ": " + e.Reason
	}
	return s
}

// DecodeRevert decodes revert data against VR's and the PoA module's errors. It returns nil for data it does not know.
func DecodeRevert(data []byte) *RevertError {
	if len(data) < 4 {
		return nil
	}
	for _, a := range []*abi.ABI{&VRABI, &PoaABI, &MultisigABI, &PosErrorsABI} {
		for _, e := range a.Errors {
			if !bytes.Equal(e.ID[:4], data[:4]) {
				continue
			}
			vals, err := e.Inputs.Unpack(data[4:])
			if err != nil {
				return nil
			}
			out := &RevertError{Name: e.Name, Args: vals}
			out.Reason = revertReason(a == &PoaABI, e.Name, vals)
			return out
		}
	}
	return nil
}

func revertReason(poa bool, name string, vals []any) string {
	code := -1
	if len(vals) == 1 {
		if c, ok := vals[0].(uint8); ok {
			code = int(c)
		}
	}
	switch {
	case name == "RegistrationRefused":
		return RegistrationRefusal(code)
	case name == "QueueRefused":
		return QueueRefusal(code)
	case name == "NotGovernor":
		return "only the Foundation multisig (VR's governor) may queue or cancel changes"
	case name == "NotCancellable":
		return "only a Queued or Scheduled change can be cancelled"
	case name == "BadSignatures":
		return "the approvals are not three or more distinct signers' valid signatures in ascending address order, or the nonce moved"
	case name == "CallFailed":
		return "the approved call reverted (the multisig hides its reason; the preview simulates the call as the governor)"
	case name == "NotOwner":
		return "the sender is not the identity's owner"
	case poa && name == "BadState":
		return fmt.Sprintf("the action is not allowed in PoA state %s", PoaState(code))
	case name == "Locked":
		return "VR is inside another call (re-entry)"
	case name == "Inconsistent":
		return "VR is Inconsistent (absorbing; only a new generation helps)"
	case name == "DelayNotElapsed":
		return "the governance delay has not passed"
	case name == "PreconditionFailed":
		return "the change or output is not in the state this action needs"
	case name == "RecordsPending":
		return "custody has root records to apply, or an election is pending: try again after the next block"
	case name == "LotStillReferenced":
		return "a term still references the lot (the closure is not imported yet)"
	case name == "TermAnchorPending":
		return "a closed term of the lot is not anchored yet (`validator claim` anchors it)"
	case name == "RetirementNotImported":
		return "the retirement record is not imported yet"
	case name == "EvidenceHoldPending":
		return "accepted evidence holds the lot"
	case name == "RoundGateNotMet":
		return "the root progress has not passed the retirement hold yet"
	case name == "EvidenceGateNotMet":
		return "the root progress has not passed the evidence window yet"
	case name == "TimeGateNotMet":
		return "the certified UC time has not reached the retirement time floor yet"
	case name == "AlreadyPublished":
		return "another party published the candidate first"
	case name == "NotCovered":
		return "a frozen member is no longer eligible or covered (a retirement request or an exclusion): the result cannot be finalized"
	}
	return ""
}

// RegistrationRefusal reads a RegistrationRefused code (VRShared REG_*).
func RegistrationRefusal(code int) string {
	switch code {
	case 1:
		return "a node id is empty or longer than 128 bytes"
	case 2:
		return "a key is not a 33-byte compressed secp256k1 point"
	case 3:
		return "the root key and the EVM key are equal"
	case 4:
		return "the payee is the zero address"
	case 5:
		return "the nonce is not the expected one (registrationNonce of the sender, or the identity's bindingNonce)"
	case 6:
		return "a key is already registered (keys are tombstoned for good across identities and roles)"
	case 7:
		return "a proof of possession does not verify"
	case 8:
		return "the proposed binding is the current one"
	}
	return fmt.Sprintf("code %d", code)
}
