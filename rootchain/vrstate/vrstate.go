// Package vrstate reads the ValidatorRegistry (VR) from a certified EVM state (VT-05a, ristik/bft-core#1145; design section 5.1-5.2 and
// 3.9.3, schema-v1 sections 2 and 13). A witness is the evmstate canonical account witness, verified against the EVM state root the root
// itself certified; every word is decoded with the frozen vrschema layout, and the reader refuses what the schema refuses (a nonzero
// reserved byte, a non-canonical bool, an undefined state). The roots never read module storage: VR is the one account a Freeze proves,
// and a HolderRetirement adds exactly the SealRegistry and the holder account.
//
// Member words and node-id strings are not proven here: the roots hash-verify them against the proven membersDigest and outputCommit
// (vradmit), whoever served them (FD-16).
package vrstate

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/unicitynetwork/bft-core/rootchain/evmstate"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The genesis EVM PDR pins VR's address and code hash (design section 2.1); ConfigHash covers both.
const (
	ParamValidatorRegistry         = "validator_registry"
	ParamValidatorRegistryCodeHash = "validator_registry_code_hash"
)

var (
	// ErrPins reports a PDR that does not pin VR, or pins it in a non-canonical spelling.
	ErrPins = errors.New("vrstate: validator registry pins")
	// ErrState reports certified VR state that the frozen layout refuses or that is not the pinned contract's.
	ErrState = errors.New("vrstate: invalid certified VR state")
)

// Pins identify the contracts a VR witness may speak about. Registry and RegistryCode come from the genesis EVM PDR; NetworkWord is the
// deployment network word the genesis plan pins (VR stores it at V+0); SealRegistry and its code hash are needed only for the
// three-account HolderRetirement witness and the RejectResult clock.
type Pins struct {
	Registry         [20]byte
	RegistryCode     [32]byte
	NetworkWord      vrschema.Word
	SealRegistry     [20]byte
	SealRegistryCode [32]byte
}

// PinsFromPDR reads the VR address and code hash of a genesis EVM PDR: lowercase 0x-prefixed hex of exactly 20 and 32 bytes, VR's
// address and a nonzero code hash. ok is false when the PDR pins no VR (a pre-VR generation); a VR mode chain needs both.
func PinsFromPDR(pdr *types.PartitionDescriptionRecord) (registry [20]byte, code [32]byte, ok bool, err error) {
	if pdr == nil {
		return registry, code, false, nil
	}
	a, hasA := pdr.PartitionParams[ParamValidatorRegistry]
	c, hasC := pdr.PartitionParams[ParamValidatorRegistryCodeHash]
	if !hasA && !hasC {
		return registry, code, false, nil
	}
	if !hasA || !hasC {
		return registry, code, false, fmt.Errorf("%w: the PDR pins one of the address and the code hash", ErrPins)
	}
	if err := canonicalHex(a, registry[:]); err != nil {
		return registry, code, false, fmt.Errorf("%w: address: %w", ErrPins, err)
	}
	if err := canonicalHex(c, code[:]); err != nil {
		return registry, code, false, fmt.Errorf("%w: code hash: %w", ErrPins, err)
	}
	if code == ([32]byte{}) {
		return registry, code, false, fmt.Errorf("%w: zero code hash", ErrPins)
	}
	if registry != vrschema.ValidatorRegistry {
		return registry, code, false, fmt.Errorf("%w: VR is at %x, not the genesis alloc %x", ErrPins, registry, vrschema.ValidatorRegistry)
	}
	return registry, code, true, nil
}

func canonicalHex(s string, out []byte) error {
	if !strings.HasPrefix(s, "0x") || len(s) != 2+2*len(out) || strings.ToLower(s) != s {
		return errors.New("not lowercase 0x-prefixed hex of the right width")
	}
	_, err := hex.Decode(out, []byte(s[2:]))
	return err
}

// Reader decodes VR storage words with the frozen layout. Its source is a verified account (consensus) or a recording builder
// (off-consensus); both see exactly the same reads, so a builder's witness carries exactly the slots the verifier consumes.
type Reader struct{ W evmstate.SlotReader }

func (r Reader) word(slot vrschema.Word) (vrschema.Word, error) { return r.W.Word(slot) }

// Scalar reads V+k.
func (r Reader) Scalar(k uint64) (vrschema.Word, error) { return r.word(vrschema.VRSlot(k)) }

// Status reads and decodes V+6.
func (r Reader) Status() (vrschema.Status, error) {
	w, err := r.Scalar(vrschema.SlotStatus)
	if err != nil {
		return vrschema.Status{}, err
	}
	s, err := vrschema.DecodeStatus(w)
	return s, wrap(err)
}

// CommitteeLimits reads and decodes V+4.
func (r Reader) CommitteeLimits() (vrschema.CommitteeLimits, error) {
	w, err := r.Scalar(vrschema.SlotCommitteeLimits)
	if err != nil {
		return vrschema.CommitteeLimits{}, err
	}
	l, err := vrschema.DecodeCommitteeLimits(w)
	return l, wrap(err)
}

// Fees reads and decodes V+11..V+15.
func (r Reader) Fees() (vrschema.Fees, error) {
	var words [5]vrschema.Word
	for i := range words {
		word, err := r.Scalar(vrschema.SlotFeesPrevious + uint64(i))
		if err != nil {
			return vrschema.Fees{}, err
		}
		words[i] = word
	}
	fees, err := vrschema.DecodeFees(words)
	return fees, wrap(err)
}

// Output reads and decodes the 11 words of outputs[R].
func (r Reader) Output(resultID vrschema.Word) (vrschema.OutputRecord, error) {
	var ws [vrschema.OutputWords]vrschema.Word
	for j := range ws {
		w, err := r.word(vrschema.OutputSlot(resultID, uint64(j)))
		if err != nil {
			return vrschema.OutputRecord{}, err
		}
		ws[j] = w
	}
	o, err := vrschema.DecodeOutput(ws)
	return o, wrap(err)
}

// Change reads changes[id] and, for a known change, its payload bytes, verified by length and payloadHash.
func (r Reader) Change(id uint64) (vrschema.ChangeRecord, []byte, error) {
	var ws [vrschema.ChangeWords]vrschema.Word
	for j := range ws {
		w, err := r.word(vrschema.ChangeSlot(id, uint64(j)))
		if err != nil {
			return vrschema.ChangeRecord{}, nil, err
		}
		ws[j] = w
	}
	c, err := vrschema.DecodeChange(ws)
	if err != nil {
		return c, nil, wrap(err)
	}
	if c.State == vrschema.ChNone {
		return c, nil, nil
	}
	payload, err := r.Bytes(vrschema.ChangePayloadSlot(id), vrschema.MaxChangePayload)
	if err != nil {
		return c, nil, err
	}
	if uint32(len(payload)) != c.PayloadLength || vrschema.PayloadHash(payload) != c.PayloadHash {
		return c, nil, fmt.Errorf("%w: change %d payload is not the one its record commits to", ErrState, id)
	}
	return c, payload, nil
}

// Bytes reads a Solidity bytes value at slot: a value under 32 bytes sits left-aligned with 2*len in the low byte, the rest of the
// word zero; a longer one stores 2*len+1 and its data from keccak256(slot), the bytes after the end zero. Any other form is refused,
// and so is a length above max (checked before any data slot is read).
func (r Reader) Bytes(slot vrschema.Word, max int) ([]byte, error) {
	head, err := r.word(slot)
	if err != nil {
		return nil, err
	}
	if head[31]&1 == 0 {
		n := int(head[31] / 2)
		if n > 31 || n > max {
			return nil, fmt.Errorf("%w: short bytes length %d", ErrState, n)
		}
		for _, b := range head[n:31] {
			if b != 0 {
				return nil, fmt.Errorf("%w: short bytes padding", ErrState)
			}
		}
		return append([]byte{}, head[:n]...), nil
	}
	l, err := vrschema.WordU64(head)
	if err != nil || l < 65 || (l-1)/2 > uint64(max) {
		return nil, fmt.Errorf("%w: long bytes length word %x", ErrState, head)
	}
	n := int((l - 1) / 2)
	out := make([]byte, 0, n)
	base := vrschema.BytesDataSlot(slot)
	for i := 0; len(out) < n; i++ {
		w, err := r.word(vrschema.SlotAdd(base, uint64(i)))
		if err != nil {
			return nil, err
		}
		take := min(32, n-len(out))
		for _, b := range w[take:] {
			if b != 0 {
				return nil, fmt.Errorf("%w: long bytes padding", ErrState)
			}
		}
		out = append(out, w[:take]...)
	}
	return out, nil
}

// Activation reads activations[i] (i < activationCount).
func (r Reader) Activation(i uint32) (vrschema.Activation, error) {
	var ws [vrschema.ActivationWords]vrschema.Word
	for j := range ws {
		w, err := r.word(vrschema.ActivationSlot(i, uint64(j)))
		if err != nil {
			return vrschema.Activation{}, err
		}
		ws[j] = w
	}
	a, err := vrschema.DecodeActivation(ws)
	return a, wrap(err)
}

// Holder reads holders[h] (h < holderCount).
func (r Reader) Holder(h uint8) (vrschema.Holder, error) {
	var ws [vrschema.HolderWords]vrschema.Word
	for j := range ws {
		w, err := r.word(vrschema.HolderSlot(h, uint64(j)))
		if err != nil {
			return vrschema.Holder{}, err
		}
		ws[j] = w
	}
	x, err := vrschema.DecodeHolder(ws)
	return x, wrap(err)
}

// Retired reads retired[holder][id][generation].
func (r Reader) Retired(h uint8, id, generation uint64) (bool, error) {
	w, err := r.word(vrschema.RetiredSlot(h, id, generation))
	if err != nil {
		return false, err
	}
	b, err := vrschema.WordBool(w)
	return b, wrap(err)
}

func wrap(err error) error {
	if err == nil {
		return nil
	}
	return errors.Join(ErrState, err)
}

// ReadOutputState reads everything admission and the rejection due table judge about R at P (design section 5.2 items 1, 2, 4, 8
// and the output record): V+0 to V+4, V+6 and outputs[R]. The order of reads is fixed, so a builder and the verifier agree.
func ReadOutputState(r Reader, resultID vrschema.Word) (vradmit.OutputState, error) {
	var s vradmit.OutputState
	var err error
	if s.Network, err = r.Scalar(vrschema.SlotNetwork); err != nil {
		return s, err
	}
	if s.OpenOutput, err = r.Scalar(vrschema.SlotOpenOutput); err != nil {
		return s, err
	}
	if s.LastAcked, err = r.Scalar(vrschema.SlotLastAcked); err != nil {
		return s, err
	}
	if s.PendingPair, err = r.Scalar(vrschema.SlotPendingPair); err != nil {
		return s, err
	}
	if s.Limits, err = r.CommitteeLimits(); err != nil {
		return s, err
	}
	if s.Status, err = r.Status(); err != nil {
		return s, err
	}
	s.ResultID = resultID
	s.Output, err = r.Output(resultID)
	return s, err
}
