package evmstate

import (
	"bytes"
	"errors"
	"fmt"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/unicitynetwork/bft-core/bridgeprofile"
	basetypes "github.com/unicitynetwork/bft-go-base/types"
)

var (
	// ErrWitness reports a witness that is malformed, non-canonical or carries an unused, duplicate or misordered entry.
	ErrWitness = errors.New("evmstate: invalid state witness")
	// ErrProof reports a proof that does not verify against the certified state root, or an account that is not the pinned contract.
	ErrProof = errors.New("evmstate: proof does not verify against the certified state")
)

// Witness limits: the control witness budget is 1 MiB per root block.
const (
	MaxWitnessBytes = 1 << 20
	maxAccounts     = 2
	maxSlots        = 4096
)

type slotProof struct {
	_      struct{} `cbor:",toarray"`
	Slot   []byte
	Value  []byte
	Proofs [][]byte
}

type accountProof struct {
	_      struct{} `cbor:",toarray"`
	Addr   []byte
	Proofs [][]byte
	Slots  []slotProof
}

// Witness is the retained witness bytes of a Retirement or RejectResult: CBOR [accounts], accounts ascending by address, each
// [address20, accountProofNodes, slots], each slot [slot32, value32, proofNodes] ascending by slot. Proof nodes are the exact RLP of the
// root-to-leaf path.
type Witness struct {
	Accounts []accountProof
}

// Encode is the canonical encoding.
func (w Witness) Encode() ([]byte, error) { return basetypes.Cbor.Marshal(w.Accounts) }

func decodeWitness(raw []byte) (Witness, error) {
	if len(raw) == 0 || len(raw) > MaxWitnessBytes {
		return Witness{}, fmt.Errorf("%w: %d bytes", ErrWitness, len(raw))
	}
	var accounts []accountProof
	if err := basetypes.Cbor.Unmarshal(raw, &accounts); err != nil {
		return Witness{}, errors.Join(ErrWitness, err)
	}
	canonical, err := basetypes.Cbor.Marshal(accounts)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Witness{}, fmt.Errorf("%w: not canonical", ErrWitness)
	}
	if len(accounts) == 0 || len(accounts) > maxAccounts {
		return Witness{}, fmt.Errorf("%w: %d accounts", ErrWitness, len(accounts))
	}
	for i, a := range accounts {
		if len(a.Addr) != 20 || (i > 0 && bytes.Compare(accounts[i-1].Addr, a.Addr) >= 0) {
			return Witness{}, fmt.Errorf("%w: accounts not strictly ascending 20-byte addresses", ErrWitness)
		}
		if len(a.Proofs) == 0 || len(a.Slots) > maxSlots {
			return Witness{}, fmt.Errorf("%w: account %x", ErrWitness, a.Addr)
		}
		for j, s := range a.Slots {
			if len(s.Slot) != 32 || len(s.Value) != 32 || (j > 0 && bytes.Compare(a.Slots[j-1].Slot, s.Slot) >= 0) {
				return Witness{}, fmt.Errorf("%w: slots of %x not strictly ascending 32-byte words", ErrWitness, a.Addr)
			}
		}
	}
	return Witness{Accounts: accounts}, nil
}

// proven is one account with its verified storage words.
type proven struct {
	storageRoot [32]byte
	codeHash    [32]byte
	slots       map[[32]byte][32]byte
	used        map[[32]byte]bool
}

func (p *proven) word(slot [32]byte) ([32]byte, error) {
	v, ok := p.slots[slot]
	if !ok {
		return v, fmt.Errorf("%w: the witness has no proof for slot %x", ErrWitness, slot)
	}
	p.used[slot] = true
	return v, nil
}

func (p *proven) unused() error {
	for slot := range p.slots {
		if !p.used[slot] {
			return fmt.Errorf("%w: slot %x is proven but unused", ErrWitness, slot)
		}
	}
	return nil
}

// verify checks every account and slot proof of the witness against the certified state root.
func (w Witness) verify(stateRoot [32]byte) (map[ethcommon.Address]*proven, error) {
	out := map[ethcommon.Address]*proven{}
	for _, a := range w.Accounts {
		addr := ethcommon.BytesToAddress(a.Addr)
		value, present, err := bridgeprofile.VerifyMPTEntry(stateRoot, [32]byte(ethcrypto.Keccak256Hash(a.Addr)), a.Proofs)
		if err != nil {
			return nil, errors.Join(ErrProof, fmt.Errorf("account %s", addr), err)
		}
		if !present {
			return nil, fmt.Errorf("%w: account %s does not exist in the certified state", ErrProof, addr)
		}
		var acct types.StateAccount
		if err := rlp.DecodeBytes(value, &acct); err != nil {
			return nil, errors.Join(ErrProof, fmt.Errorf("account %s", addr), err)
		}
		p := &proven{storageRoot: acct.Root, codeHash: [32]byte(acct.CodeHash), slots: map[[32]byte][32]byte{}, used: map[[32]byte]bool{}}
		for _, s := range a.Slots {
			var slot, claimed [32]byte
			copy(slot[:], s.Slot)
			copy(claimed[:], s.Value)
			stored, present, err := bridgeprofile.VerifyMPTEntry(p.storageRoot, [32]byte(ethcrypto.Keccak256Hash(s.Slot)), s.Proofs)
			if err != nil {
				return nil, errors.Join(ErrProof, fmt.Errorf("slot %x of %s", slot, addr), err)
			}
			var got [32]byte
			if present {
				var trimmed []byte
				if err := rlp.DecodeBytes(stored, &trimmed); err != nil || len(trimmed) == 0 || len(trimmed) > 32 || trimmed[0] == 0 {
					return nil, fmt.Errorf("%w: slot %x of %s holds a non-canonical value", ErrProof, slot, addr)
				}
				copy(got[32-len(trimmed):], trimmed)
			}
			if got != claimed {
				return nil, fmt.Errorf("%w: slot %x of %s holds %x, not the claimed %x", ErrProof, slot, addr, got, claimed)
			}
			p.slots[slot] = got
		}
		out[addr] = p
	}
	return out, nil
}
