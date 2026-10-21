package evmstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

// SlotProof is one storage slot of an account at a block: its 32-byte value and the root-to-leaf proof nodes.
type SlotProof struct {
	Value  [32]byte
	Proofs [][]byte
}

// ProofSource serves eth_getProof-shaped answers for one fixed block (the frozen parent P): the account proof nodes of addr and the
// proof of each requested slot. Nothing it returns is trusted: the witness it feeds is verified against the certified state root.
type ProofSource interface {
	Proof(ctx context.Context, addr [20]byte, slots [][32]byte) (account [][]byte, slotProofs []SlotProof, err error)
}

// ClientDeadline bounds one eth_getProof call.
const ClientDeadline = 10 * time.Second

// ErrBuild reports a source that could not supply what the witness needs.
var ErrBuild = errors.New("evmstate: cannot build the witness")

// recordingReader reads one account's slots through the source and remembers each, so the witness lists exactly what the verifier reads.
type recordingReader struct {
	ctx     context.Context
	src     ProofSource
	addr    [20]byte
	account [][]byte
	slots   map[[32]byte]SlotProof
}

func (r *recordingReader) word(slot [32]byte) ([32]byte, error) {
	if p, ok := r.slots[slot]; ok {
		return p.Value, nil
	}
	account, proofs, err := r.src.Proof(r.ctx, r.addr, [][32]byte{slot})
	if err != nil || len(proofs) != 1 {
		return [32]byte{}, errors.Join(ErrBuild, err, fmt.Errorf("slot %x of %x: %d proofs", slot, r.addr, len(proofs)))
	}
	r.account = account
	r.slots[slot] = proofs[0]
	return proofs[0].Value, nil
}

// dryReader answers every slot with the zero word and lists what was asked, in order.
type dryReader struct{ slots [][32]byte }

func (d *dryReader) word(slot [32]byte) ([32]byte, error) {
	d.slots = append(d.slots, slot)
	return [32]byte{}, nil
}

// fetch reads the slots in one call and remembers them; the slots already known are not asked for again.
func (r *recordingReader) fetch(slots [][32]byte) error {
	var want [][32]byte
	for _, s := range slots {
		if _, ok := r.slots[s]; !ok {
			want = append(want, s)
		}
	}
	if len(want) == 0 {
		return nil
	}
	account, proofs, err := r.src.Proof(r.ctx, r.addr, want)
	if err != nil || len(proofs) != len(want) {
		return errors.Join(ErrBuild, err, fmt.Errorf("%d slots of %x: %d proofs", len(want), r.addr, len(proofs)))
	}
	r.account = account
	for i, s := range want {
		r.slots[s] = proofs[i]
	}
	return nil
}

// BuildPrimaryWitness collects the witness evmassign.VerifyPrimary's authority reads for a result: the Election and custody accounts at
// the source's block, with exactly the slots the verifier consumes. The slots custody is read at depend on the session the election
// names, so they are discovered by running the same reader the verifier runs.
func BuildPrimaryWitness(ctx context.Context, src ProofSource, pins Pins, resultID [32]byte) ([]byte, error) {
	election := &recordingReader{ctx: ctx, src: src, addr: pins.Election, slots: map[[32]byte]SlotProof{}}
	custody := &recordingReader{ctx: ctx, src: src, addr: pins.Custody, slots: map[[32]byte]SlotProof{}}
	var f evmassign.PrimaryFacts
	if err := readPrimary(election, custody, pins, resultID, &f); err != nil {
		return nil, err
	}
	return encodeAccounts(election, custody)
}

// BuildRetirementWitness collects the witness Authority.VerifyRetirement reads for (id, generation): the custody and registry accounts at the
// source's block, with exactly the slots the verifier consumes, the deployment bindings the verifier checks first included. It also returns
// the facts the witness proves, so a caller can tell an eligible generation from one that is not (yet) retirable before it offers anything.
// Nothing the source answers is trusted: the witness is only as good as the verification against the certified state root.
func BuildRetirementWitness(ctx context.Context, src ProofSource, pins Pins, id, generation uint64) ([]byte, storage.RetirementFacts, error) {
	var f storage.RetirementFacts
	custody := &recordingReader{ctx: ctx, src: src, addr: pins.Custody, slots: map[[32]byte]SlotProof{}}
	registry := &recordingReader{ctx: ctx, src: src, addr: pins.Registry, slots: map[[32]byte]SlotProof{}}
	// the verifier reads custody.network and custody.roots first (accounts)
	bindings := [][32]byte{baseSlot(custodyNetwork), baseSlot(custodyRoots)}
	// One call per account for every slot that does not depend on another: a dry run of the reader against empty words lists them (the lot
	// slots depend on the lot count and are read afterwards, one by one).
	dryC, dryR := &dryReader{}, &dryReader{}
	var ignored storage.RetirementFacts
	if err := readRetirement(dryC, dryR, id, generation, &ignored); err == nil {
		if err := custody.fetch(append(append([][32]byte(nil), bindings...), dryC.slots...)); err != nil {
			return nil, f, err
		}
		if err := registry.fetch(dryR.slots); err != nil {
			return nil, f, err
		}
	}
	for _, slot := range bindings {
		if _, err := custody.word(slot); err != nil {
			return nil, f, err
		}
	}
	if err := readRetirement(custody, registry, id, generation, &f); err != nil {
		return nil, f, err
	}
	raw, err := encodeAccounts(custody, registry)
	return raw, f, err
}

// encodeAccounts is the canonical witness of the recorded accounts: ascending by address, each with its slots ascending.
func encodeAccounts(readers ...*recordingReader) ([]byte, error) {
	var accounts []accountProof
	for _, r := range readers {
		ap := accountProof{Addr: bytes.Clone(r.addr[:]), Proofs: r.account}
		var slots [][32]byte
		for s := range r.slots {
			slots = append(slots, s)
		}
		sort.Slice(slots, func(i, j int) bool { return bytes.Compare(slots[i][:], slots[j][:]) < 0 })
		for _, s := range slots {
			p := r.slots[s]
			ap.Slots = append(ap.Slots, slotProof{Slot: bytes.Clone(s[:]), Value: bytes.Clone(p.Value[:]), Proofs: p.Proofs})
		}
		accounts = append(accounts, ap)
	}
	sort.Slice(accounts, func(i, j int) bool { return bytes.Compare(accounts[i].Addr, accounts[j].Addr) < 0 })
	return Witness{Accounts: accounts}.Encode()
}

// RPCProofSource is a ProofSource over an execution client's eth_getProof at one block hash.
type RPCProofSource struct {
	Client    *rpc.Client
	BlockHash [32]byte
}

// rpcNumber is a hex number of at most 256 bits with leading zeros allowed: eth_getProof answers keys and values as hex quantities ("0x0",
// odd lengths allowed) or as zero-padded 32-byte words, depending on the client (the one the lane runs answers the padded words for the 32-byte
// keys it is asked for), and hexutil.Big refuses the padded form.
type rpcNumber big.Int

func (n *rpcNumber) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.Join(ErrBuild, err)
	}
	if len(s) < 3 || s[:2] != "0x" || len(s) > 2+64 {
		return fmt.Errorf("%w: %q is not a hex number of at most 256 bits", ErrBuild, s)
	}
	// big.Int.SetString(.., 16) would also take a sign: only hex digits are numbers here
	for _, c := range s[2:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return fmt.Errorf("%w: %q is not hex", ErrBuild, s)
		}
	}
	if _, ok := (*big.Int)(n).SetString(s[2:], 16); !ok {
		return fmt.Errorf("%w: %q is not hex", ErrBuild, s)
	}
	return nil
}

type rpcSlot struct {
	Key   rpcNumber       `json:"key"`
	Value rpcNumber       `json:"value"`
	Proof []hexutil.Bytes `json:"proof"`
}

type rpcProof struct {
	AccountProof []hexutil.Bytes `json:"accountProof"`
	StorageProof []rpcSlot       `json:"storageProof"`
}

// Proof implements ProofSource.
func (s RPCProofSource) Proof(ctx context.Context, addr [20]byte, slots [][32]byte) ([][]byte, []SlotProof, error) {
	keys := make([]string, len(slots))
	for i := range slots {
		keys[i] = hexutil.Encode(slots[i][:])
	}
	var out rpcProof
	ctx, cancel := context.WithTimeout(ctx, ClientDeadline)
	defer cancel()
	if err := s.Client.CallContext(ctx, &out, "eth_getProof", hexutil.Encode(addr[:]), keys, map[string]string{"blockHash": hexutil.Encode(s.BlockHash[:])}); err != nil {
		return nil, nil, errors.Join(ErrBuild, err)
	}
	if len(out.StorageProof) != len(slots) {
		return nil, nil, fmt.Errorf("%w: %d storage proofs for %d slots", ErrBuild, len(out.StorageProof), len(slots))
	}
	account := make([][]byte, len(out.AccountProof))
	for i, n := range out.AccountProof {
		account[i] = n
	}
	proofs := make([]SlotProof, len(slots))
	for i, sp := range out.StorageProof {
		key, value := (*big.Int)(&sp.Key), (*big.Int)(&sp.Value)
		if value.BitLen() > 256 || key.Cmp(new(big.Int).SetBytes(slots[i][:])) != 0 {
			return nil, nil, fmt.Errorf("%w: storage proof %d answers another slot", ErrBuild, i)
		}
		value.FillBytes(proofs[i].Value[:])
		for _, n := range sp.Proof {
			proofs[i].Proofs = append(proofs[i].Proofs, n)
		}
	}
	return account, proofs, nil
}
