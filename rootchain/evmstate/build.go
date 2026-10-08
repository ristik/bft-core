package evmstate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/unicitynetwork/bft-core/evmassign"
)

// SlotProof is one storage slot of an account at a block: its 32-byte value and the root-to-leaf proof nodes.
type SlotProof struct {
	Value  [32]byte
	Proofs [][]byte
}

// ProofSource serves eth_getProof-shaped answers for one fixed block (the frozen parent P): the account proof nodes of addr and the
// proof of each requested slot. Nothing it returns is trusted: the witness it feeds is verified against the certified state root.
type ProofSource interface {
	Proof(addr [20]byte, slots [][32]byte) (account [][]byte, slotProofs []SlotProof, err error)
}

// ClientDeadline bounds one eth_getProof call.
const ClientDeadline = 10 * time.Second

// ErrBuild reports a source that could not supply what the witness needs.
var ErrBuild = errors.New("evmstate: cannot build the witness")

// recordingReader reads one account's slots through the source and remembers each, so the witness lists exactly what the verifier reads.
type recordingReader struct {
	src     ProofSource
	addr    [20]byte
	account [][]byte
	slots   map[[32]byte]SlotProof
}

func (r *recordingReader) word(slot [32]byte) ([32]byte, error) {
	if p, ok := r.slots[slot]; ok {
		return p.Value, nil
	}
	account, proofs, err := r.src.Proof(r.addr, [][32]byte{slot})
	if err != nil || len(proofs) != 1 {
		return [32]byte{}, errors.Join(ErrBuild, err, fmt.Errorf("slot %x of %x: %d proofs", slot, r.addr, len(proofs)))
	}
	r.account = account
	r.slots[slot] = proofs[0]
	return proofs[0].Value, nil
}

// BuildPrimaryWitness collects the witness evmassign.VerifyPrimary's authority reads for a result: the Election and custody accounts at
// the source's block, with exactly the slots the verifier consumes. The slots custody is read at depend on the session the election
// names, so they are discovered by running the same reader the verifier runs.
func BuildPrimaryWitness(src ProofSource, pins Pins, resultID [32]byte) ([]byte, error) {
	election := &recordingReader{src: src, addr: pins.Election, slots: map[[32]byte]SlotProof{}}
	custody := &recordingReader{src: src, addr: pins.Custody, slots: map[[32]byte]SlotProof{}}
	var f evmassign.PrimaryFacts
	if err := readPrimary(election, custody, pins, resultID, &f); err != nil {
		return nil, err
	}
	var accounts []accountProof
	for _, r := range []*recordingReader{election, custody} {
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

type rpcSlot struct {
	Key   hexutil.Bytes   `json:"key"`
	Value hexutil.Bytes   `json:"value"`
	Proof []hexutil.Bytes `json:"proof"`
}

type rpcProof struct {
	AccountProof []hexutil.Bytes `json:"accountProof"`
	StorageProof []rpcSlot       `json:"storageProof"`
}

// Proof implements ProofSource.
func (s RPCProofSource) Proof(addr [20]byte, slots [][32]byte) ([][]byte, []SlotProof, error) {
	keys := make([]string, len(slots))
	for i := range slots {
		keys[i] = hexutil.Encode(slots[i][:])
	}
	var out rpcProof
	ctx, cancel := context.WithTimeout(context.Background(), ClientDeadline)
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
		if len(sp.Value) > 32 || !bytes.Equal(bytes.TrimLeft(sp.Key, "\x00"), bytes.TrimLeft(slots[i][:], "\x00")) {
			return nil, nil, fmt.Errorf("%w: storage proof %d answers another slot", ErrBuild, i)
		}
		copy(proofs[i].Value[32-len(sp.Value):], sp.Value)
		for _, n := range sp.Proof {
			proofs[i].Proofs = append(proofs[i].Proofs, n)
		}
	}
	return account, proofs, nil
}
