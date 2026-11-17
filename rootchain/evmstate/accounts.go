package evmstate

import (
	"bytes"
	"context"
	"fmt"

	ethcommon "github.com/ethereum/go-ethereum/common"
)

// The generic account layer for readers outside this package (rootchain/vrstate): a canonical witness over a fixed set of accounts,
// verified against the certified state root, and a builder that records exactly the slots a reader function consumes. The witness format,
// its bounds and the proof verification are the ones the P85 controls use.

// SlotReader reads one proven (or, while building, fetched) storage word of one account.
type SlotReader interface {
	Word(slot [32]byte) ([32]byte, error)
}

// ProvenAccount is one account of a verified witness: its code hash and its proven storage words. Every proven slot must be read
// (Unused), so a witness carries exactly what the verifier consumes.
type ProvenAccount struct {
	Address [20]byte
	p       *proven
}

// CodeHash is the account's proven code hash.
func (a ProvenAccount) CodeHash() [32]byte { return a.p.codeHash }

// Word is the proven value of slot (zero for a slot proven absent); a slot the witness does not prove is an error.
func (a ProvenAccount) Word(slot [32]byte) ([32]byte, error) { return a.p.word(slot) }

// Unused refuses a slot the witness proves but the reader never read.
func (a ProvenAccount) Unused() error { return a.p.unused() }

// VerifyAccounts decodes the canonical witness, requires it to carry exactly the given accounts (any order; at most three, as every
// control witness) and verifies every account and slot proof against the certified state root. The accounts come back in the order asked.
func VerifyAccounts(raw []byte, stateRoot [32]byte, addrs ...[20]byte) ([]ProvenAccount, error) {
	w, err := decodeWitness(raw)
	if err != nil {
		return nil, err
	}
	if len(w.Accounts) != len(addrs) {
		return nil, fmt.Errorf("%w: %d accounts, want %d", ErrWitness, len(w.Accounts), len(addrs))
	}
	all, err := w.verify(stateRoot)
	if err != nil {
		return nil, err
	}
	out := make([]ProvenAccount, len(addrs))
	for i, a := range addrs {
		p := all[ethcommon.Address(a)]
		if p == nil {
			return nil, fmt.Errorf("%w: no account %x", ErrWitness, a)
		}
		out[i] = ProvenAccount{Address: a, p: p}
	}
	return out, nil
}

// VerifyWitness decodes the canonical witness and verifies every account against the certified state root, returning the accounts in
// the witness order (strictly ascending address). It is for a reader that learns one of the account addresses from another proven account.
func VerifyWitness(raw []byte, stateRoot [32]byte) ([]ProvenAccount, error) {
	w, err := decodeWitness(raw)
	if err != nil {
		return nil, err
	}
	all, err := w.verify(stateRoot)
	if err != nil {
		return nil, err
	}
	out := make([]ProvenAccount, 0, len(w.Accounts))
	for _, a := range w.Accounts {
		addr := [20]byte(a.Addr)
		out = append(out, ProvenAccount{Address: addr, p: all[ethcommon.Address(addr)]})
	}
	return out, nil
}

// recordingSlots adapts a recordingReader to SlotReader.
type recordingSlots struct{ r *recordingReader }

func (s recordingSlots) Word(slot [32]byte) ([32]byte, error) { return s.r.word(slot) }

// drySlots adapts a dryReader to SlotReader.
type drySlots struct{ d *dryReader }

func (s drySlots) Word(slot [32]byte) ([32]byte, error) { return s.d.word(slot) }

// BuildAccounts builds the canonical witness of the given accounts at the source's block with exactly the slots read consumes. read is run
// once against zero words to batch the slots that depend on nothing (its result is ignored), then against the source, so a reader whose
// slots depend on earlier words still lists every slot it reads. Nothing the source answers is trusted: the witness is only as good as the
// verification against the certified state root.
func BuildAccounts(ctx context.Context, src ProofSource, addrs [][20]byte, read func(accounts []SlotReader) error) ([]byte, error) {
	for i := 1; i < len(addrs); i++ {
		for j := 0; j < i; j++ {
			if bytes.Equal(addrs[i][:], addrs[j][:]) {
				return nil, fmt.Errorf("%w: account %x named twice", ErrBuild, addrs[i])
			}
		}
	}
	dry := make([]*dryReader, len(addrs))
	drs := make([]SlotReader, len(addrs))
	for i := range addrs {
		dry[i] = &dryReader{}
		drs[i] = drySlots{dry[i]}
	}
	_ = read(drs) // a dry run only lists the first slots; zero words may well make the reader stop early
	recs := make([]*recordingReader, len(addrs))
	rs := make([]SlotReader, len(addrs))
	for i, a := range addrs {
		recs[i] = &recordingReader{ctx: ctx, src: src, addr: a, slots: map[[32]byte]SlotProof{}}
		if err := recs[i].fetch(dry[i].slots); err != nil {
			return nil, err
		}
		rs[i] = recordingSlots{recs[i]}
	}
	// the dry run may have fetched a slot the real run does not read: rebuild from the slots the real run asks for
	used := make([]*recordingReader, len(addrs))
	us := make([]SlotReader, len(addrs))
	for i, a := range addrs {
		used[i] = &recordingReader{ctx: ctx, src: cachedSource{src: src, cache: recs[i]}, addr: a, slots: map[[32]byte]SlotProof{}}
		us[i] = recordingSlots{used[i]}
	}
	if err := read(us); err != nil {
		return nil, err
	}
	for i, r := range used {
		if r.account == nil { // no slot read: the account proof alone
			account, _, err := src.Proof(ctx, addrs[i], nil)
			if err != nil {
				return nil, fmt.Errorf("%w: account %x: %w", ErrBuild, addrs[i], err)
			}
			r.account = account
		}
	}
	return encodeAccounts(used...)
}

// cachedSource answers from slots already fetched for one account before asking the source.
type cachedSource struct {
	src   ProofSource
	cache *recordingReader
}

func (c cachedSource) Proof(ctx context.Context, addr [20]byte, slots [][32]byte) ([][]byte, []SlotProof, error) {
	out := make([]SlotProof, 0, len(slots))
	for _, s := range slots {
		p, ok := c.cache.slots[s]
		if !ok || c.cache.account == nil {
			return c.src.Proof(ctx, addr, slots)
		}
		out = append(out, p)
	}
	return c.cache.account, out, nil
}
