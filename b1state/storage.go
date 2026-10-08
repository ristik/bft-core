package b1state

import (
	"encoding/binary"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

var RegistryAddress = [20]byte{0: 0xff, 19: 2}

func Word(v uint64) (w [32]byte) { binary.BigEndian.PutUint64(w[24:], v); return }
func FixedSlot(name string) [32]byte {
	return [32]byte(ethcrypto.Keccak256Hash([]byte("unicity.seal-registry/" + name)))
}
func derived(name string, indices ...uint64) [32]byte {
	f := FixedSlot(name)
	b := append([]byte(nil), f[:]...)
	for _, i := range indices {
		w := Word(i)
		b = append(b, w[:]...)
	}
	return [32]byte(ethcrypto.Keccak256Hash(b))
}
func QueueSlot(i uint64) [32]byte        { return derived("b1.queue", i) }
func EntrySlot(e, f uint64) [32]byte     { return derived("b1.entry", e, f) }
func MemberSlot(e, j, f uint64) [32]byte { return derived("b1.member", e, j, f) }
func memberWords(m Member) (words [8][32]byte) {
	words[0] = Word(uint64(len(m.NodeID)))
	id := []byte(m.NodeID)
	for i, b := range id {
		words[1+i/32][i%32] = b
	}
	copy(words[5][:], m.Key[:32])
	words[6][0] = m.Key[32]
	words[7] = Word(m.Weight)
	return
}
func putEntry(store func([32]byte, [32]byte), e Entry) {
	total, _ := e.TotalWeight()
	metadata := [11][32]byte{Word(1), Word(e.BodyKind), e.BodyID, e.ActivationCommitID, Word(e.Start), {}, {}, Word(e.SigningScheme), e.SigningConfigHash, Word(uint64(len(e.Members))), Word(total)}
	if e.End != nil {
		metadata[5] = Word(*e.End)
		metadata[6] = Word(1)
	}
	for i, w := range metadata {
		store(EntrySlot(e.Epoch, uint64(i)), w)
	}
	for j, m := range e.Members {
		for f, w := range memberWords(m) {
			store(MemberSlot(e.Epoch, uint64(j), uint64(f)), w)
		}
	}
}
func clearEntry(store func([32]byte, [32]byte), e Entry) {
	for i := uint64(0); i < EntryWords; i++ {
		store(EntrySlot(e.Epoch, i), [32]byte{})
	}
	for j := range e.Members {
		for f := uint64(0); f < MemberWords; f++ {
			store(MemberSlot(e.Epoch, uint64(j), f), [32]byte{})
		}
	}
}

// GenesisWords includes explicit pre-first-import zero origin words, distinct
// from assigned root epoch. registrygenesis adds the pinned operational allocation.
func GenesisWords(p Profile, genesis Entry) (map[[32]byte][32]byte, error) {
	h, err := p.Hash()
	if err != nil {
		return nil, err
	}
	if err := genesis.Validate(); err != nil {
		return nil, err
	}
	if genesis.BodyKind != 1 || genesis.BodyID != p.RootGenesisID || genesis.End != nil {
		return nil, ErrHistory
	}
	words := map[[32]byte][32]byte{}
	for name, w := range map[string][32]byte{"b1.network": Word(uint64(p.Network)), "b1.wCert": Word(p.WCert), "b1.profileHash": h, "b1.initialized": Word(1), "b1.head": {}, "b1.count": Word(1), "clock.rootRound": {}, "origin.rootEpoch": {}, "assignment.rootEpoch": Word(genesis.Epoch), "records.ucTime": Word(p.GenesisUCTime), "phase": Word(2)} {
		words[FixedSlot(name)] = w
	}
	putEntry(func(slot, value [32]byte) { words[slot] = value }, genesis)
	words[QueueSlot(0)] = Word(genesis.Epoch)
	return words, nil
}

// Write records every addressed operation, even when a ring slot is cleared
// and reused. Final is a state diff; Trace preserves gross work before refunds.
type Write struct {
	Slot, Value [32]byte
	Clear       bool
}
type Changes struct {
	Final map[[32]byte][32]byte
	Trace []Write
}

func (c *Changes) store(slot, value [32]byte, clear bool) {
	c.Final[slot] = value
	c.Trace = append(c.Trace, Write{Slot: slot, Value: value, Clear: clear})
}
func (c *Changes) insert(slot, value [32]byte) { c.store(slot, value, false) }
func (c *Changes) clear(slot, value [32]byte)  { c.store(slot, value, true) }

// WriteAllowance is the conservative profile allowance, never runtime gas.
func (c *Changes) WriteAllowance() (uint64, error) {
	var gas uint64
	for _, w := range c.Trace {
		price := uint64(22100)
		if w.Clear {
			price = 7100
		}
		if ^uint64(0)-gas < price {
			return 0, ErrOverflow
		}
		gas += price
	}
	return gas, nil
}

// EntryStorage exports every addressed metadata/member word, including zeros.
func EntryStorage(e Entry) (map[[32]byte][32]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	out := make(map[[32]byte][32]byte)
	putEntry(func(k, v [32]byte) { out[k] = v }, e)
	return out, nil
}
