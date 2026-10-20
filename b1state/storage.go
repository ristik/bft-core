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

// StoredWords are the words the registry stores for an entry: its 11 metadata fields (5 and 6 are the closure end and hasEnd) and
// the 8 words of each member in order, exactly as SealRegistry writes them.
func (e Entry) StoredWords() (metadata [11][32]byte, members [][8][32]byte) {
	total, _ := e.TotalWeight()
	metadata = [11][32]byte{Word(1), Word(e.BodyKind), e.BodyID, e.ActivationCommitID, Word(e.Start), {}, {}, Word(e.SigningScheme), e.SigningConfigHash, Word(uint64(len(e.Members))), Word(total)}
	if e.End != nil {
		metadata[5] = Word(*e.End)
		metadata[6] = Word(1)
	}
	for _, m := range e.Members {
		members = append(members, memberWords(m))
	}
	return metadata, members
}

// CommitmentField is the entry field that caches C_e, written with the entry and never rewritten.
const CommitmentField = 11

// CommitmentDomain separates C_e from every other registry hash.
var CommitmentDomain = [32]byte(ethcrypto.Keccak256Hash([]byte("unicity.seal-registry.v2/epoch-commitment")))

// Deployment is what binds an entry's commitment to one registry: its genesisCommitment and b1.profileHash words.
type Deployment struct {
	GenesisCommitment, ProfileHash [32]byte
}

// EpochCommitment is C_e (B7 design §3), the registry's trust cache for one epoch:
//
//	keccak256(CommitmentDomain || genesisCommitment || profileHash || word(epoch)
//	          || metadata words 0-4 and 7-10 || the 8 words of every member, in order)
//
// over the words StoredWords returns. The closure words 5 and 6 (end, hasEnd) are excluded, so C_e is fixed when the entry is
// written and closing the epoch does not change it.
func (d Deployment) EpochCommitment(e Entry) ([32]byte, error) {
	if err := e.Validate(); err != nil {
		return [32]byte{}, err
	}
	metadata, members := e.StoredWords()
	b := make([]byte, 0, 32*(4+9+8*len(members)))
	for _, w := range [][32]byte{CommitmentDomain, d.GenesisCommitment, d.ProfileHash, Word(e.Epoch)} {
		b = append(b, w[:]...)
	}
	for f, w := range metadata {
		if f != 5 && f != 6 {
			b = append(b, w[:]...)
		}
	}
	for _, m := range members {
		for _, w := range m {
			b = append(b, w[:]...)
		}
	}
	return [32]byte(ethcrypto.Keccak256Hash(b)), nil
}

// putEntry writes an entry's stored words and its commitment. The entry is validated by every caller.
func putEntry(store func([32]byte, [32]byte), e Entry, d Deployment) {
	metadata, members := e.StoredWords()
	for i, w := range metadata {
		store(EntrySlot(e.Epoch, uint64(i)), w)
	}
	c, _ := d.EpochCommitment(e)
	store(EntrySlot(e.Epoch, CommitmentField), c)
	for j, words := range members {
		for f, w := range words {
			store(MemberSlot(e.Epoch, uint64(j), uint64(f)), w)
		}
	}
}

// GenesisWords includes explicit pre-first-import zero origin words, distinct
// from assigned root epoch. registrygenesis adds the pinned operational allocation. The genesis entry's commitment binds
// genesisCommitment, which is derived before the allocation (registrygenesis step 2), and the profile hash.
func GenesisWords(p Profile, genesis Entry, genesisCommitment [32]byte) (map[[32]byte][32]byte, error) {
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
	for name, w := range map[string][32]byte{"b1.network": Word(uint64(p.Network)), "b1.format": Word(2), "b1.profileHash": h, "b1.initialized": Word(1), "b1.genesisEpoch": Word(genesis.Epoch), "b1.importedTipEpoch": Word(genesis.Epoch), "b1.originReady": {}, "clock.rootRound": {}, "origin.rootEpoch": {}, "assignment.rootEpoch": Word(genesis.Epoch), "records.ucTime": Word(p.GenesisUCTime), "phase": Word(2)} {
		words[FixedSlot(name)] = w
	}
	putEntry(func(slot, value [32]byte) { words[slot] = value }, genesis, Deployment{GenesisCommitment: genesisCommitment, ProfileHash: h})
	return words, nil
}

// Write records every addressed operation. Final is a state diff; Trace preserves gross work before refunds.
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

// EntryStorage exports every addressed metadata/member word, including zeros, and the commitment word.
func EntryStorage(e Entry, d Deployment) (map[[32]byte][32]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	out := make(map[[32]byte][32]byte)
	putEntry(func(k, v [32]byte) { out[k] = v }, e, d)
	return out, nil
}
