package b1ref

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unicode/utf8"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-go-base/crypto"
)

// State is the execution state CERT_BATCH_V2 reads: one 32-byte word per registry slot (briefs/b1-any-age-contract.md section 1).
// An error is a Host failure: unavailable state, never a verdict. In this package the words are an injected precondition; nothing
// here establishes that they came from authenticated state.
type State interface {
	Word(slot [32]byte) ([32]byte, error)
}

// Words is an in-memory State; an absent slot reads as zero.
type Words map[[32]byte][32]byte

func (w Words) Word(slot [32]byte) ([32]byte, error) { return w[slot], nil }

// Pins are what the native verifier is built with, not read from state: the profile hash this deployment's registry must carry.
type Pins struct {
	ProfileHash [32]byte
}

// RegistryFormat is the b1.format word of the any-age layout.
const RegistryFormat = 2

// Slot derivation (contract section 1): F(name) = keccak256("unicity.seal-registry/" || name); entry and member words are
// keccak256(abi.encode(F(..), indices...)).
func FixedSlot(name string) [32]byte {
	return [32]byte(ethcrypto.Keccak256Hash([]byte("unicity.seal-registry/" + name)))
}

func derivedSlot(name string, indices ...uint64) [32]byte {
	f := FixedSlot(name)
	b := append([]byte(nil), f[:]...)
	for _, i := range indices {
		w := word(i)
		b = append(b, w[:]...)
	}
	return [32]byte(ethcrypto.Keccak256Hash(b))
}

// EntrySlot is entry field f of epoch e; MemberSlot is field f of member j of epoch e.
func EntrySlot(e, f uint64) [32]byte     { return derivedSlot("b1.entry", e, f) }
func MemberSlot(e, j, f uint64) [32]byte { return derivedSlot("b1.member", e, j, f) }

func word(v uint64) (w [32]byte) { binary.BigEndian.PutUint64(w[24:], v); return }

// u64 decodes a zero-extended u64 word.
func u64(w [32]byte) (uint64, bool) {
	for _, b := range w[:24] {
		if b != 0 {
			return 0, false
		}
	}
	return binary.BigEndian.Uint64(w[24:]), true
}

// CommonSlots are the eleven words read once per call, in the contract's order (section 5).
var CommonSlots = []string{"genesisCommitment", "phase", "b1.initialized", "b1.network", "b1.profileHash", "b1.format",
	"b1.genesisEpoch", "b1.importedTipEpoch", "b1.originReady", "clock.rootRound", "origin.rootEpoch"}

// common is the validated common registry state of one call.
type common struct {
	phase     uint64
	network   uint16
	g, tip    uint64 // genesis epoch, imported tip I
	ready     bool
	origin, o uint64 // usable origin epoch U, its root round O
}

// readCommon reads and validates the common words. Any impossible value is ErrRegistryCommon; a read failure is ErrHost.
func readCommon(st State, pins Pins) (*common, error) {
	var w [11][32]byte
	for i, name := range CommonSlots {
		v, err := st.Word(FixedSlot(name))
		if err != nil {
			return nil, errors.Join(ErrHost, err)
		}
		w[i] = v
	}
	// every word except genesisCommitment (0) and profileHash (4) is a u64
	var vals [9]uint64
	for i, idx := range []int{1, 2, 3, 5, 6, 7, 8, 9, 10} {
		v, ok := u64(w[idx])
		if !ok {
			return nil, ErrRegistryCommon
		}
		vals[i] = v
	}
	phase, initialized, network, format, g, tip, ready, o, origin := vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], vals[7], vals[8]
	switch {
	case w[0] == [32]byte{}, phase != 1 && phase != 2, initialized != 1, network == 0 || network > 0xffff,
		pins.ProfileHash == [32]byte{} || w[4] != pins.ProfileHash, format != RegistryFormat, ready > 1, g > tip:
		return nil, ErrRegistryCommon
	}
	if ready == 1 && (origin < g || origin > tip) {
		return nil, ErrRegistryCommon
	}
	if ready == 0 && (origin != 0 || o != 0) {
		return nil, ErrRegistryCommon
	}
	c := common{phase: phase, network: uint16(network), g: g, tip: tip, ready: ready == 1, origin: origin, o: o}
	return &c, nil
}

// epochAuth is one epoch's validated authority, read once per call.
type epochAuth struct {
	entry     b1state.Entry
	members   map[string]member
	threshold uint64
}

// loadEpoch reads epoch e (g <= e <= U) word by word, validates it as admitted state and parses its keys. A missing entry is
// ErrRegistryMissingEpoch; anything an admitted registry cannot hold is ErrRegistryInvalidEpoch.
func loadEpoch(st State, c *common, e uint64) (*epochAuth, error) {
	work("epoch-load")
	read := func(slot [32]byte) ([32]byte, error) {
		v, err := st.Word(slot)
		if err != nil {
			return v, errors.Join(ErrHost, err)
		}
		return v, nil
	}
	var m [b1state.EntryWords][32]byte
	for f := range m {
		v, err := read(EntrySlot(e, uint64(f)))
		if err != nil {
			return nil, err
		}
		m[f] = v
	}
	if present, ok := u64(m[0]); ok && present == 0 {
		return nil, ErrRegistryMissingEpoch
	}
	ent := b1state.Entry{Epoch: e, BodyID: m[2], ActivationCommitID: m[3], SigningConfigHash: m[8]}
	var vals [7]uint64
	for i, f := range []int{0, 1, 4, 5, 6, 7, 9} {
		v, ok := u64(m[f])
		if !ok {
			return nil, ErrRegistryInvalidEpoch
		}
		vals[i] = v
	}
	present, end, hasEnd, count := vals[0], vals[3], vals[4], vals[6]
	ent.BodyKind, ent.Start, ent.SigningScheme = vals[1], vals[2], vals[5]
	total, ok := u64(m[10])
	if !ok || present != 1 || hasEnd > 1 || (hasEnd == 0 && end != 0) || count < 1 || count > MaxMembers {
		return nil, ErrRegistryInvalidEpoch
	}
	if hasEnd == 1 {
		ent.End = &end
	}
	for j := uint64(0); j < count; j++ {
		var mw [b1state.MemberWords][32]byte
		for f := range mw {
			v, err := read(MemberSlot(e, j, uint64(f)))
			if err != nil {
				return nil, err
			}
			mw[f] = v
		}
		mem, ok := decodeMember(mw)
		if !ok {
			return nil, ErrRegistryInvalidEpoch
		}
		ent.Members = append(ent.Members, mem)
	}
	if err := ent.Validate(); err != nil {
		return nil, errors.Join(ErrRegistryInvalidEpoch, err)
	}
	if sum, err := ent.TotalWeight(); err != nil || sum != total {
		return nil, ErrRegistryInvalidEpoch
	}
	// interval invariants of admitted state at the usable origin (section 3)
	switch {
	case ent.Start > c.o, e < c.origin && ent.End == nil, e < c.origin && *ent.End > c.o, e == c.origin && ent.End != nil && *ent.End <= c.o:
		return nil, ErrRegistryInvalidEpoch
	}
	threshold, err := b1state.Threshold(total)
	if err != nil {
		return nil, errors.Join(ErrRegistryInvalidEpoch, err)
	}
	auth := &epochAuth{entry: ent, threshold: threshold, members: make(map[string]member, count)}
	for _, mem := range ent.Members {
		work("key-parse")
		ver, err := crypto.NewVerifierSecp256k1(mem.Key[:])
		if err != nil {
			return nil, errors.Join(ErrRegistryInvalidEpoch, err)
		}
		auth.members[mem.NodeID] = member{weight: mem.Weight, ver: ver}
	}
	return auth, nil
}

// decodeMember reads the eight member words: ID length, four words of left-aligned UTF-8 ID, the 33-byte compressed key over two
// words, and the weight. Padding must be zero.
func decodeMember(w [b1state.MemberWords][32]byte) (b1state.Member, bool) {
	n, ok := u64(w[0])
	if !ok || n < 1 || n > MaxNodeIDBytes {
		return b1state.Member{}, false
	}
	var id [128]byte
	for i := 0; i < 4; i++ {
		copy(id[32*i:], w[1+i][:])
	}
	if !bytes.Equal(id[n:], make([]byte, 128-n)) || !utf8.Valid(id[:n]) {
		return b1state.Member{}, false
	}
	if !bytes.Equal(w[6][1:], make([]byte, 31)) {
		return b1state.Member{}, false
	}
	weight, ok := u64(w[7])
	if !ok {
		return b1state.Member{}, false
	}
	m := b1state.Member{NodeID: string(id[:n]), Weight: weight}
	copy(m.Key[:32], w[5][:])
	m.Key[32] = w[6][0]
	return m, true
}

// Model is a typed registry state for tools and tests. Words renders it in the format-2 layout; it establishes nothing about
// authenticity.
type Model struct {
	GenesisCommitment, ProfileHash [32]byte
	Phase                          uint64
	Network                        uint16
	GenesisEpoch, ImportedTip      uint64
	OriginReady                    bool
	Origin, RootRound              uint64
	Epochs                         []b1state.Entry
}

func (m Model) Words() Words {
	w := Words{}
	ready := uint64(0)
	if m.OriginReady {
		ready = 1
	}
	for name, v := range map[string][32]byte{"genesisCommitment": m.GenesisCommitment, "phase": word(m.Phase), "b1.initialized": word(1),
		"b1.network": word(uint64(m.Network)), "b1.profileHash": m.ProfileHash, "b1.format": word(RegistryFormat),
		"b1.genesisEpoch": word(m.GenesisEpoch), "b1.importedTipEpoch": word(m.ImportedTip), "b1.originReady": word(ready),
		"clock.rootRound": word(m.RootRound), "origin.rootEpoch": word(m.Origin)} {
		w[FixedSlot(name)] = v
	}
	for _, e := range m.Epochs {
		PutEntry(w, e)
	}
	return w
}

// PutEntry writes epoch e's eleven entry words and eight words per member.
func PutEntry(w Words, e b1state.Entry) {
	var total uint64
	for _, m := range e.Members {
		total += m.Weight
	}
	meta := [b1state.EntryWords][32]byte{word(1), word(e.BodyKind), e.BodyID, e.ActivationCommitID, word(e.Start), {}, {},
		word(e.SigningScheme), e.SigningConfigHash, word(uint64(len(e.Members))), word(total)}
	if e.End != nil {
		meta[5], meta[6] = word(*e.End), word(1)
	}
	for f, v := range meta {
		w[EntrySlot(e.Epoch, uint64(f))] = v
	}
	for j, m := range e.Members {
		var mw [b1state.MemberWords][32]byte
		mw[0] = word(uint64(len(m.NodeID)))
		for i, b := range []byte(m.NodeID) {
			mw[1+i/32][i%32] = b
		}
		copy(mw[5][:], m.Key[:32])
		mw[6][0] = m.Key[32]
		mw[7] = word(m.Weight)
		for f, v := range mw {
			w[MemberSlot(e.Epoch, uint64(j), uint64(f))] = v
		}
	}
}
