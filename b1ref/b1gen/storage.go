package b1gen

import (
	"encoding/binary"
	"encoding/hex"
	"sort"

	"golang.org/x/crypto/sha3"
)

// The generator's own rendering of the format-2 registry layout (contract section 1): F(name) = keccak256("unicity.seal-registry/"
// || name), entry/member words at keccak256(F || indices as uint256 words).

func keccak(parts ...[]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func fixedSlot(name string) [32]byte { return keccak([]byte("unicity.seal-registry/" + name)) }

func u256(v uint64) []byte {
	b := make([]byte, 32)
	binary.BigEndian.PutUint64(b[24:], v)
	return b
}

func derived(name string, idx ...uint64) [32]byte {
	f := fixedSlot(name)
	parts := [][]byte{f[:]}
	for _, i := range idx {
		parts = append(parts, u256(i))
	}
	return keccak(parts...)
}

func entrySlot(e, f uint64) [32]byte     { return derived("b1.entry", e, f) }
func memberSlot(e, j, f uint64) [32]byte { return derived("b1.member", e, j, f) }

func w64(v uint64) [32]byte { var w [32]byte; binary.BigEndian.PutUint64(w[24:], v); return w }

func h32(s string) (w [32]byte) {
	b, _ := hex.DecodeString(s)
	copy(w[:], b)
	return
}

// render fills p.Storage from the typed fields and the overrides.
func (p *PreState) render() {
	words := map[[32]byte][32]byte{}
	ready := uint64(0)
	if p.OriginReady {
		ready = 1
	}
	for name, v := range map[string][32]byte{
		"genesisCommitment": h32(p.GenesisCommitment), "phase": w64(p.Phase), "b1.initialized": w64(1),
		"b1.network": w64(uint64(p.Network)), "b1.profileHash": h32(p.ProfileHash), "b1.format": w64(2),
		"b1.genesisEpoch": w64(p.GenesisEpoch), "b1.importedTipEpoch": w64(p.ImportedTip), "b1.originReady": w64(ready),
		"clock.rootRound": w64(p.ClockRound), "origin.rootEpoch": w64(p.Origin),
	} {
		words[fixedSlot(name)] = v
	}
	for _, e := range p.Epochs {
		var total uint64
		for _, m := range e.Members {
			total += m.Weight
		}
		meta := [11][32]byte{w64(1), w64(e.BodyKind), h32(e.BodyID), h32(e.ActivationCommitID), w64(e.Start), {}, {},
			w64(e.SigningScheme), h32(e.SigningConfigHash), w64(uint64(len(e.Members))), w64(total)}
		if e.HasEnd {
			meta[5], meta[6] = w64(e.End), w64(1)
		}
		for f, v := range meta {
			words[entrySlot(e.Epoch, uint64(f))] = v
		}
		for j, m := range e.Members {
			var mw [8][32]byte
			mw[0] = w64(uint64(len(m.NodeID)))
			for i, b := range []byte(m.NodeID) {
				mw[1+i/32][i%32] = b
			}
			key, _ := hex.DecodeString(m.Key)
			copy(mw[5][:], key[:32])
			mw[6][0] = key[32]
			mw[7] = w64(m.Weight)
			for f, v := range mw {
				words[memberSlot(e.Epoch, uint64(j), uint64(f))] = v
			}
		}
	}
	for _, o := range p.Overrides {
		words[h32(o.Slot)] = h32(o.Value)
	}
	p.Storage = nil
	for s, v := range words {
		if v != ([32]byte{}) {
			p.Storage = append(p.Storage, SlotWord{Slot: hx(s[:]), Value: hx(v[:])})
		}
	}
	sort.Slice(p.Storage, func(i, j int) bool { return p.Storage[i].Slot < p.Storage[j].Slot })
}

// override sets one word after rendering.
func (p *PreState) override(slot, value [32]byte) {
	p.Overrides = append(p.Overrides, SlotWord{Slot: hx(slot[:]), Value: hx(value[:])})
}
