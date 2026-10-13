package b1gen

import "fmt"

// History is a multi-epoch registry for the any-age, reuse and pricing vectors (briefs/b1-any-age-vectors.md families A, B, D and
// G). Epochs g..8: epoch 0 runs from round 1 to 1000, epoch e >= 1 from 1000e to 1000(e+1), epoch 8 (the usable origin) is open
// from 8000, and O = 1,000,000. Epochs 0..3 are signed by node00..node03, epochs 4..8 by node01..node04: one member replaced at
// epoch 4, then the same members in successive epochs. Every member weighs 1, so three signatures reach quorum.
type History struct {
	f    *fixture
	vals []validator // node00..node04
	g    uint64
}

// HistoryOrigin and HistoryClock are the usable origin epoch and O.
const (
	HistoryOrigin = 8
	HistoryClock  = 1_000_000
)

// HistoryStart is the first root round of epoch e.
func HistoryStart(e uint64) uint64 {
	if e == 0 {
		return 1
	}
	return 1000 * e
}

// NewHistory derives the scenario from a seed with genesis epoch g.
func NewHistory(seed string, g uint64) *History {
	h := &History{f: newFixture(seed, 4), g: g}
	h.f.origin, h.f.clock = HistoryOrigin, HistoryClock
	for i := 0; i < 5; i++ {
		h.vals = append(h.vals, makeValidator(seed, fmt.Sprintf("node%02d", i)))
	}
	return h
}

// Pre is the registry: epochs g..8 installed, 8 usable and open.
func (h *History) Pre() PreState {
	p := h.f.registryBase()
	p.GenesisEpoch, p.ImportedTip, p.Origin = h.g, HistoryOrigin, HistoryOrigin
	for e := h.g; e <= HistoryOrigin; e++ {
		end := uint64(0)
		if e < HistoryOrigin {
			end = HistoryStart(e + 1)
		}
		auth := authorityOf(h.f.network, e, 2, newDRBG(h.f.seed, fmt.Sprintf("body/%d", e)).hash(), h.set(e))
		p.Epochs = append(p.Epochs, h.f.epochWords(auth, e, HistoryStart(e), end, e == h.g))
	}
	return p
}

// Preloaded is Pre with epoch 9 imported but not usable: it closes the usable epoch 8 at O+500, above O.
func (h *History) Preloaded() PreState {
	p := h.Pre()
	p.ImportedTip = 9
	p.Epochs[len(p.Epochs)-1].End, p.Epochs[len(p.Epochs)-1].HasEnd = HistoryClock+500, true
	auth := authorityOf(h.f.network, 9, 2, newDRBG(h.f.seed, "body/9").hash(), h.set(9))
	p.Epochs = append(p.Epochs, h.f.epochWords(auth, 9, HistoryClock+500, 0, false))
	return p
}

func (h *History) set(e uint64) []validator {
	if e < 4 {
		return h.vals[0:4]
	}
	return h.vals[1:5]
}

// Seal names one seal: its epoch, root round, certificate-set variant and signers (indexes into node00..node04).
type Seal struct {
	Epoch, Round uint64
	Variant      string
	Signers      []int
	// BadLast replaces the last signer's signature with a valid signature over other bytes: the unsigned seal is unchanged, the
	// complete seal is not.
	BadLast bool
}

// DefaultSigners are three members of epoch e's set: a quorum.
func DefaultSigners(e uint64) []int {
	if e < 4 {
		return []int{0, 1, 2}
	}
	return []int{1, 2, 3}
}

func hseal(epoch, round uint64, variant string) Seal {
	return Seal{Epoch: epoch, Round: round, Variant: variant, Signers: DefaultSigners(epoch)}
}

// Claim returns the claim of partition part, shard shard, certified under the seal s, in the CERT_BATCH_V2 claim encoding.
func (h *History) Claim(s Seal, part uint32, shard string) []byte {
	return claimOf(h.uc(s, part, shard)).wire()
}

// Request is a CERT_BATCH_V2 request of the given claims.
func Request(claims ...[]byte) []byte {
	out := []byte{2, 0, byte(len(claims) >> 8), byte(len(claims))}
	for _, c := range claims {
		out = append(out, c...)
	}
	return out
}

func (h *History) uc(s Seal, part uint32, shard string) ucSpec {
	f := *h.f
	f.epoch = s.Epoch
	var signers []validator
	for _, i := range s.Signers {
		signers = append(signers, h.vals[i])
	}
	u := f.build(s.Variant, s.Round, signers, false).get(part, shard)
	if s.BadLast {
		n := len(u.seal.sigs) - 1
		u.seal.sigs = append([]entry{}, u.seal.sigs...)
		u.seal.sigs[n] = entry{u.seal.sigs[n].key, h.vals[s.Signers[n]].sign([]byte("other"), false)}
	}
	return u
}
