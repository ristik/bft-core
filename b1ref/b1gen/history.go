package b1gen

import "fmt"

// History is a multi-epoch registry scenario for the any-age acceptance and verification-local reuse tests
// (briefs/b1-any-age-vectors.md families A, B and D). Epoch 0 runs from round 1 to 1000, epoch e in 1..7 from 1000e to 1000(e+1),
// and epoch 8, the usable origin, is open from 8000; O is 1,000,000. Epochs 0..3 are signed by node00..node03, epochs 4..8 by
// node01..node04 (one member replaced at epoch 4, then the same members in successive epochs). Every member weighs 1, so three
// signatures reach quorum.
//
// Certificates are returned as single claims in the v1 claim encoding; the batch ABI is not frozen yet, so the corpus does not carry
// these and tests compose them through the oracle's test-only claim entry.
type History struct {
	f    *fixture
	vals []validator // node00..node04
	Pre  PreState
}

// HistoryOrigin and HistoryClock are the scenario's usable origin epoch and O.
const (
	HistoryOrigin = 8
	HistoryClock  = 1_000_000
)

// HistoryStart is the first root round of epoch e in the scenario.
func HistoryStart(e uint64) uint64 {
	if e == 0 {
		return 1
	}
	return 1000 * e
}

// NewHistory derives the scenario from a seed.
func NewHistory(seed string) *History {
	h := &History{f: newFixture(seed, 4)}
	h.f.origin, h.f.clock = HistoryOrigin, HistoryClock
	for i := 0; i < 5; i++ {
		h.vals = append(h.vals, makeValidator(seed, fmt.Sprintf("node%02d", i)))
	}
	h.Pre = PreState{Network: h.f.network, Origin: HistoryOrigin, ClockRound: HistoryClock}
	for e := uint64(0); e <= HistoryOrigin; e++ {
		auth := authorityOf(h.f.network, e, 2, newDRBG(seed, fmt.Sprintf("body/%d", e)).hash(), h.set(e))
		var members []MemberWords
		for _, m := range auth.members {
			members = append(members, MemberWords{NodeID: m.id, Key: hx(m.pub), Weight: m.weight})
		}
		ew := EpochWords{Epoch: e, Members: members, BodyID: hex32(auth.bodyID), Start: HistoryStart(e)}
		if e < HistoryOrigin {
			ew.End = HistoryStart(e + 1)
		}
		h.Pre.Epochs = append(h.Pre.Epochs, ew)
	}
	return h
}

// set is the validator set of epoch e.
func (h *History) set(e uint64) []validator {
	if e < 4 {
		return h.vals[0:4]
	}
	return h.vals[1:5]
}

// Seal names one seal of the scenario: its epoch and root round, the certificate-set variant (which input records it certifies),
// and its signers as indexes into node00..node04.
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

// Claim returns the claim of partition part, shard shard, certified under the seal s.
func (h *History) Claim(s Seal, part uint32, shard string) []byte {
	return claimOf(h.uc(s, part, shard)).wire()
}

func (h *History) uc(s Seal, part uint32, shard string) ucSpec {
	f := *h.f
	f.epoch = s.Epoch
	var signers []validator
	for _, i := range s.Signers {
		signers = append(signers, h.vals[i])
	}
	cs := f.build(s.Variant, s.Round, signers, false)
	u := cs.get(part, shard)
	if s.BadLast {
		n := len(u.seal.sigs) - 1
		u.seal.sigs = append([]entry{}, u.seal.sigs...)
		u.seal.sigs[n] = entry{u.seal.sigs[n].key, h.vals[s.Signers[n]].sign([]byte("other"), false)}
	}
	return u
}
