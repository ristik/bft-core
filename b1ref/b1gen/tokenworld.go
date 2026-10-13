package b1gen

import (
	"fmt"
)

// TokenWorld certifies the anchors of token-level histories (briefs/b1-any-age-vectors.md family H): the History registry
// (epochs 0..8, U = I = 8, O = 1,000,000, scheme 1 then 2), aggregation partition 1 whose shard depth in each epoch is Depth(epoch)
// (a topology change is a depth change), and a second partition so every certificate has one Unicity-tree step. The state root each
// anchor certifies is the caller's: a bridge projection computes it as the RSMT root over the token's leaves in that shard round.
type TokenWorld struct {
	h     *History
	Depth func(epoch uint64) int
}

// NewTokenWorld derives the world from a seed.
func NewTokenWorld(seed string, depth func(epoch uint64) int) *TokenWorld {
	return &TokenWorld{h: NewHistory(seed, 0), Depth: depth}
}

// Pre is the registry the anchors verify against.
func (w *TokenWorld) Pre() PreState {
	p := w.h.Pre()
	p.render()
	return p
}

// IRTime is the input record timestamp of every certificate a TokenWorld issues at root round r: increasing with the round, so a
// projection's reference-time checks see a history whose anchors were certified at different times.
func IRTime(r uint64) uint64 { return genesisTime + 1000 + r }

// AnchorSpec names one anchor: the seal's epoch and root round, the shard (a bit string of the epoch's depth) and the state root it
// certifies.
type AnchorSpec struct {
	Epoch, Round uint64
	Shard        string
	StateRoot    [32]byte
}

// Anchor is one certified anchor: the CERT_BATCH_V2 claim (partition, shard, configuration hash, state root, input record digest,
// UC) and the pieces a token proof embeds.
type Anchor struct {
	Spec      AnchorSpec
	Partition uint32
	Claim     []byte // packed claim, as the batch carries it
	UC        []byte // canonical native UC
	IR        []byte // canonical native input record (its digest is in the claim)
	ShardConf [32]byte
}

// Certify signs the anchors: every spec sharing (epoch, round) shares one seal, as certificates of one root round do.
func (w *TokenWorld) Certify(specs []AnchorSpec) ([]Anchor, error) {
	type round struct{ e, r uint64 }
	groups := map[round][]int{}
	var order []round
	for i, s := range specs {
		if len(s.Shard) != w.Depth(s.Epoch) {
			return nil, fmt.Errorf("anchor %d: shard %q is not of epoch %d's depth %d", i, s.Shard, s.Epoch, w.Depth(s.Epoch))
		}
		k := round{s.Epoch, s.Round}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], i)
	}
	out := make([]Anchor, len(specs))
	for _, k := range order {
		f := *w.h.f
		f.epoch = k.e
		f.scheme = map[uint32][]string{1: shardsAt(w.Depth(k.e)), 2: {""}}
		f.states = map[string][]byte{}
		f.irTime = IRTime(k.r)
		for _, i := range groups[k] {
			root := specs[i].StateRoot
			f.states[ucKey(1, specs[i].Shard)] = root[:]
		}
		var signers []validator
		for _, i := range DefaultSigners(k.e) {
			signers = append(signers, w.h.vals[i])
		}
		cs := f.build(fmt.Sprintf("token/%d/%d", k.e, k.r), k.r, signers, false)
		for _, i := range groups[k] {
			u := cs.get(1, specs[i].Shard)
			c := claimOf(u)
			out[i] = Anchor{Spec: specs[i], Partition: 1, Claim: c.wire(), UC: c.uc, IR: u.ir.cbor(), ShardConf: u.conf}
		}
	}
	return out, nil
}

// shardsAt lists every shard bit string of a depth.
func shardsAt(depth int) []string {
	out := []string{""}
	for d := 0; d < depth; d++ {
		var next []string
		for _, s := range out {
			next = append(next, s+"0", s+"1")
		}
		out = next
	}
	return out
}
