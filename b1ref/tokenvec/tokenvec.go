// Package tokenvec is the token-level vector harness of the any-age B1 batch (briefs/b1-any-age-vectors.md family H): fixed
// token-history scenarios, a Projection interface for the bridge's proof projection to plug into, and Check, which certifies the
// scenario's anchors with the projection's own state roots, takes the CERT_BATCH_V2 request the projection builds from its token,
// and holds it to the anchor set and to the reference verifier's verdict and grouping.
//
// The token encoding, leaves, RSMT paths and the leaf-to-anchor coverage are the projection's (dev2); this package fixes only
// which certified histories a token must be verifiable against and what the native batch must then look like.
package tokenvec

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/b1ref/b1gen"
)

// Seed derives every scenario's registry, keys and certificates.
const Seed = "b1-any-age-token-v1"

// Scenario is one token history: the anchors its required leaves bind to, in the order the scenario lists them, the aggregation
// partition's shard depth per epoch, and the grouping a correct projection's batch has.
type Scenario struct {
	ID, Description string
	Depth           func(epoch uint64) int
	Anchors         []b1gen.AnchorSpec // StateRoot is supplied by the projection
	Want            Want
}

// Want is the grouping of the scenario's batch: distinct epochs, distinct seals, distinct claims.
type Want struct{ E, S, A uint64 }

func depth(d int) func(uint64) int { return func(uint64) int { return d } }

func shards(d int) []string {
	out := []string{""}
	for i := 0; i < d; i++ {
		var next []string
		for _, s := range out {
			next = append(next, s+"0", s+"1")
		}
		out = next
	}
	return out
}

// Scenarios are the token-level cases of the design's acceptance list (section 9) and the vectors plan.
var Scenarios = func() []Scenario {
	s := []Scenario{
		{ID: "split-three-epochs", Description: "an untouched fungible split whose embedded dependencies were certified in epochs 2, 5 and 8 (scheme 1 and 2)",
			Depth: depth(1), Anchors: []b1gen.AnchorSpec{{Epoch: 2, Round: 2500, Shard: "0"}, {Epoch: 5, Round: 5500, Shard: "1"}, {Epoch: 8, Round: 9000, Shard: "0"}},
			Want: Want{E: 3, S: 3, A: 3}},
		{ID: "split-across-topology-change", Description: "a dependency certified in shard 0 before a split (epoch 3) and its successor in child shard 01 after it (epoch 6)",
			Depth: func(e uint64) int {
				if e < 5 {
					return 1
				}
				return 2
			}, Anchors: []b1gen.AnchorSpec{{Epoch: 3, Round: 3500, Shard: "0"}, {Epoch: 6, Round: 6500, Shard: "01"}},
			Want: Want{E: 2, S: 2, A: 2}},
	}
	consolidated := Scenario{ID: "consolidated-eight-shards", Description: "a token over eight shards after consolidation: every anchor under one seal",
		Depth: depth(3), Want: Want{E: 1, S: 1, A: 8}}
	unconsolidated := Scenario{ID: "unconsolidated-eight-seals", Description: "the same eight shards before consolidation: eight seals over three epochs (one entry read per epoch)",
		Depth: depth(3), Want: Want{E: 3, S: 8, A: 8}}
	epochs := []uint64{6, 6, 6, 7, 7, 8, 8, 8}
	for i, sh := range shards(3) {
		consolidated.Anchors = append(consolidated.Anchors, b1gen.AnchorSpec{Epoch: 8, Round: 9000, Shard: sh})
		e := epochs[i]
		unconsolidated.Anchors = append(unconsolidated.Anchors, b1gen.AnchorSpec{Epoch: e, Round: 1000*e + 100*uint64(i+1), Shard: sh})
	}
	return append(s, consolidated, unconsolidated)
}()

// Projection is the bridge side under test.
type Projection interface {
	// Roots returns, for each of the scenario's anchors in order, the state root its certificate must carry: the RSMT root over
	// the token's leaves in that shard round.
	Roots(s Scenario) ([][32]byte, error)
	// Request builds the token over the certified anchors and projects its proof to the CERT_BATCH_V2 request.
	Request(s Scenario, anchors []b1gen.Anchor) ([]byte, error)
}

// Report is what Check found.
type Report struct {
	Anchors  []b1gen.Anchor
	Request  []byte
	Verdict  b1ref.Verdict
	Grouping b1ref.Grouping
}

// Errors of Check.
var (
	ErrCoverage = errors.New("tokenvec: the batch does not carry every anchor exactly once")
	ErrVerdict  = errors.New("tokenvec: the reference verifier does not accept the batch")
	ErrGrouping = errors.New("tokenvec: the batch's grouping is not the scenario's")
)

// Check runs one scenario through a projection.
func Check(s Scenario, p Projection) (*Report, error) {
	roots, err := p.Roots(s)
	if err != nil {
		return nil, fmt.Errorf("%s: roots: %w", s.ID, err)
	}
	if len(roots) != len(s.Anchors) {
		return nil, fmt.Errorf("%s: %d roots for %d anchors", s.ID, len(roots), len(s.Anchors))
	}
	specs := append([]b1gen.AnchorSpec(nil), s.Anchors...)
	for i := range specs {
		specs[i].StateRoot = roots[i]
	}
	w := b1gen.NewTokenWorld(Seed, s.Depth)
	anchors, err := w.Certify(specs)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.ID, err)
	}
	req, err := p.Request(s, anchors)
	if err != nil {
		return nil, fmt.Errorf("%s: request: %w", s.ID, err)
	}
	r := &Report{Anchors: anchors, Request: req}
	claims, err := split(req)
	if err != nil {
		return r, fmt.Errorf("%s: %w: %v", s.ID, ErrCoverage, err)
	}
	if len(claims) != len(anchors) {
		return r, fmt.Errorf("%s: %w: %d claims for %d anchors", s.ID, ErrCoverage, len(claims), len(anchors))
	}
	used := make([]bool, len(anchors))
	for _, c := range claims {
		found := false
		for i, a := range anchors {
			if !used[i] && bytes.Equal(a.Claim, c) {
				used[i], found = true, true
				break
			}
		}
		if !found {
			return r, fmt.Errorf("%s: %w: a claim that is no anchor, or an anchor twice", s.ID, ErrCoverage)
		}
	}
	pre := w.Pre()
	st := b1ref.Words{}
	for _, sw := range pre.Storage {
		st[word(sw.Slot)] = word(sw.Value)
	}
	pins := b1ref.Pins{GenesisCommitment: word(pre.PinnedGenesisCommitment), ProfileHash: word(pre.PinnedProfileHash)}
	if r.Verdict, err = b1ref.Cert(req, st, pins); err != nil || !r.Verdict.Valid {
		return r, fmt.Errorf("%s: %w: %v %v", s.ID, ErrVerdict, err, r.Verdict.Why)
	}
	if r.Grouping, err = b1ref.Group(req); err != nil {
		return r, err
	}
	if g := r.Grouping; g.E != s.Want.E || g.S != s.Want.S || g.A != s.Want.A {
		return r, fmt.Errorf("%s: %w: E/S/A %d/%d/%d, want %d/%d/%d", s.ID, ErrGrouping, g.E, g.S, g.A, s.Want.E, s.Want.S, s.Want.A)
	}
	return r, nil
}

// split returns a request's packed claims.
func split(req []byte) ([][]byte, error) {
	if len(req) < 4 || req[0] != 2 || req[1] != 0 {
		return nil, errors.New("not a CERT_BATCH_V2 request")
	}
	k := int(binary.BigEndian.Uint16(req[2:4]))
	var out [][]byte
	pos := 4
	for i := 0; i < k; i++ {
		start := pos
		if pos+6 > len(req) {
			return nil, errors.New("truncated")
		}
		pos += 6 + int(binary.BigEndian.Uint16(req[pos+4:])) + 96
		if pos+4 > len(req) {
			return nil, errors.New("truncated")
		}
		pos += 4 + int(binary.BigEndian.Uint32(req[pos:]))
		if pos > len(req) {
			return nil, errors.New("truncated")
		}
		out = append(out, req[start:pos])
	}
	if pos != len(req) {
		return nil, errors.New("trailing bytes")
	}
	return out, nil
}

func word(s string) (w [32]byte) {
	b, _ := hex.DecodeString(s)
	copy(w[:], b)
	return
}

// Direct is the reference projection: seed-derived state roots and the anchors in scenario order. It stands in for the bridge
// projection until that exists, and proves the harness itself.
type Direct struct{}

func (Direct) Roots(s Scenario) ([][32]byte, error) {
	out := make([][32]byte, len(s.Anchors))
	for i := range out {
		copy(out[i][:], fmt.Sprintf("%-32s", fmt.Sprintf("%s/%d", s.ID, i)))
	}
	return out, nil
}

func (Direct) Request(_ Scenario, anchors []b1gen.Anchor) ([]byte, error) {
	out := []byte{2, 0, 0, byte(len(anchors))}
	for _, a := range anchors {
		out = append(out, a.Claim...)
	}
	return out, nil
}
