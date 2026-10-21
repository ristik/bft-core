package bridgeprofile

import (
	"encoding/hex"
	"fmt"
	"math"
	"sort"
)

// BenchCase is one BRIDGE_COMPOSE_V1 workload for the price and capacity measurements of B7 PR 3 (briefs/dev4-b7-pr3-plan.md): the
// compose input, the registry the B1 kernel reads (the case's trust base rendered as RefB1 does) and the oracle's verdict with real
// B1 (RefB1), so a native run must reproduce status and gas exactly.
type BenchCase struct {
	ID          string            `json:"id"`
	Description string            `json:"description"`
	Input       string            `json:"input"`
	Registry    map[string]string `json:"registry"`
	Pins        map[string]string `json:"pins"`
	Status      uint64            `json:"status"`
	Gas         uint64            `json:"gas"`
	Leaves      int               `json:"leaves"`
	Anchors     int               `json:"anchors"`
	Shards      int               `json:"shards"`
	InputBytes  int               `json:"inputBytes"`
}

// BenchShape selects one case of the matrix.
type BenchShape struct {
	Leaves       int  // history leaves: the mint, the transfers and the burn
	Depth        int  // aggregator shard depth (2^Depth shards)
	Signers      int  // committee size: every seal carries this many signatures
	Original     bool // one root round per leaf (a seal and a UC per leaf) instead of one consolidated round
	DeepPaths    bool // 32 RSMT siblings on every leaf path (extra keys at the 32 levels below the shard)
	LateFailure  bool // the last leaf's path is wrong: all work is done, then ErrLeafProof
	ReferenceSet bool // marks the cases the price fit uses
}

// BenchMatrix is the case matrix of the plan: 24/64/256/1000 leaves over 4 and 8 shards, original and consolidated seals, plus the
// adversarial dense (16 signers, original seals), deep (32 siblings per leaf) and late-failure cases.
func BenchMatrix() map[string]BenchShape {
	m := map[string]BenchShape{}
	for _, l := range []int{24, 64, 256, 1000} {
		for _, d := range []int{2, 3} {
			m[fmt.Sprintf("cons-s%d-l%d", 1<<d, l)] = BenchShape{Leaves: l, Depth: d, Signers: 1, ReferenceSet: true}
			m[fmt.Sprintf("orig-s%d-l%d", 1<<d, l)] = BenchShape{Leaves: l, Depth: d, Signers: 1, Original: true, ReferenceSet: true}
		}
	}
	for _, l := range []int{64, 256} {
		m[fmt.Sprintf("dense16-orig-s4-l%d", l)] = BenchShape{Leaves: l, Depth: 2, Signers: 16, Original: true}
		m[fmt.Sprintf("deep32-cons-s4-l%d", l)] = BenchShape{Leaves: l, Depth: 2, Signers: 1, DeepPaths: true}
	}
	m["late-cons-s8-l1000"] = BenchShape{Leaves: 1000, Depth: 3, Signers: 1, LateFailure: true}
	m["late-orig-s8-l1000"] = BenchShape{Leaves: 1000, Depth: 3, Signers: 1, Original: true, LateFailure: true}
	return m
}

// BenchCases builds the named cases (all of BenchMatrix when names is empty), in name order.
func BenchCases(names ...string) ([]BenchCase, error) {
	matrix := BenchMatrix()
	if len(names) == 0 {
		for n := range matrix {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	d, err := NewDeployment()
	if err != nil {
		return nil, err
	}
	var out []BenchCase
	for _, n := range names {
		s, ok := matrix[n]
		if !ok {
			return nil, fmt.Errorf("bridgeprofile: no bench case %q", n)
		}
		c, err := benchCase(d, n, s)
		if err != nil {
			return nil, fmt.Errorf("bridgeprofile: bench case %s: %w", n, err)
		}
		out = append(out, *c)
	}
	return out, nil
}

func benchCase(d *Deployment, id string, s BenchShape) (*BenchCase, error) {
	auth, err := NewCommittee(fmt.Sprintf("bench-committee-%d", s.Signers), s.Signers)
	if err != nil {
		return nil, err
	}
	tb, err := auth.Genesis(DevNetwork, 1, 1)
	if err != nil {
		return nil, err
	}
	w, err := NewShardedAggregator(auth, tb, s.Depth)
	if err != nil {
		return nil, err
	}
	h, res, _, err := ReturnHistorySeeded(d.F, s.Leaves-2, "bench")
	if err != nil {
		return nil, err
	}
	// Transfer i is certified at BaseTime+10*i: every anchor's IR time is after the last of them.
	irTime := BaseTime + 10*uint64(s.Leaves) + 1000
	var extra []Leaf
	if s.DeepPaths {
		extra = deepExtra(w, res.Leaves)
	}
	var cert *CertifiedLeaves
	if s.Original {
		cert, err = w.CertifyAssigned(res.Leaves, extra, func(i int, _ Leaf) ShardRound { return ShardRound{irTime, 100 + uint64(i)} })
	} else {
		var cl *ConsolidatedLeaves
		cl, err = w.CertifyConsolidated(res.Leaves, extra, func(int, Leaf) ShardRound { return ShardRound{irTime, 100} })
		if cl != nil {
			cert = cl.CertifiedLeaves
		}
	}
	if err != nil {
		return nil, err
	}
	e := &Envelope{PolicyBody: d.F.Policy.Bytes(), History: h.Bytes(), Anchors: cert.Anchors, LeafProofs: cert.Proofs}
	if s.LateFailure {
		last := &e.LeafProofs[len(e.LeafProofs)-1]
		if len(last.Siblings) == 0 {
			// A one-leaf tree: add a consistent level (bitmap bit and sibling), so the shape checks pass and the root differs.
			last.Bitmap[31] |= 1
			last.Siblings = append(last.Siblings, H([]byte("bench late failure")))
		} else {
			last.Siblings[0][0] ^= 1
		}
	}
	env, err := e.Encode()
	if err != nil {
		return nil, err
	}
	in, err := EncodeComposeInput(OpReturn, d.F.Cfg.Bytes(), env)
	if err != nil {
		return nil, err
	}
	b1 := RefB1{TB: tb}
	words, pins, err := b1.Registry()
	if err != nil {
		return nil, err
	}
	_, status, gas, halt := NativeCompose(in, math.MaxUint64, b1)
	if halt != nil {
		return nil, halt
	}
	want := uint64(0)
	if s.LateFailure {
		want, _ = StatusOf(ErrLeafProof)
	}
	if status != want {
		return nil, fmt.Errorf("status %d (%s), want %d", status, ComposeStatusName(status), want)
	}
	reg := map[string]string{}
	for k, v := range words {
		reg[hex.EncodeToString(k[:])] = hex.EncodeToString(v[:])
	}
	return &BenchCase{ID: id, Description: describe(s), Input: hex.EncodeToString(in), Registry: reg,
		Pins:   map[string]string{"genesisCommitment": hex.EncodeToString(pins.GenesisCommitment[:]), "profileHash": hex.EncodeToString(pins.ProfileHash[:])},
		Status: status, Gas: gas, Leaves: len(res.Leaves), Anchors: len(cert.Anchors), Shards: 1 << s.Depth, InputBytes: len(in)}, nil
}

// deepExtra gives every leaf a neighbour at each of the 32 levels below its shard: the key that agrees with the leaf down to that
// level and differs at it. Each leaf's path then has exactly 32 siblings (MaxRSMTSiblings).
func deepExtra(w *AggregatorWorld, leaves []Leaf) []Leaf {
	depth := 0
	for 1<<depth < len(w.PDRs) {
		depth++
	}
	var out []Leaf
	for _, l := range leaves {
		for k := depth; k < depth+MaxRSMTSiblings; k++ {
			sid := l.SID
			sid[k/8] ^= 0x80 >> (k % 8)
			out = append(out, Leaf{SID: sid, Value: H(sid[:])})
		}
	}
	return out
}

func describe(s BenchShape) string {
	seals := "consolidated (one seal for all shards)"
	if s.Original {
		seals = "original (a seal and a UC per leaf)"
	}
	d := fmt.Sprintf("%d leaves over %d shards, %s, %d signer(s) per seal", s.Leaves, 1<<s.Depth, seals, s.Signers)
	if s.DeepPaths {
		d += ", 32 RSMT siblings per leaf"
	}
	if s.LateFailure {
		d += ", the last leaf's path wrong (ErrLeafProof after all work)"
	}
	return d
}
