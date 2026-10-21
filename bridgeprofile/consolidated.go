package bridgeprofile

import (
	"bytes"
	gocrypto "crypto"
	"fmt"
	"sort"

	"github.com/unicitynetwork/bft-go-base/types"
)

// Consolidated bundles (uc-consolidation, #526): the root seals every shard of the aggregation partition in one root round, and a
// partition view (bft-go-base PartitionViewV1, the complete shard-tree leaf vector under that seal) yields an ordinary version 1
// unicity certificate for each shard. A wallet that consolidates its token before redeeming presents those certificates as its
// anchors: K = the number of shards its leaves touch, all under one seal (E = S = 1). B1 and the bridge check each as any UC.

// NewShardedAggregator is an aggregation partition of 2^depth shards (depth <= 3: the view's V1 limit of 8 leaves) certified by
// auth under tb. The shard configurations are in increasing shard order; depth 1 gives the DEV deployment's two shards.

// fixtureAnchors is the former B1 claim bound (16), kept as the size of the fixtures and corpus cases built around it.
const fixtureAnchors = 16

func NewShardedAggregator(auth *Authority, tb *types.RootTrustBaseV2, depth int) (*AggregatorWorld, error) {
	if depth < 0 || 1<<depth > types.MaxPartitionViewLeaves {
		return nil, fmt.Errorf("bridgeprofile: %d shards exceed the partition view's %d", 1<<depth, types.MaxPartitionViewLeaves)
	}
	shards := []types.ShardID{{}}
	for i := 0; i < depth; i++ {
		var next []types.ShardID
		for _, s := range shards {
			l, r := s.Split()
			next = append(next, l, r)
		}
		shards = next
	}
	w := &AggregatorWorld{Auth: auth, TB: tb}
	for i, sh := range shards {
		w.PDRs = append(w.PDRs, FixtureShardPDR(DevNetwork, DevAggPart, sh, DevChainID, fmt.Sprint("agg-", i)))
	}
	return w, nil
}

// ConsolidatedLeaves is CertifiedLeaves whose anchors were derived from authenticated partition views, with the encoded view of
// each sealed round in first-use order.
type ConsolidatedLeaves struct {
	*CertifiedLeaves
	Views [][]byte
}

// CertifyConsolidated certifies each leaf in the root round the callback names, sealing every shard of the partition once per
// round, and derives the anchors from that round's partition view: the view is authenticated against the enclosing UC of the
// round's master shard (the shard of its last leaf, the newest proof) with one quorum check, and each participating shard's UC is
// AuthenticatedPartitionView.Certificate. So the leaves of one round share one seal whatever shards they are in; leaves of
// different rounds are under different seals. Anchors are in first-use leaf order; extra leaves enter every tree of their shard.
func (w *AggregatorWorld) CertifyConsolidated(leaves []Leaf, extra []Leaf, assign func(i int, l Leaf) ShardRound) (*ConsolidatedLeaves, error) {
	type key struct {
		round ShardRound
		row   int
	}
	var rounds []ShardRound
	trees := map[key][]rsmtKV{}
	for i, l := range leaves {
		r, row := assign(i, l), w.Row(l.SID)
		if !containsRound(rounds, r) {
			rounds = append(rounds, r)
		}
		trees[key{r, row}] = append(trees[key{r, row}], rsmtKV{l.SID, l.Value})
	}
	roots := map[key]*rnode{}
	for k, kv := range trees {
		for _, l := range extra {
			if w.Row(l.SID) == k.row {
				kv = append(kv, rsmtKV{l.SID, l.Value})
			}
		}
		sort.Slice(kv, func(i, j int) bool { return bytes.Compare(kv[i].key[:], kv[j].key[:]) < 0 })
		roots[k] = rsmtBuild(kv)
	}
	certs := map[key]*types.UnicityCertificate{}
	out := &ConsolidatedLeaves{CertifiedLeaves: &CertifiedLeaves{}}
	for _, r := range rounds {
		master := -1
		for i, l := range leaves {
			if assign(i, l) == r {
				master = w.Row(l.SID)
			}
		}
		inputs := make([]ShardInput, len(w.PDRs))
		view := types.PartitionViewV1{Version: types.PartitionViewVersionV1, PartitionID: w.PDRs[0].PartitionID}
		for row, pdr := range w.PDRs {
			// a shard no leaf of this round is in carries a placeholder state no requested leaf depends on
			hash := H([]byte(fmt.Sprint("agg-empty-shard-state-", row)))
			if n, ok := roots[key{r, row}]; ok {
				hash = n.hash
			}
			ir := &types.InputRecord{Version: 1, RoundNumber: r.RootRound, Epoch: pdr.Epoch, PreviousHash: sl(H([]byte("agg-previous-state"))),
				Hash: hash[:], SummaryValue: []byte{}, Timestamp: r.IRTime, BlockHash: sl(H([]byte("agg-block")))}
			inputs[row] = ShardInput{PDR: pdr, IR: ir}
			conf, err := pdr.Hash(gocrypto.SHA256)
			if err != nil {
				return nil, err
			}
			view.Leaves = append(view.Leaves, types.PartitionViewLeafV1{ShardID: pdr.ShardID, InputRecord: ir, TRHash: sl(fixtureTRHash), ShardConfHash: conf})
		}
		enclosing, err := w.Auth.CertifyShards(w.TB.GetNetworkID(), w.TB.GetEpoch(), r.RootRound, inputs, master)
		if err != nil {
			return nil, err
		}
		vb, err := view.MarshalCBOR()
		if err != nil {
			return nil, err
		}
		av, err := types.AuthenticatePartitionView(vb, enclosing, view.PartitionID, types.TrustBaseSealVerifier(w.TB), gocrypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("bridgeprofile: the partition view does not authenticate: %w", err)
		}
		out.Views = append(out.Views, vb)
		for row, pdr := range w.PDRs {
			if _, ok := roots[key{r, row}]; !ok {
				continue
			}
			uc, err := av.Certificate(pdr.ShardID)
			if err != nil {
				return nil, err
			}
			certs[key{r, row}] = uc
		}
	}
	index := map[key]int{}
	for i, l := range leaves {
		k := key{assign(i, l), w.Row(l.SID)}
		ai, ok := index[k]
		if !ok {
			ai = len(out.Anchors)
			index[k] = ai
			uc := certs[k]
			ucb, err := types.Cbor.Marshal(uc)
			if err != nil {
				return nil, err
			}
			irb, err := uc.InputRecord.Bytes()
			if err != nil {
				return nil, err
			}
			pdr := w.PDRs[k.row]
			a := Anchor{Partition: uint32(pdr.PartitionID), Shard: pdr.ShardID.Bytes(),
				ExpectedStateRoot: [32]byte(uc.InputRecord.Hash), ExpectedIRHash: H(irb), UC: ucb, InputRecord: irb}
			copy(a.ShardConfHash[:], uc.ShardConfHash)
			out.Anchors = append(out.Anchors, a)
			out.Rows = append(out.Rows, k.row)
		}
		bm, sibs := roots[k].proof(l.SID)
		out.Proofs = append(out.Proofs, LeafProof{AnchorIndex: uint16(ai), Bitmap: bm, Siblings: sibs})
	}
	return out, nil
}

func containsRound(rs []ShardRound, r ShardRound) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}

// SpanningHistory is the first return history (by key seed "span-<k>-…", k = 0, 1, …) with `transfers` transfers whose leaves
// touch every shard of w, so a consolidated bundle of it has exactly one anchor per shard.
func SpanningHistory(f *Fixture, w *AggregatorWorld, transfers int) (*History, *Result, error) {
	for k := 0; k < 1000; k++ {
		h, res, _, err := ReturnHistorySeeded(f, transfers, fmt.Sprint("span-", k))
		if err != nil {
			return nil, nil, err
		}
		seen := map[int]bool{}
		for _, l := range res.Leaves {
			seen[w.Row(l.SID)] = true
		}
		if len(seen) == len(w.PDRs) {
			return h, res, nil
		}
	}
	return nil, nil, fmt.Errorf("bridgeprofile: no history of %d transfers spans %d shards", transfers, len(w.PDRs))
}

// consolidated adds the proof cases of consolidated bundles: for committees of 4 and 16 members and partitions of 1, 2, 4 and 8
// shards, a 16-leaf return history spanning every shard, consolidated under one seal (K = m anchors, E = S = 1), as compose and
// gate cases; a mixed bundle (one consolidated group plus one leaf under another seal); and a derived certificate whose shard
// path was altered, which B1 does not authenticate.
func (g *gen) consolidated() {
	f := g.d.F
	envOf := func(h *History, cert *CertifiedLeaves, mut func(e *Envelope)) []byte {
		e := &Envelope{PolicyBody: f.Policy.Bytes(), History: h.Bytes(), Anchors: append([]Anchor{}, cert.Anchors...), LeafProofs: append([]LeafProof{}, cert.Proofs...)}
		if mut != nil {
			mut(e)
		}
		b, err := e.Encode()
		g.must(err)
		return b
	}
	compose := func(id, desc string, env []byte, claims string) {
		g.add(Case{ID: id, Family: "proof", Op: "compose", Cfg: "dev", Description: desc, Input: hx(env),
			Aux: map[string]string{"operation": "return", "claims": claims}})
	}
	gate := func(id, desc string, env []byte) {
		g.add(Case{ID: id, Family: "proof", Op: "gate", Cfg: "dev", Description: desc + " estimate", Input: hx(env),
			Aux: map[string]string{"operation": "return"}})
	}
	one := func(int, Leaf) ShardRound { return ShardRound{BaseTime + 1000, 100} }
	for _, n := range []int{4, 16} {
		auth, err := NewCommittee(fmt.Sprint("consolidation-committee-", n), n)
		g.must(err)
		if err != nil {
			return
		}
		tb, err := auth.Genesis(DevNetwork, 1, 1)
		g.must(err)
		for depth := 0; depth <= 3; depth++ {
			m := 1 << depth
			w, err := NewShardedAggregator(auth, tb, depth)
			g.must(err)
			if err != nil {
				return
			}
			h, res, err := SpanningHistory(f, w, fixtureAnchors-2)
			g.must(err)
			if err != nil {
				return
			}
			cl, err := w.CertifyConsolidated(res.Leaves, nil, one)
			g.must(err)
			if err != nil {
				return
			}
			if len(cl.Anchors) != m {
				g.must(fmt.Errorf("bridgeprofile: %d anchors for %d shards", len(cl.Anchors), m))
				return
			}
			id := fmt.Sprintf("consolidated-m%d-n%d", m, n)
			desc := fmt.Sprintf("%d leaves over %d shards consolidated under one seal of a %d-member committee: %d anchors", len(res.Leaves), m, n, m)
			eb := envOf(h, cl.CertifiedLeaves, nil)
			compose("compose-"+id, desc, eb, claimsOf(cl.Anchors...))
			gate("gate-"+id, desc+", gas", eb)
			if n != 4 || m != 4 {
				continue
			}
			// one consolidated group plus one leaf certified under another seal (a later round): two seals, m+1 anchors
			last := len(res.Leaves) - 1
			mixed, err := w.CertifyConsolidated(res.Leaves, nil, func(i int, _ Leaf) ShardRound {
				if i == last {
					return ShardRound{BaseTime + 1000, 101}
				}
				return ShardRound{BaseTime + 1000, 100}
			})
			g.must(err)
			if err != nil {
				return
			}
			mb := envOf(h, mixed.CertifiedLeaves, nil)
			compose("compose-consolidated-mixed", "a consolidated group of four shards plus the last leaf under a later seal: five anchors, two seals", mb, claimsOf(mixed.Anchors...))
			gate("gate-consolidated-mixed", "the mixed consolidated bundle, gas", mb)
			// a derived certificate whose shard-tree path (another shard's leaf hash) was altered: B1 refuses it as any bad UC
			bad := envOf(h, cl.CertifiedLeaves, func(e *Envelope) { e.Anchors[1].UC = ucWithAlteredShardSibling(g, e.Anchors[1].UC) })
			others := append(append([]Anchor{}, cl.Anchors[:1]...), cl.Anchors[2:]...)
			compose("compose-consolidated-altered-shard-leaf", "a derived certificate of the consolidated bundle with one shard-tree sibling altered: B1 does not authenticate that anchor", bad, claimsOf(others...))
		}
	}
}

// ucWithAlteredShardSibling flips one bit of the first shard-tree sibling of a certificate: the shard leaf it stands for changes,
// so the path no longer evaluates to the seal's hash.
func ucWithAlteredShardSibling(g *gen, ucb []byte) []byte {
	out, err := AlterShardSibling(ucb)
	g.must(err)
	return out
}

// AlterShardSibling is ucb with one bit of its first shard-tree sibling flipped.
func AlterShardSibling(ucb []byte) ([]byte, error) {
	var uc types.UnicityCertificate
	if err := types.Cbor.Unmarshal(ucb, &uc); err != nil {
		return nil, err
	}
	if len(uc.ShardTreeCertificate.SiblingHashes) == 0 {
		return nil, fmt.Errorf("bridgeprofile: the certificate has no shard-tree sibling")
	}
	uc.ShardTreeCertificate.SiblingHashes[0] = bytes.Clone(uc.ShardTreeCertificate.SiblingHashes[0])
	uc.ShardTreeCertificate.SiblingHashes[0][0] ^= 1
	return types.Cbor.Marshal(&uc)
}
