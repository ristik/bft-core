package nb2ref

import (
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// SplitScenario is the design's split: 100 into 60 and 40, then 40 into 15 and 25; each part returned once at indices 0, 1, 2.
// It returns the three evidences in the order 60, 15, 25.
func SplitScenario(w *World, so map[string]SplitOpts) ([][]byte, error) {
	a, p, q, s, u := Key("a"), Key("p"), Key("q"), Key("s"), Key("u")
	dep, err := w.MakeDeposit(big.NewInt(100), a, ReceiptOpts{Type: 2, TxIndex: 1})
	if err != nil {
		return nil, err
	}
	root := w.RootDraft(dep, []*secp256k1.PrivateKey{a, Key("b")})
	_, kids, err := w.Split(root, []SplitOut{{Amount: big.NewInt(60), Owner: p}, {Amount: big.NewInt(40), Owner: q}}, so["root"])
	if err != nil {
		return nil, err
	}
	sixty, forty := kids[0], kids[1]
	_, grand, err := w.Split(forty, []SplitOut{{Amount: big.NewInt(15), Owner: s}, {Amount: big.NewInt(25), Owner: u}}, so["forty"])
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for i, part := range []*Draft{sixty, grand[0], grand[1]} {
		amt, _ := new(big.Int).SetString([]string{"60", "15", "25"}[i], 10)
		part.Return(w.ReturnTo(amt, Recipient20(fmt.Sprint("split-", i)), uint64(i)))
		t, err := w.Finalize(part)
		if err != nil {
			return nil, err
		}
		out = append(out, Evidence(t.Bytes()))
	}
	return out, nil
}

func (g *gen) splitVectors() error {
	w := g.worlds["main"]
	evs, err := SplitScenario(w, nil)
	if err != nil {
		return err
	}
	total := new(big.Int)
	for i, ev := range evs {
		v, err := g.addVerifier(fmt.Sprintf("ok-split-%s", []string{"60", "40-15", "40-25"}[i]), "main",
			"design split: 100 -> 60 + 40, 40 -> 15 + 25; each part returned once", nil, ev, "")
		if err != nil {
			return err
		}
		total.Add(total, v.Amount)
	}
	if total.Cmp(big.NewInt(100)) != 0 {
		return fmt.Errorf("split scenario returns %s", total)
	}
	if err := g.evidenceInvariance(); err != nil {
		return err
	}
	if err := g.deepLineage(20); err != nil {
		return err
	}
	other := HU([]byte("other"))
	neg := []struct {
		id, note, want, level string
		part                  int
		o                     SplitOpts
	}{
		{id: "SplitJustif-arity", want: "SplitJustif", level: "root", o: SplitOpts{MutJ: func(i int, j []byte) []byte {
			sj, _ := scanNative(j)
			c := &sj.kids[0]
			return CTag(TagSplitJustification, CArr(c.kids[0].raw(j), c.kids[1].raw(j), CNull))
		}}},
		{id: "SplitProofCount", note: "two allocation proofs", want: "SplitProofCount", level: "root", o: SplitOpts{MutJ: func(i int, j []byte) []byte {
			sj, _ := scanNative(j)
			c := &sj.kids[0]
			p := c.kids[1].kids[0].raw(j)
			return CTag(TagSplitJustification, CArr(c.kids[0].raw(j), CArr(p, p)))
		}}},
		{id: "SplitProofShape", note: "two steps at the same depth; the manifest commits to their fold, so only the depth order is wrong", want: "SplitProofShape", level: "root", o: SplitOpts{Custom: func(l SumLeaf) (SumProof, [32]byte) {
			p := SumProof{{Depth: 7, Hash: HU([]byte("sibling-a")), Sum: big.NewInt(30)}, {Depth: 7, Hash: HU([]byte("sibling-b")), Sum: big.NewInt(10)}}
			hash, _ := SumLeafHash(l.Key, l.Data, l.Value)
			sum := new(big.Int).Set(l.Value)
			for _, st := range p {
				if keyBit(&l.Key, st.Depth) {
					hash, sum, _ = SumNodeHash(st.Depth, st.Hash, st.Sum, hash, sum)
				} else {
					hash, sum, _ = SumNodeHash(st.Depth, hash, sum, st.Hash, st.Sum)
				}
			}
			return p, hash
		}}},
		{id: "SplitManifest", note: "the parent's terminal burn is a return R: a token cannot both split and return", want: "SplitManifest", level: "root", o: SplitOpts{ParentBurn: func(t *TransferTx) {
			r := (&ReturnData{D: w.Cfg.Domain(), Asset: AssetUCT, Recipient: Recipient20("r"), Amount: big.NewInt(100)}).Bytes()
			t.Data, t.Recipient = r, BurnPredicate(HU(r))
		}}},
		{id: "SplitBurn", note: "burn params are not H(manifest)", want: "SplitBurn", level: "root", o: SplitOpts{ParentBurn: func(t *TransferTx) { t.Recipient = BurnPredicate(other) }}},
		{id: "SplitProof", note: "an allocation sibling altered", want: "SplitProof", level: "root", o: SplitOpts{MutProof: func(i int, p SumProof) SumProof {
			q := append(SumProof(nil), p...)
			q[0].Hash = other
			return q
		}}},
		{id: "SplitSum", note: "40 split into 15 and 20: the children sum to 35", want: "SplitSum", level: "forty", part: 1, o: SplitOpts{MutLeaves: nil}},
		{id: "RepeatedSID", note: "a child minted with its parent's salt repeats the parent's mint state ID", want: "RepeatedSID", level: "forty", part: 1},
	}
	for _, n := range neg {
		var evs [][]byte
		var err error
		switch n.id {
		case "SplitSum":
			evs, err = splitSum(w)
		case "RepeatedSID":
			evs, err = repeatedSID(w)
		default:
			evs, err = SplitScenario(w, map[string]SplitOpts{n.level: n.o})
		}
		if err != nil {
			return fmt.Errorf("%s: %w", n.id, err)
		}
		if _, err := g.addVerifier(n.id, "main", n.note, nil, evs[n.part], n.want); err != nil {
			return err
		}
	}
	return nil
}

// splitSum splits 40 into 15 and 20 (sum 35) and returns the 15.
func splitSum(w *World) ([][]byte, error) {
	a, q := Key("a"), Key("q")
	dep, err := w.MakeDeposit(big.NewInt(40), a, ReceiptOpts{})
	if err != nil {
		return nil, err
	}
	root := w.RootDraft(dep, []*secp256k1.PrivateKey{a, q})
	_, kids, err := w.Split(root, []SplitOut{{Amount: big.NewInt(15), Owner: Key("s")}, {Amount: big.NewInt(20), Owner: Key("u")}}, SplitOpts{})
	if err != nil {
		return nil, err
	}
	kids[0].Return(w.ReturnTo(big.NewInt(15), Recipient20("r"), 0))
	t, err := w.Finalize(kids[0])
	if err != nil {
		return nil, err
	}
	return [][]byte{nil, Evidence(t.Bytes())}, nil
}

// repeatedSID mints a child with its parent's salt: the child's ID, mint source and minter equal the parent's.
func repeatedSID(w *World) ([][]byte, error) {
	a := Key("a")
	dep, err := w.MakeDeposit(big.NewInt(40), a, ReceiptOpts{})
	if err != nil {
		return nil, err
	}
	root := w.RootDraft(dep, []*secp256k1.PrivateKey{a, Key("q")})
	salt := root.Mint.Salt
	_, kids, err := w.Split(root, []SplitOut{{Amount: big.NewInt(15), Owner: Key("s"), Salt: &salt}, {Amount: big.NewInt(25), Owner: Key("u")}}, SplitOpts{})
	if err != nil {
		return nil, err
	}
	kids[0].Return(w.ReturnTo(big.NewInt(15), Recipient20("r"), 0))
	t, err := w.Finalize(kids[0])
	if err != nil {
		return nil, err
	}
	return [][]byte{nil, Evidence(t.Bytes())}, nil
}

// evidenceInvariance: two deposits reusing one secret under distinct nonces give distinct root IDs and redemption IDs, both
// valid; and a token whose inclusion proofs are re-certified under another seal (refreshed paths, another root epoch) keeps
// its redemption ID.
func (g *gen) evidenceInvariance() error {
	w := g.worlds["main"]
	r := HU([]byte("reused-secret"))
	var etas [][32]byte
	for i, id := range []string{"ok-secret-reuse-first", "ok-secret-reuse-second"} {
		dep, err := w.MakeDepositWithSecret(big.NewInt(int64(10+i)), Key("a"), r, ReceiptOpts{})
		if err != nil {
			return err
		}
		d := w.RootDraft(dep, []*secp256k1.PrivateKey{Key("a"), Key("b")})
		d.Return(w.ReturnTo(dep.Value, Recipient20("r"), 0))
		t, err := w.Finalize(d)
		if err != nil {
			return err
		}
		v, err := g.addVerifier(id, "main", "a faulty wallet reused r: the deposit numbers separate the root IDs", nil, Evidence(t.Bytes()), "")
		if err != nil {
			return err
		}
		etas = append(etas, v.Eta)
	}
	if etas[0] == etas[1] {
		return fmt.Errorf("secret reuse: equal redemption IDs")
	}
	dep, err := w.MakeDeposit(big.NewInt(7), Key("a"), ReceiptOpts{})
	if err != nil {
		return err
	}
	d := w.RootDraft(dep, []*secp256k1.PrivateKey{Key("a"), Key("b")})
	d.Return(w.ReturnTo(dep.Value, Recipient20("r"), 3))
	first, err := w.Finalize(d)
	if err != nil {
		return err
	}
	d.Cert = map[int]CertOpts{}
	for i := 0; i <= len(d.Transfers); i++ {
		d.Cert[i] = CertOpts{IRTime: DevTime + 9000, Seal: &SealOpts{Network: DevNetwork, Epoch: 2, RootRound: RotationRound + 77}, Committee: w.Roots[1]}
	}
	second, err := w.Finalize(d)
	if err != nil {
		return err
	}
	if string(first.Bytes()) == string(second.Bytes()) {
		return fmt.Errorf("refresh: identical evidence")
	}
	a, err := g.addVerifier("ok-refresh-original", "main", "", nil, Evidence(first.Bytes()), "")
	if err != nil {
		return err
	}
	b, err := g.addVerifier("ok-refresh-recertified", "main", "the same transactions with every inclusion proof re-certified in root epoch 2: same redemption ID", nil, Evidence(second.Bytes()), "")
	if err != nil {
		return err
	}
	if a.Eta != b.Eta {
		return fmt.Errorf("refresh changed eta")
	}
	return nil
}

// deepLineage splits a deposit depth times (amount into amount-1 and 1) and returns the last part: deeper than cborDepth,
// because every SplitJ is its own decoding unit, and with a SplitJ above justificationBytes.
func (g *gen) deepLineage(depth int) error {
	w := g.worlds["main"]
	dep, err := w.MakeDeposit(big.NewInt(1000), Key("a"), ReceiptOpts{})
	if err != nil {
		return err
	}
	cur := w.RootDraft(dep, []*secp256k1.PrivateKey{Key("a")})
	amount := int64(1000)
	for i := 0; i < depth; i++ {
		hop := Key(fmt.Sprint("deep-hop-", i)) // one ordinary transfer per level before its split
		cur.Transfer(sigPred(hop), hop)
		owner := Key(fmt.Sprint("deep-", i))
		_, kids, err := w.Split(cur, []SplitOut{{Amount: big.NewInt(amount - 1), Owner: owner}, {Amount: big.NewInt(1), Owner: Key(fmt.Sprint("deep-side-", i))}}, SplitOpts{})
		if err != nil {
			return err
		}
		amount--
		cur = kids[0]
	}
	cur.Return(w.ReturnTo(big.NewInt(amount), Recipient20("deep"), 0))
	t, err := w.Finalize(cur)
	if err != nil {
		return err
	}
	if len(t.Mint.Justification) <= MaxJustificationBytes {
		return fmt.Errorf("deep lineage: SplitJ of %d bytes is within justificationBytes", len(t.Mint.Justification))
	}
	_, err = g.addVerifier(fmt.Sprintf("ok-lineage-depth-%d", depth), "main",
		fmt.Sprintf("%d nested splits: deeper than cborDepth, SplitJ of %d bytes above justificationBytes", depth, len(t.Mint.Justification)), nil, Evidence(t.Bytes()), "")
	return err
}
