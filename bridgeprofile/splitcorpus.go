package bridgeprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

// The split corpus (protocol 6): vectors for the lineage relation, kept apart from the sealed protocol 5 corpus so that corpus and
// its sealed companion replay are untouched. Cases use the layout of corpus.go (Case, Expect, FixtureSet); families are sum-tree,
// lineage and native. Replay (ReplaySplit) uses only the case and the fixture set.

// SplitCorpusFormat identifies the split case layout.
const SplitCorpusFormat = "native-bridge-split-vectors/1"

var splitFamilies = []string{"sum-tree", "lineage", "native"}

// LevelJSON is one token of a lineage in a vector.
type LevelJSON struct {
	TokenID string `json:"tokenId"`
	Amount  string `json:"amount"`
	Leaves  int    `json:"leaves"`
}

// SplitRJSON is a lineage result rendered for the corpus: the ROOT lock's fields, the redeemed part's and every leaf, root first.
type SplitRJSON struct {
	Cfg                string      `json:"cfg"`
	Nonce              string      `json:"nonce"`
	Amount             string      `json:"amount"` // the root lock's amount, minimal big-endian hex
	TokenID            string      `json:"tokenId"`
	Salt               string      `json:"salt"`
	FirstPredicateHash string      `json:"firstPredicateHash"`
	LockDigest         string      `json:"lockDigest"`
	ReleaseTo          string      `json:"releaseTo"`
	Nullifier          string      `json:"nullifier"`
	PartTokenID        string      `json:"partTokenId"`
	PartAmount         string      `json:"partAmount"`
	Depth              string      `json:"depth"`
	Levels             []LevelJSON `json:"levels"`
	Leaves             []LeafJSON  `json:"leaves"`
}

func renderLineage(l *Lineage) *SplitRJSON {
	r := l.Result
	out := &SplitRJSON{Cfg: h32(r.Cfg), Nonce: u64s(r.Nonce), Amount: hx(AmountBytes(r.Amount)), TokenID: h32(r.TokenID), Salt: h32(r.Salt),
		FirstPredicateHash: h32(r.FirstPredicateHash), LockDigest: h32(r.LockDigest), ReleaseTo: hx(r.ReleaseTo[:]), Nullifier: h32(r.Nullifier),
		PartTokenID: h32(r.PartTokenID), PartAmount: hx(AmountBytes(r.PartAmount)), Depth: u64s(r.Depth), Levels: []LevelJSON{}, Leaves: []LeafJSON{}}
	for _, lv := range l.Levels {
		out.Levels = append(out.Levels, LevelJSON{TokenID: h32(lv.TokenID), Amount: hx(AmountBytes(lv.Amount)), Leaves: lv.Leaves})
	}
	for _, x := range r.Leaves {
		out.Leaves = append(out.Leaves, LeafJSON{SID: h32(x.SID), TxHash: h32(x.TxHash), ReferenceTime: u64s(x.ReferenceTime), LeafValue: h32(x.Value)})
	}
	return out
}

// errExpectV2 is errExpect: the reason names are shared; the family is the sentinel's.
func splitExpect(l *Lineage, err error) Expect {
	if err != nil {
		return errExpect(err)
	}
	return Expect{Status: "ok", Split: renderLineage(l)}
}

func decHex(s string) []byte { b, _ := hex.DecodeString(s); return b }

func bigDec(s string) *big.Int { v, _ := new(big.Int).SetString(s, 10); return v }

func b32(s string) (o [32]byte) { copy(o[:], decHex(s)); return }

// ReplaySplit is the executable meaning of a split case.
func ReplaySplit(fs *FixtureSet, c Case) Expect {
	in, err := hex.DecodeString(c.Input)
	if err != nil && c.Op != "sum-tree" && c.Op != "split-commitment" {
		return Expect{Status: "error", Reason: "bad-hex"}
	}
	switch c.Op {
	case "sum-tree":
		// aux.leaves = "keyHex:dataHex:amountDec;..."
		var leaves []SumLeaf
		for _, p := range strings.Split(c.Aux["leaves"], ";") {
			f := strings.Split(p, ":")
			leaves = append(leaves, SumLeaf{Key: b32(f[0]), Data: b32(f[1]), Value: bigDec(f[2])})
		}
		tree, err := BuildSumTree(leaves)
		if err != nil {
			return errExpect(err)
		}
		v := map[string]string{"root": h32(tree.Root()), "total": tree.Total().String()}
		m := SplitManifest{Root: tree.Root()}
		v["manifest"], v["reasonHash"] = hx(m.Bytes()), h32(m.ReasonHash())
		for i, l := range leaves {
			p, _ := tree.Proof(l.Key)
			v["proof."+strconv.Itoa(i)] = hx(p.Bytes())
		}
		return Expect{Status: "ok", Values: v}
	case "sum-proof":
		// input = the proof's CBOR; aux key, data, amount (decimal), root
		it, err := scanOne(in)
		if err != nil {
			return errExpect(err)
		}
		p, err := decodeSumProof(it)
		if err != nil {
			return errExpect(err)
		}
		sum, ok := p.Verify(b32(c.Aux["key"]), b32(c.Aux["data"]), bigDec(c.Aux["amount"]), b32(c.Aux["root"]))
		if !ok {
			return errExpect(ErrSplitProof)
		}
		return okValues("sum", sum.String(), "steps", strconv.Itoa(len(p)))
	case "split-commitment":
		// aux: source, network (decimal), recipient (the encoded predicate, hex), salt, childId, type, data (hex)
		nw, _ := strconv.ParseUint(c.Aux["network"], 10, 16)
		rec, err := scanOne(decHex(c.Aux["recipient"]))
		if err != nil {
			return errExpect(err)
		}
		pred, err := decodePredicate(rec)
		if err != nil {
			return errExpect(err)
		}
		d := splitOutputCommitment(b32(c.Aux["source"]), uint16(nw), pred, b32(c.Aux["salt"]), b32(c.Aux["childId"]), b32(c.Aux["type"]), decHex(c.Aux["data"]))
		return okValues("commitment", h32(d))
	case "justification":
		sj, err := DecodeSplitJustification(in)
		if err != nil {
			return errExpect(err)
		}
		tok, err := DecodeToken(sj.Token)
		if err != nil {
			return errExpect(err)
		}
		return okValues("steps", strconv.Itoa(len(sj.Proof)), "parentTransfers", strconv.Itoa(len(tok.Transfers)), "parentId", h32(DeriveTokenID(tok.Mint.Salt, tok.Mint.Network)))
	case "lineage":
		cfg, err := fs.cfg(c.Cfg)
		if err != nil {
			return errExpect(err)
		}
		b1, err := parseClaims(c.Aux["claims"])
		if err != nil {
			return errExpect(err)
		}
		op := uint8(OpReturn)
		if c.Aux["operation"] == "mint" {
			op = OpMint
		}
		l, err := ComposeLineage(cfg, op, in, b1)
		return splitExpect(l, err)
	case "native-compose-v2":
		b1, err := parseClaims(c.Aux["claims"])
		if err != nil {
			return errExpect(err)
		}
		limit := uint64(math.MaxUint64)
		if v, ok := c.Aux["gasLimit"]; ok {
			limit, _ = strconv.ParseUint(v, 10, 64)
		}
		out, status, gas, halt := NativeComposeV2(in, limit, b1)
		switch {
		case errors.Is(halt, ErrComposeABI):
			return Expect{Status: "halt", Values: map[string]string{"halt": "abi"}}
		case errors.Is(halt, ErrComposeOutOfGas):
			return Expect{Status: "halt", Values: map[string]string{"halt": "out-of-gas"}}
		}
		return Expect{Status: "ok", Output: hx(out[:]), Values: map[string]string{"status": u64s(status), "statusName": ComposeStatusNameV2(status), "gas": u64s(gas)}}
	}
	return Expect{Status: "error", Reason: "unknown-op"}
}

type splitGen struct {
	d      *Deployment
	b      *LineageBuilder
	real   *LineageBuilder
	fs     *FixtureSet
	cases  map[string][]Case
	muts   *MutationFile
	failed error
}

func (g *splitGen) must(err error) {
	if err != nil && g.failed == nil {
		g.failed = err
	}
}

// add replays the case and, when want is non-empty, requires the oracle to give exactly that reason: a vector that fails for another
// reason than its description names would pass for the wrong cause.
func (g *splitGen) add(c Case, want string) {
	c.Expected = ReplaySplit(g.fs, c)
	if want != "" && (c.Expected.Status != "error" || c.Expected.Reason != want) {
		g.must(fmt.Errorf("%s: want %s, got %s %s", c.ID, want, c.Expected.Status, c.Expected.Reason))
	}
	if want == "" && c.Expected.Status == "error" {
		g.must(fmt.Errorf("%s: expected success, got %s", c.ID, c.Expected.Reason))
	}
	g.cases[c.Family] = append(g.cases[c.Family], c)
}

// BuildSplitCorpus generates the split corpus deterministically.
func BuildSplitCorpus() (*Corpus, error) {
	d, err := NewDeployment()
	if err != nil {
		return nil, err
	}
	b, err := NewLineageBuilder(d)
	if err != nil {
		return nil, err
	}
	rb, err := NewLineageBuilder(d)
	if err != nil {
		return nil, err
	}
	rb.Real = true
	fs := &FixtureSet{Format: SplitCorpusFormat, Proto: SplitProtoVersion, Notes: splitNotes,
		Cfgs: map[string]FixtureJSON{"dev": fixtureJSON("dev", d.F)}, TrustBases: map[string]TrustJSON{}, Pins: map[string]PinJSON{}, Aggregat: map[string]string{}}
	g := &splitGen{d: d, b: b, real: rb, fs: fs, cases: map[string][]Case{}}
	g.sumTrees()
	g.commitments()
	g.lineages()
	g.nativeTwins()
	g.mutations()
	if g.failed != nil {
		return nil, g.failed
	}
	return g.pack()
}

var splitNotes = []string{
	"Protocol 6 split lineage vectors (docs/design/bridge-split-lineage-spec.md). Every fixture value is a DEV fixture input.",
	"Expectations are produced by the Go oracle; the sum-tree, proof and commitment cases are byte-for-byte the Rust SDK's (state-transition-sdk-rust src/rsmst and src/payment) and the JS and Rust SDKs must reproduce them.",
	"B1 in lineage cases is the claim set in aux.claims plus the real RSMT_MEMBER_V1, as in the protocol 5 corpus.",
	"Gas is the trial schedule of the spec (lineage.go split terms); it is an estimate with no ceiling, not a measurement.",
	"referenceTime and nonce are decimal strings; amounts are minimal big-endian hex unless a field says decimal.",
}

func leafKey(i int) [32]byte  { return H([]byte(fmt.Sprint("k", i))) }
func leafData(i int) [32]byte { return H([]byte(fmt.Sprint("d", i))) }

func leavesAux(ls []SumLeaf) string {
	var p []string
	for _, l := range ls {
		p = append(p, h32(l.Key)+":"+h32(l.Data)+":"+l.Value.String())
	}
	return strings.Join(p, ";")
}

func (g *splitGen) sumTrees() {
	for _, n := range []int{1, 2, 3, 16, 256} {
		var ls []SumLeaf
		for i := 0; i < n; i++ {
			ls = append(ls, SumLeaf{Key: leafKey(i), Data: leafData(i), Value: big.NewInt(int64(i%7 + 1))})
		}
		g.add(Case{ID: fmt.Sprintf("sum-tree-%d", n), Family: "sum-tree", Op: "sum-tree", Description: fmt.Sprintf("a sum tree of %d allocations: root, total, manifest and every leaf's proof", n),
			Aux: map[string]string{"leaves": leavesAux(ls)}}, "")
	}
	// Max-depth tree: two keys that agree on 255 bits.
	var k0, k1 [32]byte
	k1[31] = 1
	g.add(Case{ID: "sum-tree-depth-255", Family: "sum-tree", Op: "sum-tree", Description: "two keys that differ only in the last bit: one step at depth 255",
		Aux: map[string]string{"leaves": leavesAux([]SumLeaf{{k0, leafData(0), big.NewInt(7)}, {k1, leafData(1), big.NewInt(5)}})}}, "")
	// Builder refusals.
	one := big.NewInt(1)
	max := new(big.Int).Sub(new(big.Int).Lsh(one, 256), one)
	g.add(Case{ID: "sum-tree-duplicate-key", Family: "sum-tree", Op: "sum-tree", Description: "two allocations to one token ID",
		Aux: map[string]string{"leaves": leavesAux([]SumLeaf{{leafKey(0), leafData(0), one}, {leafKey(0), leafData(1), one}})}}, "ErrSplitProofShape")
	g.add(Case{ID: "sum-tree-zero-amount", Family: "sum-tree", Op: "sum-tree", Description: "an allocation of zero",
		Aux: map[string]string{"leaves": leavesAux([]SumLeaf{{leafKey(0), leafData(0), new(big.Int)}})}}, "ErrSplitProofShape")
	g.add(Case{ID: "sum-tree-sum-overflow", Family: "sum-tree", Op: "sum-tree", Description: "allocations whose sum is 2^256",
		Aux: map[string]string{"leaves": leavesAux([]SumLeaf{{leafKey(0), leafData(0), max}, {leafKey(1), leafData(1), one}})}}, "ErrSplitProofShape")

	// Proof checks over a four-leaf tree.
	ls := []SumLeaf{{leafKey(0), leafData(0), big.NewInt(10)}, {leafKey(1), leafData(1), big.NewInt(20)}, {leafKey(2), leafData(2), big.NewInt(30)}, {leafKey(3), leafData(3), big.NewInt(40)}}
	tree, err := BuildSumTree(ls)
	g.must(err)
	p, _ := tree.Proof(ls[0].Key)
	aux := func(key, data [32]byte, amount string, root [32]byte) map[string]string {
		return map[string]string{"key": h32(key), "data": h32(data), "amount": amount, "root": h32(root)}
	}
	g.add(Case{ID: "sum-proof-valid", Family: "sum-tree", Op: "sum-proof", Description: "a proof verifies and reconstructs the total", Input: hx(p.Bytes()), Aux: aux(ls[0].Key, ls[0].Data, "10", tree.Root())}, "")
	g.add(Case{ID: "sum-proof-wrong-amount", Family: "sum-tree", Op: "sum-proof", Description: "the leaf amount is one more", Input: hx(p.Bytes()), Aux: aux(ls[0].Key, ls[0].Data, "11", tree.Root())}, "ErrSplitProof")
	g.add(Case{ID: "sum-proof-wrong-key", Family: "sum-tree", Op: "sum-proof", Description: "the sibling's key", Input: hx(p.Bytes()), Aux: aux(ls[1].Key, ls[0].Data, "10", tree.Root())}, "ErrSplitProof")
	g.add(Case{ID: "sum-proof-wrong-data", Family: "sum-tree", Op: "sum-proof", Description: "another commitment", Input: hx(p.Bytes()), Aux: aux(ls[0].Key, ls[1].Data, "10", tree.Root())}, "ErrSplitProof")
	g.add(Case{ID: "sum-proof-wrong-root", Family: "sum-tree", Op: "sum-proof", Description: "another root", Input: hx(p.Bytes()), Aux: aux(ls[0].Key, ls[0].Data, "10", H([]byte("r")))}, "ErrSplitProof")
	q := append(SumProof{}, p...)
	q[len(q)-1].Sum = new(big.Int).Add(q[len(q)-1].Sum, one)
	g.add(Case{ID: "sum-proof-inflated-sibling-sum", Family: "sum-tree", Op: "sum-proof", Description: "the root-most sibling sum raised by one", Input: hx(q.Bytes()), Aux: aux(ls[0].Key, ls[0].Data, "10", tree.Root())}, "ErrSplitProof")
	q = append(SumProof{}, p[:len(p)-1]...)
	g.add(Case{ID: "sum-proof-truncated", Family: "sum-tree", Op: "sum-proof", Description: "the root-most step dropped", Input: hx(q.Bytes()), Aux: aux(ls[0].Key, ls[0].Data, "10", tree.Root())}, "ErrSplitProof")
	h := make([]byte, 32)
	step := func(depth uint64, sum []byte) []byte { return CArr(CUint(depth), CBytes(h), CBytes(sum)) }
	bad := func(id, desc string, proof []byte) {
		g.add(Case{ID: id, Family: "sum-tree", Op: "sum-proof", Description: desc, Input: hx(proof), Aux: aux(ls[0].Key, ls[0].Data, "10", tree.Root())}, "ErrSplitProofShape")
	}
	bad("sum-proof-zero-sibling-sum", "a sibling sum of zero", CArr(step(3, []byte{})))
	bad("sum-proof-nonminimal-sum", "a sibling sum with a leading zero byte", CArr(step(3, []byte{0, 1})))
	bad("sum-proof-sum-over-256-bits", "a 33-byte sibling sum", CArr(step(3, make([]byte, 33))))
	bad("sum-proof-equal-depths", "two steps at one depth", CArr(step(3, []byte{1}), step(3, []byte{1})))
	bad("sum-proof-increasing-depths", "depths that increase toward the root", CArr(step(3, []byte{1}), step(5, []byte{1})))
	bad("sum-proof-depth-256", "a depth of 256", CArr(step(256, []byte{1})))
	var many [][]byte
	for i := 0; i < 257; i++ {
		many = append(many, step(uint64(255-i%256), []byte{1}))
	}
	bad("sum-proof-257-steps", "257 steps", CArr(many...))
	big2 := make([]byte, 32)
	for i := range big2 {
		big2[i] = 0xff
	}
	g.add(Case{ID: "sum-proof-sibling-sum-overflow", Family: "sum-tree", Op: "sum-proof", Description: "a sibling sum of 2^256-1 beside a positive leaf",
		Input: hx(CArr(step(3, big2))), Aux: aux(ls[0].Key, ls[0].Data, "10", tree.Root())}, "ErrSplitProof")
}

func (g *splitGen) commitments() {
	pred := SignaturePredicate(bytes32x33(2))
	src, out, salt, ty := H([]byte("src")), H([]byte("out")), H([]byte("salt")), H([]byte("type"))
	base := map[string]string{"source": h32(src), "network": "3", "recipient": hx(pred.Bytes()), "salt": h32(salt), "childId": h32(out), "type": h32(ty), "data": hx([]byte("payload-bytes"))}
	g.add(Case{ID: "commitment-sdk-vector", Family: "sum-tree", Op: "split-commitment", Description: "the output commitment of the Rust SDK vector (examples/splitvec.rs)", Aux: base}, "")
	for _, k := range []string{"source", "salt", "childId", "type", "data", "recipient", "network"} {
		a := map[string]string{}
		for kk, vv := range base {
			a[kk] = vv
		}
		switch k {
		case "network":
			a[k] = "4"
		case "data":
			a[k] = hx([]byte("payload-bytez"))
		case "recipient":
			a[k] = hx(sigPred(KeyFromSeed("alt-recipient")).Bytes())
		default:
			x := b32(a[k])
			x[0] ^= 1
			a[k] = h32(x)
		}
		g.add(Case{ID: "commitment-changed-" + k, Family: "sum-tree", Op: "split-commitment", Description: "the commitment with " + k + " changed: a different value", Aux: a}, "")
	}
}

func (g *splitGen) envelope(t *LineageToken, irTime uint64) (*Envelope, *CertifiedLeaves) {
	env, _, cert, err := g.b.Envelope(t, irTime)
	g.must(err)
	return env, cert
}

func (g *splitGen) encode(env *Envelope) string {
	b, err := env.Encode()
	g.must(err)
	return hx(b)
}

func (g *splitGen) lineageCase(id, desc string, env *Envelope, claims string, want string) Case {
	c := Case{ID: id, Family: "lineage", Op: "lineage", Cfg: "dev", Description: desc, Input: g.encode(env), Aux: map[string]string{"claims": claims}}
	g.add(c, want)
	return g.cases["lineage"][len(g.cases["lineage"])-1]
}

func (g *splitGen) lineages() {
	cfg := g.d.F.Cfg
	one := big.NewInt(1)
	// Depth 0: ordinary full redemption.
	plain, err := g.b.Root(5, big.NewInt(100), lineageKeys("root"))
	g.must(err)
	g.b.Return(plain, rcpt, big.NewInt(100))
	env, cert := g.envelope(plain, BaseTime+1000)
	g.lineageCase("lineage-depth-0", "an unsplit token redeemed whole: depth 0, the part is the root", env, claimsOf(cert.Anchors...), "")

	// Depth 1: root(100) -> 40 + 60; both siblings redeem against one lock; real embedded proofs and structural ones.
	for _, mode := range []struct {
		name string
		b    *LineageBuilder
	}{{"", g.b}, {"-real-proofs", g.real}} {
		root, err := mode.b.Root(5, big.NewInt(100), lineageKeys("root"))
		g.must(err)
		kids, err := mode.b.Split(root, []SplitOut{
			{Label: "x", Amount: big.NewInt(40), Owners: lineageKeys("x")},
			{Label: "y", Amount: big.NewInt(60), Owners: lineageKeys("y")},
		}, nil)
		g.must(err)
		for i, amt := range []int64{40, 60} {
			g.b.Return(kids[i], rcpt, big.NewInt(amt))
			env, cert := g.envelope(kids[i], BaseTime+1000)
			g.lineageCase(fmt.Sprintf("lineage-depth-1-part-%d%s", amt, mode.name),
				fmt.Sprintf("root 100 split 40+60, the %d part redeemed: root identity and lock amount 100, part amount %d", amt, amt), env, claimsOf(cert.Anchors...), "")
		}
	}

	// Nested: chains of depth 2, 3 and 8 (the lock amount 2^20, each split halves the remainder).
	for _, depth := range []int{2, 3, 8} {
		part, err := g.b.Chain(7, big.NewInt(1<<20), depth, "chain")
		g.must(err)
		g.b.Return(part, rcpt, part.Amount)
		env, cert := g.envelope(part, BaseTime+1000)
		g.lineageCase(fmt.Sprintf("lineage-depth-%d", depth), fmt.Sprintf("a chain of %d repeated splits: the deepest part redeems, the lock stays the root's", depth), env, claimsOf(cert.Anchors...), "")
	}

	// A split into 16 outputs and into 256: one part's proof carries 4 and 8 steps.
	for _, n := range []int{16, 256} {
		root, err := g.b.Root(5, big.NewInt(int64(n)*10), lineageKeys("root"))
		g.must(err)
		var outs []SplitOut
		for i := 0; i < n; i++ {
			outs = append(outs, SplitOut{Label: fmt.Sprint("o", i), Amount: big.NewInt(10), Owners: lineageKeys(fmt.Sprint("o", i))[:1]})
		}
		kids, err := g.b.Split(root, outs, nil)
		g.must(err)
		g.b.Return(kids[n/2], rcpt, big.NewInt(10))
		env, cert := g.envelope(kids[n/2], BaseTime+1000)
		g.lineageCase(fmt.Sprintf("lineage-fanout-%d", n), fmt.Sprintf("a split into %d equal parts, one redeemed", n), env, claimsOf(cert.Anchors...), "")
	}

	// A valid base for the negatives: root(100) -> x=40, y=60; x redeemed.
	tw := func(hk *SplitHooks, x SplitOut) *LineageToken {
		root, err := g.b.Root(5, big.NewInt(100), lineageKeys("root"))
		g.must(err)
		kids, err := g.b.Split(root, []SplitOut{x, {Label: "y", Amount: big.NewInt(60), Owners: lineageKeys("y")}}, hk)
		g.must(err)
		return kids[0]
	}
	x40 := SplitOut{Label: "x", Amount: big.NewInt(40), Owners: lineageKeys("x")}
	base := tw(nil, x40)
	g.b.Return(base, rcpt, big.NewInt(40))
	baseEnv, baseCert := g.envelope(base, BaseTime+1000)
	claims := claimsOf(baseCert.Anchors...)
	neg := func(id, desc string, part *LineageToken, ret *big.Int, want string) {
		g.b.Return(part, rcpt, ret)
		e := *baseEnv
		e.History = part.H.Bytes()
		g.lineageCase(id, desc, &e, claims, want)
	}
	neg("lineage-neg-tree-understates-part", "the tree commits 39 for the part that mints 40", tw(&SplitHooks{TreeValues: []*big.Int{big.NewInt(39), big.NewInt(60)}}, x40), big.NewInt(40), "ErrSplitProof")
	neg("lineage-neg-tree-total-under", "the tree totals 99 against a burned source of 100", tw(&SplitHooks{TreeValues: []*big.Int{big.NewInt(40), big.NewInt(59)}}, x40), big.NewInt(40), "ErrSplitSum")
	neg("lineage-neg-tree-total-over", "the tree totals 101 against a burned source of 100", tw(&SplitHooks{TreeValues: []*big.Int{big.NewInt(40), big.NewInt(61)}}, x40), big.NewInt(40), "ErrSplitSum")
	neg("lineage-neg-changed-recipient", "the proof was prepared for another recipient than the mint names", tw(nil, SplitOut{Label: "x", Amount: big.NewInt(40), Owners: lineageKeys("x"), CommitTo: KeyFromSeed("intended")}), big.NewInt(40), "ErrSplitProof")
	neg("lineage-neg-changed-salt", "the child's salt changed after the commitment (a different token ID)", tw(&SplitHooks{ChildMint: func(i int, m *MintTx) {
		if i == 0 {
			m.Salt[0] ^= 1
		}
	}}, x40), big.NewInt(40), "ErrSplitProof")
	neg("lineage-neg-changed-amount", "the child mints 41 against a commitment to 40", tw(&SplitHooks{ChildMint: func(i int, m *MintTx) {
		if i == 0 {
			m.Data = ValueData(cfg.Aid, big.NewInt(41))
		}
	}}, x40), big.NewInt(41), "ErrSplitProof")
	neg("lineage-neg-changed-type", "the child's token type changed", tw(&SplitHooks{ChildMint: func(i int, m *MintTx) {
		if i == 0 {
			m.Type[0] ^= 1
		}
	}}, x40), big.NewInt(40), "ErrMintType")
	neg("lineage-neg-changed-network", "the child's network changed", tw(&SplitHooks{ChildMint: func(i int, m *MintTx) {
		if i == 0 {
			m.Network++
		}
	}}, x40), big.NewInt(40), "ErrMintShape")
	neg("lineage-neg-changed-asset", "the child's asset is another asset", tw(&SplitHooks{ChildMint: func(i int, m *MintTx) {
		if i == 0 {
			m.Data = ValueData(H([]byte("another asset")), big.NewInt(40))
		}
	}}, x40), big.NewInt(40), "ErrMintData")
	neg("lineage-neg-lock-reason-on-a-part", "a part claims the lock reason: its salt is not the lock's", tw(&SplitHooks{ChildMint: func(i int, m *MintTx) {
		if i == 0 {
			m.Justification = MintJustification(cfg.ChainID, cfg.Vault, cfg.ZeroAddress, 5, g.d.F.StructuralProof(5))
		}
	}}, x40), big.NewInt(40), "ErrMintSalt")
	neg("lineage-neg-unknown-reason", "a part with a justification that is neither reason", tw(&SplitHooks{ChildMint: func(i int, m *MintTx) {
		if i == 0 {
			m.Justification = CTag(39099, CArr(CUint(1)))
		}
	}}, x40), big.NewInt(40), "ErrMintJustif")
	neg("lineage-neg-proof-depth-changed", "one proof step's depth changed", tw(&SplitHooks{Proof: func(i int, p SumProof) SumProof {
		if i == 0 {
			q := append(SumProof{}, p...)
			q[0].Depth = 200
			return q
		}
		return p
	}}, x40), big.NewInt(40), "ErrSplitProof")
	neg("lineage-neg-manifest-root-changed", "the burn commits a manifest with another root", tw(&SplitHooks{Manifest: func(m SplitManifest) []byte {
		m.Root[0] ^= 1
		return m.Bytes()
	}}, x40), big.NewInt(40), "ErrSplitProof")
	neg("lineage-neg-burn-predicate-not-manifest-hash", "the parent burns to a predicate that is not the hash of its (valid) manifest", tw(&SplitHooks{BurnTo: &[32]byte{1}}, x40), big.NewInt(40), "ErrSplitBurn")
	neg("lineage-neg-ancestor-certificate-outside-codec", "an embedded ancestor certificate outside the native/SDK codec intersection (seal network 65536)", tw(&SplitHooks{ParentToken: CorruptedMintUC}, x40), big.NewInt(40), "ErrCertScan")
	neg("lineage-neg-ancestor-signature-width", "an embedded ancestor certificate whose seal signature has 63 bytes", tw(&SplitHooks{ParentToken: CorruptedMintUCSig}, x40), big.NewInt(40), "ErrCertSigLength")
	neg("lineage-neg-not-a-manifest", "the burn data is not a manifest", tw(&SplitHooks{Manifest: func(SplitManifest) []byte { return []byte{0x01} }}, x40), big.NewInt(40), "ErrSplitManifest")
	neg("lineage-neg-parent-return", "the parent was returned: its burn carries a return reason, not a manifest", tw(&SplitHooks{Manifest: func(SplitManifest) []byte {
		return ReturnReason(cfg.ChainID, cfg.Vault, cfg.ZeroAddress, cfg.Ty, cfg.Aid, rcpt, big.NewInt(100))
	}}, x40), big.NewInt(40), "ErrSplitManifest")
	neg("lineage-neg-parent-not-burned", "the parent ends in an ordinary transfer", tw(&SplitHooks{NoSplitBurn: true}, x40), big.NewInt(40), "ErrSplitBurn")
	neg("lineage-neg-parent-forged-unlock", "the parent's last unlock signature is forged", tw(&SplitHooks{ParentSource: func(h *History) { h.CDs[len(h.CDs)-1].Unlock[0] ^= 1 }}, x40), big.NewInt(40), "ErrUnlockKey")
	neg("lineage-neg-parent-foreign-lock", "the root names another vault", tw(&SplitHooks{ParentSource: func(h *History) {
		h.Mint.Justification = MintJustification(cfg.ChainID, [20]byte{9}, cfg.ZeroAddress, 5, g.d.F.StructuralProof(5))
		g.must(h.Resign(lineageKeys("root")))
	}}, x40), big.NewInt(40), "ErrMintJustif")
	neg("lineage-neg-partial-part-return", "the part returns 39 of its 40", tw(nil, x40), big.NewInt(39), "ErrReturnAmount")
	neg("lineage-neg-return-more-than-part", "the part returns the root's 100", tw(nil, x40), big.NewInt(100), "ErrReturnAmount")
	// A child that reuses the root's token ID repeats the root's mint state.
	{
		root, err := g.b.Root(5, big.NewInt(100), lineageKeys("root"))
		g.must(err)
		salt := root.H.Mint.Salt
		kids, err := g.b.Split(root, []SplitOut{{Label: "x", Amount: big.NewInt(40), Owners: lineageKeys("x"), Salt: &salt}, {Label: "y", Amount: big.NewInt(60), Owners: lineageKeys("y")}}, nil)
		g.must(err)
		neg("lineage-neg-repeated-token-id", "a part with the root's own token ID: the root's mint state repeats", kids[0], big.NewInt(40), "ErrRepeatedSID")
	}

	// Witness negatives on the valid base: the envelope, not the relation, is wrong.
	e := *baseEnv
	e.LeafProofs = baseEnv.LeafProofs[1:]
	g.lineageCase("lineage-neg-ancestor-leaf-unwitnessed", "the root's mint leaf has no witness", &e, claims, "ErrPolicyLeafCount")
	e = *baseEnv
	e.LeafProofs = append([]LeafProof{}, baseEnv.LeafProofs...)
	e.LeafProofs[1], e.LeafProofs[2] = e.LeafProofs[2], e.LeafProofs[1]
	g.lineageCase("lineage-neg-witnesses-out-of-order", "two ancestor witnesses swapped", &e, claims, "ErrLeafProof")
	early, earlyCert := g.envelope(base, BaseTime+5)
	g.lineageCase("lineage-neg-seal-before-ancestor-times", "every leaf is witnessed under a seal earlier than the lineage's reference times", early, claimsOf(earlyCert.Anchors...), "ErrIRTime")
	g.lineageCase("lineage-neg-anchor-not-authenticated", "the anchors are not in the admitted claim set", baseEnv, "", "ErrAnchorAuth")
	// Refreshed witnesses: the same lineage under a later seal verifies to the same nullifier.
	later, laterCert := g.envelope(base, BaseTime+5000)
	g.lineageCase("lineage-refreshed-witnesses", "the same part under fresh anchors: identical lock, part and nullifier", later, claimsOf(laterCert.Anchors...), "")
	_ = one
}

func (g *splitGen) nativeTwins() {
	var twins []Case
	for _, c := range g.cases["lineage"] {
		c := c
		cfg := g.d.F.Cfg
		env := decHex(c.Input)
		in, err := EncodeComposeInput(OpReturn, cfg.Bytes(), env)
		g.must(err)
		t := Case{ID: "native-" + c.ID, Family: "native", Op: "native-compose-v2", Cfg: "dev", Description: "BRIDGE_COMPOSE_V2 of " + c.ID + ": " + c.Description, Input: hx(in), Aux: map[string]string{"claims": c.Aux["claims"]}}
		g.add(t, "")
		twins = append(twins, g.cases["native"][len(g.cases["native"])-1])
	}
	// Statuses: every native twin of a failing lineage case must carry that case's reason as a status.
	byID := map[string]Case{}
	for _, c := range g.cases["lineage"] {
		byID[c.ID] = c
	}
	for _, t := range twins {
		src := byID[strings.TrimPrefix(t.ID, "native-")]
		if src.Expected.Status == "error" && t.Expected.Values["statusName"] != src.Expected.Reason {
			g.must(fmt.Errorf("%s: native status %s, oracle %s", t.ID, t.Expected.Values["statusName"], src.Expected.Reason))
		}
	}
	// Exact gas and one short, for the depth 0, 1, 2 and 8 returns.
	for _, id := range []string{"lineage-depth-0", "lineage-depth-1-part-40", "lineage-depth-2", "lineage-depth-8"} {
		for _, t := range twins {
			if t.ID != "native-"+id {
				continue
			}
			gas, _ := strconv.ParseUint(t.Expected.Values["gas"], 10, 64)
			for _, v := range []struct {
				suffix string
				limit  uint64
				desc   string
			}{{"-exact-gas", gas, "forwarded exactly its charge"}, {"-out-of-gas", gas - 1, "forwarded one gas less than its charge: an out-of-gas halt"}} {
				g.add(Case{ID: t.ID + v.suffix, Family: "native", Op: "native-compose-v2", Cfg: "dev", Description: t.ID + " " + v.desc, Input: t.Input,
					Aux: map[string]string{"claims": t.Aux["claims"], "gasLimit": strconv.FormatUint(v.limit, 10)}}, "")
			}
		}
	}
	valid := decHex(twins[0].Input)
	g.add(Case{ID: "native-v2-trailing-word", Family: "native", Op: "native-compose-v2", Cfg: "dev", Description: "a valid input followed by one zero word: not the canonical ABI, a halt",
		Input: hx(append(append([]byte{}, valid...), make([]byte, 32)...)), Aux: map[string]string{"claims": twins[0].Aux["claims"]}}, "")
}

func (g *splitGen) pack() (*Corpus, error) {
	out := &Corpus{Files: map[string][]byte{}, Set: g.fs, Cases: g.cases}
	js := func(v any) ([]byte, error) {
		b, err := json.MarshalIndent(v, "", " ")
		return append(b, '\n'), err
	}
	fsb, err := js(g.fs)
	if err != nil {
		return nil, err
	}
	out.Files["config/fixtures.json"] = fsb
	fdig := sha256.Sum256(fsb)
	for _, fam := range splitFamilies {
		seen := map[string]bool{}
		for _, c := range g.cases[fam] {
			if seen[c.ID] {
				return nil, fmt.Errorf("duplicate case id %s", c.ID)
			}
			seen[c.ID] = true
		}
		b, err := js(CaseFile{Format: SplitCorpusFormat, Proto: SplitProtoVersion, Family: fam, Fixture: hex.EncodeToString(fdig[:]), Cases: g.cases[fam]})
		if err != nil {
			return nil, err
		}
		out.Files[fam+"/cases.json"] = b
	}
	var table []composeStatusEntry
	table = append(table, composeStatusEntry{0, "ok"})
	for i := 1; i < len(ComposeStatusV2); i++ {
		table = append(table, composeStatusEntry{uint64(i), ComposeStatusNameV2(uint64(i))})
	}
	st, err := js(table)
	if err != nil {
		return nil, err
	}
	out.Files["config/compose-status-v2.json"] = st
	if g.muts != nil {
		mb, err := js(g.muts)
		if err != nil {
			return nil, err
		}
		out.Files["mutation/cases.json"] = mb
	}
	return out, nil
}

// SplitFiles lists the generated file names in order.
func (c *Corpus) SplitFiles() []string {
	var names []string
	for p := range c.Files {
		names = append(names, p)
	}
	sort.Strings(names)
	return names
}

// MutationFile is a differential-replay file: one valid BRIDGE_COMPOSE_V2 input and many small byte patches of it, each with the
// outcome the oracle gives. It exists so a second implementation is compared on malformed inputs (every embedded-token, proof and
// certificate fault) without storing a copy of the input per case.
type MutationFile struct {
	Format string         `json:"format"`
	Base   string         `json:"base"` // the input, hex
	Claims string         `json:"claims"`
	Cases  []MutationCase `json:"cases"`
}

// MutationCase patches Base (xor Patch[i].X into byte Patch[i].O) and expects Expected.
type MutationCase struct {
	ID       string      `json:"id"`
	Patch    []BytePatch `json:"patch"`
	Expected Expect      `json:"expected"`
}

// BytePatch is one xor.
type BytePatch struct {
	O int  `json:"o"`
	X byte `json:"x"`
}

// ReplayMutation applies the patch to base and runs NativeComposeV2 with an unlimited gas allowance.
func ReplayMutation(base []byte, claims string, patch []BytePatch) Expect {
	in := append([]byte{}, base...)
	for _, p := range patch {
		in[p.O] ^= p.X
	}
	b1, err := parseClaims(claims)
	if err != nil {
		return errExpect(err)
	}
	_, status, gas, halt := NativeComposeV2(in, math.MaxUint64>>1, b1)
	if halt != nil {
		return Expect{Status: "halt", Values: map[string]string{"halt": "abi"}}
	}
	return Expect{Status: "ok", Values: map[string]string{"status": u64s(status), "statusName": ComposeStatusNameV2(status), "gas": u64s(gas)}}
}

func (g *splitGen) mutations() {
	part, err := g.real.Chain(7, big.NewInt(1<<20), 2, "m")
	g.must(err)
	g.real.Return(part, rcpt, part.Amount)
	env, _, cert, err := g.real.Envelope(part, BaseTime+1000)
	g.must(err)
	in, err := EncodeComposeInput(OpReturn, g.d.F.Cfg.Bytes(), mustEncodeEnv(g, env))
	g.must(err)
	mf := &MutationFile{Format: "native-bridge-split-mutations/1", Base: hx(in), Claims: claimsOf(cert.Anchors...)}
	rng := uint64(0x9e3779b97f4a7c15)
	next := func() uint64 { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng }
	for i := 0; i < 400; i++ {
		var patch []BytePatch
		for k := 0; k < 1+int(next()%3); k++ {
			patch = append(patch, BytePatch{O: int(next() % uint64(len(in))), X: byte(1 + next()%255)})
		}
		mf.Cases = append(mf.Cases, MutationCase{ID: fmt.Sprintf("mutation-%03d", i), Patch: patch, Expected: ReplayMutation(in, mf.Claims, patch)})
	}
	g.muts = mf
}

func mustEncodeEnv(g *splitGen, env *Envelope) []byte {
	b, err := env.Encode()
	g.must(err)
	return b
}

// SplitDir is the directory of the split corpus inside the sealed tree.
const SplitDir = "split"

// BuildSealedCorpus is the one tree the plug-ins seal: the base corpus, and the split corpus under SplitDir, so that one
// manifest digest covers both.
func BuildSealedCorpus() (*Corpus, error) {
	base, err := BuildCorpus()
	if err != nil {
		return nil, err
	}
	split, err := BuildSplitCorpus()
	if err != nil {
		return nil, err
	}
	for p, b := range split.Files {
		base.Files[SplitDir+"/"+p] = b
	}
	return base, nil
}
