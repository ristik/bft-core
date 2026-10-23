package bridgeprofile

import (
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// The lineage builders below construct valid split lineages for the vectors, tests and benchmarks, as build.go does for plain
// histories. They are the oracle's own construction: the SDKs (JS, Rust) build the same bytes independently and are checked against
// the corpus, not against this code.

// LineageToken is one token of a built lineage.
type LineageToken struct {
	H      *History
	ID     [32]byte
	Amount *big.Int
	Owners []*secp256k1.PrivateKey // Owners[0] is the mint recipient, the last is the current owner
	Token  []byte                  // the SDK token bytes, set once a split burn is appended
}

// SplitOut is one output of a split: its amount and the owners of its own history (the first is the mint recipient). The salt
// is derived from the label so a vector never depends on randomness.
type SplitOut struct {
	Label  string
	Amount *big.Int
	Owners []*secp256k1.PrivateKey
	// CommitTo, when set, is the key whose recipient predicate the allocation commits to instead of Owners[0]'s: the mint then
	// names a recipient the proof was not prepared for.
	CommitTo *secp256k1.PrivateKey
	// Salt, when set, replaces the label-derived salt (a child can then reuse an ancestor's token ID).
	Salt *[32]byte
}

// SplitHooks tamper with exactly one property of a split; every field is optional. They run at the point named, so the rest of the
// lineage stays self-consistent.
type SplitHooks struct {
	TreeValues   []*big.Int                       // the amounts committed in the tree (default: the outputs')
	Manifest     func(SplitManifest) []byte       // the burn transfer's data; the burn predicate is its hash
	Proof        func(i int, p SumProof) SumProof // the proof embedded in output i
	ChildMint    func(i int, m *MintTx)           // output i's mint after the commitment is computed (the child is re-signed)
	ParentSource func(h *History)                 // the parent history after its burn, before it is embedded; the caller re-signs
	ParentToken  func(token []byte) []byte        // the embedded parent token bytes, before the children's justifications are built
	BurnTo       *[32]byte                        // the burn predicate's hash instead of H(manifest data)
	NoSplitBurn  bool                             // end the parent with an ordinary transfer instead of a burn
}

// LineageBuilder builds lineages in a deployment. Real selects embedded inclusion proofs certified by the aggregator world; otherwise
// every embedded proof carries one structurally valid, unrelated certificate (the bridge never verifies embedded proofs: the
// envelope's witnesses do).
type LineageBuilder struct {
	D    *Deployment
	Real bool
	uc   []byte
}

// NewLineageBuilder is a builder for d.
func NewLineageBuilder(d *Deployment) (*LineageBuilder, error) {
	c, err := d.Agg.Certify([]Leaf{{SID: H([]byte("embedded")), Value: H([]byte("embedded"))}}, nil, BaseTime+500, 50)
	if err != nil {
		return nil, err
	}
	return &LineageBuilder{D: d, uc: c.Anchors[0].UC}, nil
}

// Root builds the lock-backed root token of nonce n with owners.
func (b *LineageBuilder) Root(n uint64, amount *big.Int, owners []*secp256k1.PrivateKey) (*LineageToken, error) {
	h, err := b.D.F.BuildToken(n, amount, owners)
	if err != nil {
		return nil, err
	}
	id := DeriveTokenID(h.Mint.Salt, b.D.F.Cfg.Network)
	return &LineageToken{H: h, ID: id, Amount: new(big.Int).Set(amount), Owners: owners}, nil
}

func (b *LineageBuilder) newHistory(m MintTx, owners []*secp256k1.PrivateKey) (*History, [32]byte, error) {
	id := DeriveTokenID(m.Salt, m.Network)
	mk, err := MinterKey(id)
	if err != nil {
		return nil, id, err
	}
	h0 := MintSourceHash(id)
	raw := m.Bytes()
	cd := Certification{Source: sigPred(mk), SourceHash: h0, TxHash: H(raw), Deadline: m.Deadline}
	cd.Unlock = SignUnlock(mk, cd.SourceHash, cd.TxHash)
	h := &History{Mint: m, MintCD: cd, MintTime: BaseTime, mintRaw: raw}
	state := ResultState(h0, id[:])
	for i := 1; i < len(owners); i++ {
		if err := h.appendTransfer(&state, owners[i-1], sigPred(owners[i]), nil, uint64(i)); err != nil {
			return nil, id, err
		}
	}
	return h, id, nil
}

// embed sets t.Token: the SDK token of t's history with one inclusion proof per certified transaction.
func (b *LineageBuilder) embed(t *LineageToken) error {
	h := t.H
	proofs := make([]InclusionProof, 1+len(h.Transfers))
	if b.Real {
		leaves, err := historyLeavesOf(b.D.F.Cfg, h)
		if err != nil {
			return err
		}
		cert, err := b.D.Agg.Certify(leaves, nil, BaseTime+1000, 60)
		if err != nil {
			return err
		}
		proofs = cert.InclusionProofs()
	} else {
		for i := range proofs {
			proofs[i] = InclusionProof{UC: b.uc}
		}
	}
	t.Token = TokenFromHistory(h, proofs).Bytes()
	return nil
}

// historyLeavesOf is the leaves of a history without classifying its terminal transfer.
func historyLeavesOf(cfg *Cfg, h *History) ([]Leaf, error) {
	tag, _ := justificationTag(h.Mint.Justification)
	lv, err := verifyLevel(cfg, h, tag == TagMintLock, map[[32]byte]bool{})
	if err != nil {
		return nil, err
	}
	return lv.leaves, nil
}

// Split burns parent into outs: the children's mints are fixed first (their commitments), the sum tree and manifest follow, the
// parent ends in the manifest burn, and each child's mint carries the split reason with the parent's token and its own proof.
func (b *LineageBuilder) Split(parent *LineageToken, outs []SplitOut, hk *SplitHooks) ([]*LineageToken, error) {
	if hk == nil {
		hk = &SplitHooks{}
	}
	cfg := b.D.F.Cfg
	type child struct {
		m  MintTx
		id [32]byte
		d  [32]byte
	}
	kids := make([]child, len(outs))
	var leaves []SumLeaf
	for i, o := range outs {
		salt := H([]byte(fmt.Sprintf("split-salt|%x|%s", parent.ID, o.Label)))
		if o.Salt != nil {
			salt = *o.Salt
		}
		m := MintTx{Network: cfg.Network, Recipient: sigPred(o.Owners[0]), Salt: salt, Type: cfg.Ty, Data: ValueData(cfg.Aid, o.Amount)}
		id := DeriveTokenID(salt, cfg.Network)
		cm := m
		if o.CommitTo != nil {
			cm.Recipient = sigPred(o.CommitTo)
		}
		d := SplitOutputCommitment(parent.ID, &cm)
		val := o.Amount
		if hk.TreeValues != nil {
			val = hk.TreeValues[i]
		}
		kids[i] = child{m, id, d}
		leaves = append(leaves, SumLeaf{Key: id, Data: d, Value: val})
	}
	tree, err := BuildSumTree(leaves)
	if err != nil {
		return nil, err
	}
	man := SplitManifest{Root: tree.Root()}
	data := man.Bytes()
	if hk.Manifest != nil {
		data = hk.Manifest(man)
	}
	owner := parent.Owners[len(parent.Owners)-1]
	state := parent.H.finalState(cfg)
	if hk.NoSplitBurn {
		if err := parent.H.appendTransfer(&state, owner, sigPred(owner), nil, 1000); err != nil {
			return nil, err
		}
	} else if err := parent.H.appendTransfer(&state, owner, BurnPredicate(burnHash(data, hk.BurnTo)), data, 1000); err != nil {
		return nil, err
	}
	if hk.ParentSource != nil {
		hk.ParentSource(parent.H)
	}
	if err := b.embed(parent); err != nil {
		return nil, err
	}
	if hk.ParentToken != nil {
		parent.Token = hk.ParentToken(parent.Token)
	}
	var out []*LineageToken
	for i, k := range kids {
		proof, ok := tree.Proof(k.id)
		if !ok {
			return nil, fmt.Errorf("no proof for output %d", i)
		}
		if hk.Proof != nil {
			proof = hk.Proof(i, proof)
		}
		m := k.m
		m.Justification = SplitJustificationBytes(parent.Token, proof)
		if hk.ChildMint != nil {
			hk.ChildMint(i, &m)
		}
		h, id, err := b.newHistory(m, outs[i].Owners)
		if err != nil {
			return nil, err
		}
		out = append(out, &LineageToken{H: h, ID: id, Amount: new(big.Int).Set(outs[i].Amount), Owners: outs[i].Owners})
	}
	return out, nil
}

// Return appends the return burn of the whole token to t's current owner.
func (b *LineageBuilder) Return(t *LineageToken, recipient [20]byte, amount *big.Int) {
	b.D.F.AppendBurn(t.H, t.Owners[len(t.Owners)-1], recipient, amount)
}

// Envelope certifies every leaf of t's lineage in one seal at irTime and returns the envelope, the verified lineage and the
// certificate. t must end in its return burn.
func (b *LineageBuilder) Envelope(t *LineageToken, irTime uint64) (*Envelope, *Lineage, *CertifiedLeaves, error) {
	lin, err := VerifyLineageReturn(b.D.F.Cfg, t.H.Bytes(), ComposedHistory)
	if err != nil {
		return nil, nil, nil, err
	}
	extra := []Leaf{{SID: H([]byte("other-1")), Value: H([]byte("v1"))}, {SID: H([]byte("other-2")), Value: H([]byte("v2"))}}
	cert, err := b.D.Agg.Certify(lin.Leaves, extra, irTime, 100)
	if err != nil {
		return nil, nil, nil, err
	}
	env := &Envelope{PolicyBody: b.D.F.Policy.Bytes(), History: t.H.Bytes(), Anchors: cert.Anchors, LeafProofs: cert.Proofs}
	return env, lin, cert, nil
}

// Chain builds a lineage of the given depth: each split halves the remainder into a part (a) and the rest (b), and the next split
// takes the rest, so the returned token's ancestry is the whole chain. Depth 0 is the root itself.
func (b *LineageBuilder) Chain(n uint64, amount *big.Int, depth int, seed string) (*LineageToken, error) {
	key := func(label string) []*secp256k1.PrivateKey {
		return []*secp256k1.PrivateKey{KeyFromSeed(seed + "-" + label + "-0"), KeyFromSeed(seed + "-" + label + "-1")}
	}
	cur, err := b.Root(n, amount, key("root"))
	if err != nil {
		return nil, err
	}
	rem := new(big.Int).Set(amount)
	for i := 0; i < depth; i++ {
		part := new(big.Int).Div(rem, big.NewInt(2))
		rest := new(big.Int).Sub(rem, part)
		kids, err := b.Split(cur, []SplitOut{
			{Label: fmt.Sprint("a", i), Amount: part, Owners: key(fmt.Sprint("a", i))},
			{Label: fmt.Sprint("b", i), Amount: rest, Owners: key(fmt.Sprint("b", i))},
		}, nil)
		if err != nil {
			return nil, err
		}
		cur, rem = kids[1], rest
	}
	return cur, nil
}

// lineageKeys are the two owners (mint recipient, then one transfer) of the vector token named by seed.
func lineageKeys(seed string) []*secp256k1.PrivateKey {
	return []*secp256k1.PrivateKey{KeyFromSeed(seed + "-0"), KeyFromSeed(seed + "-1")}
}

// rcpt is the EVM recipient of every vector return.
var rcpt = [20]byte{0xAA, 19: 0x01}

// bytes32x33 is 33 copies of b: a dummy predicate parameter for commitment vectors.
func bytes32x33(b byte) []byte {
	out := make([]byte, 33)
	for i := range out {
		out[i] = b
	}
	return out
}

func burnHash(data []byte, to *[32]byte) [32]byte {
	if to != nil {
		return *to
	}
	return H(data)
}

// Real2 is a depth-2 part under real embedded proofs (for the mutation test).
func (b *LineageBuilder) Real2(t interface{ Helper() }) (*LineageToken, error) {
	rb := *b
	rb.Real = true
	return rb.Chain(7, big.NewInt(1<<20), 2, "m")
}

// CorruptedMintUC is a ParentToken hook that replaces the parent mint proof's certificate by one with an out-of-range seal network:
// outside the native/SDK codec intersection, with every transaction byte (and so every signature) untouched.
func CorruptedMintUC(token []byte) []byte {
	t, err := DecodeToken(token)
	if err != nil {
		panic(err)
	}
	uc, err := replaceCertificateItem(t.MintProof.UC, CUint(65536), 0, 6, 0, 1)
	if err != nil {
		panic(err)
	}
	t.MintProof.UC = uc
	return t.Bytes()
}
