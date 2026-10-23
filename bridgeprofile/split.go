package bridgeprofile

import (
	"bytes"
	"math/big"
	"sort"
)

// Split primitives of the lineage relation (docs/design/bridge-split-lineage-spec.md). Byte formats are the SDK's
// (state-transition-sdk-rust src/payment/{manifest,commitment,justification}.rs and src/rsmst); nothing here is bridge-specific
// except the single-asset restriction.

const (
	TagSplitJustification = 39044 // split mint reason: [burnedSourceToken, [allocationProof]]
	TagSplitManifest      = 39046 // [b(root)] committed by the burn

	// SplitProtoVersion is the byte-contract version that admits lineage; since the cutover it is NativeBridgeProtoVersion. The
	// version 5 composition (BRIDGE_COMPOSE, which refuses every split) stays in this package until the fresh deployment
	// replaces the old precompile.
	SplitProtoVersion = NativeBridgeProtoVersion

	// MaxSumProofSteps is one step per key bit.
	MaxSumProofSteps = 256

	sumLeafPrefix = 0x10
	sumNodePrefix = 0x11
)

// splitOutputDomain is the ASCII domain of the output commitment.
var splitOutputDomain = []byte("UNICITY_SPLIT_OUTPUT")

// validAmount is the protocol amount domain 1 <= v < 2^256.
func validAmount(v *big.Int) bool { return v != nil && v.Sign() > 0 && v.BitLen() <= 256 }

func u256(v *big.Int) (w [32]byte) { v.FillBytes(w[:]); return }

// keyBit is bit i of a 256-bit key, MSB first (the one radix bit order of the SDK).
func keyBit(key *[32]byte, i uint8) bool { return key[i/8]>>(7-i%8)&1 == 1 }

// SumLeafHash is SHA-256(0x10 || key || data || u256(value)).
func SumLeafHash(key, data [32]byte, value *big.Int) ([32]byte, bool) {
	if !validAmount(value) {
		return [32]byte{}, false
	}
	v := u256(value)
	return H(cat([]byte{sumLeafPrefix}, key[:], data[:], v[:])), true
}

// SumNodeHash is SHA-256(0x11 || depth || hL || u256(sumL) || hR || u256(sumR)) and the checked 256-bit sum.
func SumNodeHash(depth uint8, hl [32]byte, sl *big.Int, hr [32]byte, sr *big.Int) ([32]byte, *big.Int, bool) {
	if !validAmount(sl) || !validAmount(sr) {
		return [32]byte{}, nil, false
	}
	sum := new(big.Int).Add(sl, sr)
	if sum.BitLen() > 256 {
		return [32]byte{}, nil, false
	}
	l, r := u256(sl), u256(sr)
	return H(cat([]byte{sumNodePrefix, depth}, hl[:], l[:], hr[:], r[:])), sum, true
}

// SumStep is one sibling entry of a leaf-to-root path: the parent's bifurcation depth, the sibling subtree hash and its positive sum.
type SumStep struct {
	Depth uint8
	Hash  [32]byte
	Sum   *big.Int
}

// SumProof is a leaf-first allocation proof with strictly decreasing depths. The empty proof is the single-leaf tree.
type SumProof []SumStep

// Bytes is the exact CBOR: [[depth, b(hash), b(sum)], ...].
func (p SumProof) Bytes() []byte {
	steps := make([][]byte, len(p))
	for i, s := range p {
		steps[i] = CArr(CUint(uint64(s.Depth)), CBytes(s.Hash[:]), CAmount(s.Sum))
	}
	return CArr(steps...)
}

func decodeSumProof(it *item) (SumProof, error) {
	if it.major != majArray {
		return nil, ErrShape
	}
	if len(it.kids) > MaxSumProofSteps {
		return nil, ErrSplitProofShape
	}
	p := make(SumProof, 0, len(it.kids))
	prev := 256
	for i := range it.kids {
		k := &it.kids[i]
		if !k.isArray(3) {
			return nil, ErrShape
		}
		d, err := k.kids[0].uintMax(255)
		if err != nil {
			return nil, ErrSplitProofShape
		}
		if int(d) >= prev {
			return nil, ErrSplitProofShape
		}
		prev = int(d)
		h, err := k.kids[1].bytesN(32)
		if err != nil {
			return nil, err
		}
		sum, err := k.kids[2].amount()
		if err != nil {
			return nil, ErrSplitProofShape
		}
		st := SumStep{Depth: uint8(d), Sum: sum}
		copy(st.Hash[:], h)
		p = append(p, st)
	}
	return p, nil
}

// Verify reconstructs the root hash from the leaf upward and returns the reconstructed root sum iff it equals root. The caller
// compares that sum with the authenticated source amount: the root hash alone does not conserve value.
func (p SumProof) Verify(key, data [32]byte, value *big.Int, root [32]byte) (*big.Int, bool) {
	if len(p) > MaxSumProofSteps {
		return nil, false
	}
	hash, ok := SumLeafHash(key, data, value)
	if !ok {
		return nil, false
	}
	sum := new(big.Int).Set(value)
	prev := 256
	for _, s := range p {
		if int(s.Depth) >= prev || !validAmount(s.Sum) {
			return nil, false
		}
		var nh [32]byte
		var ns *big.Int
		if keyBit(&key, s.Depth) {
			nh, ns, ok = SumNodeHash(s.Depth, s.Hash, s.Sum, hash, sum)
		} else {
			nh, ns, ok = SumNodeHash(s.Depth, hash, sum, s.Hash, s.Sum)
		}
		if !ok {
			return nil, false
		}
		hash, sum, prev = nh, ns, int(s.Depth)
	}
	if hash != root {
		return nil, false
	}
	return sum, true
}

// SplitManifest is tag(39046,[b(root)]). The bridge admits exactly one asset, so exactly one root.
type SplitManifest struct{ Root [32]byte }

// Bytes is the exact manifest b_M.
func (m SplitManifest) Bytes() []byte { return CTag(TagSplitManifest, CArr(CBytes(m.Root[:]))) }

// ReasonHash is SHA-256(b_M), the burn predicate's params.
func (m SplitManifest) ReasonHash() [32]byte { return H(m.Bytes()) }

// DecodeSplitManifest strictly decodes the burn transfer's data.
func DecodeSplitManifest(b []byte) (SplitManifest, error) {
	root, err := scanOne(b)
	if err != nil {
		return SplitManifest{}, ErrSplitManifest
	}
	c, err := root.tagContent(TagSplitManifest)
	if err != nil || !c.isArray(1) {
		return SplitManifest{}, ErrSplitManifest
	}
	r, err := c.kids[0].bytesN(32)
	if err != nil {
		return SplitManifest{}, ErrSplitManifest
	}
	var m SplitManifest
	copy(m.Root[:], r)
	return m, nil
}

// SplitOutputCommitment is d_j = SHA-256(CBOR([b("UNICITY_SPLIT_OUTPUT"), b(sourceId), network, b(encodedRecipient), b(salt),
// b(childId), b(type), b(exactPaymentBytes)])): the child mint without its justification.
func SplitOutputCommitment(sourceID [32]byte, m *MintTx) [32]byte {
	return splitOutputCommitment(sourceID, m.Network, m.Recipient, m.Salt, DeriveTokenID(m.Salt, m.Network), m.Type, m.Data)
}

func splitOutputCommitment(sourceID [32]byte, network uint16, recipient Predicate, salt, childID, ty [32]byte, data []byte) [32]byte {
	return H(CArr(CBytes(splitOutputDomain), CBytes(sourceID[:]), CUint(uint64(network)), CBytes(recipient.Bytes()),
		CBytes(salt[:]), CBytes(childID[:]), CBytes(ty[:]), CBytes(data)))
}

// SplitJustification is the decoded split mint reason tag(39044,[token,[proof]]): the exact burned source token bytes (an inline
// item, never re-encoded) and one allocation proof (the bridge admits one asset).
type SplitJustification struct {
	Token []byte
	Proof SumProof
	// Items is the CBOR item count of the justification's own scan; nested justifications inside Token are byte strings and are
	// scanned, and charged, when the walk reaches them.
	Items int
}

// SplitJustificationBytes is the exact encoding of a justification from the burned token's bytes and the proof.
func SplitJustificationBytes(token []byte, proof SumProof) []byte {
	return CTag(TagSplitJustification, CArr(token, CArr(proof.Bytes())))
}

// justificationTag is the tag number of a justification without scanning it: the first head must be a tag.
func justificationTag(j []byte) (uint64, bool) {
	if len(j) == 0 {
		return 0, false
	}
	s := scanner{b: j}
	major, arg, err := s.head()
	if err != nil || major != majTag {
		return 0, false
	}
	return arg, true
}

// DecodeSplitJustification strictly decodes a split mint reason. The burned token is validated by DecodeToken by the caller.
func DecodeSplitJustification(j []byte) (*SplitJustification, error) {
	s := scanner{b: j, native: true, maxItems: ComposedHistory.Items}
	it, err := s.item(0)
	if err != nil {
		return nil, ErrSplitJustif
	}
	if s.pos != len(j) {
		return nil, ErrSplitJustif
	}
	c, err := it.tagContent(TagSplitJustification)
	if err != nil || !c.isArray(2) || c.kids[0].major != majTag || c.kids[1].major != majArray {
		return nil, ErrSplitJustif
	}
	// One proof per output asset; the profile admits one asset.
	if len(c.kids[1].kids) != 1 {
		return nil, ErrSplitProofCount
	}
	proof, err := decodeSumProof(&c.kids[1].kids[0])
	if err != nil {
		return nil, err
	}
	return &SplitJustification{Token: c.kids[0].raw(j), Proof: proof, Items: s.tokens}, nil
}

// SumTree is the oracle's builder of a radix sparse Merkle sum tree: the sorted-key, path-compressed tree whose structure and root
// are determined by the key set alone (SDK src/rsmst/build.rs).
type SumTree struct {
	root *sumNode
}

type sumNode struct {
	leaf        bool
	key, data   [32]byte
	value       *big.Int
	depth       uint8
	left, right *sumNode
	hash        [32]byte
	sum         *big.Int
}

// SumLeaf is one allocation: the child token ID, its output commitment and its amount.
type SumLeaf struct {
	Key, Data [32]byte
	Value     *big.Int
}

// BuildSumTree builds the tree of one asset's allocations. Duplicate keys, empty sets, invalid amounts and a 256-bit sum overflow
// are errors.
func BuildSumTree(leaves []SumLeaf) (*SumTree, error) {
	if len(leaves) == 0 {
		return nil, ErrSplitProofShape
	}
	nodes := make([]*sumNode, len(leaves))
	for i, l := range leaves {
		h, ok := SumLeafHash(l.Key, l.Data, l.Value)
		if !ok {
			return nil, ErrSplitProofShape
		}
		nodes[i] = &sumNode{leaf: true, key: l.Key, data: l.Data, value: new(big.Int).Set(l.Value), hash: h, sum: new(big.Int).Set(l.Value)}
	}
	sort.Slice(nodes, func(i, j int) bool { return bytes.Compare(nodes[i].key[:], nodes[j].key[:]) < 0 })
	for i := 1; i < len(nodes); i++ {
		if nodes[i].key == nodes[i-1].key {
			return nil, ErrSplitProofShape
		}
	}
	root, err := buildSumSubtree(nodes, 0)
	if err != nil {
		return nil, err
	}
	return &SumTree{root: root}, nil
}

func buildSumSubtree(nodes []*sumNode, start int) (*sumNode, error) {
	if len(nodes) == 1 {
		return nodes[0], nil
	}
	depth := start
	for ; depth < 256; depth++ {
		first := keyBit(&nodes[0].key, uint8(depth))
		differs := false
		for _, n := range nodes[1:] {
			if keyBit(&n.key, uint8(depth)) != first {
				differs = true
				break
			}
		}
		if differs {
			break
		}
	}
	if depth == 256 {
		return nil, ErrSplitProofShape
	}
	var l, r []*sumNode
	for _, n := range nodes {
		if keyBit(&n.key, uint8(depth)) {
			r = append(r, n)
		} else {
			l = append(l, n)
		}
	}
	ln, err := buildSumSubtree(l, depth+1)
	if err != nil {
		return nil, err
	}
	rn, err := buildSumSubtree(r, depth+1)
	if err != nil {
		return nil, err
	}
	h, s, ok := SumNodeHash(uint8(depth), ln.hash, ln.sum, rn.hash, rn.sum)
	if !ok {
		return nil, ErrSplitProofShape
	}
	return &sumNode{depth: uint8(depth), left: ln, right: rn, hash: h, sum: s}, nil
}

// Root is the manifest root.
func (t *SumTree) Root() [32]byte { return t.root.hash }

// Total is the root sum.
func (t *SumTree) Total() *big.Int { return new(big.Int).Set(t.root.sum) }

// Proof is the leaf-first allocation proof of key, or false when the key is not a leaf.
func (t *SumTree) Proof(key [32]byte) (SumProof, bool) {
	var steps SumProof
	n := t.root
	for !n.leaf {
		var sib, next *sumNode
		if keyBit(&key, n.depth) {
			sib, next = n.left, n.right
		} else {
			sib, next = n.right, n.left
		}
		steps = append(steps, SumStep{Depth: n.depth, Hash: sib.hash, Sum: new(big.Int).Set(sib.sum)})
		n = next
	}
	if n.key != key {
		return nil, false
	}
	for i, j := 0, len(steps)-1; i < j; i, j = i+1, j-1 {
		steps[i], steps[j] = steps[j], steps[i]
	}
	return steps, true
}
