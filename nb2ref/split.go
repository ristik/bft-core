package nb2ref

import (
	"bytes"
	"math/big"
	"sort"
)

// Split primitives of the lineage relation, unchanged from protocol 6 (docs/design/bridge-split-lineage-spec.md), from
// bridgeprofile/split.go:
//
//	Manifest = tag(39046, [b(root32)])
//	leaf     = H(0x10 || key32 || data32 || u256(v))        // key = child token ID
//	node     = H(0x11 || u8(depth) || hL || u256(sL) || hR || u256(sR))
//	Proof    = [[depth, b(hash32), b(sum)], ...]            // leaf first, strictly decreasing depths, at most 256 steps
//	data     = H(C(b("UNICITY_SPLIT_OUTPUT"), b(parentId), network, b(P), b(salt), b(childId), b(ty), b(exactChildMintData)))
//	SplitJ   = tag(39044, [ParentToken, [Proof]])

const (
	maxSumProofSteps = 256
	sumLeafPrefix    = 0x10
	sumNodePrefix    = 0x11
)

func validAmount(v *big.Int) bool { return v != nil && v.Sign() > 0 && v.BitLen() <= 256 }

func keyBit(key *[32]byte, i uint8) bool { return key[i/8]>>(7-i%8)&1 == 1 }

// SumLeafHash is H(0x10 || key || data || u256(value)).
func SumLeafHash(key, data [32]byte, value *big.Int) ([32]byte, bool) {
	if !validAmount(value) {
		return [32]byte{}, false
	}
	v := u256(value)
	return HU([]byte{sumLeafPrefix}, key[:], data[:], v[:]), true
}

// SumNodeHash is H(0x11 || depth || hL || u256(sL) || hR || u256(sR)) and the checked 256-bit sum.
func SumNodeHash(depth uint8, hl [32]byte, sl *big.Int, hr [32]byte, sr *big.Int) ([32]byte, *big.Int, bool) {
	if !validAmount(sl) || !validAmount(sr) {
		return [32]byte{}, nil, false
	}
	sum := new(big.Int).Add(sl, sr)
	if sum.BitLen() > 256 {
		return [32]byte{}, nil, false
	}
	l, r := u256(sl), u256(sr)
	return HU([]byte{sumNodePrefix, depth}, hl[:], l[:], hr[:], r[:]), sum, true
}

// SumStep is one sibling of a leaf-to-root allocation path.
type SumStep struct {
	Depth uint8
	Hash  [32]byte
	Sum   *big.Int
}

// SumProof is a leaf-first allocation proof.
type SumProof []SumStep

// Bytes is [[depth, b(hash), b(sum)], ...].
func (p SumProof) Bytes() []byte {
	steps := make([][]byte, len(p))
	for i, s := range p {
		steps[i] = CArr(CUint(uint64(s.Depth)), CBytes(s.Hash[:]), CAmount(s.Sum))
	}
	return CArr(steps...)
}

// decodeFlatAllocation bounds the outer step array before the generic scanner
// reserves child storage. Its steps remain ordinary NB2 sum-proof items.
func decodeFlatAllocation(raw []byte) (SumProof, error) {
	s := scanner{b: raw}
	major, count, err := s.head()
	if err != nil {
		return nil, err
	}
	if major != majArray || count > maxSumProofSteps {
		return nil, ErrSplitProofShape
	}
	it, err := scanOne(raw)
	if err != nil {
		return nil, err
	}
	return decodeSumProof(it)
}

// decodeSumProof: any step outside [depth < 256, strictly decreasing, b(32), Amount] is SplitProofShape.
func decodeSumProof(it *item) (SumProof, error) {
	if it.major != majArray || len(it.kids) > maxSumProofSteps {
		return nil, ErrSplitProofShape
	}
	p := make(SumProof, 0, len(it.kids))
	prev := 256
	for i := range it.kids {
		k := &it.kids[i]
		if k.array(3) != nil {
			return nil, ErrSplitProofShape
		}
		d, err := k.kids[0].uintIn(0, 255)
		if err != nil || int(d) >= prev {
			if e := fail(ErrSplitProofShape); e != nil {
				return nil, e
			}
		}
		prev = int(d)
		h, err := k.kids[1].bytesN(32)
		if err != nil {
			return nil, ErrSplitProofShape
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

// Verify folds the leaf to the root and returns the root sum iff the fold equals root.
func (p SumProof) Verify(key, data [32]byte, value *big.Int, root [32]byte) (*big.Int, bool) {
	hash, ok := SumLeafHash(key, data, value)
	if !ok {
		return nil, false
	}
	sum := new(big.Int).Set(value)
	for _, s := range p {
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
		hash, sum = nh, ns
	}
	if hash != root {
		return nil, false
	}
	return sum, true
}

// SplitManifest is tag(39046, [b(root)]); one asset, one root.
type SplitManifest struct{ Root [32]byte }

// Bytes is the exact manifest.
func (m SplitManifest) Bytes() []byte { return CTag(TagSplitManifest, CArr(CBytes(m.Root[:]))) }

// DecodeSplitManifest strictly decodes a split burn's data (SplitManifest).
func DecodeSplitManifest(b []byte) (SplitManifest, error) {
	root, err := scanOne(b)
	if err != nil {
		return SplitManifest{}, ErrSplitManifest
	}
	c, err := root.tagContent(TagSplitManifest)
	if err != nil || c.array(1) != nil {
		return SplitManifest{}, ErrSplitManifest
	}
	r, err := c.kids[0].bytesN(32)
	if err != nil {
		return SplitManifest{}, ErrSplitManifest
	}
	return SplitManifest{Root: [32]byte(r)}, nil
}

// SplitOutputCommitment is the child mint's commitment without its justification.
func SplitOutputCommitment(parentID [32]byte, m *MintTx) [32]byte {
	childID := TokenID(m.Salt, m.Network)
	return HU(CArr(CBytes([]byte(domainSplitOutput)), CBytes(parentID[:]), CUint(uint64(m.Network)), CBytes(m.Recipient.Bytes()),
		CBytes(m.Salt[:]), CBytes(childID[:]), CBytes(m.Type[:]), CBytes(m.Data)))
}

// SplitJustification is a decoded tag(39044, [ParentToken, [Proof]]).
type SplitJustification struct {
	Parent *Token
	Proof  SumProof
}

// SplitJustificationBytes encodes a split reason from the exact parent token bytes and one proof.
func SplitJustificationBytes(parent []byte, proof SumProof) []byte {
	return CTag(TagSplitJustification, CArr(parent, CArr(proof.Bytes())))
}

// DecodeSplitJustification strictly decodes a split reason: arity, the inline parent token (its own wire rules) and exactly
// one allocation proof (SplitJustif, SplitProofCount, SplitProofShape).
func DecodeSplitJustification(j []byte) (*SplitJustification, error) {
	it, err := scanNative(j)
	if err != nil {
		return nil, wrap(ErrSplitJustif, err)
	}
	c, err := it.tagContent(TagSplitJustification)
	if err != nil || c.array(2) != nil || c.kids[0].major != majTag || c.kids[1].major != majArray {
		return nil, ErrSplitJustif
	}
	if len(c.kids[1].kids) != 1 {
		if err := fail(ErrSplitProofCount); err != nil {
			return nil, err
		}
		if len(c.kids[1].kids) == 0 {
			return nil, ErrSplitProofCount
		}
	}
	proof, err := decodeSumProof(&c.kids[1].kids[0])
	if err != nil {
		return nil, err
	}
	parent, err := decodeTokenItem(&c.kids[0], j)
	if err != nil {
		return nil, err
	}
	return &SplitJustification{Parent: parent, Proof: proof}, nil
}

// reasonTag is the tag number at the head of a mint reason, without scanning it.
func reasonTag(j []byte) (uint64, bool) {
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

// SumTree builds a radix sparse Merkle sum tree (the SDK's) for the fixtures.
type SumTree struct{ root *sumNode }

type sumNode struct {
	leaf        bool
	key         [32]byte
	depth       uint8
	left, right *sumNode
	hash        [32]byte
	sum         *big.Int
}

// SumLeaf is one allocation.
type SumLeaf struct {
	Key, Data [32]byte
	Value     *big.Int
}

// BuildSumTree builds the tree of one asset's allocations.
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
		nodes[i] = &sumNode{leaf: true, key: l.Key, hash: h, sum: new(big.Int).Set(l.Value)}
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
		first, differs := keyBit(&nodes[0].key, uint8(depth)), false
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

// Proof is the leaf-first allocation proof of key.
func (t *SumTree) Proof(key [32]byte) (SumProof, bool) {
	var steps SumProof
	n := t.root
	for !n.leaf {
		sib, next := n.right, n.left
		if keyBit(&key, n.depth) {
			sib, next = n.left, n.right
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
