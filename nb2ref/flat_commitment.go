package nb2ref

import (
	"bytes"
	"math/bits"
)

type FlatPage struct {
	Index    uint64
	Data     []byte
	Siblings [][32]byte
}

func flatPageCount(n uint64) uint64 { return (n-1)/FlatPageBytes + 1 }
func flatPageDepth(n uint64) int    { return bits.Len64(flatPageCount(n) - 1) }

func flatPageLen(n, i uint64) int {
	// Index must already be in range.
	return int(min(n-i*FlatPageBytes, FlatPageBytes))
}

func flatPageLeaf(n, i uint64, data []byte) [32]byte {
	return FlatHash("PAGE", flatU64(n), flatU64(i), flatU16(uint16(len(data))), data)
}

func flatPageNode(left, right [32]byte) [32]byte { return FlatHash("PAGE_NODE", left[:], right[:]) }

var flatPagePadding = func() (out [53][32]byte) {
	out[0] = FlatHash("PAD")
	for i := 1; i < len(out); i++ {
		out[i] = flatPageNode(out[i-1], out[i-1])
	}
	return
}()

func (p FlatPage) verifies(h FlatHeader) bool {
	count := flatPageCount(h.Length)
	if p.Index >= count || len(p.Data) != flatPageLen(h.Length, p.Index) ||
		len(p.Siblings) != flatPageDepth(h.Length) {
		return false
	}
	node := flatPageLeaf(h.Length, p.Index, p.Data)
	for height, sibling := range p.Siblings {
		index := p.Index >> height
		if ((index^1)<<height) >= count && sibling != flatPagePadding[height] {
			return false
		}
		if index&1 == 0 {
			node = flatPageNode(node, sibling)
		} else {
			node = flatPageNode(sibling, node)
		}
	}
	return node == h.Root
}

// FlatEvidence builds wallet-side position openings. Verifiers do not allocate
// this tree: they only see the authenticated pages of the current packet.
type FlatEvidence struct {
	raw  []byte
	tree [][][32]byte
}

func NewFlatEvidence(raw []byte) (*FlatEvidence, error) {
	if len(raw) < flatPreludeBytes {
		return nil, ErrEvidenceShape
	}
	n := uint64(len(raw))
	base := make([][32]byte, uint64(1)<<flatPageDepth(n))
	for i := range base {
		if uint64(i) >= flatPageCount(n) {
			base[i] = flatPagePadding[0]
			continue
		}
		offset := i * FlatPageBytes
		base[i] = flatPageLeaf(n, uint64(i), raw[offset:offset+flatPageLen(n, uint64(i))])
	}
	tree := [][][32]byte{base}
	for len(base) > 1 {
		next := make([][32]byte, len(base)/2)
		for i := range next {
			next[i] = flatPageNode(base[i*2], base[i*2+1])
		}
		tree = append(tree, next)
		base = next
	}
	return &FlatEvidence{bytes.Clone(raw), tree}, nil
}

func (e *FlatEvidence) Header() FlatHeader {
	return FlatHeader{uint64(len(e.raw)), e.tree[len(e.tree)-1][0]}
}

func (e *FlatEvidence) Page(index uint64) (FlatPage, error) {
	n := uint64(len(e.raw))
	if index >= flatPageCount(n) {
		return FlatPage{}, ErrFlatPage
	}
	start := index * FlatPageBytes
	p := FlatPage{Index: index, Data: bytes.Clone(e.raw[start : start+uint64(flatPageLen(n, index))])}
	for _, layer := range e.tree[:len(e.tree)-1] {
		p.Siblings = append(p.Siblings, layer[index^1])
		index >>= 1
	}
	return p, nil
}

type flatPageReader struct {
	byIndex map[uint64][]byte
	used    map[uint64]bool
	length  uint64
}

func (r *flatPageReader) read(pos uint64, n int) ([]byte, error) {
	if pos > r.length || uint64(n) > r.length-pos {
		return nil, ErrTruncated
	}
	result := make([]byte, n)
	for done := 0; done < n; {
		index := pos / FlatPageBytes
		page, ok := r.byIndex[index]
		if !ok {
			return nil, ErrFlatPage
		}
		r.used[index] = true
		copied := copy(result[done:], page[pos%FlatPageBytes:])
		pos += uint64(copied)
		done += copied
	}
	return result, nil
}

type FlatSparseOpening struct {
	Bitmap   [32]byte
	Siblings [][32]byte
}

func (p FlatSparseOpening) appendTo(out []byte) []byte {
	out = append(out, p.Bitmap[:]...)
	for _, s := range p.Siblings {
		out = append(out, s[:]...)
	}
	return out
}

func (p FlatSparseOpening) shape() bool {
	count := 0
	for _, b := range p.Bitmap {
		count += bits.OnesCount8(b)
	}
	return count == len(p.Siblings)
}

func (r *flatReader) sparse() (p FlatSparseOpening) {
	p.Bitmap = r.hash()
	for _, b := range p.Bitmap {
		for range bits.OnesCount8(b) {
			p.Siblings = append(p.Siblings, r.hash())
		}
	}
	return p
}

type flatSparseDomain uint8

const (
	flatSIDTree flatSparseDomain = iota
	flatClaimTree
)

func (d flatSparseDomain) node(l, r [32]byte) [32]byte {
	label := "SID_NODE"
	if d == flatClaimTree {
		label = "CLAIM_NODE"
	}
	return FlatHash(label, l[:], r[:])
}

var flatSparseDefaults = func() (defaults [2][257][32]byte) {
	for d := range defaults {
		for i := 1; i < len(defaults[d]); i++ {
			x := defaults[d][i-1]
			defaults[d][i] = flatSparseDomain(d).node(x, x)
		}
	}
	return
}()

func flatBit(k [32]byte, height int) bool {
	return k[31-height/8]&(byte(1)<<uint(height%8)) != 0
}

func (d flatSparseDomain) fold(height int, key, node, sibling [32]byte) [32]byte {
	if flatBit(key, height) {
		return d.node(sibling, node)
	}
	return d.node(node, sibling)
}

func (d flatSparseDomain) update(root, key, old, next [32]byte, p FlatSparseOpening) ([32]byte, error) {
	if !p.shape() {
		return [32]byte{}, ErrFlatStep
	}
	n := 0
	for i := range 256 {
		sibling := flatSparseDefaults[d][i]
		if flatBit(p.Bitmap, i) {
			if p.Siblings[n] == sibling {
				return [32]byte{}, ErrFlatStep
			}
			sibling = p.Siblings[n]
			n++
		}
		old = d.fold(i, key, old, sibling)
		next = d.fold(i, key, next, sibling)
	}
	if old != root {
		return [32]byte{}, ErrFlatStep
	}
	return next, nil
}

func flatSIDLeaf(sid [32]byte) [32]byte { return FlatHash("SID", sid[:]) }

func flatClaimLeaf(key, value [32]byte) [32]byte {
	return FlatHash("CLAIM", key[:], value[:])
}

// flatSparseTree is fixture/wallet scratch; only the verifier update above is
// needed to verify a packet. A node key has all bits below its height zeroed.
type flatSparseTree struct {
	domain flatSparseDomain
	nodes  [257]map[[32]byte][32]byte
}

func (t *flatSparseTree) lookup(height int, key [32]byte) [32]byte {
	if h, ok := t.nodes[height][key]; ok {
		return h
	}
	return flatSparseDefaults[t.domain][height]
}

func (t *flatSparseTree) opening(key [32]byte) (p FlatSparseOpening) {
	for height := range 256 {
		i, bit := 31-height/8, byte(1)<<uint(height%8)
		key[i] ^= bit
		if h := t.lookup(height, key); h != flatSparseDefaults[t.domain][height] {
			p.Bitmap[i] |= bit
			p.Siblings = append(p.Siblings, h)
		}
		key[i] &^= bit
	}
	return p
}

func (t *flatSparseTree) insert(key, h [32]byte) {
	for height := range 257 {
		if t.nodes[height] == nil {
			t.nodes[height] = make(map[[32]byte][32]byte)
		}
		t.nodes[height][key] = h
		if height < 256 {
			i, bit := 31-height/8, byte(1)<<uint(height%8)
			sibling := key
			sibling[i] ^= bit
			h = t.domain.fold(height, key, h, t.lookup(height, sibling))
			key[i] &^= bit
		}
	}
}
