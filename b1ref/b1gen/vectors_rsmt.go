package b1gen

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
	"sort"
)

// ---- an independent radix sparse Merkle tree (RSMT v6a semantics) ----------

func leafHash(key [32]byte, value []byte) [32]byte { return sum([]byte{0}, key[:], value) }

func keyBit(key [32]byte, d int) int { return int(key[d/8]>>uint(7-d%8)) & 1 }

func prefix(key [32]byte, d int) [32]byte {
	var r [32]byte
	copy(r[:d/8], key[:d/8])
	if d%8 != 0 {
		r[d/8] = key[d/8] & (0xff << uint(8-d%8))
	}
	return r
}

func nodeHash(d int, region [32]byte, l, r [32]byte) [32]byte {
	return sum([]byte{1, byte(d)}, region[:], l[:], r[:])
}

type rnode struct {
	hash   [32]byte
	key    [32]byte // leaf key; for junctions the smallest key below
	depth  int
	leaf   bool
	lo, hi *rnode
}

type leafKV struct {
	key   [32]byte
	value []byte
}

func rBuild(ls []leafKV) *rnode {
	if len(ls) == 1 {
		return &rnode{hash: leafHash(ls[0].key, ls[0].value), key: ls[0].key, leaf: true}
	}
	first, last := ls[0].key, ls[len(ls)-1].key
	d := 0
	for keyBit(first, d) == keyBit(last, d) {
		d++
	}
	split := sort.Search(len(ls), func(i int) bool { return keyBit(ls[i].key, d) == 1 })
	lo, hi := rBuild(ls[:split]), rBuild(ls[split:])
	return &rnode{hash: nodeHash(d, prefix(first, d), lo.hash, hi.hash), key: first, depth: d, lo: lo, hi: hi}
}

// proof is the inclusion path of key: junction depths and root-to-leaf siblings.
func (n *rnode) proof(key [32]byte) (bitmap [32]byte, sibs [][32]byte) {
	for cur := n; !cur.leaf; {
		bitmap[cur.depth/8] |= 0x80 >> uint(cur.depth%8)
		if keyBit(key, cur.depth) == 1 {
			sibs = append(sibs, cur.lo.hash)
			cur = cur.hi
		} else {
			sibs = append(sibs, cur.hi.hash)
			cur = cur.lo
		}
	}
	return
}

func (g *gen) rsmt(seed string) {
	const fam = "Paths/encoding"
	r := newDRBG(seed, "rsmt")
	randKey := func() (k [32]byte) { copy(k[:], r.bytes32()); return }
	mk := func(keys []leafKV) *rnode {
		sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i].key[:], keys[j].key[:]) < 0 })
		return rBuild(keys)
	}
	req := func(root, key [32]byte, value []byte, bitmap [32]byte, sibs [][32]byte) []byte {
		var vl [4]byte
		binary.BigEndian.PutUint32(vl[:], uint32(len(value)))
		out := cat([]byte{1, 0, 0, 1}, root[:], key[:], vl[:], value, bitmap[:])
		for _, s := range sibs {
			out = append(out, s[:]...)
		}
		return out
	}
	gas := func(b []byte, bitmap [32]byte) uint64 {
		pop := 0
		for _, x := range bitmap {
			pop += bits.OnesCount8(x)
		}
		return 2000 + 16*uint64(len(b)) + 250*uint64(1+pop)
	}
	add := func(id, desc, want string, b []byte, bitmap [32]byte, in map[string]string) {
		valid := want == ""
		g.m.Vectors = append(g.m.Vectors, Vector{ID: id, Family: fam, Op: opMember, Description: desc, Request: hx(b), Intermediate: in,
			Expected: Expected{Status: "ok", Valid: &valid, Sentinel: want, Output: hx(outputWords(valid)), Gas: gas(b, bitmap)}})
	}
	bad := func(id, desc, want string, b []byte) {
		g.m.Vectors = append(g.m.Vectors, Vector{ID: id, Family: fam, Op: opMember, Description: desc, Request: hx(b),
			Expected: Expected{Status: "error", Sentinel: want}})
	}

	// zero-depth single leaf: the empty bitmap.
	k0 := randKey()
	t := mk([]leafKV{{k0, []byte("only")}})
	bm, sibs := t.proof(k0)
	add("rsmt.single-leaf.ok", "single leaf tree: bitmap 0, no siblings", "", req(t.hash, k0, []byte("only"), bm, sibs), bm, map[string]string{"root": hex32(t.hash)})
	t = mk([]leafKV{{k0, nil}})
	bm, sibs = t.proof(k0)
	add("rsmt.empty-value.ok", "empty value", "", req(t.hash, k0, nil, bm, sibs), bm, nil)
	big := bytes.Repeat([]byte{0xab}, 4096)
	t = mk([]leafKV{{k0, big}})
	bm, sibs = t.proof(k0)
	add("rsmt.value-4096.ok", "value of 4096 bytes", "", req(t.hash, k0, big, bm, sibs), bm, nil)

	// a small tree.
	var kvs []leafKV
	for i := 0; i < 9; i++ {
		kvs = append(kvs, leafKV{randKey(), []byte(fmt.Sprintf("value-%d", i))})
	}
	t = mk(append([]leafKV{}, kvs...))
	target := kvs[4]
	bm, sibs = t.proof(target.key)
	good := req(t.hash, target.key, target.value, bm, sibs)
	add("rsmt.small.ok", "nine-leaf tree, member proof", "", good, bm, map[string]string{"root": hex32(t.hash)})
	for i, kv := range kvs {
		if i%4 != 0 {
			continue
		}
		b2, s2 := t.proof(kv.key)
		add(fmt.Sprintf("rsmt.small.leaf%d.ok", i), "member proof of another leaf", "", req(t.hash, kv.key, kv.value, b2, s2), b2, nil)
	}

	// perturbations of the small proof.
	k2 := target.key
	k2[31] ^= 1
	add("rsmt.neg.key", "key changed", "ErrRSMTFold", req(t.hash, k2, target.value, bm, sibs), bm, nil)
	add("rsmt.neg.value", "value changed", "ErrRSMTFold", req(t.hash, target.key, []byte("other"), bm, sibs), bm, nil)
	add("rsmt.neg.root", "root changed", "ErrRSMTFold", req(flip32(t.hash), target.key, target.value, bm, sibs), bm, nil)
	add("rsmt.neg.zero-root", "all-zero root", "ErrRSMTZeroRoot", req([32]byte{}, target.key, target.value, bm, sibs), bm, nil)
	if len(sibs) >= 2 {
		sw := append([][32]byte{}, sibs...)
		sw[0], sw[1] = sw[1], sw[0]
		add("rsmt.neg.sibling-order", "two siblings swapped", "ErrRSMTFold", req(t.hash, target.key, target.value, bm, sw), bm, nil)
	}
	fl := append([][32]byte{}, sibs...)
	fl[len(fl)-1] = flip32(fl[len(fl)-1])
	add("rsmt.neg.sibling-value", "last sibling flipped", "ErrRSMTFold", req(t.hash, target.key, target.value, bm, fl), bm, nil)
	// move the first set bitmap bit to an unset depth: same popcount.
	mv := bm
	for d := 0; d < 256; d++ {
		if bm[d/8]&(0x80>>uint(d%8)) != 0 {
			mv[d/8] &^= 0x80 >> uint(d%8)
			e := 255
			for bm[e/8]&(0x80>>uint(e%8)) != 0 {
				e--
			}
			mv[e/8] |= 0x80 >> uint(e%8)
			break
		}
	}
	add("rsmt.neg.bitmap-bit", "one bitmap bit moved to another depth", "ErrRSMTFold", req(t.hash, target.key, target.value, mv, sibs), mv, nil)
	// hash rule: root computed without the region commitment.
	add("rsmt.neg.no-region", "tree hashed without the region field", "ErrRSMTFold", req(noRegionRoot(target, bm, sibs), target.key, target.value, bm, sibs), bm, nil)
	bad("rsmt.neg.truncated-sibling", "one sibling missing", "ErrRSMTLength", good[:len(good)-32])
	bad("rsmt.neg.extra-sibling", "one sibling too many", "ErrRSMTLength", append(append([]byte{}, good...), make([]byte, 32)...))
	bad("rsmt.neg.partial-sibling", "sibling cut to 31 bytes", "ErrRSMTLength", good[:len(good)-1])
	bad("rsmt.neg.version", "unknown version", "ErrVersion", append([]byte{2}, good[1:]...))
	bad("rsmt.neg.flags", "nonzero flags", "ErrFlags", append([]byte{1, 1}, good[2:]...))
	bad("rsmt.neg.count-2", "count 2", "ErrCount", append([]byte{1, 0, 0, 2}, good[4:]...))
	bad("rsmt.neg.short-header", "input shorter than the header", "ErrTruncated", good[:3])
	bad("rsmt.neg.truncated-value", "input ends inside the value", "ErrTruncated", good[:4+32+32+4+2])
	vh := append([]byte{}, good...)
	copy(vh[68:72], []byte{0xff, 0xff, 0xff, 0xff})
	bad("rsmt.neg.value-length-u32max", "value length 2^32-1", "ErrValueTooLarge", vh)
	t1 := mk([]leafKV{{k0, make([]byte, 4097)}})
	b1, s1 := t1.proof(k0)
	bad("rsmt.neg.value-4097", "value of 4097 bytes", "ErrValueTooLarge", req(t1.hash, k0, make([]byte, 4097), b1, s1))
	bad("rsmt.neg.too-large", "input of 12393 bytes", "ErrInputTooLarge", make([]byte, MaxRSMT+1))

	// depth 255 and 256: a target whose path has a junction at every depth.
	for _, depth := range []int{255, 256} {
		tk := randKey()
		deep := []leafKV{{tk, []byte("deep")}}
		for d := 0; d < depth; d++ {
			o := prefix(tk, d)
			if keyBit(tk, d) == 0 {
				o[d/8] |= 0x80 >> uint(d%8)
			}
			// o shares d bits with tk, differs at bit d; fill the rest from the stream.
			rest := randKey()
			for b := d + 1; b < 256; b++ {
				if keyBit(rest, b) == 1 {
					o[b/8] |= 0x80 >> uint(b%8)
				}
			}
			deep = append(deep, leafKV{o, []byte{byte(d)}})
		}
		td := mk(deep)
		bmd, sd := td.proof(tk)
		add(fmt.Sprintf("rsmt.depth-%d.ok", depth), fmt.Sprintf("%d junctions on the path, %d siblings", depth, depth), "", req(td.hash, tk, []byte("deep"), bmd, sd), bmd, map[string]string{"root": hex32(td.hash)})
		if depth == 256 {
			add("rsmt.depth-256.neg.sibling", "deepest sibling flipped", "ErrRSMTFold", req(td.hash, tk, []byte("deep"), bmd, append(append([][32]byte{}, sd[:255]...), flip32(sd[255]))), bmd, nil)
		}
	}
}

// noRegionRoot folds the proof with the region commitment left out of each
// node hash, the perturbation of the node hash rule.
func noRegionRoot(kv leafKV, bitmap [32]byte, sibs [][32]byte) [32]byte {
	h := leafHash(kv.key, kv.value)
	idx := len(sibs)
	for d := 255; d >= 0; d-- {
		if bitmap[d/8]&(0x80>>uint(d%8)) == 0 {
			continue
		}
		idx--
		l, r := h, sibs[idx]
		if keyBit(kv.key, d) == 1 {
			l, r = sibs[idx], h
		}
		h = sum([]byte{1, byte(d)}, l[:], r[:])
	}
	return h
}

// MaxRSMT is the RSMT input bound, 4+32+32+4+4096+32+256*32.
const MaxRSMT = 12392
