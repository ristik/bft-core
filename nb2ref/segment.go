package nb2ref

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"sort"
)

// Segments, the sorted circular-gap tree, gap proofs and the archive chain (section 10).

// Bucket is bucket(eta) = eta >> (256 - log2 B), the top log2 B bits.
func Bucket(eta [32]byte, b uint64) uint64 {
	lb := uint(bits.TrailingZeros64(b))
	return uint64(eta[0]) >> (8 - lb) // log2 B <= 5 for every admitted B
}

func less(a, b [32]byte) bool { return bytes.Compare(a[:], b[:]) < 0 }

// GapLeaf is H_E(0x00 || l || u).
func GapLeaf(l, u [32]byte) [32]byte { return HE([]byte{0x00}, l[:], u[:]) }

// GapNode is H_E(0x01 || left || right).
func GapNode(l, r [32]byte) [32]byte { return HE([]byte{0x01}, l[:], r[:]) }

// GapTree is the complete binary tree over the leaves of K strictly sorted identifiers.
type GapTree struct {
	Z      [][32]byte   // z_0 < ... < z_{K-1}
	levels [][][32]byte // levels[0] are the leaves
}

// BuildGapTree requires len(z) a power of two >= 2 and z strictly increasing.
func BuildGapTree(z [][32]byte) (*GapTree, bool) {
	k := len(z)
	if k < 2 || bits.OnesCount(uint(k)) != 1 {
		return nil, false
	}
	for i := 1; i < k; i++ {
		if !less(z[i-1], z[i]) {
			return nil, false
		}
	}
	leaves := make([][32]byte, k)
	for i := range z {
		leaves[i] = GapLeaf(z[i], z[(i+1)%k])
	}
	t := &GapTree{Z: append([][32]byte(nil), z...), levels: [][][32]byte{leaves}}
	for row := leaves; len(row) > 1; {
		next := make([][32]byte, len(row)/2)
		for i := range next {
			next[i] = GapNode(row[2*i], row[2*i+1])
		}
		t.levels = append(t.levels, next)
		row = next
	}
	return t, true
}

// Root is M_j.
func (t *GapTree) Root() [32]byte { return t.levels[len(t.levels)-1][0] }

// GapProofLen is 65 + 32h.
func GapProofLen(k uint64) int { return 65 + 32*bits.TrailingZeros64(k) }

// Prove returns the gap proof of eta, or false when eta is one of the identifiers (it was paid in this segment).
func (t *GapTree) Prove(eta [32]byte) ([]byte, bool) {
	k := len(t.Z)
	i := sort.Search(k, func(i int) bool { return !less(t.Z[i], eta) }) // first z_i >= eta
	if i < k && t.Z[i] == eta {
		return nil, false
	}
	// eta lies in gap i-1 (z_{i-1} < eta < z_i), or in the exterior gap K-1 when i == 0 or i == K.
	g := i - 1
	if i == 0 || i == k {
		g = k - 1
	}
	out := []byte{byte(g)}
	out = append(out, t.Z[g][:]...)
	out = append(out, t.Z[(g+1)%k][:]...)
	pos := g
	for _, row := range t.levels[:len(t.levels)-1] {
		s := row[pos^1]
		out = append(out, s[:]...)
		pos /= 2
	}
	return out, true
}

// GapRoot derives M from a gap proof for eta (section 10.2), or reports the proof invalid: wrong length, index >= K, the gap
// inequalities, or the exterior-gap rule.
func GapRoot(k uint64, eta [32]byte, proof []byte) ([32]byte, bool) {
	h := bits.TrailingZeros64(k)
	if len(proof) != 65+32*h {
		return [32]byte{}, false
	}
	i := uint64(proof[0])
	l, u := [32]byte(proof[1:33]), [32]byte(proof[33:65])
	switch {
	case i >= k:
		return [32]byte{}, false
	case i < k-1:
		if !(less(l, u) && less(l, eta) && less(eta, u)) {
			return [32]byte{}, false
		}
	default:
		if !(less(u, l) && (less(l, eta) || less(eta, u))) {
			return [32]byte{}, false
		}
	}
	x := GapLeaf(l, u)
	for s := 0; s < h; s++ {
		sib := [32]byte(proof[65+32*s : 97+32*s])
		if i>>uint(s)&1 == 0 {
			x = GapNode(x, sib)
		} else {
			x = GapNode(sib, x)
		}
	}
	return x, true
}

// GenesisHead is H_0 = H_E(ARCHIVE_GENESIS || D || u16(K)).
func GenesisHead(d [32]byte, k uint64) [32]byte {
	var kk [2]byte
	binary.BigEndian.PutUint16(kk[:], uint16(k))
	return HE(TagArchiveGenesis[:], d[:], kk[:])
}

// NextHead is H_{j+1} = H_E(ARCHIVE_STEP || D || u64(j) || H_j || M_j).
func NextHead(d [32]byte, j uint64, hj, mj [32]byte) [32]byte {
	var jj [8]byte
	binary.BigEndian.PutUint64(jj[:], j)
	return HE(TagArchiveStep[:], d[:], jj[:], hj[:], mj[:])
}

// FoldHistory is redeem step 3: from startHead through j = a .. a+P-1, each M_j derived from proof j-a for eta. It returns
// the folded head, or BadGapProof(position).
func FoldHistory(d [32]byte, k uint64, eta [32]byte, a uint64, startHead [32]byte, proofs [][]byte) ([32]byte, error) {
	x := startHead
	for p, pr := range proofs {
		m, ok := GapRoot(k, eta, pr)
		if !ok {
			if err := fail(ErrBadGapProof); err != nil {
				return x, &PositionError{Rule: ErrBadGapProof, Position: uint64(p)}
			}
		}
		x = NextHead(d, a+uint64(p), x, m)
	}
	return x, nil
}

// PositionError is BadGapProof(uint256 position).
type PositionError struct {
	Rule     *Rule
	Position uint64
}

func (e *PositionError) Error() string { return e.Rule.Error() }
func (e *PositionError) Unwrap() error { return e.Rule }

// EncodeHistory is the redeem history: empty for P = 0, else startHead || proof_0 || ... || proof_{P-1}.
func EncodeHistory(startHead [32]byte, proofs [][]byte) []byte {
	if len(proofs) == 0 {
		return []byte{}
	}
	out := append([]byte{}, startHead[:]...)
	for _, p := range proofs {
		out = append(out, p...)
	}
	return out
}

// SegmentSealedData is the 128 + 32K bytes of SegmentSealed(c, H_c, H_{c+1}, z_0 || ... || z_{K-1}).
func SegmentSealedData(before, after [32]byte, z [][32]byte) []byte {
	off, ln := u256u(0x60), u256u(uint64(32*len(z)))
	out := cat(before[:], after[:], off[:], ln[:])
	for _, x := range z {
		out = append(out, x[:]...)
	}
	return out
}

// Segment is one verified SegmentSealed log.
type Segment struct {
	Index         uint64
	Before, After [32]byte
	Z             [][32]byte
	Root          [32]byte
}

// CheckSegmentLog is the wallet's check of one SegmentSealed log of segment j (section 12.3): exact length 128 + 32K, the
// standard offset and length words, strictly sorted identifiers, and H_{j+1} == NextHead(D, j, headBefore, M_j) == headAfter,
// with headBefore the expected previous head. Every failure is SegmentLog.
func CheckSegmentLog(d [32]byte, k uint64, j uint64, expectBefore [32]byte, data []byte) (*Segment, error) {
	if uint64(len(data)) != 128+32*k {
		return nil, detail(ErrSegmentLog, "length %d", len(data))
	}
	if [32]byte(data[64:96]) != u256u(0x60) || [32]byte(data[96:128]) != u256u(32*k) {
		return nil, detail(ErrSegmentLog, "offset or length word")
	}
	s := &Segment{Index: j, Before: [32]byte(data[0:32]), After: [32]byte(data[32:64])}
	for i := uint64(0); i < k; i++ {
		s.Z = append(s.Z, [32]byte(data[128+32*i:160+32*i]))
	}
	tree, ok := BuildGapTree(s.Z)
	if !ok {
		return nil, detail(ErrSegmentLog, "identifiers not strictly sorted")
	}
	s.Root = tree.Root()
	if s.Before != expectBefore || NextHead(d, j, s.Before, s.Root) != s.After {
		return nil, detail(ErrSegmentLog, "chain link")
	}
	return s, nil
}

// BuildHistory is the wallet's proof builder (section 12.3): one gap proof of eta per segment a .. e-1 of the verified logs
// segs[a..e-1] (segs indexed by segment), and the start head H_a. It reports paid=true when eta is in a segment.
func BuildHistory(segs []*Segment, eta [32]byte, a, e uint64, ha [32]byte) (history []byte, paid bool) {
	var proofs [][]byte
	for j := a; j < e; j++ {
		tree, _ := BuildGapTree(segs[j].Z)
		p, ok := tree.Prove(eta)
		if !ok {
			return nil, true
		}
		proofs = append(proofs, p)
	}
	return EncodeHistory(ha, proofs), false
}
