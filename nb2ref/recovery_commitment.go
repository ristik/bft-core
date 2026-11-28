package nb2ref

import (
	"encoding/binary"
	"errors"
)

const RecoveryPageBytes = 4096
const RecoveryMaxWindowBytes = 128 << 10

var ErrRecoveryWitness = errors.New("axis B: invalid or missing recovery witness")
var ErrRecoveryState = errors.New("axis B: invalid recovery state")

// RecoveryWindow authenticates whole consecutive pages. The last evidence page
// is short when Length is not a multiple of RecoveryPageBytes.
type RecoveryWindow struct {
	Start uint64
	Data  []byte
	Paths [][][32]byte
}

func recoveryNum(n uint64) []byte { return binary.BigEndian.AppendUint64(nil, n) }

func recoveryLeaf(offset, total uint64, data []byte) [32]byte {
	return HE([]byte{0}, recoveryNum(offset), recoveryNum(total), data)
}

func recoveryNode(left, right [32]byte) [32]byte { return HE([]byte{1}, left[:], right[:]) }

func recoveryDepth(total uint64) int {
	n := (total-1)/RecoveryPageBytes + 1
	depth := 0
	for n > 1 {
		n = (n + 1) / 2
		depth++
	}
	return depth
}

func (w RecoveryWindow) verify(root [32]byte, total uint64) error {
	if total == 0 || w.Start >= total || w.Start%RecoveryPageBytes != 0 ||
		len(w.Data) == 0 || len(w.Data) > RecoveryMaxWindowBytes || uint64(len(w.Data)) > total-w.Start {
		return ErrRecoveryWitness
	}
	if end := w.Start + uint64(len(w.Data)); end < total && end%RecoveryPageBytes != 0 {
		return ErrRecoveryWitness
	}
	n := (len(w.Data)-1)/RecoveryPageBytes + 1
	if n != len(w.Paths) {
		return ErrRecoveryWitness
	}
	for i, path := range w.Paths {
		if len(path) != recoveryDepth(total) {
			return ErrRecoveryWitness
		}
		offset := i * RecoveryPageBytes
		pos := w.Start + uint64(offset)
		index := pos / RecoveryPageBytes
		h := recoveryLeaf(pos, total, w.Data[offset:min(offset+RecoveryPageBytes, len(w.Data))])
		for _, sibling := range path {
			if index&1 == 0 {
				h = recoveryNode(h, sibling)
			} else {
				h = recoveryNode(sibling, h)
			}
			index >>= 1
		}
		if h != root {
			return ErrRecoveryWitness
		}
	}
	return nil
}

// RecoveryEvidence builds the wallet's position tree over the exact NB2 wire.
type RecoveryEvidence struct {
	raw  []byte
	tree [][][32]byte
}

func NewRecoveryEvidence(raw []byte) (*RecoveryEvidence, error) {
	if len(raw) == 0 {
		return nil, ErrRecoveryWitness
	}
	total := uint64(len(raw))
	depth := recoveryDepth(total)
	base := make([][32]byte, 1<<depth)
	for i := range base {
		pos := i * RecoveryPageBytes
		if pos < len(raw) {
			base[i] = recoveryLeaf(uint64(pos), total, raw[pos:min(pos+RecoveryPageBytes, len(raw))])
		}
	}
	e := &RecoveryEvidence{raw: append([]byte(nil), raw...), tree: [][][32]byte{base}}
	for len(base) > 1 {
		next := make([][32]byte, len(base)/2)
		for i := range next {
			next[i] = recoveryNode(base[2*i], base[2*i+1])
		}
		e.tree = append(e.tree, next)
		base = next
	}
	return e, nil
}

func (e *RecoveryEvidence) Root() [32]byte { return e.tree[len(e.tree)-1][0] }
func (e *RecoveryEvidence) Length() uint64 { return uint64(len(e.raw)) }

// Window returns a window that opens [start,end), including its partial pages.
func (e *RecoveryEvidence) Window(start, end uint64) (RecoveryWindow, error) {
	if start >= end || end > e.Length() {
		return RecoveryWindow{}, ErrRecoveryWitness
	}
	first, last := start/RecoveryPageBytes, (end-1)/RecoveryPageBytes
	hi := min((last+1)*RecoveryPageBytes, e.Length())
	lo := first * RecoveryPageBytes
	if hi-lo > RecoveryMaxWindowBytes {
		return RecoveryWindow{}, ErrRecoveryWitness
	}
	w := RecoveryWindow{Start: lo, Data: append([]byte(nil), e.raw[lo:hi]...)}
	for index := first; index <= last; index++ {
		k := index
		var path [][32]byte
		for _, nodes := range e.tree[:len(e.tree)-1] {
			path = append(path, nodes[k^1])
			k >>= 1
		}
		w.Paths = append(w.Paths, path)
	}
	return w, nil
}

var recoveryEmpty = func() (out [257][32]byte) {
	for i := 1; i < len(out); i++ {
		out[i] = recoveryNode(out[i-1], out[i-1])
	}
	return out
}()

// RecoverySeenWitness is a leaf-first sparse proof for an empty source-ID slot.
type RecoverySeenWitness struct {
	Bitmap   [32]byte // bit i (LSB first) names a nondefault sibling at height i
	Siblings [][32]byte
}

func (w RecoverySeenWitness) insert(root, sid [32]byte) ([32]byte, error) {
	var empty [32]byte
	used := HE([]byte{2}, sid[:])
	n := 0
	for i := range 256 {
		sibling := recoveryEmpty[i]
		index, bit := 31-i/8, byte(1<<uint(i%8))
		if w.Bitmap[index]&bit != 0 {
			if n >= len(w.Siblings) || w.Siblings[n] == sibling {
				return [32]byte{}, ErrRecoveryWitness
			}
			sibling = w.Siblings[n]
			n++
		}
		if sid[index]&bit == 0 {
			empty, used = recoveryNode(empty, sibling), recoveryNode(used, sibling)
		} else {
			empty, used = recoveryNode(sibling, empty), recoveryNode(sibling, used)
		}
	}
	if n != len(w.Siblings) {
		return [32]byte{}, ErrRecoveryWitness
	}
	if empty != root {
		return [32]byte{}, ErrRepeatedSID
	}
	return used, nil
}

// RecoverySeen is the wallet's sparse scratch tree. It can be reconstructed
// from the authenticated transcript and exact evidence after a restart.
type RecoverySeen struct{ levels [257]map[[32]byte][32]byte }

func (s *RecoverySeen) Witness(sid [32]byte) RecoverySeenWitness {
	var w RecoverySeenWitness
	for i := range 256 {
		j, bit := 31-i/8, byte(1<<uint(i%8))
		sibling := sid
		sibling[j] ^= bit
		if h, ok := s.levels[i][sibling]; ok {
			w.Bitmap[j] |= bit
			w.Siblings = append(w.Siblings, h)
		}
		sid[j] &^= bit
	}
	return w
}

func (s *RecoverySeen) Insert(sid [32]byte) {
	h := HE([]byte{2}, sid[:])
	for i := range 256 {
		if s.levels[i] == nil {
			s.levels[i] = make(map[[32]byte][32]byte)
		}
		s.levels[i][sid] = h
		j, bit := 31-i/8, byte(1<<uint(i%8))
		siblingKey := sid
		siblingKey[j] ^= bit
		sibling, ok := s.levels[i][siblingKey]
		if !ok {
			sibling = recoveryEmpty[i]
		}
		if sid[j]&bit == 0 {
			h = recoveryNode(h, sibling)
		} else {
			h = recoveryNode(sibling, h)
		}
		sid[j] &^= bit
	}
}
