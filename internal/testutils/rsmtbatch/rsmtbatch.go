// Package rsmtbatch builds real aggregator_rsmt_v1 consistency proofs for tests: a populated pre-state tree, and the insertion of a batch of fresh
// leaves with the opcode stream the verifier of rootchain/consensus/zkverifier/rsmt checks. It is a test generator, not the aggregator's prover.
package rsmtbatch

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/bits"
	"slices"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier/rsmt"
)

// preStateTime is the reference time the pre-state's leaves were stored under.
const preStateTime = 1

type leaf struct {
	key   [32]byte
	value []byte // the stored value in the pre-state, the declared transaction hash in a batch
}

// Batch is one shard's pre-state and the leaves it inserts.
type Batch struct {
	pre, fresh []leaf
	preRoot    [32]byte // computed once: a shard's request takes it for every resubmission
	seed       string
	keyBit     int
	generation int // 0 for New's batch, one more for each Next
}

// Stats is what specifies a proof's cost, beyond the count of its batch.
type Stats struct {
	PreLeaves, Inserted, EnvelopeLeaves, Bytes        int
	Opaque, New, Junctions, OpenJunctions, OpenLeaves int
}

// New derives distinct deterministic hash-distributed keys. keyBit fixes the first key bit to keep them in a shard's half of the key space; -1 leaves it free.
func New(seed string, keyBit, preLeaves, inserted int) *Batch {
	b := &Batch{seed: seed, keyBit: keyBit}
	for i := range preLeaves {
		tx := b.derive("pre-tx", i)
		stored := rsmt.LeafValue(tx[:], preStateTime)
		b.pre = append(b.pre, leaf{b.key("pre-key", i), stored[:]})
	}
	b.fresh = b.freshLeaves(inserted)
	slices.SortFunc(b.pre, byKey)
	b.preRoot = root(b.pre)
	return b
}

// Next is the shard's following batch once this one is certified under referenceTime: its leaves join the pre-state with the values the
// verifier stores for them, and as many fresh keys as this batch inserted are derived for the next generation. A shard that certifies a batch
// after each certificate makes a chain of real transitions, each from the root the last one certified.
func (b *Batch) Next(referenceTime uint64) *Batch {
	n := &Batch{seed: b.seed, keyBit: b.keyBit, generation: b.generation + 1, pre: slices.Clone(b.pre)}
	for _, l := range b.fresh {
		stored := rsmt.LeafValue(l.value, referenceTime)
		n.pre = append(n.pre, leaf{l.key, stored[:]})
	}
	slices.SortFunc(n.pre, byKey)
	n.fresh = n.freshLeaves(len(b.fresh))
	n.preRoot = root(n.pre)
	return n
}

func byKey(a, b leaf) int { return bytes.Compare(a.key[:], b.key[:]) }

func (b *Batch) derive(kind string, i int) [32]byte {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(i)) // #nosec G115 i is a leaf index
	return sha256.Sum256(slices.Concat([]byte(b.seed), []byte(kind), n[:]))
}

// key derives a key in the batch's half of the key space.
func (b *Batch) key(kind string, i int) [32]byte {
	k := b.derive(kind, i)
	switch b.keyBit {
	case 0:
		k[0] &= 0x7f
	case 1:
		k[0] |= 0x80
	}
	return k
}

// freshLeaves are the generation's inserted leaves, sorted; generation 0 keeps New's original derivation.
func (b *Batch) freshLeaves(inserted int) []leaf {
	tag := ""
	if b.generation > 0 {
		tag = fmt.Sprintf("-%d", b.generation)
	}
	var out []leaf
	for i := range inserted {
		tx := b.derive("new-tx"+tag, i)
		out = append(out, leaf{b.key("new-key"+tag, i), tx[:]})
	}
	slices.SortFunc(out, byKey)
	return out
}

// firstDiff is the first bit at which two different keys differ.
func firstDiff(a, b [32]byte) int {
	for i := range a {
		if x := a[i] ^ b[i]; x != 0 {
			return i*8 + bits.LeadingZeros8(x)
		}
	}
	panic("rsmtbatch: equal keys")
}

// splitAt is the index of the first leaf whose key has bit depth set, in leaves sorted and sharing the prefix before depth.
func splitAt(leaves []leaf, depth int) int {
	i, _ := slices.BinarySearchFunc(leaves, byte(1), func(l leaf, one byte) int { return int(rsmt.KeyBitAt(l.key, depth)) - int(one) })
	return i
}

func root(leaves []leaf) [32]byte {
	if len(leaves) == 1 {
		return rsmt.HashLeaf(leaves[0].key, leaves[0].value)
	}
	d := firstDiff(leaves[0].key, leaves[len(leaves)-1].key)
	at := splitAt(leaves, d)
	return rsmt.HashNode(root(leaves[:at]), root(leaves[at:]), uint8(d), rsmt.PrefixRegion(leaves[0].key, d)) // #nosec G115 d is below 256
}

// PreRoot is the root of the pre-state.
func (b *Batch) PreRoot() [32]byte { return b.preRoot }

// Envelope is the insertion of the batch under the reference time, its new root and its shape.
func (b *Batch) Envelope(referenceTime uint64) ([]byte, [32]byte, Stats, error) {
	var proof []byte
	var s Stats
	s.PreLeaves, s.Inserted = len(b.pre), len(b.fresh)
	var emit func(pre, fresh []leaf, opaqueAllowed bool)
	preserved := func(pre []leaf, opaqueAllowed bool) {
		switch {
		case opaqueAllowed:
			h := root(pre)
			proof = append(append(proof, 0x00), h[:]...)
			s.Opaque++
		case len(pre) == 1:
			proof = append(append(proof, 0x04), pre[0].key[:]...)
			proof = binary.BigEndian.AppendUint16(proof, uint16(len(pre[0].value))) // #nosec G115 a stored value is 32 bytes
			proof = append(proof, pre[0].value...)
			s.OpenLeaves++
		default:
			d := firstDiff(pre[0].key, pre[len(pre)-1].key)
			at := splitAt(pre, d)
			region, l, r := rsmt.PrefixRegion(pre[0].key, d), root(pre[:at]), root(pre[at:])
			proof = append(proof, 0x03, uint8(d)) // #nosec G115 d is below 256
			proof = append(append(append(proof, region[:]...), l[:]...), r[:]...)
			s.OpenJunctions++
		}
	}
	emit = func(pre, fresh []leaf, opaqueAllowed bool) {
		if len(fresh) == 0 {
			preserved(pre, opaqueAllowed)
			return
		}
		if len(pre) == 0 && len(fresh) == 1 {
			proof = append(proof, 0x01)
			s.New++
			return
		}
		lo, hi := fresh[0].key, fresh[len(fresh)-1].key
		if len(pre) > 0 {
			if bytes.Compare(pre[0].key[:], lo[:]) < 0 {
				lo = pre[0].key
			}
			if bytes.Compare(pre[len(pre)-1].key[:], hi[:]) > 0 {
				hi = pre[len(pre)-1].key
			}
		}
		d := firstDiff(lo, hi)
		preAt, freshAt := splitAt(pre, d), splitAt(fresh, d)
		existed := preAt > 0 && preAt < len(pre) // both sides held leaves: this junction is in the pre-state
		emit(pre[:preAt], fresh[:freshAt], existed)
		emit(pre[preAt:], fresh[freshAt:], existed)
		proof = append(proof, 0x02, uint8(d)) // #nosec G115 d is below 256
		s.Junctions++
	}
	emit(b.pre, b.fresh, false)

	declared := make([]rsmt.Leaf, len(b.fresh))
	merged := slices.Clone(b.pre)
	for i, l := range b.fresh {
		declared[i] = rsmt.Leaf{Key: l.key, Value: l.value}
		stored := rsmt.LeafValue(l.value, referenceTime)
		merged = append(merged, leaf{l.key, stored[:]})
	}
	slices.SortFunc(merged, byKey)
	env, err := rsmt.EncodeEnvelope(declared, proof)
	if err != nil {
		return nil, [32]byte{}, s, fmt.Errorf("encoding the envelope: %w", err)
	}
	s.EnvelopeLeaves, s.Bytes = len(declared), len(env)
	return env, root(merged), s, nil
}
