package b1gen

import (
	"bytes"
	"encoding/binary"
)

// The generator's own reading of a structurally valid CERT_BATCH_V2 request: claim framing, and in each certificate only what the
// grouping needs (shard siblings, Unicity steps, the seal's bytes, epoch and signature count). It trusts its own construction
// and does no validation; a request it cannot walk panics, since every grouped vector is built well formed.

type cur struct {
	b   []byte
	pos int
}

func (c *cur) head() (major byte, arg uint64) {
	ib := c.b[c.pos]
	c.pos++
	major, ai := ib>>5, ib&31
	switch {
	case ai < 24:
		return major, uint64(ai)
	case ai == 24:
		arg = uint64(c.b[c.pos])
		c.pos++
	case ai == 25:
		arg = uint64(binary.BigEndian.Uint16(c.b[c.pos:]))
		c.pos += 2
	case ai == 26:
		arg = uint64(binary.BigEndian.Uint32(c.b[c.pos:]))
		c.pos += 4
	case ai == 27:
		arg = binary.BigEndian.Uint64(c.b[c.pos:])
		c.pos += 8
	default:
		panic("b1gen: unsupported CBOR head")
	}
	return
}

// skip passes one complete item.
func (c *cur) skip() {
	if c.b[c.pos] == 0xf6 {
		c.pos++
		return
	}
	major, n := c.head()
	switch major {
	case 2, 3:
		c.pos += int(n)
	case 4:
		for i := uint64(0); i < n; i++ {
			c.skip()
		}
	case 5:
		for i := uint64(0); i < 2*n; i++ {
			c.skip()
		}
	case 6:
		c.skip()
	}
}

// count reads a null-or-array/map head and returns its cardinality, leaving the cursor on the first element.
func (c *cur) count() uint64 {
	if c.b[c.pos] == 0xf6 {
		c.pos++
		return 0
	}
	_, n := c.head()
	return n
}

type occ struct {
	claim, seal []byte
	epoch       uint64
	sigs, steps uint64
}

// occurrences walks the request.
func occurrences(req []byte) []occ {
	k := int(binary.BigEndian.Uint16(req[2:4]))
	pos := 4
	var out []occ
	for i := 0; i < k; i++ {
		start := pos
		sl := int(binary.BigEndian.Uint16(req[pos+4:]))
		pos += 6 + sl + 96
		ul := int(binary.BigEndian.Uint32(req[pos:]))
		pos += 4
		uc := req[pos : pos+ul]
		pos += ul
		o := occ{claim: req[start:pos]}
		c := &cur{b: uc}
		c.head() // UC tag
		c.head() // array(7)
		c.skip() // version
		c.skip() // IR
		c.skip() // TRHash
		c.skip() // shard conf hash
		c.head() // shard tree certificate tag
		c.head() // array(3)
		c.skip() // version
		c.skip() // shard
		n := c.count()
		o.steps += n
		for j := uint64(0); j < n; j++ {
			c.skip()
		}
		c.head() // unicity tree certificate tag
		c.head() // array(3)
		c.skip() // version
		c.skip() // partition
		n = c.count()
		o.steps += n
		for j := uint64(0); j < n; j++ {
			c.skip()
		}
		sealStart := c.pos
		c.head() // seal tag
		c.head() // array(8)
		c.skip() // version
		c.skip() // network
		c.skip() // round
		_, o.epoch = c.head()
		c.skip() // timestamp
		c.skip() // previous hash
		c.skip() // hash
		o.sigs = c.count()
		c.pos = sealStart
		c.skip()
		o.seal = uc[sealStart:c.pos]
		out = append(out, o)
	}
	return out
}

// grouping is the canonical first-use grouping of a request (contract section 3).
func grouping(req []byte) (Grouping, []occ) {
	os := occurrences(req)
	g := Grouping{C: uint64(len(req)), K: uint64(len(os))}
	for i, o := range os {
		newE, newS, newA := true, true, true
		for _, p := range os[:i] {
			newE = newE && p.epoch != o.epoch
			newS = newS && !bytes.Equal(p.seal, o.seal)
			newA = newA && !bytes.Equal(p.claim, o.claim)
		}
		if newE {
			g.E++
		}
		if newS {
			g.S++
			g.Q += o.sigs
		}
		if newA {
			g.A++
			g.P += o.steps
		}
	}
	return g, os
}

// batchGas is G_batch (contract section 5), written out independently of the oracle.
func batchGas(g Grouping) uint64 {
	return 60000 + 16*g.C + 500*g.K*(g.K-1) + 100*11 + (1000*16+100*(11+8*16))*g.E + 6000*g.Q + 2000*g.A + 250*g.P
}
