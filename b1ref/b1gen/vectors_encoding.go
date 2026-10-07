package b1gen

import (
	"bytes"
	"fmt"
)

func nested(n int) []byte { return append(bytes.Repeat([]byte{0x81}, n), 0xf6) }

// withReplaced swaps the unique occurrence of old in the claim's UC for repl.
func withReplaced(c claimSpec, old, repl []byte) claimSpec {
	if bytes.Count(c.uc, old) != 1 {
		panic("b1gen: replaced bytes are not unique in the certificate")
	}
	c.uc = bytes.Replace(c.uc, old, repl, 1)
	return c
}

// customUC builds a signed, internally consistent certificate for a single
// partition with arbitrary shard siblings and unicity path steps, so path
// bounds can be exercised at their limits.
func customUC(f *fixture, part uint32, shard string, sibs [][32]byte, steps []pathStep, signers []validator) ucSpec {
	r := newDRBG(f.seed, fmt.Sprintf("custom/%d/%s/%d/%d", part, shard, len(sibs), len(steps)))
	ir := irSpec{round: 5, epoch: 1, prev: r.bytes32(), state: r.bytes32(), summary: r.bytes32()[:8], timestamp: genesisTime + 1000, block: r.bytes32(), fees: 3, et: nil}
	u := ucSpec{part: part, shard: shard, ir: ir, shardSibs: sibs, steps: steps}
	copy(u.tr[:], r.bytes32())
	copy(u.conf[:], r.bytes32())
	root := shardFold(shardLeaf(ir, u.tr, u.conf), shard, sibs, false)
	h := sum(cBytes([]byte{1}), cBytes([]byte{byte(part >> 24), byte(part >> 16), byte(part >> 8), byte(part)}), cBytes(sumHash(cBytes(root[:]))))
	pk := []byte{byte(part >> 24), byte(part >> 16), byte(part >> 8), byte(part)}
	for _, s := range steps {
		sk := []byte{byte(s.key >> 24), byte(s.key >> 16), byte(s.key >> 8), byte(s.key)}
		if string(pk) > string(sk) {
			h = sum(cBytes([]byte{0}), cBytes(sk), cBytes(s.hash[:]), cBytes(h[:]))
		} else {
			h = sum(cBytes([]byte{0}), cBytes(sk), cBytes(h[:]), cBytes(s.hash[:]))
		}
	}
	u.seal = sealSpec{network: f.network, round: f.round, epoch: f.epoch, timestamp: genesisTime + 6000, prev: r.hash(), root: h}
	u.seal.signWith(signers, false)
	return u
}

func sumHash(b []byte) []byte { h := sum(b); return h[:] }

func randSibs(seed string, n int) [][32]byte {
	r := newDRBG(seed, "sibs")
	out := make([][32]byte, n)
	for i := range out {
		copy(out[i][:], r.bytes32())
	}
	return out
}

func randSteps(seed string, n int, part uint32) []pathStep {
	r := newDRBG(seed, "steps")
	out := make([]pathStep, n)
	for i := range out {
		out[i].key = part + uint32(i*7) + 1
		copy(out[i].hash[:], r.bytes32())
	}
	return out
}

func (g *gen) encoding(seed string) {
	const fam = "Paths/encoding"
	f := newFixture(seed, 4)
	pre := f.pre()
	q := f.vals[:3]
	cs := f.build("a", f.round, q, false)
	u := cs.get(1, "")
	u2 := cs.get(2, "0")
	c := claimOf(u)
	req := func(cl ...claimSpec) []byte { return newRequest(cl...).wire() }
	malformed := func(id, desc, want string, b []byte) { g.bad(id, fam, opUC, desc, b, &pre, want) }
	mal := func(id, desc, want string, cl claimSpec) { malformed(id, desc, want, req(cl)) }

	// positive limits of the path bounds.
	for _, depth := range []int{255, 256} {
		shard := string(bytes.Repeat([]byte{'1'}, depth))
		x := customUC(f, 9, shard, randSibs(seed, depth), nil, q)
		g.ok(fmt.Sprintf("paths.shard-depth-%d.ok", depth), fam, opUC, fmt.Sprintf("shard of %d bits with %d siblings", depth, depth),
			req(claimOf(x)), pre, shapeOf(x), "", &x.seal, nil)
	}
	x := customUC(f, 9, "", nil, randSteps(seed, 32, 9), q)
	g.ok("paths.unicity-steps-32.ok", fam, opUC, "unicity path of 32 steps", req(claimOf(x)), pre, shapeOf(x), "", &x.seal, nil)

	// bit-string and header level.
	cc := c
	cc.shardWire = []byte{0x00}
	mal("enc.shard.no-terminator", "shard bit string without an end marker", "ErrShardEncoding", cc)
	cc = c
	cc.shardWire = []byte{}
	mal("enc.shard.empty", "zero-length shard encoding", "ErrShardEncoding", cc)
	cc = c
	cc.shardWire = append(bytes.Repeat([]byte{0}, 32), 0x40)
	mal("enc.shard.depth-257", "shard of 257 bits", "ErrShardTooDeep", cc)
	cc = c
	cc.shardWire = append(bytes.Repeat([]byte{0}, 33), 0x80)
	mal("enc.shard.34-bytes", "shard encoding of 34 bytes", "ErrShardTooDeep", cc)

	r := newRequest(c)
	r.version = 2
	malformed("enc.header.version", "unknown version", "ErrVersion", r.wire())
	r = newRequest(c)
	r.flags = 1
	malformed("enc.header.flags", "nonzero flags", "ErrFlags", r.wire())
	zero := uint16(0)
	r = newRequest(c)
	r.count = &zero
	malformed("enc.header.count-zero", "count 0", "ErrCount", r.wire())
	malformed("enc.header.uc-count-2", "UC_V1 with two claims", "ErrCount", req(c, claimOf(u2)))
	malformed("enc.header.truncated", "input shorter than the header", "ErrTruncated", []byte{1, 0, 0})
	r = newRequest(c)
	r.trailing = []byte{0}
	malformed("enc.trailing", "one trailing byte", "ErrTrailingBytes", r.wire())
	full := req(c)
	malformed("enc.truncated", "request cut inside the certificate", "ErrTruncated", full[:len(full)-5])

	// CBOR level.
	w := withReplaced(c, []byte{0xd9, 0x98, 0x59, 0x87, 0x01}, []byte{0xd9, 0x98, 0x59, 0x87, 0x18, 0x01})
	mal("enc.cbor.nonminimal-int", "UC version 1 encoded as 0x18 0x01", "ErrNonCanonical", w)
	w = withReplaced(c, []byte{0xd9, 0x98, 0x59}, []byte{0xd9, 0x98, 0x5e})
	mal("enc.cbor.wrong-tag", "UC wrapped in tag 39006", "ErrShape", w)
	w = withReplaced(c, cBytes(u.tr[:]), []byte{0xfb, 0, 0, 0, 0, 0, 0, 0, 0})
	mal("enc.cbor.float", "TRHash replaced by a float", "ErrForbiddenCBOR", w)
	w = withReplaced(c, cBytes(u.tr[:]), append(append([]byte{0x5f}, cBytes(u.tr[:])...), 0xff))
	mal("enc.cbor.indefinite", "TRHash as an indefinite-length byte string", "ErrForbiddenCBOR", w)
	et := cBytes(u.ir.et)
	w = withReplaced(c, et, nested(13))
	mal("enc.cbor.depth-17", "nesting of 17 containers", "ErrDepth", w)
	w = withReplaced(c, et, nested(12))
	mal("enc.cbor.depth-16", "nesting of 16 containers passes the depth bound (rejected by shape instead)", "ErrShape", w)
	bs := cat([]byte{0x5b}, bytes.Repeat([]byte{0xff}, 8))
	w = withReplaced(c, et, bs)
	mal("enc.cbor.huge-bytes-length", "byte string claiming 2^64-1 bytes", "ErrTruncated", w)
	ar := cat([]byte{0x9b}, bytes.Repeat([]byte{0xff}, 8))
	w = withReplaced(c, et, ar)
	mal("enc.cbor.huge-array-count", "array claiming 2^64-1 elements", "ErrTruncated", w)
	badKey := u
	badKey.sealBytes = u.seal.fields(cTextMapRaw([]entry{{"\xff\xfe", cBytes(u.seal.sigs[0].val)}}))
	mal("enc.cbor.invalid-utf8", "signer ID that is not UTF-8", "ErrInvalidUTF8", claimOf(badKey))
	unsorted := u
	unsorted.sealBytes = u.seal.fields(cTextMapRaw([]entry{
		{u.seal.sigs[1].key, cBytes(u.seal.sigs[1].val)}, {u.seal.sigs[0].key, cBytes(u.seal.sigs[0].val)}}))
	mal("enc.cbor.map-order", "signature map keys out of canonical order", "ErrNonCanonical", claimOf(unsorted))
	for _, ir := range []struct {
		id, desc string
		mod      func(*ucSpec)
		want     string
	}{
		{"enc.ir.summary-257", "summaryValue of 257 bytes", func(x *ucSpec) { x.ir.summary = bytes.Repeat([]byte{1}, 257) }, "ErrSummaryTooLong"},
	} {
		y := u
		ir.mod(&y)
		mal(ir.id, ir.desc, ir.want, claimOf(y))
	}

	// path perturbations on a two-shard certificate.
	y := u2
	y.shardSibs = nil
	g.ok("paths.shard.truncated-sibling", fam, opUC, "sibling count mismatch is false", req(claimOf(y)), pre, shapeOf(y), "ErrNativeInvalid", nil, nil)
	y = u2
	y.shardSibs = append(append([][32]byte{}, u2.shardSibs...), u2.shardSibs[0])
	g.ok("paths.shard.extra-sibling", fam, opUC, "sibling count mismatch is false", req(claimOf(y)), pre, shapeOf(y), "ErrNativeInvalid", nil, nil)
	y = u2
	y.shardSibs = [][32]byte{flip32(u2.shardSibs[0])}
	g.ok("paths.shard.sibling-value", fam, opUC, "shard sibling hash flipped", req(claimOf(y)), pre, shapeOf(y), "ErrTreeRoot", nil, nil)
	y = u
	y.steps = append([]pathStep{}, u2.steps...)
	g.ok("paths.unicity.wrong-path", fam, opUC, "unicity path of another partition used for partition 1", req(claimOf(y)), pre, shapeOf(y), "ErrTreeRoot", nil, nil)
	y = u2
	y.steps = append([]pathStep{}, u2.steps...)
	y.steps[0].hash = flip32(y.steps[0].hash)
	g.ok("paths.unicity.step-value", fam, opUC, "unicity path step hash flipped", req(claimOf(y)), pre, shapeOf(y), "ErrTreeRoot", nil, nil)

	// bounds at limit+1.
	y = customUC(f, 9, string(bytes.Repeat([]byte{'0'}, 256)), randSibs(seed, 257), nil, q)
	mal("bound.shard-siblings-257", "257 shard siblings", "ErrTooManySiblings", claimOf(y))
	y = customUC(f, 9, "", nil, randSteps(seed, 33, 9), q)
	mal("bound.unicity-steps-33", "33 unicity path steps", "ErrTooManySteps", claimOf(y))
	y = u
	var many []entry
	for i := 0; i < 65; i++ {
		many = append(many, entry{fmt.Sprintf("s%02d", i), cBytes(bytes.Repeat([]byte{byte(i + 1)}, 64))})
	}
	y.sealBytes = u.seal.fields(cTextMap(many))
	mal("bound.signatures-65", "65 signatures in the seal", "ErrTooManySigs", claimOf(y))
	y = u
	y.sealBytes = u.seal.fields(cTextMap([]entry{{string(bytes.Repeat([]byte{'a'}, 129)), cBytes(u.seal.sigs[0].val)}}))
	mal("bound.seal-node-id-129", "signer ID of 129 bytes in the seal", "ErrNodeIDTooLong", claimOf(y))
	padded := newRequest(c)
	padded.trailing = make([]byte, MaxCall+1-len(req(c)))
	malformed("bound.call-262145", "call of 262145 bytes", "ErrInputTooLarge", padded.wire())
	cc = c
	cc.uc = append(append([]byte{}, c.uc...), make([]byte, MaxUC+1-len(c.uc))...)
	mal("bound.uc-24577", "certificate of 24577 bytes", "ErrUCTooLarge", cc)

}

// Limits mirrored from the design (section 4); the generator keeps its own copy.
const (
	MaxCall = 262144
	MaxUC   = 24576
)
