package s1gen

import (
	"fmt"
	"strings"
)

// views covers the trust view: B1 v2 classification (ordering, emptiness,
// duplicates, weights and curve points are false) and the structural bounds.
func (g *gen) views() {
	w := g.w
	e := w.sign(w.nc("v1", 150, 0x11))
	ctxFor := func(v viewSpec) *ContextJSON {
		return &ContextJSON{Network: uint16(w.net), OpenEpoch: 2, Epochs: []EpochJSON{w.entry(v, w.boundary, 0, 2, w.genesis)}}
	}
	v2 := w.view2()
	const fam = "Trust view"
	no := func(id, desc, want string, v viewSpec) { g.no(id, fam, desc, ctxFor(v), v, want, e) }

	no("view.empty", "no members (the carried commitment matches): false", "ErrViewEmpty", v2.with(func(v *viewSpec) { v.members = nil }))
	no("view.unsorted", "members not sorted by node ID bytes: false", "ErrViewOrder", v2.with(func(v *viewSpec) { v.members[0], v.members[1] = v.members[1], v.members[0] }))
	no("view.duplicate-id", "repeated node ID with another key", "ErrViewDuplicate", v2.with(func(v *viewSpec) { v.members[1].id = "v1"; v.members[1].key = w.vals["v2"].pub }))
	no("view.duplicate-key", "repeated key under another ID", "ErrViewDuplicate", v2.with(func(v *viewSpec) { v.members[1].key = v.members[0].key }))
	no("view.duplicate-wins-over-order", "a repeated ID that also breaks the ordering is false for duplication", "ErrViewDuplicate", v2.with(func(v *viewSpec) {
		v.members = append(v.members, memberSpec{id: "v1", key: w.vals["x1"].pub, weight: 1})
	}))
	no("view.weight-two", "non-unit weight", "ErrWeightProfile", v2.with(func(v *viewSpec) { v.members[2].weight = 2 }))
	no("view.weight-zero", "zero weight", "ErrWeightProfile", v2.with(func(v *viewSpec) { v.members[2].weight = 0 }))
	invalid := invalidPoint()
	no("view.invalid-point.other-member", "a bstr33 that is not a curve point (02 followed by 32 ff) for a non-author member: false", "ErrViewKey", v2.with(func(v *viewSpec) { v.members[3].key = invalid }))
	no("view.invalid-point.author", "an invalid point for the author", "ErrViewKey", v2.with(func(v *viewSpec) { v.members[0].key = invalid }))
	no("view.key-prefix-04", "a 33-byte key with an uncompressed prefix", "ErrViewKey", v2.with(func(v *viewSpec) { v.members[3].key = append([]byte{0x04}, v.members[3].key[1:]...) }))

	// Structural view errors are malformed, in every case with a matching commitment.
	raw := func(version, network, epoch, kind uint64, body []byte, members []byte) []byte {
		return cArr(cUint(version), cUint(network), cUint(epoch), cUint(kind), body, members)
	}
	good := func(id, key []byte, weight []byte) []byte { return cArr(cText(string(id)), key, weight) }
	m1 := cArr(good([]byte("v1"), cBytes(w.vals["v1"].pub), cUint(1)))
	body := cBytes(w.body[2][:])
	bad := func(id, desc, want string, view []byte) {
		g.bad(id, fam, desc, ctxFor(v2), frame(view, e.enc()), want)
	}
	bad("view.malformed.arity-5", "five-element view", "ErrShape", cArr(cUint(1), cUint(w.net), cUint(2), cUint(2), body))
	bad("view.malformed.version-2", "unsupported view version", "ErrVersion", raw(2, w.net, 2, 2, body, m1))
	bad("view.malformed.version-text", "view version is not an integer", "ErrShape", cArr(cText("1"), cUint(w.net), cUint(2), cUint(2), body, m1))
	bad("view.malformed.network-65536", "network does not fit uint16", "ErrShape", raw(1, 65536, 2, 2, body, m1))
	bad("view.malformed.kind-0", "unknown source kind 0", "ErrViewKind", raw(1, w.net, 2, 0, body, m1))
	bad("view.malformed.kind-3", "unknown source kind 3", "ErrViewKind", raw(1, w.net, 2, 3, body, m1))
	bad("view.malformed.body-31", "body identity of 31 bytes", "ErrShape", raw(1, w.net, 2, 2, cBytes(w.body[2][:31]), m1))
	bad("view.malformed.members-null", "null members", "ErrShape", raw(1, w.net, 2, 2, body, cNull))
	bad("view.malformed.members-map", "members as a map", "ErrShape", raw(1, w.net, 2, 2, body, []byte{0xa0}))
	bad("view.malformed.member-arity-2", "member with two elements", "ErrShape", raw(1, w.net, 2, 2, body, cArr(cArr(cText("v1"), cBytes(w.vals["v1"].pub)))))
	bad("view.malformed.member-null", "null member", "ErrShape", raw(1, w.net, 2, 2, body, cArr(cNull)))
	bad("view.malformed.id-bytes", "node ID as a byte string", "ErrShape", raw(1, w.net, 2, 2, body, cArr(cArr(cBytes([]byte("v1")), cBytes(w.vals["v1"].pub), cUint(1)))))
	bad("view.malformed.key-32", "key of 32 bytes", "ErrShape", raw(1, w.net, 2, 2, body, cArr(good([]byte("v1"), cBytes(w.vals["v1"].pub[1:]), cUint(1)))))
	bad("view.malformed.key-34", "key of 34 bytes", "ErrShape", raw(1, w.net, 2, 2, body, cArr(good([]byte("v1"), cBytes(append(append([]byte{}, w.vals["v1"].pub...), 0)), cUint(1)))))
	bad("view.malformed.key-text", "key as a text string", "ErrShape", raw(1, w.net, 2, 2, body, cArr(good([]byte("v1"), cText(strings.Repeat("a", 33)), cUint(1)))))
	bad("view.malformed.weight-text", "weight as text", "ErrShape", raw(1, w.net, 2, 2, body, cArr(good([]byte("v1"), cBytes(w.vals["v1"].pub), cText("1")))))
	long := make([]byte, 129)
	for i := range long {
		long[i] = 'a'
	}
	bad("view.malformed.node-id-129", "node ID of 129 bytes", "ErrNodeIDTooLong", raw(1, w.net, 2, 2, body, cArr(good(long, cBytes(w.vals["v1"].pub), cUint(1)))))
	many := make([][]byte, 65)
	for i := range many {
		many[i] = good([]byte(fmt.Sprintf("m%02d", i)), cBytes(w.vals["v1"].pub), cUint(1))
	}
	bad("view.malformed.members-65", "65 members", "ErrTooManyMembers", raw(1, w.net, 2, 2, body, cArr(many...)))
	bad("view.malformed.map-duplicate-key", "a map with a repeated key where the view is expected", "ErrDuplicateMapKey", []byte{0xa2, 0x01, 0x01, 0x01, 0x02})
	bad("view.malformed.map-unsorted", "a map with unsorted keys where the view is expected", "ErrNonCanonical", []byte{0xa2, 0x02, 0x01, 0x01, 0x02})
	bad("view.malformed.map", "a map where the view array is expected", "ErrShape", []byte{0xa1, 0x01, 0x01})
	bad("view.malformed.trailing", "trailing byte after the view value", "ErrTrailingBytes", append(v2.cbor(), 0x00))
	bad("view.malformed.empty", "zero-length view", "ErrTruncated", []byte{})
	bad("view.malformed.nonshortest-version", "version 1 in a non-shortest head", "ErrNonCanonical", append([]byte{0x86, 0x18, 0x01}, v2.cbor()[2:]...))

	// Bounds that are reachable and valid.
	idMax := make([]byte, 128)
	for i := range idMax {
		idMax[i] = 'b'
	}
	vMax := v2.with(func(v *viewSpec) {
		v.members = []memberSpec{{id: string(idMax), key: w.vals["v1"].pub, weight: 1}, {id: "v1x", key: w.vals["v2"].pub, weight: 1}}
	})
	eMax := w.signWith(w.nc(string(idMax), 150, 0x11), w.vals["v1"])
	g.yes("view.node-id-128.ok", fam, "node ID of exactly 128 bytes", ctxFor(vMax), vMax, eMax)
}
