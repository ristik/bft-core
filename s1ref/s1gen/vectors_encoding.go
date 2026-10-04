package s1gen

import "encoding/binary"

// encoding covers the header, lengths, CBOR admission and the evidence shapes.
// Every malformed case uses an otherwise valid request so only the named
// defect can fail.
func (g *gen) encoding() {
	w := g.w
	v2 := w.view2()
	c := w.ctx()
	const fam = "Encoding"
	e := w.sign(w.nc("v1", 150, 0x11))
	good := frame(v2.cbor(), e.enc())
	l := w.sign(w.leg("v1", 50, 0x31))
	v1 := w.view1()

	// Header and framing.
	patch := func(f func([]byte) []byte) []byte { return f(append([]byte{}, good...)) }
	g.bad("enc.header.version-0", fam, "version 0", c, patch(func(b []byte) []byte { b[0] = 0; return b }), "ErrVersion")
	g.bad("enc.header.version-2", fam, "version 2", c, patch(func(b []byte) []byte { b[0] = 2; return b }), "ErrVersion")
	g.bad("enc.header.flags-1", fam, "non-zero flags", c, patch(func(b []byte) []byte { b[1] = 1; return b }), "ErrFlags")
	g.bad("enc.header.count-0", fam, "count 0", c, patch(func(b []byte) []byte { b[3] = 0; return b }), "ErrCount")
	g.bad("enc.header.count-3", fam, "count 3", c, patch(func(b []byte) []byte { b[3] = 3; return b }), "ErrCount")
	g.bad("enc.header.count-65535", fam, "count 0xffff", c, patch(func(b []byte) []byte { b[2], b[3] = 0xff, 0xff; return b }), "ErrCount")
	g.bad("enc.header.count-256", fam, "count 256: the high byte is part of the count", c, patch(func(b []byte) []byte { b[2], b[3] = 1, 0; return b }), "ErrCount")
	g.bad("enc.header.truncated-3", fam, "three bytes", c, good[:3], "ErrTruncated")
	g.bad("enc.header.only", fam, "header without a view length", c, good[:4], "ErrTruncated")
	g.bad("enc.header.empty", fam, "empty input", c, []byte{}, "ErrTruncated")
	g.bad("enc.trailing", fam, "one byte after the last evidence", c, append(append([]byte{}, good...), 0), "ErrTrailingBytes")
	g.bad("enc.count-2-one-evidence", fam, "count 2 with a single evidence frame", c, patch(func(b []byte) []byte { b[3] = 2; return b }), "ErrTruncated")
	g.bad("enc.count-1-two-evidence", fam, "count 1 with a second evidence frame", c, func() []byte { b := frame(v2.cbor(), e.enc(), e.enc()); b[3] = 1; return b }(), "ErrTrailingBytes")

	u32 := func(n uint32) []byte { return binary.BigEndian.AppendUint32(nil, n) }
	hdr := []byte{1, 0, 0, 1}
	g.bad("enc.view-length.max-u32", fam, "view length 0xffffffff: checked, never allocated", c, append(append([]byte{}, hdr...), u32(0xffffffff)...), "ErrViewTooLarge")
	g.bad("enc.view-length.16385", fam, "view length 16385", c, append(append([]byte{}, hdr...), u32(16385)...), "ErrViewTooLarge")
	g.bad("enc.view-length.beyond-input", fam, "view length within the bound but beyond the input", c, append(append([]byte{}, hdr...), u32(16384)...), "ErrTruncated")
	pad16384 := append(v2.cbor(), make([]byte, 16384-len(v2.cbor()))...)
	g.bad("enc.view-length.16384-padded", fam, "a 16384-byte view is admitted to the scanner: trailing bytes inside the view", c, frame(pad16384, e.enc()), "ErrTrailingBytes")
	tail := append(append(append([]byte{}, hdr...), u32(uint32(len(v2.cbor())))...), v2.cbor()...)
	g.bad("enc.evidence-length.max-u32", fam, "evidence length 0xffffffff", c, append(append([]byte{}, tail...), u32(0xffffffff)...), "ErrEvidenceTooLarge")
	g.bad("enc.evidence-length.1025", fam, "evidence length 1025", c, append(append([]byte{}, tail...), u32(1025)...), "ErrEvidenceTooLarge")
	g.bad("enc.evidence-length.beyond-input", fam, "evidence length within the bound but beyond the input", c, append(append([]byte{}, tail...), u32(1024)...), "ErrTruncated")
	pad1024 := append(e.enc(), make([]byte, 1024-len(e.enc()))...)
	g.bad("enc.evidence-length.1024-padded", fam, "a 1024-byte evidence is admitted to the scanner: trailing bytes inside it", c, frame(v2.cbor(), pad1024), "ErrTrailingBytes")
	g.bad("enc.input-too-large", fam, "18449 bytes: over the complete-input bound before any parsing", c, make([]byte, 18449), "ErrInputTooLarge")
	g.bad("enc.input-18448-garbage", fam, "18448 bytes are within the bound; the header decides", c, make([]byte, 18448), "ErrVersion")

	// Evidence CBOR admission, edited in place so every other byte stays valid.
	rawEv := func(b []byte) []byte { return frame(v2.cbor(), b) }
	enc := e.enc()
	bad := func(id, desc, want string, evb []byte) { g.bad(id, fam, desc, c, rawEv(evb), want) }
	// replace the first occurrence of a marker, rebuilding with explicit items instead where simpler
	items := func(scheme []byte, author []byte, vi []byte, seal []byte, vs []byte, ss []byte) []byte {
		return cat([]byte{0x86}, scheme, author, vi, seal, vs, ss)
	}
	vi2, seal, vs := e.domainVoteInfo(), e.sealBytes(), cBytes(e.voteSig)
	sc2, au := cUint(2), cText("v1")
	bad("enc.cbor.evidence-trailing", "one byte after the evidence value", "ErrTrailingBytes", append(append([]byte{}, enc...), 0xf6))
	bad("enc.cbor.evidence-arity-5", "five-element evidence", "ErrShape", cat([]byte{0x85}, sc2, au, vi2, seal, vs))
	bad("enc.cbor.evidence-arity-7", "seven-element evidence", "ErrShape", cat([]byte{0x87}, sc2, au, vi2, seal, vs, cNull, cNull))
	bad("enc.cbor.evidence-null", "null evidence", "ErrShape", cNull)
	bad("enc.cbor.indefinite-array", "indefinite-length evidence array", "ErrForbiddenCBOR", cat([]byte{0x9f}, sc2, au, vi2, seal, vs, cNull, []byte{0xff}))
	bad("enc.cbor.nonshortest-scheme", "scheme 2 in a one-byte head", "ErrNonCanonical", items([]byte{0x18, 0x02}, au, vi2, seal, vs, cNull))
	bad("enc.cbor.nonshortest-round", "round in a non-shortest head", "ErrNonCanonical", items(sc2, au, cArr(cUint(2), []byte{0x19, 0x00, 0x96}, cUint(e.parent), cBytes(e.exec[:])), seal, vs, cNull))
	bad("enc.cbor.float", "a float where an integer is expected", "ErrForbiddenCBOR", items(sc2, au, cArr(cUint(2), []byte{0xf9, 0x3c, 0x00}, cUint(e.parent), cBytes(e.exec[:])), seal, vs, cNull))
	bad("enc.cbor.bool", "a boolean where null is expected", "ErrForbiddenCBOR", items(sc2, au, e.domainVoteInfo(), seal, vs, []byte{0xf5}))
	bad("enc.cbor.undefined", "undefined where null is expected", "ErrForbiddenCBOR", items(sc2, au, e.domainVoteInfo(), seal, vs, []byte{0xf7}))
	bad("enc.cbor.invalid-utf8", "author with invalid UTF-8", "ErrInvalidUTF8", items(sc2, []byte{0x62, 0xc3, 0x28}, vi2, seal, vs, cNull))
	bad("enc.cbor.map-duplicate-key", "a map with a repeated key where the author is expected", "ErrDuplicateMapKey", items(sc2, []byte{0xa2, 0x01, 0x01, 0x01, 0x02}, vi2, seal, vs, cNull))
	bad("enc.cbor.map-unsorted", "a map with unsorted keys where the author is expected", "ErrNonCanonical", items(sc2, []byte{0xa2, 0x02, 0x01, 0x01, 0x02}, vi2, seal, vs, cNull))
	bad("enc.cbor.tag-on-author", "a tag on the author", "ErrShape", items(sc2, cTag(40000, au), vi2, seal, vs, cNull))
	deep := cNull
	for i := 0; i < 16; i++ {
		deep = cArr(deep)
	}
	bad("enc.cbor.depth-17", "nesting beyond 16 levels inside the evidence", "ErrDepth", items(sc2, au, deep, seal, vs, cNull))
	deep15 := cNull
	for i := 0; i < 14; i++ {
		deep15 = cArr(deep15)
	}
	bad("enc.cbor.depth-16-shape", "nesting of 16 levels including the evidence is admitted by the scanner and then fails on shape", "ErrShape", items(sc2, au, deep15, seal, vs, cNull))

	// Scheme, author, signatures.
	bad("enc.scheme-0", "scheme 0", "ErrScheme", items(cUint(0), au, vi2, seal, vs, cNull))
	bad("enc.scheme-3", "scheme 3", "ErrScheme", items(cUint(3), au, vi2, seal, vs, cNull))
	bad("enc.scheme-text", "scheme as text", "ErrShape", items(cText("2"), au, vi2, seal, vs, cNull))
	bad("enc.author-bytes", "author as a byte string", "ErrShape", items(sc2, cBytes([]byte("v1")), vi2, seal, vs, cNull))
	long := make([]byte, 129)
	for i := range long {
		long[i] = 'a'
	}
	bad("enc.author-129", "author of 129 bytes", "ErrNodeIDTooLong", items(sc2, cText(string(long)), vi2, seal, vs, cNull))
	bad("enc.vote-signature-null", "null vote signature", "ErrShape", items(sc2, au, vi2, seal, cNull, cNull))
	bad("enc.vote-signature-text", "vote signature as text", "ErrShape", items(sc2, au, vi2, seal, cText("x"), cNull))
	bad("enc.seal-signature-int", "seal signature as an integer", "ErrShape", items(sc2, au, vi2, seal, vs, cUint(0)))

	// VoteInfo shapes.
	bad("enc.vote-info.scheme2-tagged", "scheme 2 vote info carrying the legacy tag", "ErrShape", items(sc2, au, cTag(39007, cArr(cUint(1), cUint(e.round), cUint(e.epoch), cUint(1), cUint(e.parent), cBytes(e.exec[:]))), seal, vs, cNull))
	bad("enc.vote-info.scheme2-arity-3", "scheme 2 vote info with three elements", "ErrShape", items(sc2, au, cArr(cUint(2), cUint(150), cUint(149)), seal, vs, cNull))
	bad("enc.vote-info.scheme2-arity-5", "scheme 2 vote info with a timestamp: scheme 2 does not carry one", "ErrShape", items(sc2, au, cArr(cUint(2), cUint(150), cUint(149), cUint(1), cBytes(e.exec[:])), seal, vs, cNull))
	bad("enc.vote-info.exec-31", "scheme 2 exec of 31 bytes", "ErrShape", items(sc2, au, cArr(cUint(2), cUint(150), cUint(149), cBytes(e.exec[:31])), seal, vs, cNull))
	bad("enc.vote-info.exec-null", "scheme 2 exec null", "ErrShape", items(sc2, au, cArr(cUint(2), cUint(150), cUint(149), cNull), seal, vs, cNull))
	ri := func(tag uint64, version uint64, exec []byte, n int) []byte {
		its := [][]byte{cUint(version), cUint(50), cUint(1), cUint(1050), cUint(49), cBytes(exec)}
		return cTag(tag, cArr(its[:n]...))
	}
	lseal, lvs, sc1 := l.sealBytes(), cBytes(l.voteSig), cUint(1)
	lbad := func(id, desc, want string, vi []byte) {
		g.bad(id, fam, desc, c, frame(v1.cbor(), items(sc1, au, vi, lseal, lvs, cNull)), want)
	}
	lbad("enc.vote-info.legacy-untagged", "scheme 1 vote info without the native tag", "ErrShape", cArr(cUint(1), cUint(50), cUint(1), cUint(1050), cUint(49), cBytes(l.exec[:])))
	lbad("enc.vote-info.legacy-wrong-tag", "scheme 1 vote info with the seal tag", "ErrShape", ri(39005, 1, l.exec[:], 6))
	lbad("enc.vote-info.legacy-version-2", "native object version 2", "ErrVersion", ri(39007, 2, l.exec[:], 6))
	lbad("enc.vote-info.legacy-arity-5", "scheme 1 vote info with five elements", "ErrShape", ri(39007, 1, l.exec[:], 5))
	lbad("enc.vote-info.legacy-exec-31", "scheme 1 exec of 31 bytes: narrower than the native variable-length field (S1-O1)", "ErrShape", ri(39007, 1, l.exec[:31], 6))
	lbad("enc.vote-info.legacy-exec-33", "scheme 1 exec of 33 bytes (S1-O1)", "ErrShape", ri(39007, 1, append(l.exec[:], 0), 6))

	// LedgerCommitInfo shapes.
	sealItems := func(tag uint64, ver uint64, net uint64, hash []byte, last []byte, prev []byte, n int) []byte {
		its := [][]byte{cUint(ver), cUint(net), cUint(0), cUint(0), cUint(0), cBytes(prev), hash, last}
		return cTag(tag, cArr(its[:n]...))
	}
	nc := e.prev
	sbad := func(id, desc, want string, s []byte) {
		g.bad(id, fam, desc, c, frame(v2.cbor(), items(sc2, au, vi2, s, vs, cNull)), want)
	}
	sbad("enc.commit-info.untagged", "commit info without its tag", "ErrShape", cArr(cUint(1), cUint(0), cUint(0), cUint(0), cUint(0), cBytes(nc), cNull, cNull))
	sbad("enc.commit-info.wrong-tag", "commit info with the round info tag", "ErrShape", sealItems(39007, 1, 0, cNull, cNull, nc, 8))
	sbad("enc.commit-info.version-2", "commit info version 2", "ErrVersion", sealItems(39005, 2, 0, cNull, cNull, nc, 8))
	sbad("enc.commit-info.arity-7", "commit info with seven elements", "ErrShape", sealItems(39005, 1, 0, cNull, cNull, nc, 7))
	sbad("enc.commit-info.signatures-empty-map", "transport signature map present (empty): stripped means exactly null", "ErrShape", sealItems(39005, 1, 0, cNull, []byte{0xa0}, nc, 8))
	sbad("enc.commit-info.signatures-bytes", "signature slot as a byte string", "ErrShape", sealItems(39005, 1, 0, cNull, cBytes([]byte{1}), nc, 8))
	sbad("enc.commit-info.network-65536", "seal network does not fit uint16", "ErrShape", sealItems(39005, 1, 65536, cNull, cNull, nc, 8))
	sbad("enc.commit-info.previous-hash-31", "previous hash of 31 bytes", "ErrShape", sealItems(39005, 1, 0, cNull, cNull, nc[:31], 8))
	sbad("enc.commit-info.previous-hash-33", "previous hash of 33 bytes", "ErrShape", sealItems(39005, 1, 0, cNull, cNull, append(append([]byte{}, nc...), 0), 8))
	sbad("enc.commit-info.hash-31", "commit hash of 31 bytes", "ErrShape", sealItems(39005, 1, 0, cBytes(make([]byte, 31)), cNull, nc, 8))
	sbad("enc.commit-info.hash-33", "commit hash of 33 bytes", "ErrShape", sealItems(39005, 1, 0, cBytes(make([]byte, 33)), cNull, nc, 8))
	sbad("enc.commit-info.hash-int", "commit hash as an integer", "ErrShape", sealItems(39005, 1, 0, cUint(0), cNull, nc, 8))

	// A malformed request wins over any semantic result, whichever evidence it is in, and whichever view
	// or context is false.
	badEv := items(cUint(3), au, vi2, seal, vs, cNull)
	g.bad("enc.precedence.false-first-malformed-second", fam, "a semantically false first vote followed by a malformed second one", c, frame(v2.cbor(), flipEv(e).enc(), badEv), "ErrScheme")
	g.bad("enc.precedence.unknown-epoch-malformed-evidence", fam, "an unknown epoch with a malformed evidence record", &ContextJSON{Network: uint16(w.net)}, frame(v2.cbor(), badEv), "ErrScheme")
	emptyView := v2.with(func(v *viewSpec) { v.members = nil })
	g.bad("enc.precedence.empty-view-malformed-evidence", fam, "an empty view (false) with a malformed evidence record", c, frame(emptyView.cbor(), badEv), "ErrScheme")
	g.bad("enc.precedence.invalid-point-malformed-later", fam, "an invalid point (false) followed by a malformed second evidence", c, frame(v2.with(func(v *viewSpec) { v.members[3].key = invalidPoint() }).cbor(), e.enc(), badEv), "ErrScheme")

	// Null versus empty commit hash: both are admitted and stay distinct.
	g.yes("enc.null-vs-empty.scheme1-null.ok", fam, "legacy null commit hash: content is SHA256 of the null form", c, v1, l)
	le := w.leg("v1", 50, 0x31)
	le.hash = []byte{}
	g.yes("enc.null-vs-empty.scheme1-empty.ok", fam, "legacy empty commit hash: different native seal bytes, different content digest", c, v1, w.sign(le))
}

// flipEv returns a copy of e whose signature no longer verifies.
func flipEv(e *ev) *ev { c := e.cp(); c.voteSig = flip(c.voteSig, 3); return c }
