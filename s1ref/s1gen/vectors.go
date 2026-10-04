package s1gen

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Build generates the whole manifest from a seed and the published Q1 vectors
// file. It is a pure function of both: same inputs, same bytes.
func Build(seed string, q1File []byte) (*Manifest, error) {
	src := sha256.Sum256(q1File)
	g := &gen{m: &Manifest{Format: FormatVersion, Seed: seed, SourceSHA256: hx(src[:]), Pins: Pins, Notes: Notes, OpenItems: OpenItems},
		w: newWorld(seed, 9)}
	if err := g.q1(seed, q1File); err != nil {
		return nil, err
	}
	g.single(seed)
	g.statement()
	g.signatures()
	g.binding()
	g.context()
	g.views()
	g.encoding()
	g.pairs()
	g.resources(seed)
	g.m.Deferred = []Deferred{
		{"Independent construction", "Rust construction of the same bytes and verdicts", "Slice B (ureth); consuming these Go fixtures alone is conformance, not independent generation"},
		{"Authenticated source", "layout 3 or layout 2 witness adapter, historical lookup, journal reads", "owner choice between layout 3 and a layout-2 witness is OPEN; the Context is an injected precondition"},
		{"Gas", "measured pricing and the authenticated-source charge", "an activation gate; this manifest carries the candidate pure-relation formula only"},
		{"State/path parity", "builder, follower, replay, eth_call, reorg, journal warmth", "needs the Rust/EVM execution paths"},
	}
	return g.m, nil
}

type gen struct {
	m *Manifest
	w *world
}

// shapeInfo is what the gas formula needs of a well-formed call.
type shapeInfo struct{ members, count, sealSigs int }

func (s shapeInfo) gas(reqLen int) uint64 {
	sigs := uint64(s.count + s.sealSigs)
	return 2000 + 16*uint64(reqLen) + 1000*uint64(s.members) + 6000*sigs + 2000*uint64(s.count)
}

// frame assembles header | viewLength | view | (evidenceLength | evidence)[count].
func frame(view []byte, evs ...[]byte) []byte {
	out := []byte{1, 0, 0, byte(len(evs))}
	out = binary.BigEndian.AppendUint32(out, uint32(len(view)))
	out = append(out, view...)
	for _, e := range evs {
		out = binary.BigEndian.AppendUint32(out, uint32(len(e)))
		out = append(out, e...)
	}
	return out
}

func (g *gen) req(view viewSpec, evs ...*ev) ([]byte, shapeInfo) {
	var encs [][]byte
	sh := shapeInfo{members: len(view.members), count: len(evs)}
	for _, e := range evs {
		encs = append(encs, e.enc())
		if e.raw == nil && e.sealSig != nil {
			sh.sealSigs++
		}
	}
	return frame(view.cbor(), encs...), sh
}

func (g *gen) add(v Vector) { g.m.Vectors = append(g.m.Vectors, v) }

// yes adds a request whose relation holds.
func (g *gen) yes(id, fam, desc string, c *ContextJSON, view viewSpec, evs ...*ev) {
	req, sh := g.req(view, evs...)
	valid := true
	g.add(Vector{ID: id, Family: fam, Description: desc, Context: c, Request: hx(req), Intermediate: intermediates(view, evs),
		Expected: Expected{Status: "ok", Valid: &valid, Output: hx(offenceWords(c.Network, view, evs)), Gas: sh.gas(len(req))}})
}

// no adds a well-formed request whose relation is false for the named reason.
func (g *gen) no(id, fam, desc string, c *ContextJSON, view viewSpec, want string, evs ...*ev) {
	req, sh := g.req(view, evs...)
	g.noRaw(id, fam, desc, c, req, sh, want)
}

func (g *gen) noRaw(id, fam, desc string, c *ContextJSON, req []byte, sh shapeInfo, want string) {
	valid := false
	out := make([]byte, 64)
	out[31] = 1
	g.add(Vector{ID: id, Family: fam, Description: desc, Context: c, Request: hx(req),
		Expected: Expected{Status: "ok", Valid: &valid, Sentinel: want, Output: hx(out), Gas: sh.gas(len(req))}})
}

// bad adds a malformed request: a precompile error naming the sentinel.
func (g *gen) bad(id, fam, desc string, c *ContextJSON, req []byte, want string) {
	g.add(Vector{ID: id, Family: fam, Description: desc, Context: c, Request: hx(req),
		Expected: Expected{Status: "error", Sentinel: want}})
}

// offenceWords is the independent derivation of the 384-byte true output:
// (1,1,scheme,N,domainHash,signerID,votingEpoch,votingRound,kind,conflictID,contentA,contentB).
func offenceWords(n uint16, view viewSpec, evs []*ev) []byte {
	e := evs[0]
	signer := sha256.Sum256(view.pub(e.author))
	var domain, conflict [32]byte
	if e.scheme == 2 {
		domain = sha256.Sum256([]byte(dv(e.genesis)))
		conflict = sum(cArr(cText("S1_CONFLICT_V1"), cBytes(signer[:]), cUint(uint64(n)), cText(dv(e.genesis)), cUint(e.epoch), cUint(e.round), cUint(1)))
	}
	a, b := e.content, [32]byte{}
	if len(evs) == 2 {
		a, b = evs[0].content, evs[1].content
		if string(a[:]) > string(b[:]) {
			a, b = b, a
		}
	}
	out := make([]byte, 0, 384)
	u := func(x uint64) []byte { w := make([]byte, 32); binary.BigEndian.PutUint64(w[24:], x); return w }
	for _, w := range [][]byte{u(1), u(1), u(e.scheme), u(uint64(n)), domain[:], signer[:], u(e.epoch), u(e.round), u(1), conflict[:], a[:], b[:]} {
		out = append(out, w...)
	}
	return out
}

func intermediates(view viewSpec, evs []*ev) map[string]string {
	m := map[string]string{}
	for i, e := range evs {
		p := fmt.Sprintf("vote%d.", i)
		m[p+"signedBytes"] = hx(e.pv)
		m[p+"digest"] = hx(e.content[:])
		m[p+"voteInfoHash"] = hx(e.prev)
		if e.scheme == 2 {
			m[p+"domain"] = dv(e.genesis)
			if e.committing() {
				m[p+"nativeSealSigBytes"] = hx(e.sealBytes())
			}
		}
		s := sha256.Sum256(view.pub(e.author))
		m[p+"signerID"] = hx(s[:])
	}
	if evs[0].scheme == 2 {
		e := evs[0]
		s := sha256.Sum256(view.pub(e.author))
		c := sum(cArr(cText("S1_CONFLICT_V1"), cBytes(s[:]), cUint(uint64(evs[0].signNet)), cText(dv(e.genesis)), cUint(e.epoch), cUint(e.round), cUint(1)))
		m["conflictID"] = hx(c[:])
	}
	return m
}
