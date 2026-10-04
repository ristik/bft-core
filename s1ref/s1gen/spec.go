package s1gen

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ---- trust views ----------------------------------------------------------

type memberSpec struct {
	id     string
	key    []byte
	weight uint64
}

// viewSpec is a TrustView [1, network, epoch, sourceKind, bodyID, members].
type viewSpec struct {
	network uint64
	epoch   uint64
	kind    uint64
	body    [32]byte
	members []memberSpec
}

func (v viewSpec) cbor() []byte {
	ms := make([][]byte, len(v.members))
	for i, m := range v.members {
		ms[i] = cArr(cText(m.id), cBytes(m.key), cUint(m.weight))
	}
	return cArr(cUint(1), cUint(v.network), cUint(v.epoch), cUint(v.kind), cBytes(v.body[:]), cArr(ms...))
}

func (v viewSpec) hash() [32]byte { return sha256.Sum256(v.cbor()) }

func (v viewSpec) pub(id string) []byte {
	for _, m := range v.members {
		if m.id == id {
			return m.key
		}
	}
	return nil
}

func (v viewSpec) with(f func(*viewSpec)) viewSpec {
	c := v
	c.members = append([]memberSpec{}, v.members...)
	f(&c)
	return c
}

// ---- evidence ---------------------------------------------------------------

// ev is one evidence record
// [scheme, author, VoteInfo, LedgerCommitInfo, voteSig, sealSig|null]. Fields
// are plain values so a test case signs a base record with sign and then edits
// it: an edit made after signing leaves the signatures stale on purpose.
type ev struct {
	scheme uint64
	author string
	epoch  uint64
	round  uint64
	parent uint64
	ts     uint64 // scheme 1 VoteInfo timestamp
	exec   [32]byte

	// LedgerCommitInfo.
	net       uint64
	sealRound uint64
	sealEpoch uint64
	sealTS    uint64
	prev      []byte
	hash      []byte // nil: null; empty: bstr0

	voteSig, sealSig []byte // sealSig nil: null

	// raw replaces the whole encoding when set (malformed cases).
	raw []byte

	// derived by sign
	genesis [32]byte // scheme 2 domain genesis the preimage was built with
	signNet uint64
	pv      []byte // scheme 2 vote preimage; scheme 1 native seal sig bytes
	content [32]byte
}

func (e *ev) committing() bool { return len(e.hash) != 0 || e.sealRound != 0 }

func dv(g [32]byte) string { return "root-vote/" + hex.EncodeToString(g[:]) }
func dt(g [32]byte) string { return "root-timeout/" + hex.EncodeToString(g[:]) }

// legacyRoundInfo is the native RoundInfo, tag39007 [1, round, epoch, ts, parent, exec].
func (e *ev) legacyRoundInfo() []byte {
	return cTag(tagRoundInfo, cArr(cUint(1), cUint(e.round), cUint(e.epoch), cUint(e.ts), cUint(e.parent), cBytes(e.exec[:])))
}

// domainVoteInfo is the wire VoteInfo of scheme 2: [epoch, round, parent, exec].
func (e *ev) domainVoteInfo() []byte {
	return cArr(cUint(e.epoch), cUint(e.round), cUint(e.parent), cBytes(e.exec[:]))
}

// vi is the signed VI = C([N, Dv, epoch, round, parent, exec]).
func (e *ev) vi(net uint64, g [32]byte) []byte {
	return cArr(cUint(net), cText(dv(g)), cUint(e.epoch), cUint(e.round), cUint(e.parent), cBytes(e.exec[:]))
}

// sealBytes is the native seal with its signatures nulled, which is both the
// wire LedgerCommitInfo and what SigBytes signs.
func (e *ev) sealBytes() []byte {
	return cTag(tagSeal, cArr(cUint(1), cUint(e.net), cUint(e.sealRound), cUint(e.sealEpoch), cUint(e.sealTS), cBytes(e.prev), cNullOr(e.hash), cNull))
}

// preimage is PV = C(["UNICITY_POS_VOTE", N, Dv, VH, commitHash|null, commitRound]);
// an empty commit hash with commit round 0 maps to null.
func (e *ev) preimage(net uint64, g [32]byte, vh []byte) []byte {
	commit := cNull
	if e.committing() {
		commit = cNullOr(e.hash)
	}
	return cArr(cText(voteTag), cUint(net), cText(dv(g)), cBytes(vh), commit, cUint(e.sealRound))
}

// timeoutPreimage is PT for a normal timeout of the author:
// C(["UNICITY_POS_TIMEOUT", N, Dt, epoch, round, highQC, null, author]).
func timeoutPreimage(net uint64, g [32]byte, epoch, round, highQC uint64, author string) []byte {
	return cArr(cText(timeoutTag), cUint(net), cText(dt(g)), cUint(epoch), cUint(round), cUint(highQC), cNull, cText(author))
}

func (e *ev) enc() []byte {
	if e.raw != nil {
		return e.raw
	}
	var vi []byte
	if e.scheme == 1 {
		vi = e.legacyRoundInfo()
	} else {
		vi = e.domainVoteInfo()
	}
	var seal []byte
	if e.sealSig != nil {
		seal = cBytes(e.sealSig)
	} else {
		seal = cNull
	}
	return cArr(cUint(e.scheme), cText(e.author), vi, e.sealBytes(), cBytes(e.voteSig), seal)
}

// ---- world ------------------------------------------------------------------

// world is one fixed scenario: a network, a root genesis, validators and two
// epochs, the first signed with scheme 1 and the second with scheme 2.
type world struct {
	seed    string
	net     uint64
	genesis [32]byte
	vals    map[string]validator
	body    [3][32]byte
	// epoch 1 is [1, boundary) with scheme 1; epoch 2 is [boundary, open) with scheme 2.
	boundary uint64
}

func newWorld(seed string, net uint64) *world {
	w := &world{seed: seed, net: net, vals: map[string]validator{}, boundary: 100}
	w.genesis = newDRBG(seed, fmt.Sprintf("genesis/%d", net)).hash()
	for _, id := range []string{"v1", "v2", "v3", "v4", "v5", "x1"} {
		w.vals[id] = makeValidator(seed, id)
	}
	for i := range w.body {
		w.body[i] = newDRBG(seed, fmt.Sprintf("body/%d/%d", net, i)).hash()
	}
	return w
}

func (w *world) members(ids ...string) []memberSpec {
	var ms []memberSpec
	for _, id := range ids {
		ms = append(ms, memberSpec{id: id, key: w.vals[id].pub, weight: 1})
	}
	return ms
}

// view1 has the legacy epoch's four validators; v4 is retired by epoch 2, whose
// view replaces it with v5.
func (w *world) view1() viewSpec {
	return viewSpec{network: w.net, epoch: 1, kind: 1, body: w.body[1], members: w.members("v1", "v2", "v3", "v4")}
}

func (w *world) view2() viewSpec {
	return viewSpec{network: w.net, epoch: 2, kind: 2, body: w.body[2], members: w.members("v1", "v2", "v3", "v5")}
}

func (w *world) entry(v viewSpec, start, end, scheme uint64, g [32]byte) EpochJSON {
	return EpochJSON{Epoch: v.epoch, ViewHash: hx32(v.hash()), BodyID: hx32(v.body), SourceKind: v.kind,
		Start: start, End: end, Scheme: scheme, SigNetwork: w.net, Genesis: hx32(g)}
}

// ctx is the honest context: epoch 1 is scheme 1 on [1, boundary), epoch 2 is
// scheme 2 on [boundary, open), and epoch 2 is the current open epoch.
func (w *world) ctx() *ContextJSON {
	return &ContextJSON{Network: uint16(w.net), OpenEpoch: 2, Epochs: []EpochJSON{
		w.entry(w.view1(), 1, w.boundary, 1, [32]byte{}),
		w.entry(w.view2(), w.boundary, 0, 2, w.genesis),
	}}
}

// wide is the honest context with epoch 2 starting at round 1, so that the
// statement rules at tiny rounds are reachable without the interval failing.
func (w *world) wide() *ContextJSON {
	c := w.ctx()
	c.Epochs[1].Start = 1
	c.Epochs[0].End = 1
	return c
}

func (c *ContextJSON) clone() *ContextJSON {
	d := *c
	d.Epochs = append([]EpochJSON{}, c.Epochs...)
	return &d
}

func (c *ContextJSON) mut(epoch uint64, f func(*EpochJSON)) *ContextJSON {
	d := c.clone()
	for i := range d.Epochs {
		if d.Epochs[i].Epoch == epoch {
			f(&d.Epochs[i])
		}
	}
	return d
}

// sign fills prev, the signed preimage and the signatures of e with the key of
// its author, using the world's network and genesis (scheme 2) or the legacy
// rules (scheme 1).
func (w *world) sign(e *ev) *ev {
	v, ok := w.vals[e.author]
	if !ok {
		panic("unknown validator " + e.author)
	}
	return w.signWith(e, v)
}

func (w *world) signWith(e *ev, v validator) *ev {
	e.signNet, e.genesis = w.net, w.genesis
	if e.scheme == 1 {
		e.genesis = [32]byte{}
		h := sum(e.legacyRoundInfo())
		e.prev = h[:]
		e.pv = e.sealBytes()
		e.voteSig = v.sign(e.pv)
		e.sealSig = nil
		e.content = sha256.Sum256(e.pv)
		return e
	}
	vh := sum(e.vi(w.net, w.genesis))
	e.prev = vh[:]
	e.pv = e.preimage(w.net, w.genesis, vh[:])
	e.voteSig = v.sign(e.pv)
	e.sealSig = nil
	if e.committing() {
		e.sealSig = v.sign(e.sealBytes())
	}
	e.content = sha256.Sum256(e.pv)
	return e
}

// base builds an unsigned scheme 2 vote with the usual shape.
func (w *world) nc(author string, round uint64, tag byte) *ev {
	e := &ev{scheme: 2, author: author, epoch: 2, round: round, parent: round - 1}
	for i := range e.exec {
		e.exec[i] = tag
	}
	return e
}

// cm builds a committing scheme 2 vote that commits state c-tagged at
// commitRound in commitEpoch.
func (w *world) cm(author string, round uint64, tag byte, commitRound, commitEpoch uint64, c byte) *ev {
	e := w.nc(author, round, tag)
	e.net, e.sealRound, e.sealEpoch, e.sealTS = w.net, commitRound, commitEpoch, 5000+commitRound
	e.hash = make([]byte, 32)
	for i := range e.hash {
		e.hash[i] = c
	}
	return e
}

// leg builds an unsigned scheme 1 vote of epoch 1.
func (w *world) leg(author string, round uint64, tag byte) *ev {
	e := &ev{scheme: 1, author: author, epoch: 1, round: round, parent: round - 1, ts: 1000 + round}
	for i := range e.exec {
		e.exec[i] = tag
	}
	return e
}

// legcm is a legacy committing vote (a seal with a commit hash, round and epoch).
func (w *world) legcm(author string, round uint64, tag byte, commitRound uint64, c byte) *ev {
	e := w.leg(author, round, tag)
	e.net, e.sealRound, e.sealEpoch, e.sealTS = w.net, commitRound, 1, 5000+commitRound
	e.hash = make([]byte, 32)
	for i := range e.hash {
		e.hash[i] = c
	}
	return e
}

func (e *ev) cp() *ev { c := *e; return &c }

// invalidPoint is a bstr33 payload that is not a secp256k1 point: 02 followed
// by 32 ff bytes (x is above the field prime).
func invalidPoint() []byte {
	b := make([]byte, 33)
	b[0] = 0x02
	for i := 1; i < 33; i++ {
		b[i] = 0xff
	}
	return b
}
