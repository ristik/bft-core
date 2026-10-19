package s1gen

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
)

// DigestCorpusFormat identifies the layout of the evidence-digest corpus.
const DigestCorpusFormat = "s1-evidence-digest/1"

// The evidence-digest corpus is what a second implementation of the scheme 2 vote digest (the PoS contracts' Evidence.sol, #595) must reproduce byte for
// byte: for each statement the typed fields, VI, VH, PV and the digest sha256(PV), the signer's compressed key and real low-s secp256k1 signatures over
// PV (the signer hashes PV itself), the committing vote's native seal bytes with their signature, and the timeout preimage. Numbers are decimal strings
// (they reach 2^64-1). The corpus is generated here by the generator's own CBOR writer; s1ref's tests check every figure against the production
// encoder (votesig) and the production verifier, so a disagreement between the two fails there.

// DigestSeal is the native UnicitySeal of a committing vote (signatures stripped).
type DigestSeal struct {
	Network      uint64 `json:"network"`
	Round        uint64 `json:"commitRound"`
	Epoch        uint64 `json:"commitEpoch"`
	Timestamp    uint64 `json:"timestamp"`
	PreviousHash string `json:"previousHash"` // VH
	Hash         string `json:"commitHash"`
	SigBytes     string `json:"sigBytes"` // the native encoding with the signature map null
	Signature    string `json:"signature"`
}

// DigestVote is one scheme 2 vote statement.
type DigestVote struct {
	ID           string     `json:"id"`
	Description  string     `json:"description"`
	Signer       string     `json:"signer"`
	Key          string     `json:"key"` // compressed secp256k1
	Epoch        uint64     `json:"epoch"`
	Round        uint64     `json:"round"`
	Parent       uint64     `json:"parent"`
	Exec         string     `json:"exec"`
	Timestamp    uint64     `json:"timestamp"` // "0": omitted from VI
	Committing   bool       `json:"committing"`
	CommitHash   string     `json:"commitHash"` // 32 bytes hex, "" when the vote does not commit
	CommitRound  uint64     `json:"commitRound"`
	VoteInfo     string     `json:"voteInfo"`     // VI
	VoteInfoHash string     `json:"voteInfoHash"` // VH = sha256(VI)
	Preimage     string     `json:"preimage"`     // PV
	Digest       string     `json:"digest"`       // sha256(PV)
	Sig64        string     `json:"sig64"`        // r||s, low s
	Sig65        string     `json:"sig65"`        // r||s||v with the true recovery id (0 or 1)
	SigHighS     string     `json:"sigHighS"`     // r||(n-s): valid for the key, refused by the low-s rule
	Seal         DigestSeal `json:"seal"`         // zero values ("0", "") when the vote does not commit: one fixed schema for every vote
}

// DigestAnchor is the anchor of a first-round-after-epoch-change timeout.
type DigestAnchor struct {
	GenesisID string `json:"genesisId"`
	Epoch     uint64 `json:"epoch"`
	Slot      uint64 `json:"slot"`
}

// DigestTimeout is one scheme 2 timeout statement.
type DigestTimeout struct {
	ID          string       `json:"id"`
	Description string       `json:"description"`
	Signer      string       `json:"signer"`
	Key         string       `json:"key"`
	Epoch       uint64       `json:"epoch"`
	Round       uint64       `json:"round"`
	HighQcRound uint64       `json:"highQcRound"`
	HasAnchor   bool         `json:"hasAnchor"`
	Anchor      DigestAnchor `json:"anchor"` // zero values when there is no anchor
	Author      string       `json:"author"`
	Preimage    string       `json:"preimage"` // PT
	Digest      string       `json:"digest"`
	Sig64       string       `json:"sig64"`
}

// DigestPair names two votes of one context; Equivocation says whether they are an offence (same key, domain, epoch and round, different signed PV).
type DigestPair struct {
	ID           string `json:"id"`
	Description  string `json:"description"`
	A            string `json:"a"`
	B            string `json:"b"`
	Equivocation bool   `json:"equivocation"`
}

// DigestContext is one authenticated deployment: the numeric network N and the root genesis G.
type DigestContext struct {
	Network       uint64          `json:"network"`
	Genesis       string          `json:"genesis"`
	VoteDomain    string          `json:"voteDomain"`
	TimeoutDomain string          `json:"timeoutDomain"`
	Votes         []DigestVote    `json:"votes"`
	Timeouts      []DigestTimeout `json:"timeouts"`
	Pairs         []DigestPair    `json:"pairs"`
}

// DigestCorpus is the document.
type DigestCorpus struct {
	Format   string            `json:"format"`
	Seed     string            `json:"seed"`
	Notes    []string          `json:"notes"`
	VoteTag  string            `json:"voteTag"`
	Timeout  string            `json:"timeoutTag"`
	Curve    map[string]string `json:"curve"` // n and n/2, for the low-s rule
	Keys     map[string]string `json:"keys"`
	Contexts []DigestContext   `json:"contexts"`
}

func dec(n uint64) string { return strconv.FormatUint(n, 10) }

// hx0 is the 0x-prefixed lower-case hex of b. The prefix is what makes a consumer's JSON decoder read the value as bytes, never as a number.
func hx0(b []byte) string { return "0x" + hex.EncodeToString(b) }

// widths are the CBOR head-width boundaries of an unsigned integer.
var widths = []uint64{0, 1, 23, 24, 255, 256, 65535, 65536, 1<<32 - 1, 1 << 32, ^uint64(0)}

func (g *gen) digestVote(w *world, id, desc string, e *ev) DigestVote {
	w.sign(e)
	v := w.vals[e.author]
	vi := e.vi(w.net, w.genesis)
	dg := sha256.Sum256(e.pv)
	zero := hx0(make([]byte, 32))
	out := DigestVote{Seal: DigestSeal{PreviousHash: zero, Hash: zero, SigBytes: "0x", Signature: "0x"}, CommitHash: zero, ID: id, Description: desc, Signer: e.author, Key: hx0(v.pub), Epoch: e.epoch, Round: e.round, Parent: e.parent,
		Exec: hx0(e.exec[:]), Timestamp: e.ts, CommitRound: e.sealRound, VoteInfo: hx0(vi), VoteInfoHash: hx0(e.prev), Preimage: hx0(e.pv), Digest: hx0(dg[:]),
		Sig64: hx0(e.voteSig), Sig65: hx0(v.signV(e.pv)), SigHighS: hx0(highS(e.voteSig))}
	if e.committing() {
		h := hx0(e.hash)
		out.Committing, out.CommitHash = true, h
		out.Seal = DigestSeal{Network: e.net, Round: e.sealRound, Epoch: e.sealEpoch, Timestamp: e.sealTS, PreviousHash: hx0(e.prev), Hash: h,
			SigBytes: hx0(e.sealBytes()), Signature: hx0(e.sealSig)}
	}
	return out
}

func (g *gen) digestTimeout(w *world, id, desc, signer string, epoch, round, high uint64, anchor *DigestAnchor, anchorRaw *[3]uint64, gid [32]byte) DigestTimeout {
	zero := DigestAnchor{GenesisID: hx0(make([]byte, 32))}
	var pt []byte
	if anchor == nil {
		pt = timeoutPreimage(w.net, w.genesis, epoch, round, high, signer)
	} else {
		pt = cArr(cText(timeoutTag), cUint(w.net), cText(dt(w.genesis)), cUint(epoch), cUint(round), cUint(high),
			cArr(cBytes(gid[:]), cUint(anchorRaw[0]), cUint(anchorRaw[1])), cText(signer))
	}
	v := w.vals[signer]
	dg := sha256.Sum256(pt)
	a, has := zero, anchor != nil
	if has {
		a = *anchor
	}
	return DigestTimeout{ID: id, Description: desc, Signer: signer, Key: hx0(v.pub), Epoch: epoch, Round: round, HighQcRound: high, HasAnchor: has, Anchor: a,
		Author: signer, Preimage: hx0(pt), Digest: hx0(dg[:]), Sig64: hx0(v.sign(pt))}
}

// BuildDigestCorpus generates the corpus from a seed. It is a pure function of the seed.
func BuildDigestCorpus(seed string) *DigestCorpus {
	c := &DigestCorpus{Format: DigestCorpusFormat, Seed: seed, VoteTag: voteTag, Timeout: timeoutTag,
		Curve: map[string]string{"n": curveN.Text(16), "halfN": halfOf(curveN).Text(16)},
		Keys:  map[string]string{},
		Notes: []string{
			"VI = C([N, Dv, epoch, round, parent, exec]) with the timestamp appended exactly when it is non-zero; VH = sha256(VI); PV = C([\"UNICITY_POS_VOTE\", N, Dv, VH, commitHash|null, commitRound]); digest = sha256(PV). The signer hashes PV itself: signatures are over the digest of PV.",
			"A non-committing vote has commitHash null and commitRound 0; a committing vote has a 32-byte commit hash and a commit round below the voting round, and its native seal (previousHash = VH) is signed by the same key over the seal bytes.",
			"sig64 is r||s with low s; sig65 appends the true recovery id (0 or 1); sigHighS is the same signature with s replaced by n-s (valid for the key, refused by the low-s rule).",
			"Numbers are decimal strings. Every figure here is checked against the production encoder and verifier in s1ref's tests.",
		}}
	for _, net := range []uint64{5, 1, 24, 256, 65535} {
		w := newWorld(seed, net)
		for _, id := range []string{"v1", "v2", "v3", "v5"} {
			c.Keys[id] = hx0(w.vals[id].pub)
		}
		g := &gen{w: w}
		ctx := DigestContext{Network: net, Genesis: hx0(w.genesis[:]), VoteDomain: dv(w.genesis), TimeoutDomain: dt(w.genesis)}
		votes := &ctx.Votes
		add := func(id, desc string, e *ev) { *votes = append(*votes, g.digestVote(w, id, desc, e)) }
		tag := byte(0x50)
		next := func() byte { tag++; return tag }

		add("nc", "non-committing, timestamp zero (VI has six elements)", w.nc("v1", 150, next()))
		add("nc.ts", "non-committing with a proposal timestamp (VI has seven elements)", withTS(w.nc("v1", 150, next()), 1_700_000_123))
		add("cm", "committing, timestamp zero", w.cm("v2", 150, next(), 149, 1, 0xc1))
		add("cm.ts", "committing with a proposal timestamp", withTS(w.cm("v2", 150, next(), 149, 1, 0xc2), 1_700_000_124))
		if net == 5 {
			add("nc.hash-bstr0", "an empty commit hash of a non-committing vote maps to null in PV", func() *ev { e := w.nc("v1", 150, next()); e.hash = []byte{}; return e }())
			for _, x := range widths {
				add("width.epoch."+dec(x), "voting epoch at a CBOR head-width boundary", func() *ev { e := w.nc("v1", 150, next()); e.epoch = x; return e }())
			}
			for _, x := range widths {
				if x == 0 {
					continue // round zero is refused
				}
				add("width.round."+dec(x), "voting round (and its parent) at a head-width boundary", func() *ev { e := w.nc("v1", x, next()); e.parent = x - 1; return e }())
			}
			for _, x := range widths {
				if x == ^uint64(0) {
					continue // the parent is below the voting round
				}
				add("width.parent."+dec(x), "parent round at a head-width boundary (voting round 2^64-1)", func() *ev { e := w.nc("v1", ^uint64(0), next()); e.parent = x; return e }())
			}
			for _, x := range widths {
				if x == 0 {
					continue
				}
				add("width.timestamp."+dec(x), "proposal timestamp at a head-width boundary", withTS(w.nc("v1", 150, next()), x))
			}
			for _, x := range widths {
				if x == 0 || x == ^uint64(0) {
					continue
				}
				add("width.commit-round."+dec(x), "commit round at a head-width boundary (voting round 2^64-1)", w.cm("v2", ^uint64(0), next(), x, 1, 0xc3))
			}
			for _, x := range widths {
				add("width.commit-epoch."+dec(x), "commit epoch at a head-width boundary (seal bytes only)", func() *ev { e := w.cm("v2", 150, next(), 149, x, 0xc4); return e }())
			}
		}

		// Pairs: equivocations (same key, domain, epoch and round; different PV) and statements that are not.
		pair := func(id, desc, a, b string, eq bool) {
			ctx.Pairs = append(ctx.Pairs, DigestPair{ID: id, Description: desc, A: a, B: b, Equivocation: eq})
		}
		add("eq.a", "equivocation, first: state 0x61", w.nc("v1", 160, 0x61))
		add("eq.b", "equivocation, second: state 0x62", w.nc("v1", 160, 0x62))
		add("eq.ts-a", "equivocation by timestamp, first", withTS(w.nc("v1", 161, 0x63), 1_700_000_001))
		add("eq.ts-b", "equivocation by timestamp, second: same state, other timestamp", withTS(w.nc("v1", 161, 0x63), 1_700_000_002))
		add("eq.cm-a", "committing vote, first", w.cm("v2", 162, 0x64, 161, 1, 0xc5))
		add("eq.cm-b", "committing vote on another commit hash, same slot", w.cm("v2", 162, 0x64, 161, 1, 0xc6))
		add("eq.nc-cm", "a non-committing vote of the committing vote's slot", w.nc("v2", 162, 0x64))
		add("other.signer", "the same slot, another key", w.nc("v2", 160, 0x62))
		add("other.round", "another round", w.nc("v1", 161, 0x62))
		pair("pair.exec", "different executed state", "eq.a", "eq.b", true)
		pair("pair.timestamp", "different proposal timestamps", "eq.ts-a", "eq.ts-b", true)
		pair("pair.commit-hash", "different commit hashes", "eq.cm-a", "eq.cm-b", true)
		pair("pair.committing-vs-not", "committing against non-committing", "eq.cm-a", "eq.nc-cm", true)
		pair("pair.same", "the same statement twice", "eq.a", "eq.a", false)
		pair("pair.signer", "different keys", "eq.a", "other.signer", false)
		pair("pair.round", "different rounds", "eq.b", "other.round", false)

		for _, x := range []struct {
			id, desc    string
			e, r, h     uint64
			anchor      bool
			slotOrEpoch uint64
		}{
			{"normal", "normal timeout", 2, 150, 149, false, 0},
			{"normal.wide", "normal timeout at head-width boundaries", 65536, 1 << 32, 255, false, 0},
			{"normal.high-zero", "high QC round zero", 2, 1, 0, false, 0},
		} {
			ctx.Timeouts = append(ctx.Timeouts, g.digestTimeout(w, x.id, x.desc, "v1", x.e, x.r, x.h, nil, nil, [32]byte{}))
		}
		gid := sum([]byte("anchor genesis"), []byte(seed))
		ctx.Timeouts = append(ctx.Timeouts, g.digestTimeout(w, "anchor", "first round after an epoch change: the anchor names the epoch and slot", "v1", 3, 40, 39,
			&DigestAnchor{GenesisID: hx0(gid[:]), Epoch: 3, Slot: 39}, &[3]uint64{3, 39}, gid))
		ctx.Timeouts = append(ctx.Timeouts, g.digestTimeout(w, "other-author", "another author, same slot", "v2", 2, 150, 149, nil, nil, [32]byte{}))
		c.Contexts = append(c.Contexts, ctx)
	}
	return c
}

func withTS(e *ev, ts uint64) *ev { e.ts = ts; return e }

// JSON renders the corpus deterministically.
func (c *DigestCorpus) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(c, "", " ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

var _ = fmt.Sprintf
var _ = hex.EncodeToString

func halfOf(n *big.Int) *big.Int { return new(big.Int).Rsh(n, 1) }
