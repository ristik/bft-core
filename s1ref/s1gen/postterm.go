package s1gen

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"sort"
	"strings"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/b1ref/b1gen"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// PostTermCorpusFormat identifies the layout of the post-term seal corpus.
const PostTermCorpusFormat = "p85-post-term-seal/1"

// The post-term seal corpus (#1297) is what the P85 Evidence contract's post-term verifier must reproduce: a predecessor committee of epoch e and
// its successor e+1 with start[e+1] = A*, the Closure facts (H round o, H RecordID, terminal root R_H), native scheme 2 seals of epoch e with real
// member signatures (PreviousHash an opaque signed word; the VoteInfo opening, where one exists, informational), seals an open-tip consumer
// (b1ref with e as the installed open tip) accepts, and submissions (a seal statement, a strictly increasing subset of predecessor member indices, one
// signature per index, a charged index) with the verdict of the P85 rule.
//
// Unlike the S1 vectors, every byte here is produced by the native code paths on purpose: votesig builds VI, bft-go-base types.UnicitySeal
// builds and signs the seal bytes with the in-memory secp256k1 signer, types.RootTrustBaseV2 builds and signs the trust-base entries, b1state
// derives the registry threshold. The corpus pins what a running root signs; the test of this package re-derives every byte with the
// generator's own CBOR writer and every signature verdict with dcrd, independently of go-ethereum and bft-go-base.

// PTMember is one installed committee member at its registry index (members sorted by node id).
type PTMember struct {
	Index   int    `json:"index"`
	NodeID  string `json:"nodeId"`
	Key     string `json:"key"`     // compressed secp256k1
	Address string `json:"address"` // keccak256(uncompressed key)[12:], what ecrecover returns for this member
	Weight  string `json:"weight"`
}

// PTCommittee is one installed epoch: the registry facts the evidence reads and the signed trust-base entry they come from.
type PTCommittee struct {
	Epoch           string     `json:"epoch"`
	Start           string     `json:"start"`
	End             *string    `json:"end"` // null while the epoch is the tip
	SigningScheme   string     `json:"signingScheme"`
	Members         []PTMember `json:"members"`
	TotalWeight     string     `json:"totalWeight"`
	Threshold       string     `json:"threshold"` // floor(2W/3)+1
	EntryID         string     `json:"entryId"`
	PreviousEntryID string     `json:"previousEntryId"`
	UTB             string     `json:"utb"` // the tag 39000 RootTrustBaseV2 entry, signed by the previous epoch's members
}

// PTClosure is the applied Closure of epoch e: H's ordered round o, its RecordID (the successor's activationCommitID) and R_H.
type PTClosure struct {
	ClosedEpoch  string `json:"closedEpoch"`
	HRound       string `json:"hRound"`
	HRecordID    string `json:"hRecordId"`
	TerminalRoot string `json:"terminalRoot"`
}

// PTStatement is the typed seal statement a reporter supplies: the native seal fields, with PreviousHash an opaque signed word (astra's option
// (a): no VoteInfo opening is required). The VoteInfo fields are informational: present when the opening behind PreviousHash is known
// (PreviousHash = sha256(VI) under the installed N and G), empty for a seal whose PreviousHash has no known opening.
type PTStatement struct {
	VotingEpoch     string `json:"votingEpoch,omitempty"`
	VotingRound     string `json:"votingRound,omitempty"`
	Parent          string `json:"parent,omitempty"`
	Exec            string `json:"exec,omitempty"`
	VoteTimestamp   string `json:"voteTimestamp,omitempty"` // "0": omitted from VI
	CommitRound     string `json:"commitRound"`             // the seal's RootChainRoundNumber
	CommitEpoch     string `json:"commitEpoch"`
	CommitTimestamp string `json:"commitTimestamp"`
	PreviousHash    string `json:"previousHash"`
	Hash            string `json:"hash"`
}

// PTOpenTip is the open-tip consumer's acceptance of a seal: a CERT_BATCH_V2 request certifying a UC under the seal, and the registry words in
// which epoch e is the installed, usable and open tip (no successor installed). bft-core's b1ref verifier accepts it (the generator and the
// replay test both run it); ureth's 0x0100 is the same relation.
type PTOpenTip struct {
	Request                 string           `json:"request"`
	Storage                 []b1gen.SlotWord `json:"storage"`
	PinnedGenesisCommitment string           `json:"pinnedGenesisCommitment"`
	PinnedProfileHash       string           `json:"pinnedProfileHash"`
	Accepted                bool             `json:"accepted"`
}

// PTSignature is one signature with its recovery facts against a digest (the seal's own, or for a submission the digest the installed context
// rebuilds) and the key of the member at Index.
type PTSignature struct {
	Index        int     `json:"index"`
	NodeID       string  `json:"nodeId"`   // the member at Index ("" when Index is not a member)
	Signer       string  `json:"signer"`   // who made the signature
	Mutation     string  `json:"mutation"` // "" for the signer's unaltered native signature
	Signature    string  `json:"signature"`
	RecoveredKey *string `json:"recoveredKey"` // libsecp256k1 recovery with the supplied recovery id (65 bytes, id 0..3), compressed; null if it fails
	Ecrecover    *string `json:"ecrecover"`    // what precompile 0x01 returns for (digest, v+27, r, s) when the input is 65 bytes with v 0 or 1; null if it refuses
	Native       bool    `json:"native"`       // bft-go-base VerifyBytes against the member key (65 bytes, v 0..3, low s, one recovery)
	Valid        bool    `json:"valid"`        // the P85 rule: 65 bytes, v 0 or 1, 1 <= r < n, 1 <= s <= n/2, recovery with that parity gives the member key
	Reason       string  `json:"reason"`       // ok, length, recovery-id, r-range, s-range, key, not-a-member
}

// PTSeal is one native seal of epoch e signed by committee members.
type PTSeal struct {
	ID            string        `json:"id"`
	Description   string        `json:"description"`
	Class         string        `json:"class"` // in-term, offence, exempt (by the installed context's rule); foreign seals carry their statement's class
	SignedNetwork uint64        `json:"signedNetwork"`
	SignedGenesis string        `json:"signedGenesis"`
	Statement     PTStatement   `json:"statement"`
	VoteInfo      string        `json:"voteInfo"`     // VI under the signed network and genesis; "" when PreviousHash has no known opening
	PreviousHash  string        `json:"previousHash"` // the signed word (sha256(VI) when VI is known)
	SigBytes      string        `json:"sigBytes"`     // tag 39005 [1, N, commitRound, commitEpoch, commitTimestamp, VH, Hash, null]
	SealDigest    string        `json:"sealDigest"`   // sha256(SigBytes), the signed digest
	Signatures    []PTSignature `json:"signatures"`   // every member's own native signature
	OpenTip       *PTOpenTip    `json:"openTip,omitempty"`
}

// PTSubmission is one evidence submission and its verdict.
type PTSubmission struct {
	ID          string        `json:"id"`
	Description string        `json:"description"`
	Seal        string        `json:"seal"` // the seal the signatures come from
	Statement   PTStatement   `json:"statement"`
	Indices     []int         `json:"indices"`
	Signatures  []PTSignature `json:"signatures"` // aligned with Indices
	Charged     int           `json:"charged"`
	// What a verifier holding the installed N rebuilds from the statement (sigBytes, digest); empty when the statement is refused before any
	// encoding. voteInfo is informational (the opening under the installed N and G, when the statement has one).
	VoteInfo     string   `json:"voteInfo"`
	PreviousHash string   `json:"previousHash"`
	SigBytes     string   `json:"sigBytes"`
	Digest       string   `json:"digest"`
	SignedWeight string   `json:"signedWeight"` // weight of the distinct valid signers at member indices
	Accept       bool     `json:"accept"`
	Reason       string   `json:"reason"`   // ok, or the condition the case is built to break
	Failures     []string `json:"failures"` // every condition that fails, in the order listed in the notes
	Offence      string   `json:"offence"`  // accepted submissions with the same statement and charged key share this label (one case, one debit)
}

// PTScenario is one deployment and handoff.
type PTScenario struct {
	ID              string         `json:"id"`
	Description     string         `json:"description"`
	Network         uint64         `json:"network"`
	Genesis         string         `json:"genesis"`
	VoteDomain      string         `json:"voteDomain"`
	ActivationRound string         `json:"activationRound"` // A* = start[e+1] = end[e]
	Predecessor     PTCommittee    `json:"predecessor"`
	Successor       PTCommittee    `json:"successor"`
	Closure         PTClosure      `json:"closure"`
	Seals           []PTSeal       `json:"seals"`
	Submissions     []PTSubmission `json:"submissions"`
}

// PostTermCorpus is the document.
type PostTermCorpus struct {
	Format    string            `json:"format"`
	Seed      string            `json:"seed"`
	Notes     []string          `json:"notes"`
	Curve     map[string]string `json:"curve"`
	MaxSubset int               `json:"maxSubset"`
	Scenarios []PTScenario      `json:"scenarios"`
}

// PostTermMaxSubset bounds the subset of a submission (the registry's member bound).
const PostTermMaxSubset = b1state.MaxMembers

// The failure conditions, in evaluation order.
const (
	ptStatement = "statement"             // commitEpoch == e and commitRound > 0
	ptIndices   = "indices"               // 1..16 strictly increasing member indices, one signature each
	ptSignature = "signature"             // every supplied signature valid for its member under the P85 rule
	ptWeight    = "below-threshold"       // distinct signed weight >= floor(2W/3)+1
	ptCharged   = "charged-not-in-subset" // the charged index is in the subset
	ptPostTerm  = "not-post-term"         // commitRound >= A*
	ptExempt    = "exempt-terminal-root"  // Hash != R_H
)

// ---- keys ----------------------------------------------------------------

type ptKey struct {
	label  string
	priv   [32]byte
	signer *crypto.InMemorySecp256K1Signer
	pub    []byte // compressed
	addr   [20]byte
}

func newPTKey(seed, label string) ptKey {
	priv := sha256.Sum256([]byte("s1gen/post-term|" + seed + "|key|" + label))
	s, err := crypto.NewInMemorySecp256K1SignerFromKey(priv[:])
	must(err)
	v, err := s.Verifier()
	must(err)
	pub, err := v.MarshalPublicKey()
	must(err)
	ep, err := ethcrypto.DecompressPubkey(pub)
	must(err)
	return ptKey{label: label, priv: priv, signer: s, pub: pub, addr: ethcrypto.PubkeyToAddress(*ep)}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// ---- statements ----------------------------------------------------------

type ptStmt struct {
	ve, vr, parent uint64
	exec           [32]byte
	vts            uint64
	cr, ce, cts    uint64
	hash           [32]byte
	opaque         *[32]byte // the signed PreviousHash when it has no known VoteInfo opening; nil: sha256(VI)
}

// vi is VI under network net and genesis g in the generator's own CBOR writer (any field values; nil for an opaque statement).
func (s ptStmt) vi(net uint64, g [32]byte) []byte {
	if s.opaque != nil {
		return nil
	}
	items := [][]byte{cUint(net), cText(dv(g)), cUint(s.ve), cUint(s.vr), cUint(s.parent), cBytes(s.exec[:])}
	if s.vts != 0 {
		items = append(items, cUint(s.vts))
	}
	return cArr(items...)
}

// prevHash is the seal's PreviousHash: the opaque word, or sha256(VI).
func (s ptStmt) prevHash(net uint64, g [32]byte) [32]byte {
	if s.opaque != nil {
		return *s.opaque
	}
	return sha256.Sum256(s.vi(net, g))
}

func (s ptStmt) json(net uint64, g [32]byte) PTStatement {
	pv := s.prevHash(net, g)
	out := PTStatement{CommitRound: dec(s.cr), CommitEpoch: dec(s.ce), CommitTimestamp: dec(s.cts), PreviousHash: hx(pv[:]), Hash: hx(s.hash[:])}
	if s.opaque == nil {
		out.VotingEpoch, out.VotingRound, out.Parent, out.Exec, out.VoteTimestamp = dec(s.ve), dec(s.vr), dec(s.parent), hx(s.exec[:]), dec(s.vts)
	}
	return out
}

// shapeOK is what the opaque statement can be checked for: a seal of epoch e (commitEpoch = e) at a real root round. The VoteInfo opening is not
// part of the evidence (astra's option (a)), so its shape is not a condition: a wrong opening changes PreviousHash and fails the signatures.
func (s ptStmt) shapeOK(e uint64) bool { return s.ce == e && s.cr > 0 }

// sealOf is the native seal (types.UnicitySeal) of the statement under network net, PreviousHash taken under genesis g.
func (s ptStmt) sealOf(net uint64, g [32]byte) types.UnicitySeal {
	pv := s.prevHash(net, g)
	return types.UnicitySeal{Version: 1, NetworkID: types.NetworkID(net), RootChainRoundNumber: s.cr, Epoch: s.ce, Timestamp: s.cts,
		PreviousHash: pv[:], Hash: s.hash[:]}
}

// nativeVI encodes a signed statement's VI with votesig (refusing an invalid scheme 2 shape) and checks the generator's own encoding against it.
func (s ptStmt) nativeVI(net uint64, g [32]byte) []byte {
	if s.opaque != nil {
		return nil
	}
	cfg := votesig.Config{Scheme: votesig.SchemeDomainBound, Network: net, Genesis: g}
	info := votesig.VoteInfo{Epoch: s.ve, Round: s.vr, Parent: s.parent, Exec: s.exec, Timestamp: s.vts}
	vi, err := cfg.VoteInfoBytes(info)
	must(err)
	// the commit side is checked by the vote preimage encoder (a commit round below the voting round)
	_, err = cfg.VotePreimage(info, votesig.Commit{Hash: s.hash[:], Round: s.cr})
	must(err)
	if !bytes.Equal(vi, s.vi(net, g)) {
		panic("votesig and the generator encode VI differently")
	}
	return vi
}

func sigBytesOf(seal types.UnicitySeal) []byte {
	sb, err := seal.SigBytes()
	must(err)
	return sb
}

// ---- signature verdicts --------------------------------------------------

var halfN = new(big.Int).Rsh(curveN, 1)

// ptVerdict applies the P85 rule and records what the native verifier, libsecp256k1 recovery and the ecrecover precompile make of sig over
// sha256(data) for the member key (nil key: the index is not a member).
func ptVerdict(sig, data, key []byte) PTSignature {
	digest := sha256.Sum256(data)
	out := PTSignature{Signature: hx(sig)}
	if len(sig) == 65 && sig[64] <= 3 {
		if pub, err := ethcrypto.Ecrecover(digest[:], sig); err == nil {
			if p, err := ethcrypto.UnmarshalPubkey(pub); err == nil {
				k := hx(ethcrypto.CompressPubkey(p))
				out.RecoveredKey = &k
			}
		}
	}
	if len(sig) == 65 && sig[64] <= 1 {
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64])
		if ethcrypto.ValidateSignatureValues(sig[64], r, s, false) {
			if pub, err := ethcrypto.Ecrecover(digest[:], sig); err == nil {
				p, err := ethcrypto.UnmarshalPubkey(pub)
				must(err)
				a := hx(ethcrypto.PubkeyToAddress(*p).Bytes())
				out.Ecrecover = &a
			}
		}
	}
	if key == nil {
		out.Reason = "not-a-member"
		return out
	}
	ver, err := crypto.NewVerifierSecp256k1(key)
	must(err)
	out.Native = ver.VerifyBytes(sig, data) == nil
	switch {
	case len(sig) != 65:
		out.Reason = "length"
	case sig[64] > 1:
		out.Reason = "recovery-id"
	case func() bool { r := new(big.Int).SetBytes(sig[:32]); return r.Sign() == 0 || r.Cmp(curveN) >= 0 }():
		out.Reason = "r-range"
	case func() bool { s := new(big.Int).SetBytes(sig[32:64]); return s.Sign() == 0 || s.Cmp(halfN) > 0 }():
		out.Reason = "s-range"
	case out.RecoveredKey == nil || *out.RecoveredKey != hx(key):
		out.Reason = "key"
	default:
		out.Reason, out.Valid = "ok", true
	}
	return out
}

// ---- signature mutations -------------------------------------------------

func mutate(sig []byte, m string) []byte {
	c := append([]byte{}, sig...)
	s := new(big.Int).SetBytes(sig[32:64])
	switch m {
	case "wrong-parity":
		c[64] ^= 1
	case "compact-64":
		c = c[:64]
	case "length-66":
		c = append(c, 0)
	case "high-s":
		// the same ECDSA signature with s replaced by n-s and the parity flipped: recovery still yields the signer's key
		copy(c[32:64], pad32(new(big.Int).Sub(curveN, s)))
		c[64] ^= 1
	case "high-s-same-parity":
		copy(c[32:64], pad32(new(big.Int).Sub(curveN, s)))
	case "v2":
		c[64] = 2 + sig[64]&1
	case "v3":
		c[64] = 3 - sig[64]&1
	case "v27":
		c[64] = 27 + sig[64]
	case "r-zero":
		copy(c[:32], make([]byte, 32))
	case "s-zero":
		copy(c[32:64], make([]byte, 32))
	case "r-n":
		copy(c[:32], pad32(curveN))
	case "s-n":
		copy(c[32:64], pad32(curveN))
	case "byte-flip":
		c[7] ^= 0x01
	default:
		panic("unknown mutation " + m)
	}
	return c
}

// ---- scenario builder ----------------------------------------------------

type ptMemberDef struct {
	id     string
	key    string // key label; the same label is the same key in another committee
	weight uint64
}

type ptCommittee struct {
	epoch, start uint64
	end          *uint64
	members      []ptMemberDef // sorted by id
	keys         map[string]ptKey
	tb           *types.RootTrustBaseV2
	entryID      [32]byte
	total, thr   uint64
}

type ptScn struct {
	seed   string
	net    uint64
	g      [32]byte
	aStar  uint64
	pred   *ptCommittee
	succ   *ptCommittee
	o      uint64
	hRecID [32]byte
	rH     [32]byte
	seals  map[string]*ptSealRec
	out    PTScenario
}

type ptSealRec struct {
	stmt ptStmt
	sigs map[string][]byte // member id -> native signature
	json PTSeal
}

func (sc *ptScn) committee(epoch, start uint64, defs []ptMemberDef, prev *ptCommittee) *ptCommittee {
	defs = slices.Clone(defs)
	sort.Slice(defs, func(i, j int) bool { return defs[i].id < defs[j].id })
	c := &ptCommittee{epoch: epoch, start: start, members: defs, keys: map[string]ptKey{}}
	tb := &types.RootTrustBaseV2{Version: types.TrustBaseV2Version, NetworkID: types.NetworkID(sc.net), Epoch: epoch, EpochStart: start,
		PreviousEntryID: make([]byte, 32)}
	var bm []b1state.Member
	for _, d := range defs {
		k := newPTKey(sc.seed, d.key)
		c.keys[d.id] = k
		tb.RootNodes = append(tb.RootNodes, &types.NodeInfo{NodeID: d.id, SigKey: k.pub, Stake: d.weight})
		var kk [33]byte
		copy(kk[:], k.pub)
		bm = append(bm, b1state.Member{NodeID: d.id, Key: kk, Weight: d.weight})
		c.total += d.weight
	}
	e := b1state.Entry{Epoch: epoch, Start: start, SigningScheme: votesig.SchemeDomainBound, Members: bm}
	total, err := e.TotalWeight()
	must(err)
	c.thr, err = b1state.Threshold(total)
	must(err)
	tb.QuorumThreshold = c.total*2/3 + 1
	if tb.QuorumThreshold != c.thr {
		panic("B1 and UTB thresholds differ")
	}
	if prev != nil {
		copy(tb.PreviousEntryID, prev.entryID[:])
		for _, d := range prev.members {
			must(tb.Sign(d.id, prev.keys[d.id].signer))
		}
		must(tb.VerifySuccessor(prev.tb))
		end := start
		prev.end = &end
	} else {
		must(tb.VerifyGenesis())
	}
	c.tb = tb
	c.entryID, err = tb.EntryID()
	must(err)
	return c
}

func (c *ptCommittee) json() PTCommittee {
	raw, err := c.tb.MarshalCBOR()
	must(err)
	out := PTCommittee{Epoch: dec(c.epoch), Start: dec(c.start), SigningScheme: dec(votesig.SchemeDomainBound), TotalWeight: dec(c.total),
		Threshold: dec(c.thr), EntryID: hx(c.entryID[:]), PreviousEntryID: hx(c.tb.PreviousEntryID), UTB: hx(raw)}
	if c.end != nil {
		e := dec(*c.end)
		out.End = &e
	}
	for i, d := range c.members {
		k := c.keys[d.id]
		out.Members = append(out.Members, PTMember{Index: i, NodeID: d.id, Key: hx(k.pub), Address: hx(k.addr[:]), Weight: dec(d.weight)})
	}
	return out
}

func (sc *ptScn) class(s ptStmt) string {
	switch {
	case s.cr < sc.aStar:
		return "in-term"
	case s.hash == sc.rH:
		return "exempt"
	}
	return "offence"
}

// seal signs stmt under (net, g) by every member of c and records it.
func (sc *ptScn) seal(id, desc string, s ptStmt, net uint64, g [32]byte, c *ptCommittee) *ptSealRec {
	vi := s.nativeVI(net, g)
	seal := s.sealOf(net, g)
	rec := &ptSealRec{stmt: s, sigs: map[string][]byte{}}
	for _, d := range c.members {
		must(seal.Sign(d.id, c.keys[d.id].signer))
	}
	sb := sigBytesOf(seal)
	dg := sha256.Sum256(sb)
	rec.json = PTSeal{ID: id, Description: desc, Class: sc.class(s), SignedNetwork: net, SignedGenesis: hx32(g), Statement: s.json(net, g),
		VoteInfo: hx(vi), PreviousHash: hx(seal.PreviousHash), SigBytes: hx(sb), SealDigest: hx(dg[:])}
	for i, d := range c.members {
		sig := seal.Signatures[d.id]
		if err := votesig.CheckSignatureShape(sig); err != nil {
			panic(err)
		}
		rec.sigs[d.id] = sig
		v := ptVerdict(sig, sb, c.keys[d.id].pub)
		v.Index, v.NodeID, v.Signer = i, d.id, d.id
		if !v.Valid || !v.Native {
			panic(fmt.Sprintf("%s: native signature of %s refused: %s", id, d.id, v.Reason))
		}
		rec.json.Signatures = append(rec.json.Signatures, v)
	}
	sc.seals[id] = rec
	sc.out.Seals = append(sc.out.Seals, rec.json)
	return rec
}

// openTipSeal records a seal of the predecessor signed by every member, certifying a UC of `variant` (its Hash is that UC's tree root and its
// timestamp the generator's), and checks that the open-tip consumer accepts it: bft-core's b1ref verifier with epoch e as the installed, usable
// and open tip. terminal: the seal's Hash is R_H (the scenario's terminal root becomes that tree root).
func (sc *ptScn) openTipSeal(id, desc string, s ptStmt, variant string, terminal bool) *ptSealRec {
	p := sc.pred
	var members []b1gen.OpenTipMember
	var signers []string
	for _, d := range p.members {
		members = append(members, b1gen.OpenTipMember{ID: d.id, Priv: p.keys[d.id].priv, Weight: d.weight})
		signers = append(signers, d.id)
	}
	ot := b1gen.OpenTip(sc.seed, uint16(sc.net), p.epoch, p.start, s.cr, s.prevHash(sc.net, sc.g), variant, members, signers)
	s.hash, s.cts = ot.Root, ot.Timestamp
	if terminal {
		sc.rH = s.hash
		sc.out.Closure.TerminalRoot = hx32(sc.rH)
	}
	st, pins := openTipState(ot.Pre)
	v, err := b1ref.Cert(ot.Request, st, pins)
	must(err)
	if !v.Valid {
		panic(fmt.Sprintf("%s: the open-tip consumer refuses the seal: %v", id, v.Why))
	}
	seal := s.sealOf(sc.net, sc.g)
	sb := sigBytesOf(seal)
	if !bytes.Equal(sb, ot.SigBytes) {
		panic(id + ": the certificate's seal bytes are not types.UnicitySeal's")
	}
	dg := sha256.Sum256(sb)
	rec := &ptSealRec{stmt: s, sigs: map[string][]byte{}}
	rec.json = PTSeal{ID: id, Description: desc, Class: sc.class(s), SignedNetwork: sc.net, SignedGenesis: hx32(sc.g), Statement: s.json(sc.net, sc.g),
		VoteInfo: hx(s.nativeVI(sc.net, sc.g)), PreviousHash: hx(seal.PreviousHash), SigBytes: hx(sb), SealDigest: hx(dg[:]),
		OpenTip: &PTOpenTip{Request: hx(ot.Request), Storage: ot.Pre.Storage, PinnedGenesisCommitment: ot.Pre.PinnedGenesisCommitment,
			PinnedProfileHash: ot.Pre.PinnedProfileHash, Accepted: true}}
	for i, d := range p.members {
		sig := ot.Signatures[d.id]
		rec.sigs[d.id] = sig
		v := ptVerdict(sig, sb, p.keys[d.id].pub)
		v.Index, v.NodeID, v.Signer = i, d.id, d.id
		if !v.Valid || !v.Native {
			panic(fmt.Sprintf("%s: signature of %s refused: %s", id, d.id, v.Reason))
		}
		rec.json.Signatures = append(rec.json.Signatures, v)
	}
	sc.seals[id] = rec
	sc.out.Seals = append(sc.out.Seals, rec.json)
	return rec
}

// openTipState is the registry words and pins of a rendered b1gen PreState.
func openTipState(p b1gen.PreState) (b1ref.Words, b1ref.Pins) {
	w := b1ref.Words{}
	word := func(s string) [32]byte {
		b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
		must(err)
		var out [32]byte
		copy(out[32-len(b):], b)
		return out
	}
	for _, sw := range p.Storage {
		w[word(sw.Slot)] = word(sw.Value)
	}
	return w, b1ref.Pins{GenesisCommitment: word(p.PinnedGenesisCommitment), ProfileHash: word(p.PinnedProfileHash)}
}

// ptSig names one supplied signature: index, the seal and member that made it, and a mutation.
type ptSig struct {
	index    int
	seal     string
	signer   string
	foreignC *ptCommittee // a signer outside the predecessor (successor key), signing the seal bytes of seal
	mutation string
}

func (sc *ptScn) sig(index int) ptSig {
	return ptSig{index: index, signer: sc.pred.members[index].id}
}

// submit evaluates a submission, checks it against the declared verdict and records it.
func (sc *ptScn) submit(id, desc, sealID string, stmt ptStmt, sigs []ptSig, indices []int, charged int, reason, offence string) {
	p := sc.pred
	sub := PTSubmission{ID: id, Description: desc, Seal: sealID, Statement: stmt.json(sc.net, sc.g), Indices: indices, Charged: charged, Reason: reason}
	if sub.Indices == nil {
		sub.Indices = []int{}
	}
	var fail []string
	shape := stmt.shapeOK(p.epoch)
	var sb []byte
	if !shape {
		fail = append(fail, ptStatement)
	} else {
		seal := stmt.sealOf(sc.net, sc.g)
		sb = sigBytesOf(seal)
		dg := sha256.Sum256(sb)
		sub.VoteInfo, sub.PreviousHash, sub.SigBytes, sub.Digest = hx(stmt.vi(sc.net, sc.g)), hx(seal.PreviousHash), hx(sb), hx(dg[:])
	}
	// every supplied signature, verdict against the rebuilt digest (or the seal's own bytes when the statement is refused)
	verdictBytes := sb
	if verdictBytes == nil {
		verdictBytes, _ = hexBytes(sc.seals[sealID].json.SigBytes)
	}
	for _, s := range sigs {
		src := sealID
		if s.seal != "" {
			src = s.seal
		}
		var raw []byte
		if s.foreignC != nil {
			rec := sc.seals[src]
			seal := rec.stmt.sealOf(sc.net, sc.g)
			must(seal.Sign(s.signer, s.foreignC.keys[s.signer].signer))
			raw = seal.Signatures[s.signer]
		} else {
			raw = sc.seals[src].sigs[s.signer]
		}
		if raw == nil {
			panic(fmt.Sprintf("%s: no signature of %s on %s", id, s.signer, src))
		}
		if s.mutation != "" {
			raw = mutate(raw, s.mutation)
		}
		var key []byte
		node := ""
		if s.index >= 0 && s.index < len(p.members) {
			node = p.members[s.index].id
			key = p.keys[node].pub
		}
		v := ptVerdict(raw, verdictBytes, key)
		v.Index, v.NodeID, v.Signer, v.Mutation = s.index, node, s.signer, s.mutation
		if s.foreignC != nil {
			v.Signer = s.signer + "@epoch" + dec(s.foreignC.epoch)
		}
		if src != sealID {
			v.Signer += " on " + src
		}
		if v.Native != v.Valid {
			panic(fmt.Sprintf("%s: native and P85 verdicts differ for %s", id, v.Signer))
		}
		sub.Signatures = append(sub.Signatures, v)
	}
	if sub.Signatures == nil {
		sub.Signatures = []PTSignature{}
	}
	// indices: 1..16, strictly increasing, members, one signature each
	idxOK := len(indices) > 0 && len(indices) <= PostTermMaxSubset && len(sigs) == len(indices)
	for i, x := range indices {
		if x < 0 || x >= len(p.members) || (i > 0 && indices[i-1] >= x) || (i < len(sigs) && sigs[i].index != x) {
			idxOK = false
		}
	}
	if !idxOK {
		fail = append(fail, ptIndices)
	}
	var weight uint64
	if len(sigs) == len(indices) {
		sigOK := true
		seen := map[int]bool{}
		for i, v := range sub.Signatures {
			if v.NodeID == "" {
				continue // counted under indices
			}
			if !v.Valid {
				sigOK = false
				continue
			}
			if !seen[indices[i]] {
				seen[indices[i]] = true
				weight += p.members[indices[i]].weight
			}
		}
		if !sigOK && shape {
			fail = append(fail, ptSignature)
		}
		if weight < p.thr && shape {
			fail = append(fail, ptWeight)
		}
	}
	if !slices.Contains(indices, charged) {
		fail = append(fail, ptCharged)
	}
	if stmt.cr < sc.aStar {
		fail = append(fail, ptPostTerm)
	}
	if stmt.hash == sc.rH {
		fail = append(fail, ptExempt)
	}
	sub.SignedWeight = dec(weight)
	sub.Failures = fail
	if sub.Failures == nil {
		sub.Failures = []string{}
	}
	sub.Accept = len(fail) == 0
	if sub.Accept != (reason == "ok") || (!sub.Accept && !slices.Contains(fail, reason)) {
		panic(fmt.Sprintf("post-term %s/%s: declared %q, evaluated %v", sc.out.ID, id, reason, fail))
	}
	if sub.Accept {
		sub.Offence = offence
	}
	sc.out.Submissions = append(sc.out.Submissions, sub)
}

func hexBytes(s string) ([]byte, error) { return hex.DecodeString(s) }

func label32(seed, s string) [32]byte { return sum([]byte("s1gen/post-term|"+seed+"|"), []byte(s)) }

func newPTScn(seed, id, desc string, net uint64, e, startE, aStar uint64, pred, succ []ptMemberDef) *ptScn {
	sc := &ptScn{seed: seed + "/" + id, net: net, aStar: aStar, seals: map[string]*ptSealRec{}}
	sc.g = label32(seed, "root genesis")
	gen := sc.committee(e-1, 1, pred, nil)
	sc.pred = sc.committee(e, startE, pred, gen)
	sc.succ = sc.committee(e+1, aStar, succ, sc.pred)
	sc.o = aStar - 6
	sc.hRecID = label32(sc.seed, "H record id")
	sc.rH = label32(sc.seed, "terminal root R_H")
	sc.out = PTScenario{ID: id, Description: desc, Network: net, Genesis: hx32(sc.g), VoteDomain: dv(sc.g), ActivationRound: dec(aStar),
		Closure: PTClosure{ClosedEpoch: dec(e), HRound: dec(sc.o), HRecordID: hx32(sc.hRecID), TerminalRoot: hx32(sc.rH)}}
	return sc
}

func (sc *ptScn) finish() PTScenario {
	sc.out.Predecessor = sc.pred.json()
	sc.out.Successor = sc.succ.json()
	return sc.out
}

const ptT0 = 1_764_028_800 // UC seconds at round 0 of the scenarios

// commitStmt is the statement of the commit QC of block c: VoteInfo (c+1, e, c, exec) and LedgerCommitInfo (c, e, hash).
func commitStmt(e, c uint64, exec, hash [32]byte) ptStmt {
	return ptStmt{ve: e, vr: c + 1, parent: c, exec: exec, vts: ptT0 + c + 1, cr: c, ce: e, cts: ptT0 + c + 1, hash: hash}
}

// BuildPostTermCorpus generates the corpus from a seed. It is a pure function of the seed.
func BuildPostTermCorpus(seed string) *PostTermCorpus {
	c := &PostTermCorpus{Format: PostTermCorpusFormat, Seed: seed, MaxSubset: PostTermMaxSubset,
		Curve: map[string]string{"n": curveN.Text(16), "halfN": halfN.Text(16), "p": secpP.Text(16)},
		Notes: []string{
			"Offence (#1297): a quorum of epoch e's installed committee signed a native scheme 2 seal with commitEpoch e, commitRound >= A* = start[e+1] = end[e] and Hash != R_H, the terminal root of epoch e's applied Closure. commitRound is the seal's RootChainRoundNumber; the VoteInfo round is never compared with A*, so commitRound A*-1 is in term even when votingRound >= A*. Every seal with Hash == R_H is exempt (H's own late commit and honest empty-suffix repeats), whatever VoteInfo.exec says.",
			"Statement (astra's option (a)): the reporter supplies the native seal fields with PreviousHash as an opaque signed word; no VoteInfo opening is required or checked. sigBytes = C(tag 39005 [1, N, commitRound, commitEpoch, commitTimestamp, previousHash, Hash, null]) under the verifier's installed N; the members sign sha256(sigBytes). A submission's sigBytes and digest are what that verifier rebuilds from the typed statement, never bytes the reporter supplies. The only statement conditions are commitEpoch = e and commitRound > 0. The VoteInfo fields are informational: where the opening is known, previousHash = sha256(VI) with VI = C([N, Dv, votingEpoch, votingRound, parent, exec(, voteTimestamp if non-zero)]) and Dv = \"root-vote/\"+hex(G); an altered opening changes previousHash and so fails the signatures (the no.statement.* cases that alter VoteInfo fields).",
			"Open-tip consumers: the opaque.* seals certify a real UC (their Hash is its unicity tree root) and carry openTip: a CERT_BATCH_V2 request and the registry words in which epoch e is the installed, usable and open tip. bft-core's b1ref verifier accepts each one (as a wallet or B1 caller that has not installed the successor would), while the post-term rule charges the random-previousHash and successor-epoch-VoteInfo seals and exempts the frozen-root repeat (Hash = R_H; R_H is that repeat's tree root here).",
			"Root genesis: N is signed, G is not (only inside a VoteInfo opening). ok.foreign-genesis.opaque is a seal signed by e's keys for another root history sharing N, presented with its own previousHash: the opaque rule charges it. Honest signers are protected only by key isolation: fresh, genesis-specific consensus keys for every validator in every root history (D5 section 2.1).",
			"Signature rule (P85, both offences): exactly 65 bytes r||s||v, 1 <= r < n, 1 <= s <= n/2, v in {0,1}, one recovery with that parity (ecrecover with v+27) equal to the member's installed key. v 2 and 3 are ineligible (the native signer emits only 0 and 1; 2/3 need r+n < p). A 64-byte compact signature, a high s (whose parity-flipped twin ecrecover still maps to the signer: the 'ecrecover' field shows it) and a v of 27/28 are refused.",
			"Quorum: one strictly increasing subset of 1..16 distinct predecessor member indices, one signature per index; every supplied signature must be valid (an invalid, unknown or repeated extra refuses the whole submission); the distinct signed weight must reach floor(2W/3)+1 (the registry's W - floor((W-1)/3)); the charged index must be in the subset.",
			"Failure order: statement, indices, signature, below-threshold, charged-not-in-subset, not-post-term, exempt-terminal-root. A verifier may check in another order; 'reason' is the condition a case is built to break and 'failures' lists every condition that fails. Accepted submissions with the same 'offence' label are one case (one signer, one statement): a different subset or reporter must not debit twice.",
			"Committees: members are sorted by node id and indexed in that order (the registry order). Each scenario's predecessor entry is signed by an epoch e-1 genesis entry of the same members; the successor entry is signed by the predecessor and starts at A*. A member that continues with its key has the same key label in both; 'r5' rotates its key at e+1. The Closure facts are labels: H's RecordID is the successor's activationCommitID, hRound o < A*.",
			"Numbers are decimal strings, bytes are lowercase hex without 0x. Generated by bft-core s1ref/s1gen (BuildPostTermCorpus); the test there regenerates and diffs this file and re-derives every byte and verdict independently.",
		}}

	// Base scenario: five members with distinct weights 1..5 (W = 15, threshold 11), A* = 65536 (commitRound A*-1 = 65535 has a 2-byte CBOR head).
	{
		pred := []ptMemberDef{{"r1", "r1", 1}, {"r2", "r2", 2}, {"r3", "r3", 3}, {"r4", "r4", 4}, {"r5", "r5", 5}}
		succ := []ptMemberDef{{"r3", "r3", 3}, {"r4", "r4", 4}, {"r5", "r5-rotated", 5}, {"r6", "r6", 2}, {"r7", "r7", 2}}
		const e, aStar = 2, 65536
		sc := newPTScn(seed, "weighted", "five weighted members, rotation of r5 at e+1, A* at a CBOR head-width boundary", 5, e, 4096, aStar, pred, succ)
		x := label32(sc.seed, "successor state")
		y := label32(sc.seed, "conflicting state")
		z := label32(sc.seed, "in-term state")
		p := sc.pred
		ptp := func(b [32]byte) *[32]byte { return &b }

		// R_H is a real unicity tree root: the genuine frozen-root repeat certifies a UC under it with an opaque previous hash (built first: every
		// exempt seal below commits R_H)
		frozen := sc.openTipSeal("opaque.frozen-root", "a genuine frozen-root repeat at c' = A*+60 with an opaque previousHash: Hash = R_H, exempt; the open-tip consumer accepts it",
			ptStmt{ce: e, cr: aStar + 60, opaque: ptp(label32(sc.seed, "opaque previous hash, frozen root"))}, "terminal", true)

		at := sc.seal("post.at-a", "commitRound = A*, Hash != R_H: the offence at the boundary", commitStmt(e, aStar, x, y), sc.net, sc.g, p)
		above := sc.seal("post.above", "commitRound = A*+7, Hash != R_H", commitStmt(e, aStar+7, x, y), sc.net, sc.g, p)
		execRH := sc.seal("post.exec-is-rh", "VoteInfo.exec = R_H but Hash != R_H: still an offence", commitStmt(e, aStar+2, sc.rH, y), sc.net, sc.g, p)
		in1 := sc.seal("in.a-minus-1", "commitRound = A*-1 (votingRound = A*): in term", commitStmt(e, aStar-1, z, z), sc.net, sc.g, p)
		in2s := commitStmt(e, aStar-1, z, z)
		in2s.vr, in2s.parent, in2s.vts = aStar+3, aStar+2, ptT0+aStar+3
		in2 := sc.seal("in.a-minus-1.late-vote", "commitRound = A*-1 committed by a later vote (votingRound = A*+3 >= A*): in term", in2s, sc.net, sc.g, p)
		hc := sc.seal("exempt.h-commit", "H's own commit at c = A*: Hash = exec = R_H", commitStmt(e, aStar, sc.rH, sc.rH), sc.net, sc.g, p)
		sfx := sc.seal("exempt.suffix", "a later empty-suffix repeat at c' = A*+40: Hash = exec = R_H", commitStmt(e, aStar+40, sc.rH, sc.rH), sc.net, sc.g, p)
		sfx2 := sc.seal("exempt.suffix.exec-differs", "Hash = R_H with VoteInfo.exec != R_H: exempt, no exec test turns it into a charge", commitStmt(e, aStar+41, x, sc.rH), sc.net, sc.g, p)
		fn := sc.seal("foreign.network", "the post.at-a statement signed under network N+1", at.stmt, sc.net+1, sc.g, p)
		otherG := label32(seed, "other root genesis")
		fg := sc.seal("foreign.genesis", "the post.at-a statement signed under another root genesis (the same N)", at.stmt, sc.net, otherG, p)
		op1 := sc.openTipSeal("opaque.random-prev", "commitRound = A*, previousHash random bytes (no VoteInfo opening): an offence; the open-tip consumer accepts the seal",
			ptStmt{ce: e, cr: aStar, opaque: ptp(label32(sc.seed, "opaque previous hash 1"))}, "opaque-1", false)
		op2 := sc.openTipSeal("opaque.random-prev.above", "commitRound = A*+9, previousHash random bytes: an offence; the open-tip consumer accepts the seal",
			ptStmt{ce: e, cr: aStar + 9, opaque: ptp(label32(sc.seed, "opaque previous hash 2"))}, "opaque-2", false)
		viNext := commitStmt(e, aStar+3, x, y)
		viNext.ve = e + 1
		opVI := sc.openTipSeal("opaque.vi-successor-epoch", "previousHash = sha256(VI) of a VoteInfo with voting epoch e+1, signed by e's quorum as an epoch-e seal at A*+3: an offence; the open-tip consumer accepts it",
			viNext, "opaque-3", false)

		sig := sc.sig
		set := func(idx ...int) []ptSig {
			out := make([]ptSig, len(idx))
			for i, x := range idx {
				out[i] = sig(x)
			}
			return out
		}
		q := []int{1, 3, 4} // weights 2+4+5 = 11 = threshold
		sc.submit("ok.min-quorum", "exact threshold weight, charged r5", at.json.ID, at.stmt, set(q...), q, 4, "ok", "post.at-a/r5")
		sc.submit("ok.other-subset", "another valid subset (3+4+5 = 12): the same offence", at.json.ID, at.stmt, set(2, 3, 4), []int{2, 3, 4}, 4, "ok", "post.at-a/r5")
		sc.submit("ok.all", "all five members: the same offence", at.json.ID, at.stmt, set(0, 1, 2, 3, 4), []int{0, 1, 2, 3, 4}, 4, "ok", "post.at-a/r5")
		sc.submit("ok.other-signer", "the lightest member r1 charged within a quorum (1+2+4+5): a separate offence", at.json.ID, at.stmt, set(0, 1, 3, 4), []int{0, 1, 3, 4}, 0, "ok", "post.at-a/r1")
		sc.submit("ok.above", "commitRound A*+7", above.json.ID, above.stmt, set(q...), q, 3, "ok", "post.above/r4")
		sc.submit("ok.exec-is-rh", "exec = R_H, Hash != R_H", execRH.json.ID, execRH.stmt, set(q...), q, 4, "ok", "post.exec-is-rh/r5")

		sc.submit("no.in-term", "commitRound A*-1", in1.json.ID, in1.stmt, set(q...), q, 4, ptPostTerm, "")
		sc.submit("no.in-term.late-vote", "commitRound A*-1, votingRound A*+3", in2.json.ID, in2.stmt, set(q...), q, 4, ptPostTerm, "")
		sc.submit("no.exempt.h-commit", "H's commit at A*", hc.json.ID, hc.stmt, set(q...), q, 4, ptExempt, "")
		sc.submit("no.exempt.suffix", "suffix repeat at A*+40", sfx.json.ID, sfx.stmt, set(q...), q, 4, ptExempt, "")
		sc.submit("no.exempt.suffix.exec-differs", "Hash = R_H, exec != R_H", sfx2.json.ID, sfx2.stmt, set(q...), q, 4, ptExempt, "")

		sc.submit("no.lone", "the heaviest member alone (5 < 11)", at.json.ID, at.stmt, set(4), []int{4}, 4, ptWeight, "")
		sc.submit("no.below", "1+4+5 = 10 < 11", at.json.ID, at.stmt, set(0, 3, 4), []int{0, 3, 4}, 4, ptWeight, "")
		sc.submit("no.charged-not-in-subset", "a valid quorum that r1 did not sign, r1 charged", at.json.ID, at.stmt, set(q...), q, 0, ptCharged, "")

		for _, m := range []string{"wrong-parity", "compact-64", "length-66", "high-s", "high-s-same-parity", "v2", "v3", "v27", "r-zero", "s-zero", "r-n", "s-n", "byte-flip"} {
			// r1's signature is an extra: the other four reach the threshold, so the mutated signature is the only defect
			s := set(0, 1, 2, 3, 4)
			s[0].mutation = m
			sc.submit("no.sig."+m, "all five, r1's signature altered ("+m+"): one bad extra refuses the submission", at.json.ID, at.stmt, s, []int{0, 1, 2, 3, 4}, 4, ptSignature, "")
		}
		{
			s := set(q...)
			s[2].mutation = "wrong-parity"
			sc.submit("no.charged-unsigned", "the charged member's own signature does not verify (wrong parity)", at.json.ID, at.stmt, s, q, 4, ptSignature, "")
		}
		{
			s := set(0, 1, 3, 4)
			s[0].mutation = "wrong-parity"
			sc.submit("no.invalid-extra", "a valid quorum plus r1 with a wrong-parity signature: the whole submission is refused", at.json.ID, at.stmt, s, []int{0, 1, 3, 4}, 4, ptSignature, "")
			s = set(0, 1, 3, 4)
			s[0].seal = above.json.ID
			sc.submit("no.extra-other-seal", "a valid quorum plus r1's valid signature of another seal", at.json.ID, at.stmt, s, []int{0, 1, 3, 4}, 4, ptSignature, "")
			s = append(set(q...), ptSig{index: 5, signer: "r6", foreignC: sc.succ})
			sc.submit("no.unknown-extra", "a valid quorum plus index 5, which is not a predecessor member", at.json.ID, at.stmt, s, []int{1, 3, 4, 5}, 4, ptIndices, "")
			s = []ptSig{sig(1), sig(3), sig(3), sig(4)}
			sc.submit("no.duplicate-index", "index 3 twice", at.json.ID, at.stmt, s, []int{1, 3, 3, 4}, 4, ptIndices, "")
			s = []ptSig{sig(3), sig(1), sig(4)}
			sc.submit("no.unsorted", "indices not increasing", at.json.ID, at.stmt, s, []int{3, 1, 4}, 4, ptIndices, "")
			sc.submit("no.signature-count", "three indices, two signatures", at.json.ID, at.stmt, set(1, 3), q, 4, ptIndices, "")
			sc.submit("no.empty", "no indices", at.json.ID, at.stmt, nil, nil, 4, ptIndices, "")
		}
		{
			s := set(q...)
			for i := range s {
				s[i].seal = fn.json.ID
			}
			sc.submit("no.wrong-network", "signatures over the statement under network N+1", at.json.ID, at.stmt, s, q, 4, ptSignature, "")
			s = set(q...)
			for i := range s {
				s[i].seal = fg.json.ID
			}
			sc.submit("no.wrong-genesis", "signatures over the statement under another root genesis, presented with the opening under the installed G: the signed previousHash differs, the signatures fail (ok.foreign-genesis.opaque is the same seal with its own word)", at.json.ID, at.stmt, s, q, 4, ptSignature, "")
			fgOpaque := at.stmt
			fgOpaque.opaque = ptp(fg.stmt.prevHash(sc.net, otherG))
			s = set(q...)
			for i := range s {
				s[i].seal = fg.json.ID
			}
			sc.submit("ok.foreign-genesis.opaque", "the foreign.genesis seal with its own signed previousHash: N matches and e's quorum signed it, so the opaque rule charges it; only key isolation across root histories protects an honest signer (D5 section 2.1)", fg.json.ID, fgOpaque, s, q, 4, "ok", "foreign.genesis/r5")
			s = set(q...)
			s[2] = ptSig{index: 4, signer: "r5", foreignC: sc.succ}
			sc.submit("no.rotated-key", "r5 signs with its epoch e+1 key: the historical key is installed for e", at.json.ID, at.stmt, s, q, 4, ptSignature, "")
		}
		{
			bad := func(id, desc, reason string, f func(*ptStmt)) {
				s := at.stmt
				f(&s)
				sc.submit(id, desc, at.json.ID, s, set(q...), q, 4, reason, "")
			}
			bad("no.statement.commit-epoch", "commitEpoch e+1", ptStatement, func(s *ptStmt) { s.ce = e + 1 })
			bad("no.statement.voting-epoch", "the opening altered to votingEpoch e+1: another previousHash, the signatures fail", ptSignature, func(s *ptStmt) { s.ve = e + 1 })
			bad("no.statement.commit-round-not-below", "commitRound altered to the voting round: other seal bytes, the signatures fail", ptSignature, func(s *ptStmt) { s.cr = s.vr })
			bad("no.statement.parent-not-below", "the opening altered to parent = votingRound: another previousHash, the signatures fail", ptSignature, func(s *ptStmt) { s.parent = s.vr })
			bad("no.statement.commit-round-zero", "commitRound 0", ptStatement, func(s *ptStmt) { s.cr = 0 })
		}
		{
			sc.submit("ok.opaque.random-prev", "a quorum on a seal whose previousHash has no opening: charged from the seal alone", op1.json.ID, op1.stmt, set(q...), q, 4, "ok", "opaque.random-prev/r5")
			sc.submit("ok.opaque.random-prev.above", "another opaque seal, r4 charged", op2.json.ID, op2.stmt, set(2, 3, 4), []int{2, 3, 4}, 3, "ok", "opaque.random-prev.above/r4")
			sc.submit("ok.opaque.vi-successor-epoch", "previousHash of a VoteInfo with voting epoch e+1: the seal is epoch e's, charged", opVI.json.ID, opVI.stmt, set(q...), q, 4, "ok", "opaque.vi-successor-epoch/r5")
			sc.submit("no.opaque.frozen-root", "the genuine frozen-root repeat with an opaque previousHash: exempt", frozen.json.ID, frozen.stmt, set(q...), q, 4, ptExempt, "")
		}
		c.Scenarios = append(c.Scenarios, sc.finish())
	}

	// Bound scenario: the registry's maximum of 16 unit-weight members (W = 16, threshold 11).
	{
		var pred []ptMemberDef
		for i := 0; i < PostTermMaxSubset; i++ {
			id := fmt.Sprintf("m%02d", i)
			pred = append(pred, ptMemberDef{id, id, 1})
		}
		succ := []ptMemberDef{{"m00", "m00", 1}, {"m01", "m01", 1}, {"m02", "m02", 1}, {"m03", "m03", 1}}
		const e, aStar = 7, 1 << 32
		sc := newPTScn(seed, "max-committee", "sixteen unit-weight members, A* = 2^32 (A*-1 has a 4-byte CBOR head)", 65535, e, 1<<20, aStar, pred, succ)
		x := label32(sc.seed, "successor state")
		y := label32(sc.seed, "conflicting state")
		at := sc.seal("post.at-a", "commitRound = A*, Hash != R_H", commitStmt(e, aStar, x, y), sc.net, sc.g, sc.pred)
		in := sc.seal("in.a-minus-1", "commitRound = A*-1", commitStmt(e, aStar-1, x, y), sc.net, sc.g, sc.pred)
		all := make([]int, PostTermMaxSubset)
		for i := range all {
			all[i] = i
		}
		set := func(idx []int) []ptSig {
			out := make([]ptSig, len(idx))
			for i, x := range idx {
				out[i] = sc.sig(x)
			}
			return out
		}
		sc.submit("ok.all-16", "all sixteen signatures (the bound)", at.json.ID, at.stmt, set(all), all, 15, "ok", "post.at-a/m15")
		sc.submit("ok.threshold-11", "eleven signatures", at.json.ID, at.stmt, set(all[5:]), all[5:], 15, "ok", "post.at-a/m15")
		sc.submit("no.ten", "ten signatures (10 < 11)", at.json.ID, at.stmt, set(all[6:]), all[6:], 15, ptWeight, "")
		over := append(slices.Clone(all), 15)
		sc.submit("no.seventeen", "seventeen entries (index 15 twice): above the bound", at.json.ID, at.stmt, set(over), over, 15, ptIndices, "")
		sc.submit("no.in-term", "all sixteen on commitRound A*-1", in.json.ID, in.stmt, set(all), all, 15, ptPostTerm, "")
		c.Scenarios = append(c.Scenarios, sc.finish())
	}
	return c
}

var secpP, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)

// JSON renders the corpus deterministically.
func (c *PostTermCorpus) JSON() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
