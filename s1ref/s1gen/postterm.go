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

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// PostTermCorpusFormat identifies the layout of the post-term seal corpus.
const PostTermCorpusFormat = "p85-post-term-seal/1"

// The post-term seal corpus (#1297) is what the P85 Evidence contract's post-term verifier must reproduce: a predecessor committee of epoch e and
// its successor e+1 with start[e+1] = A*, the Closure facts (H round o, H RecordID, terminal root R_H), native scheme 2 seals of epoch e with their
// VoteInfo openings and real member signatures, and submissions (a seal statement, a strictly increasing subset of predecessor member indices, one
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

// PTStatement is the typed seal statement a reporter supplies: the VoteInfo opening behind PreviousHash and the native seal fields.
type PTStatement struct {
	VotingEpoch     string `json:"votingEpoch"`
	VotingRound     string `json:"votingRound"`
	Parent          string `json:"parent"`
	Exec            string `json:"exec"`
	VoteTimestamp   string `json:"voteTimestamp"` // "0": omitted from VI
	CommitRound     string `json:"commitRound"`   // the seal's RootChainRoundNumber
	CommitEpoch     string `json:"commitEpoch"`
	CommitTimestamp string `json:"commitTimestamp"`
	Hash            string `json:"hash"`
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
	VoteInfo      string        `json:"voteInfo"`     // VI under the signed network and genesis
	PreviousHash  string        `json:"previousHash"` // VH = sha256(VI)
	SigBytes      string        `json:"sigBytes"`     // tag 39005 [1, N, commitRound, commitEpoch, commitTimestamp, VH, Hash, null]
	SealDigest    string        `json:"sealDigest"`   // sha256(SigBytes), the signed digest
	Signatures    []PTSignature `json:"signatures"`   // every member's own native signature
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
	// What a verifier holding the installed N and G rebuilds; empty when the statement shape is refused before any encoding.
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
	ptStatement = "statement"             // scheme 2 committing shape, votingEpoch == commitEpoch == e
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
	return ptKey{label: label, signer: s, pub: pub, addr: ethcrypto.PubkeyToAddress(*ep)}
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
}

func (s ptStmt) json() PTStatement {
	return PTStatement{VotingEpoch: dec(s.ve), VotingRound: dec(s.vr), Parent: dec(s.parent), Exec: hx(s.exec[:]), VoteTimestamp: dec(s.vts),
		CommitRound: dec(s.cr), CommitEpoch: dec(s.ce), CommitTimestamp: dec(s.cts), Hash: hx(s.hash[:])}
}

// shapeOK is the scheme 2 committing shape of an epoch-e seal: 0 < commitRound < votingRound, parent < votingRound, votingEpoch = commitEpoch = e.
func (s ptStmt) shapeOK(e uint64) bool {
	return s.vr > 0 && s.parent < s.vr && s.cr > 0 && s.cr < s.vr && s.ve == e && s.ce == e
}

// build encodes VI with votesig and the seal with types.UnicitySeal under network net and genesis g.
func (s ptStmt) build(net uint64, g [32]byte) (vi []byte, vh [32]byte, seal types.UnicitySeal) {
	cfg := votesig.Config{Scheme: votesig.SchemeDomainBound, Network: net, Genesis: g}
	info := votesig.VoteInfo{Epoch: s.ve, Round: s.vr, Parent: s.parent, Exec: s.exec, Timestamp: s.vts}
	vi, err := cfg.VoteInfoBytes(info)
	must(err)
	vh = sha256.Sum256(vi)
	// the commit side is checked by the vote preimage encoder (a commit round below the voting round)
	_, err = cfg.VotePreimage(info, votesig.Commit{Hash: s.hash[:], Round: s.cr})
	must(err)
	seal = types.UnicitySeal{Version: 1, NetworkID: types.NetworkID(net), RootChainRoundNumber: s.cr, Epoch: s.ce, Timestamp: s.cts,
		PreviousHash: vh[:], Hash: s.hash[:]}
	return vi, vh, seal
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
	vi, vh, seal := s.build(net, g)
	rec := &ptSealRec{stmt: s, sigs: map[string][]byte{}}
	for _, d := range c.members {
		must(seal.Sign(d.id, c.keys[d.id].signer))
	}
	sb := sigBytesOf(seal)
	dg := sha256.Sum256(sb)
	rec.json = PTSeal{ID: id, Description: desc, Class: sc.class(s), SignedNetwork: net, SignedGenesis: hx32(g), Statement: s.json(),
		VoteInfo: hx(vi), PreviousHash: hx(vh[:]), SigBytes: hx(sb), SealDigest: hx(dg[:])}
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
	sub := PTSubmission{ID: id, Description: desc, Seal: sealID, Statement: stmt.json(), Indices: indices, Charged: charged, Reason: reason}
	if sub.Indices == nil {
		sub.Indices = []int{}
	}
	var fail []string
	shape := stmt.shapeOK(p.epoch)
	var sb []byte
	if !shape {
		fail = append(fail, ptStatement)
	} else {
		vi, vh, seal := stmt.build(sc.net, sc.g)
		sb = sigBytesOf(seal)
		dg := sha256.Sum256(sb)
		sub.VoteInfo, sub.PreviousHash, sub.SigBytes, sub.Digest = hx(vi), hx(vh[:]), hx(sb), hx(dg[:])
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
			_, _, seal := rec.stmt.build(sc.net, sc.g)
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
			"Statement: VI = C([N, Dv, votingEpoch, votingRound, parent, exec(, voteTimestamp if non-zero)]) with Dv = \"root-vote/\"+hex(G); previousHash = sha256(VI); sigBytes = C(tag 39005 [1, N, commitRound, commitEpoch, commitTimestamp, previousHash, Hash, null]); the members sign sha256(sigBytes). N and G are the verifier's installed values: a submission's voteInfo, previousHash, sigBytes and digest are what that verifier rebuilds from the typed statement, never bytes the reporter supplies. Shape: 0 < commitRound < votingRound, parent < votingRound, votingEpoch = commitEpoch = e.",
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
		fg := sc.seal("foreign.genesis", "the post.at-a statement signed under another root genesis", at.stmt, sc.net, label32(seed, "other root genesis"), p)

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
			sc.submit("no.wrong-genesis", "signatures over the statement under another root genesis (another VI, so another previousHash)", at.json.ID, at.stmt, s, q, 4, ptSignature, "")
			s = set(q...)
			s[2] = ptSig{index: 4, signer: "r5", foreignC: sc.succ}
			sc.submit("no.rotated-key", "r5 signs with its epoch e+1 key: the historical key is installed for e", at.json.ID, at.stmt, s, q, 4, ptSignature, "")
		}
		{
			bad := func(id, desc string, f func(*ptStmt)) {
				s := at.stmt
				f(&s)
				sc.submit(id, desc, at.json.ID, s, set(q...), q, 4, ptStatement, "")
			}
			bad("no.statement.commit-epoch", "commitEpoch e+1", func(s *ptStmt) { s.ce = e + 1 })
			bad("no.statement.voting-epoch", "votingEpoch e+1 (a successor statement)", func(s *ptStmt) { s.ve = e + 1 })
			bad("no.statement.commit-round-not-below", "commitRound = votingRound", func(s *ptStmt) { s.cr = s.vr })
			bad("no.statement.parent-not-below", "parent = votingRound", func(s *ptStmt) { s.parent = s.vr })
			bad("no.statement.commit-round-zero", "commitRound 0", func(s *ptStmt) { s.cr = 0 })
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
