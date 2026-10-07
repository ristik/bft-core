package consensus

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
)

// Q4 #51 (A) oracle: expected verdicts are computed here with plain integers, subset enumeration and a reference schedule. The
// production quorum accumulator (quorumweight.Tally, the votesig and trust base verifiers) and the production selector are never used
// to compute an expected value; the production trust base is built only to compare against it as a premise, and the selector is the
// subject of the schedule test.

var (
	errQ4EvEpoch       = errors.New("q4 oracle: evidence is for another epoch")
	errQ4EvDomain      = errors.New("q4 oracle: evidence is for another signing domain")
	errQ4EvUnknown     = errors.New("q4 oracle: signer is not a member of the epoch")
	errQ4EvDuplicate   = errors.New("q4 oracle: signer counted twice")
	errQ4EvSignature   = errors.New("q4 oracle: invalid signature over the statement")
	errQ4EvUnderweight = errors.New("q4 oracle: signed weight is below the quorum")

	errQ4TraceDuplicateID = errors.New("q4 trace: send ID repeated")
	errQ4TraceNoAttempt   = errors.New("q4 trace: delivery without an attempt")
	errQ4TraceTampered    = errors.New("q4 trace: delivered bytes differ from the attempted bytes")
	errQ4TraceNoOutcome   = errors.New("q4 trace: attempt without delivery, drop or hold outcome")
	errQ4TraceEpoch       = errors.New("q4 trace: message for an epoch the oracle does not know")
	errQ4TraceAuthor      = errors.New("q4 trace: author is not a member of the epoch")
	errQ4TraceSignature   = errors.New("q4 trace: signature does not verify")
	errQ4TraceStatement   = errors.New("q4 trace: statement does not decode")
	errQ4TraceMixed       = errors.New("q4 trace: the seal does not sign the vote info the vote carries")
)

func q4Sum(ws []uint64) (s uint64) {
	for _, w := range ws {
		s += w
	}
	return s
}

// q4Threshold is the root quorum floor(2W/3)+1, written out here so the oracle does not depend on the production helper.
func q4Threshold(total uint64) uint64 { return 2*total/3 + 1 }

func q4TrustBase(r *q4Roster) (*types.RootTrustBaseV1, error) {
	return quorumweight.NewTrustBase(5, r.NodeInfos())
}

// q4CanonicalVector is the canonical identity of a vector: its (peer ID, weight) pairs sorted by peer ID.
func q4CanonicalVector(infos []*types.NodeInfo) string {
	parts := make([]string, len(infos))
	for i, n := range infos {
		parts[i] = fmt.Sprintf("%s:%d", n.NodeID, n.Stake)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// ---- signer-set arithmetic ----

type q4Pair struct {
	S, T         uint // bit i = member i
	Inter        uint
	InterWeight  uint64
	SolelyFaulty bool // the intersection is a subset of the declared Byzantine set
}

type q4Quorums struct {
	Weights []uint64
	Q       uint64
	Sets    []uint
}

func q4Weight(ws []uint64, set uint) (w uint64) {
	for i := range ws {
		if set>>i&1 == 1 {
			w += ws[i]
		}
	}
	return w
}

// q4EnumerateQuorums lists every subset of the members whose weight reaches Q.
func q4EnumerateQuorums(ws []uint64, q uint64) q4Quorums {
	out := q4Quorums{Weights: ws, Q: q}
	for s := uint(1); s < 1<<len(ws); s++ {
		if q4Weight(ws, s) >= q {
			out.Sets = append(out.Sets, s)
		}
	}
	return out
}

// Pairs lists every ordered pair of quorums with the weight of its intersection and whether the intersection lies in byz.
func (qs q4Quorums) Pairs(byz uint) []q4Pair {
	var out []q4Pair
	for _, s := range qs.Sets {
		for _, t := range qs.Sets {
			inter := s & t
			out = append(out, q4Pair{s, t, inter, q4Weight(qs.Weights, inter), inter&^byz == 0})
		}
	}
	return out
}

func (qs q4Quorums) MinIntersection() uint64 {
	min := ^uint64(0)
	for _, p := range qs.Pairs(0) {
		min = min64(min, p.InterWeight)
	}
	return min
}

func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func q4Mask(r *q4Roster, names ...string) (m uint) {
	for _, n := range names {
		m |= 1 << r.Index(n)
	}
	return m
}

// ---- certificate evidence ----

// q4Evidence is a certificate-like set of signatures over one statement: the unit the oracle checks without the production verifiers.
type q4Evidence struct {
	Epoch     uint64
	Domain    string
	Statement []byte
	Sigs      map[string][]byte // signer peer ID -> signature
}

const q4Domain = "q4/evidence/v1"

func q4SignedBytes(domain string, epoch uint64, statement []byte) []byte {
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], epoch)
	return bytes.Join([][]byte{[]byte(domain), e[:], statement}, []byte{0})
}

func q4Sign(signer abcrypto.Signer, domain string, epoch uint64, statement []byte) []byte {
	sig, err := signer.SignBytes(q4SignedBytes(domain, epoch, statement))
	if err != nil {
		panic(err)
	}
	return sig
}

// q4EpochView is what the oracle knows of one epoch: member weights and verification keys by peer ID string.
type q4EpochView struct {
	Epoch     uint64
	Weights   map[string]uint64
	Verifiers map[string]abcrypto.Verifier
}

func q4View(r *q4Roster, epoch uint64) q4EpochView {
	v := q4EpochView{Epoch: epoch, Weights: map[string]uint64{}, Verifiers: map[string]abcrypto.Verifier{}}
	for i, e := range r.Entities {
		v.Weights[e.ID.String()] = r.Weights[i]
		v.Verifiers[e.ID.String()] = e.Verifier
	}
	return v
}

func (v q4EpochView) Quorum() uint64 {
	var total uint64
	for _, w := range v.Weights {
		total += w
	}
	return q4Threshold(total)
}

// Check returns the verified signer weight of the evidence under the epoch's own rule, or the first violation. Signers are
// counted once, in sorted order; a map cannot carry a duplicate, so a listed duplicate is checked by CheckList.
func (v q4EpochView) Check(ev q4Evidence) (uint64, error) {
	if ev.Epoch != v.Epoch {
		return 0, fmt.Errorf("%w: %d, expected %d", errQ4EvEpoch, ev.Epoch, v.Epoch)
	}
	if ev.Domain != q4Domain {
		return 0, fmt.Errorf("%w: %q", errQ4EvDomain, ev.Domain)
	}
	ids := make([]string, 0, len(ev.Sigs))
	for id := range ev.Sigs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var weight uint64
	for _, id := range ids {
		verifier, ok := v.Verifiers[id]
		if !ok {
			return 0, fmt.Errorf("%w: %s", errQ4EvUnknown, id)
		}
		if err := verifier.VerifyBytes(ev.Sigs[id], q4SignedBytes(ev.Domain, ev.Epoch, ev.Statement)); err != nil {
			return 0, fmt.Errorf("%w: %s", errQ4EvSignature, id)
		}
		weight += v.Weights[id]
	}
	if weight < v.Quorum() {
		return weight, fmt.Errorf("%w: %d of %d", errQ4EvUnderweight, weight, v.Quorum())
	}
	return weight, nil
}

// CheckList is Check for evidence received as a list of signers, so that a signer listed twice is refused, not summed.
func (v q4EpochView) CheckList(ev q4Evidence, signers []string) (uint64, error) {
	seen := map[string]bool{}
	for _, id := range signers {
		if seen[id] {
			return 0, fmt.Errorf("%w: %s", errQ4EvDuplicate, id)
		}
		seen[id] = true
	}
	return v.Check(ev)
}

func q4Evidence1(r *q4Roster, epoch uint64, statement []byte, names ...string) q4Evidence {
	ev := q4Evidence{Epoch: epoch, Domain: q4Domain, Statement: statement, Sigs: map[string][]byte{}}
	for _, n := range names {
		e := r.Entities[r.Index(n)]
		ev.Sigs[e.ID.String()] = q4Sign(e.Signer, q4Domain, epoch, statement)
	}
	return ev
}

// ---- signed decisions and traces ----

type q4Decision struct {
	Author string
	Epoch  uint64
	Round  uint64
	Kind   string
}

// q4Classify distinguishes the repetition of one signed decision from a second statement for the same (author, epoch, round, kind).
func q4Classify(a, b q4SignedStatement) string {
	switch {
	case a.q4Decision != b.q4Decision:
		return "unrelated"
	case bytes.Equal(a.Statement, b.Statement):
		return "rebroadcast"
	default:
		return "equivocation"
	}
}

type q4SignedStatement struct {
	q4Decision
	Statement []byte
}

// Statements are the vote and timeout statements of the trace's attempts, as the canonical bytes a signature covers; signed keeps
// only those that verify under the epoch's own keys, so a forged message cannot frame the identity it claims.
func (tr q4Trace) Statements() []q4SignedStatement { return tr.signed(nil) }

func (tr q4Trace) signed(views map[uint64]q4EpochView) []q4SignedStatement {
	var out []q4SignedStatement
	for _, ev := range tr {
		if ev.Kind == "attempt" && (ev.Msg.Class == q4Vote || ev.Msg.Class == q4Timeout) {
			if views != nil && q4VerifyMsg(ev.Msg, views) != nil {
				continue
			}
			out = append(out, q4SignedStatement{q4Decision{ev.Msg.Author, ev.Msg.Epoch, ev.Msg.Round, string(ev.Msg.Class)}, ev.Msg.Statement})
		}
	}
	return out
}

// Equivocators are the authors with two different validly signed statements for one decision key.
func (tr q4Trace) Equivocators(views map[uint64]q4EpochView) map[string][]q4Decision {
	by := map[q4Decision]map[string]bool{}
	for _, s := range tr.signed(views) {
		if by[s.q4Decision] == nil {
			by[s.q4Decision] = map[string]bool{}
		}
		by[s.q4Decision][string(s.Statement)] = true
	}
	out := map[string][]q4Decision{}
	for d, statements := range by {
		if len(statements) > 1 {
			out[d.Author] = append(out[d.Author], d)
		}
	}
	return out
}

// HonestDoubleSigns are the equivocations of authors that are not in byzantine; the honest set must have none.
func (tr q4Trace) HonestDoubleSigns(views map[uint64]q4EpochView, byzantine map[string]bool) []q4Decision {
	var out []q4Decision
	for author, ds := range tr.Equivocators(views) {
		if !byzantine[author] {
			out = append(out, ds...)
		}
	}
	return out
}

// Malformed are the send IDs of the attempts that are not a member's well formed signed statement of a known epoch.
func (tr q4Trace) Malformed(views map[uint64]q4EpochView) []uint64 {
	var out []uint64
	for _, ev := range tr {
		if ev.Kind == "attempt" && q4VerifyMsg(ev.Msg, views) != nil {
			out = append(out, ev.SendID)
		}
	}
	return out
}

// Verify is the offline check of a recorded trace, independent of any live counter: every attempt has a unique ID, every delivery
// refers to an attempt and carries its exact bytes, every attempt has an outcome, and every vote and timeout is a member's
// signature of its epoch over the statement it carries. byzantineOK authors may have forged nothing: a bad signature is an error
// whoever the author is.
func (tr q4Trace) Verify(views map[uint64]q4EpochView) error {
	attempts := map[uint64]q4Event{}
	outcome := map[uint64]bool{}
	for _, ev := range tr {
		switch ev.Kind {
		case "attempt":
			if _, dup := attempts[ev.SendID]; dup {
				return fmt.Errorf("%w: %d", errQ4TraceDuplicateID, ev.SendID)
			}
			attempts[ev.SendID] = ev
			if err := q4VerifyMsg(ev.Msg, views); err != nil {
				return fmt.Errorf("send %d: %w", ev.SendID, err)
			}
		case "deliver", "drop", "hold", "offline", "discard":
			at, ok := attempts[ev.SendID]
			if !ok {
				return fmt.Errorf("%w: %d", errQ4TraceNoAttempt, ev.SendID)
			}
			if ev.Kind == "deliver" && !bytes.Equal(ev.Msg.Raw, at.Msg.Raw) {
				return fmt.Errorf("%w: %d", errQ4TraceTampered, ev.SendID)
			}
			if ev.Kind != "hold" {
				outcome[ev.SendID] = true
			}
		}
	}
	for id := range attempts {
		if !outcome[id] {
			return fmt.Errorf("%w: %d", errQ4TraceNoOutcome, id)
		}
	}
	return nil
}

func q4VerifyMsg(m q4Msg, views map[uint64]q4EpochView) error {
	if m.Class != q4Vote && m.Class != q4Timeout {
		return nil
	}
	view, ok := views[m.Epoch]
	if !ok {
		return fmt.Errorf("%w: %d", errQ4TraceEpoch, m.Epoch)
	}
	verifier, ok := view.Verifiers[m.Author]
	if !ok {
		return fmt.Errorf("%w: %s", errQ4TraceAuthor, m.Author)
	}
	var sig []byte
	switch m.Class {
	case q4Vote:
		var v abdrc.VoteMsg
		if err := types.Cbor.Unmarshal(m.Raw, &v); err != nil {
			return fmt.Errorf("%w: %w", errQ4TraceStatement, err)
		}
		sig = v.Signature
		if h, err := v.VoteInfo.Hash(crypto.SHA256); err != nil || !bytes.Equal(h, v.LedgerCommitInfo.PreviousHash) {
			return fmt.Errorf("%w: %s", errQ4TraceMixed, m.Author)
		}
	default:
		var v abdrc.TimeoutMsg
		if err := types.Cbor.Unmarshal(m.Raw, &v); err != nil {
			return fmt.Errorf("%w: %w", errQ4TraceStatement, err)
		}
		sig = v.Signature
	}
	if err := verifier.VerifyBytes(sig, m.Statement); err != nil {
		return fmt.Errorf("%w: %s", errQ4TraceSignature, m.Author)
	}
	return nil
}

// ---- reference schedule ----

// q4RefSchedule is the exact-priority reference of root-wrr-v1 in int64: priorities grow by the weights, the maximum leads (the
// smallest canonical index on a tie) and loses the total. It returns the member index of every round from the epoch start.
func q4RefSchedule(weights []uint64, rounds int) []int {
	prio := make([]int64, len(weights))
	var total int64
	for _, w := range weights {
		total += int64(w)
	}
	out := make([]int, rounds)
	for r := range out {
		win := 0
		for i, w := range weights {
			prio[i] += int64(w)
			if prio[i] > prio[win] {
				win = i
			}
		}
		prio[win] -= total
		out[r] = win
	}
	return out
}

// q4TripleStarts are the round offsets at which three consecutive rounds are all led by members of the responsive set.
func q4TripleStarts(sched []int, responsive uint) []int {
	var out []int
	for i := 0; i+2 < len(sched); i++ {
		if responsive>>sched[i]&1 == 1 && responsive>>sched[i+1]&1 == 1 && responsive>>sched[i+2]&1 == 1 {
			out = append(out, i)
		}
	}
	return out
}

func q4MaxGap(starts []int) (gap int) {
	for i := 1; i < len(starts); i++ {
		gap = max(gap, starts[i]-starts[i-1])
	}
	return gap
}

// q4SufficientWindow is the smallest integer L with L(q-2/3) > m*n+2, q = responsive/total: L(3r-2W) > 3W(mn+2).
func q4SufficientWindow(total, responsive uint64, m, n int) uint64 {
	return 3*total*uint64(m*n+2)/(3*responsive-2*total) + 1
}

func q4NodeInfos(r *q4Roster) []*types.NodeInfo { return r.NodeInfos() }

func q4Leaders(t testing.TB, r *q4Roster, start uint64, from, to uint64) []int {
	t.Helper()
	sel, err := leader.NewWeighted(start, q4NodeInfos(r))
	require.NoError(t, err)
	idx := map[peer.ID]int{}
	for i, e := range r.Entities {
		idx[e.ID] = i
	}
	out := make([]int, 0, to-from+1)
	for round := from; round <= to; round++ {
		id, err := sel.GetLeaderForRound(round)
		require.NoError(t, err)
		out = append(out, idx[id])
	}
	return out
}

func TestQ4QuorumOracle(t *testing.T) {
	a, b := q4DefaultRoster(t, q4SetA), q4DefaultRoster(t, q4SetB)

	t.Run("exhaustive A and B quorums and pairs", func(t *testing.T) {
		qa, qb := q4EnumerateQuorums(a.Weights, a.Quorum()), q4EnumerateQuorums(b.Weights, b.Quorum())
		require.Len(t, qa.Sets, 7, "A: H with any non-empty set of lights")
		require.Len(t, qb.Sets, 3, "B: the complement weighs at most 2")
		for _, s := range qa.Sets {
			require.NotZero(t, s&q4Mask(a, "H"), "every A quorum contains H: the three lights weigh 3")
		}
		for _, s := range qb.Sets {
			require.Equal(t, q4Mask(b, "H1", "H2"), s&q4Mask(b, "H1", "H2"), "omitting either weight-3 identity leaves weight 6 < 7")
		}
		require.Equal(t, uint64(2*7-9), 2*qa.Q-q4Sum(qa.Weights), "the generic lower bound 2Q-W is 5")
		require.EqualValues(t, 6, qa.MinIntersection(), "A: minimum intersection is H alone, weight 6")
		require.EqualValues(t, 6, qb.MinIntersection(), "B: stronger than the generic bound 5")

		// B: one faulty heavy identity is never the whole intersection, the other honest heavy is in it
		for _, h := range []string{"H1", "H2"} {
			for _, p := range qb.Pairs(q4Mask(b, h)) {
				require.False(t, p.SolelyFaulty, "B, only %s Byzantine", h)
				require.NotZero(t, p.Inter&q4Mask(b, map[string]string{"H1": "H2", "H2": "H1"}[h]))
			}
		}
		// A: the pair {H,a}, {H,b} intersects solely in Byzantine H
		var found bool
		for _, p := range qa.Pairs(q4Mask(a, "H")) {
			if p.S == q4Mask(a, "H", "a") && p.T == q4Mask(a, "H", "b") {
				found = true
				require.True(t, p.SolelyFaulty)
				require.EqualValues(t, 6, p.InterWeight)
			}
		}
		require.True(t, found)
		require.EqualValues(t, 7, q4Weight(a.Weights, q4Mask(a, "H", "a")))
		// B optional construction: both heavies Byzantine
		byz := q4Mask(b, "H1", "H2")
		s, u := q4Mask(b, "H1", "H2", "n2"), q4Mask(b, "H1", "H2", "n1")
		require.EqualValues(t, 8, q4Weight(b.Weights, s))
		require.EqualValues(t, 7, q4Weight(b.Weights, u))
		require.EqualValues(t, 6, q4Weight(b.Weights, s&u))
		require.Zero(t, (s&u)&^byz, "the intersection is entirely Byzantine")
	})

	t.Run("A heavy equivocation: the constructive certificate pair, declared outside the assumptions", func(t *testing.T) {
		view := q4View(a, 3)
		stmtA, stmtB := []byte("block A"), []byte("block B")
		qcA := q4Evidence1(a, 3, stmtA, "H", "a")
		qcB := q4Evidence1(a, 3, stmtB, "H", "b")
		wa, err := view.Check(qcA)
		require.NoError(t, err)
		wb, err := view.Check(qcB)
		require.NoError(t, err)
		require.EqualValues(t, 7, wa)
		require.EqualValues(t, 7, wb)
		// the two certificates conflict (same epoch, different statement) and share only the Byzantine signer
		var shared []string
		for id := range qcA.Sigs {
			if _, both := qcB.Sigs[id]; both {
				shared = append(shared, id)
			}
		}
		require.Equal(t, []string{a.Entities[a.Index("H")].ID.String()}, shared)
		// the optional two-heavy B pair
		bv := q4View(b, 3)
		_, err = bv.Check(q4Evidence1(b, 3, stmtA, "H1", "H2", "n2"))
		require.NoError(t, err)
		_, err = bv.Check(q4Evidence1(b, 3, stmtB, "H1", "H2", "n1"))
		require.NoError(t, err)
		// one B heavy cannot form the second certificate: without the other heavy the weight is 3+2+1 = 6
		_, err = bv.Check(q4Evidence1(b, 3, stmtB, "H1", "n2", "n1"))
		require.ErrorIs(t, err, errQ4EvUnderweight)
	})

	t.Run("evidence checks refuse every tampering and each is detected for its own reason", func(t *testing.T) {
		view := q4View(a, 3)
		stmt := []byte("statement")
		good := q4Evidence1(a, 3, stmt, "H", "a")
		_, err := view.Check(good)
		require.NoError(t, err, "control: the untouched evidence verifies")

		mutated := func(f func(ev *q4Evidence)) q4Evidence {
			ev := q4Evidence1(a, 3, stmt, "H", "a")
			f(&ev)
			return ev
		}
		hID, aID := a.Entities[a.Index("H")].ID.String(), a.Entities[a.Index("a")].ID.String()
		cases := map[string]struct {
			ev   q4Evidence
			want error
		}{
			"wrong epoch":                 {mutated(func(ev *q4Evidence) { ev.Epoch = 4 }), errQ4EvEpoch},
			"wrong domain":                {mutated(func(ev *q4Evidence) { ev.Domain = "q4/other/v1" }), errQ4EvDomain},
			"tampered statement":          {mutated(func(ev *q4Evidence) { ev.Statement = []byte("statement!") }), errQ4EvSignature},
			"tampered signature":          {mutated(func(ev *q4Evidence) { ev.Sigs[aID][0] ^= 1 }), errQ4EvSignature},
			"signed in the other epoch":   {mutated(func(ev *q4Evidence) { ev.Sigs[aID] = q4Sign(a.Entities[a.Index("a")].Signer, q4Domain, 4, stmt) }), errQ4EvSignature},
			"signed under another domain": {mutated(func(ev *q4Evidence) { ev.Sigs[aID] = q4Sign(a.Entities[a.Index("a")].Signer, "q4/other/v1", 3, stmt) }), errQ4EvSignature},
			"unknown signer": {mutated(func(ev *q4Evidence) {
				ev.Sigs[q4DefaultRoster(t, q4SetB).Entities[0].ID.String()] = []byte{1}
			}), errQ4EvUnknown},
			"underweight (three lights)": {q4Evidence1(a, 3, stmt, "a", "b", "c"), errQ4EvUnderweight},
			"underweight (H alone)":      {q4Evidence1(a, 3, stmt, "H"), errQ4EvUnderweight},
		}
		for name, tc := range cases {
			_, err := view.Check(tc.ev)
			require.ErrorIs(t, err, tc.want, name)
		}
		_, err = view.CheckList(good, []string{hID, aID, hID})
		require.ErrorIs(t, err, errQ4EvDuplicate, "a signer listed twice is refused, never summed to a quorum")
		_, err = view.CheckList(q4Evidence1(a, 3, stmt, "H"), []string{hID, hID})
		require.ErrorIs(t, err, errQ4EvDuplicate)
	})

	t.Run("equivocation is told from an identical rebroadcast", func(t *testing.T) {
		d := q4Decision{"x", 2, 7, "vote"}
		same := q4Classify(q4SignedStatement{d, []byte("s")}, q4SignedStatement{d, []byte("s")})
		other := q4Classify(q4SignedStatement{d, []byte("s")}, q4SignedStatement{d, []byte("t")})
		diffRound := q4Classify(q4SignedStatement{d, []byte("s")}, q4SignedStatement{q4Decision{"x", 2, 8, "vote"}, []byte("t")})
		require.Equal(t, []string{"rebroadcast", "equivocation", "unrelated"}, []string{same, other, diffRound})
	})

	t.Run("the oracle detects each deliberate corruption of a trace", func(t *testing.T) {
		r := q4DefaultRoster(t, q4SetA)
		views := map[uint64]q4EpochView{1: q4View(r, 1)}
		h, light := r.Entities[r.Index("H")], r.Entities[r.Index("a")]
		vote := func(e *q4Entity, round uint64, hash byte) q4Msg {
			v := NewDummyVote(t, e.ID.String(), round, bytes.Repeat([]byte{hash}, 32))
			v.VoteInfo.Epoch = 1
			require.NoError(t, v.Sign(e.Signer))
			m, err := q4Describe(v)
			require.NoError(t, err)
			return m
		}
		build := func() q4Trace {
			v1, v2 := vote(h, 5, 1), vote(light, 5, 1)
			return q4Trace{
				{Seq: 1, Kind: "attempt", SendID: 1, From: h.ID, To: light.ID, Msg: v1},
				{Seq: 2, Kind: "deliver", SendID: 1, From: h.ID, To: light.ID, Msg: v1},
				{Seq: 3, Kind: "attempt", SendID: 2, From: light.ID, To: h.ID, Msg: v2},
				{Seq: 4, Kind: "drop", SendID: 2, From: light.ID, To: h.ID, Msg: v2},
			}
		}
		require.NoError(t, build().Verify(views), "control: the clean trace verifies")
		require.Empty(t, build().HonestDoubleSigns(views, nil))

		corrupt := map[string]struct {
			f    func(tr q4Trace) q4Trace
			want error
		}{
			"repeated send ID":        {func(tr q4Trace) q4Trace { tr[2].SendID = 1; return tr }, errQ4TraceDuplicateID},
			"delivery of nothing":     {func(tr q4Trace) q4Trace { tr[1].SendID = 9; return tr }, errQ4TraceNoAttempt},
			"delivered bytes differ":  {func(tr q4Trace) q4Trace { tr[1].Msg.Raw = append(slices.Clone(tr[1].Msg.Raw), 0); return tr }, errQ4TraceTampered},
			"attempt without outcome": {func(tr q4Trace) q4Trace { return tr[:3] }, errQ4TraceNoOutcome},
			"unknown epoch":           {func(tr q4Trace) q4Trace { tr[0].Msg.Epoch = 9; return tr }, errQ4TraceEpoch},
			"unknown author":          {func(tr q4Trace) q4Trace { tr[0].Msg.Author = "nobody"; return tr }, errQ4TraceAuthor},
			"mixed statement": {func(tr q4Trace) q4Trace {
				v := NewDummyVote(t, h.ID.String(), 5, bytes.Repeat([]byte{1}, 32))
				v.VoteInfo.Epoch = 1
				require.NoError(t, v.Sign(h.Signer))
				v.VoteInfo.CurrentRootHash = bytes.Repeat([]byte{9}, 32) // validly signed seal, other vote info
				m, err := q4Describe(v)
				require.NoError(t, err)
				tr[0].Msg = m
				return tr
			}, errQ4TraceMixed},
			"forged signature": {func(tr q4Trace) q4Trace {
				m := vote(h, 5, 1)
				m.Author = light.ID.String() // signed by H, claimed by a
				tr[2].Msg = m
				return tr
			}, errQ4TraceSignature},
		}
		for name, tc := range corrupt {
			require.ErrorIs(t, tc.f(build()).Verify(views), tc.want, name)
		}
		// an honest author's second statement for the same decision is found; the same statement again is not
		tr := build()
		again := tr[0]
		again.Seq, again.SendID = 9, 9
		tr = append(tr, again, q4Event{Seq: 10, Kind: "drop", SendID: 9})
		require.Empty(t, tr.HonestDoubleSigns(views, nil), "an identical rebroadcast is no double signature")
		second := vote(h, 5, 2)
		tr = append(tr, q4Event{Seq: 11, Kind: "attempt", SendID: 10, From: h.ID, To: light.ID, Msg: second}, q4Event{Seq: 12, Kind: "drop", SendID: 10})
		require.NoError(t, tr.Verify(views), "a second, validly signed statement is well formed evidence")
		require.Len(t, tr.HonestDoubleSigns(views, nil), 1)
		require.Empty(t, tr.HonestDoubleSigns(views, map[string]bool{h.ID.String(): true}), "a declared Byzantine author is classified, not counted as an honest double signature")
	})
}

func TestQ4Schedule(t *testing.T) {
	// the reference is exact and independent: A repeats H H a H b H c H H from the epoch start for every heavy placement
	for _, arr := range q4Arrangements(q4SetA.Weights) {
		r := q4NewRoster(t, q4SetA, "q4-sched", arr)
		ref := q4RefSchedule(r.Weights, 9*40)
		names := make([]string, 18)
		for i := range names {
			names[i] = r.Entities[ref[i]].Name
		}
		require.Equal(t, strings.Split("H H a H b H c H H H H a H b H c H H", " "), names, "heavy at position %v", arr)
		for i := range ref {
			require.Equal(t, ref[i], ref[i%9], "period 9")
		}
		var gaps []int
		for _, light := range []string{"a", "b", "c"} {
			gaps = append(gaps, q4MaxGap(q4TripleStarts(ref, q4Mask(r, "H", light))))
		}
		require.Equal(t, []int{6, 4, 6}, gaps, "maximum gaps between responsive H+light triples")

		// production selector against the reference, and the query-order invariance of the production selector
		got := q4Leaders(t, r, 1, 1, uint64(len(ref)))
		require.Equal(t, ref, got)
	}

	type responsive struct {
		name string
		set  q4Set
		who  []string
		want uint64
	}
	for _, tc := range []responsive{
		{"A H+light", q4SetA, []string{"H", "a"}, 91},
		{"B 3+3+1", q4SetB, []string{"H1", "H2", "n1"}, 127},
		{"many-small H+light", q4SetManySmall, []string{"H", "l1"}, 595},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arrs := q4Arrangements(tc.set.Weights)
			if len(arrs) > 4 { // B: all 12 placements are covered by the first rows below; many-small: first, middle, last
				arrs = [][]uint64{arrs[0], arrs[len(arrs)/2], arrs[len(arrs)-1]}
			}
			for _, arr := range arrs {
				r := q4NewRoster(t, tc.set, "q4-sched", arr)
				resp := q4Mask(r, tc.who...)
				L := q4SufficientWindow(r.Total(), r.Weight(tc.who...), len(tc.who), len(r.Entities))
				require.Equal(t, tc.want, L, "the sufficient window")
				// every window of L rounds, anywhere in 3L rounds of the exact schedule, holds a responsive triple
				ref := q4RefSchedule(r.Weights, int(3*L))
				starts := q4TripleStarts(ref, resp)
				require.NotEmpty(t, starts)
				require.Less(t, uint64(q4MaxGap(starts)), L, "a triple recurs within the window")
				require.Less(t, uint64(starts[0]), L)

				// production equals the reference, whatever the query order, a jump, a restart or an epoch reset
				fresh := func(start uint64) *leader.Weighted {
					sel, err := leader.NewWeighted(start, r.NodeInfos())
					require.NoError(t, err)
					return sel
				}
				at := func(sel *leader.Weighted, round uint64) int {
					id, err := sel.GetLeaderForRound(round)
					require.NoError(t, err)
					for i, e := range r.Entities {
						if e.ID == id {
							return i
						}
					}
					return -1
				}
				const start = 40
				long := q4RefSchedule(r.Weights, 2100)
				jump := fresh(start)
				for _, rd := range []uint64{start + 500, start + 3, start + 3, start + 2000, start, start + 499, start + 1} { // out of order, repeated, jumping
					require.Equal(t, long[rd-start], at(jump, rd), "round %d", rd)
				}
				asc := fresh(start)
				for rd := uint64(start); rd < start+100; rd++ { // ascending, against a selector that is built fresh for each query (a restart)
					require.Equal(t, long[rd-start], at(asc, rd))
					require.Equal(t, long[rd-start], at(fresh(start), rd), "restart at round %d", rd)
				}
				// epoch reset: an epoch that starts at round 40 repeats the schedule of an epoch that starts at round 1
				require.Equal(t, q4Leaders(t, r, 1, 1, 100), q4Leaders(t, r, start, start, start+99), "epoch reset")
			}
		})
	}
}
