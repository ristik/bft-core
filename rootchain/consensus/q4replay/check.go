package q4replay

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"slices"
	"sort"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// Violations. Each check fails with its own sentinel so a negative test (and a reader of the report) can tell the reasons apart.
var (
	ErrFormat          = errors.New("q4replay: unsupported bundle format")
	ErrManifest        = errors.New("q4replay manifest: invalid epoch membership")
	ErrArithmetic      = errors.New("q4replay manifest: claimed total, quorum or faulty weight differs from the weights")
	ErrByzantineName   = errors.New("q4replay manifest: declared Byzantine name is not a member")
	ErrClass           = errors.New("q4replay manifest: claimed assumption class differs from the Byzantine weight")
	ErrDuplicateSend   = errors.New("q4replay trace: send ID repeated")
	ErrNoAttempt       = errors.New("q4replay trace: delivery, drop or hold without an attempt")
	ErrTampered        = errors.New("q4replay trace: delivered bytes differ from the attempted bytes")
	ErrNoOutcome       = errors.New("q4replay trace: attempt without delivery, drop, hold or offline outcome")
	ErrNoRaw           = errors.New("q4replay trace: attempt without the serialized message")
	ErrDecode          = errors.New("q4replay message: serialized message does not decode")
	ErrClaim           = errors.New("q4replay message: claimed class, epoch, round or author differs from the bytes")
	ErrUnknownEpoch    = errors.New("q4replay message: epoch is not in the manifest")
	ErrUnknownAuthor   = errors.New("q4replay message: author is not a member of its epoch")
	ErrStatement       = errors.New("q4replay message: signed statement cannot be derived")
	ErrSignature       = errors.New("q4replay message: signature does not verify")
	ErrProposalRound   = errors.New("q4replay message: proposal round does not follow its certificate")
	ErrCertificate     = errors.New("q4replay message: carried certificate has an unknown or duplicate signer or too little weight")
	ErrHonestDoubleSig = errors.New("q4replay safety: an honest member signed two statements for one decision")
	ErrEquivocator     = errors.New("q4replay safety: equivocator set differs from the declared Byzantine set")
	ErrChainConflict   = errors.New("q4replay safety: two nodes committed different blocks for one round")
	ErrChainShared     = errors.New("q4replay safety: two nodes share no committed round, so agreement is unevidenced")
	ErrChainParent     = errors.New("q4replay safety: committed block does not extend a lower round")
	ErrMalformedCount  = errors.New("q4replay trace: malformed sends differ from the declared injections")
	ErrWindow          = errors.New("q4replay window: malformed expectation")
	ErrNoProgress      = errors.New("q4replay timing: fewer ordinary commits than required inside the frozen deadline")
	ErrCommitGap       = errors.New("q4replay timing: commit gap above the frozen bound")
	ErrStalled         = errors.New("q4replay timing: ordinary commit inside a stall window")
)

// Report is the offline verdict of one bundle. Errors is every violation found (each wraps one sentinel); the counters say what was
// actually examined, so an empty bundle cannot pass for a clean one.
type Report struct {
	Scenario string `json:"scenario"`
	Coverage string `json:"coverage"`
	Class    string `json:"class"`
	// ComputedClass is the class recomputed from the declared Byzantine weight and the epoch's faulty bound.
	ComputedClass string `json:"computedClass"`
	Attempts      int    `json:"attempts"`
	Deliveries    int    `json:"deliveries"`
	Signed        int    `json:"signed"` // votes and timeouts whose signature was verified
	Proposals     int    `json:"proposals"`
	Other         int    `json:"other"`        // attempts of a class that carries no round statement (accounted for, not signature checked)
	Certificates  int    `json:"certificates"` // carried QCs whose signer weight was checked
	// Unchecked counts carried certificates the checker could not weigh (unknown epoch or no signatures: a genesis or anchor).
	Unchecked int `json:"unchecked"`
	// Malformed are the sends flagged as forged, mixed-statement, undecodable or from a non-member, with the reason; they are
	// violations unless the bundle declared exactly that many injections.
	Malformed   []string            `json:"malformed,omitempty"`
	Equivocated map[string][]string `json:"equivocated,omitempty"` // member name -> decisions with two statements
	Windows     []WindowResult      `json:"windows,omitempty"`
	Errors      []string            `json:"errors,omitempty"`
	errs        []error
}

// WindowResult is the recomputed timing of one window.
type WindowResult struct {
	Name         string `json:"name"`
	Expect       string `json:"expect"`
	FirstMs      int64  `json:"firstCommitMs,omitempty"`
	LastNthMs    int64  `json:"nthCommitMs,omitempty"`
	MaxGapMs     int64  `json:"maxCommitGapMs,omitempty"`
	CommitsInWin int    `json:"commits"`
}

// Err is nil for a clean bundle, otherwise every violation joined (errors.Is finds each sentinel).
func (r *Report) Err() error { return errors.Join(r.errs...) }

func (r *Report) fail(err error) {
	r.errs = append(r.errs, err)
	r.Errors = append(r.Errors, err.Error())
}

type member struct {
	Member
	verifier abcrypto.Verifier
}

type epochView struct {
	Epoch
	by map[string]*member
}

// Check re-derives every verdict of the bundle.
func Check(b *Bundle) *Report {
	r := &Report{Scenario: b.Scenario, Coverage: b.Coverage, Class: b.Class}
	if b.Version != Version {
		r.fail(fmt.Errorf("%w: version %d", ErrFormat, b.Version))
		return r
	}
	views := checkManifest(b, r)
	byzantine := declared(b, views, r)
	checkTrace(b, views, byzantine, r)
	checkChains(b, r)
	checkWindows(b, r)
	return r
}

func checkManifest(b *Bundle, r *Report) map[uint64]*epochView {
	views := map[uint64]*epochView{}
	for _, e := range b.Epochs {
		v := &epochView{Epoch: e, by: map[string]*member{}}
		if _, dup := views[e.Epoch]; dup || len(e.Members) == 0 {
			r.fail(fmt.Errorf("%w: epoch %d", ErrManifest, e.Epoch))
			continue
		}
		names := map[string]bool{}
		keys := map[string]bool{}
		var total uint64
		ok := true
		for _, m := range e.Members {
			ver, err := abcrypto.NewVerifierSecp256k1(m.PubKey)
			if err != nil || m.Weight == 0 || m.ID == "" || names[m.Name] || keys[string(m.PubKey)] || v.by[m.ID] != nil || total+m.Weight < total {
				r.fail(fmt.Errorf("%w: epoch %d member %q", ErrManifest, e.Epoch, m.Name))
				ok = false
				continue
			}
			names[m.Name], keys[string(m.PubKey)] = true, true
			v.by[m.ID] = &member{Member: m, verifier: ver}
			total += m.Weight
		}
		if e.Scheme == votesig.SchemeDomainBound && len(e.Genesis) != 32 {
			r.fail(fmt.Errorf("%w: epoch %d scheme 2 without a 32 byte genesis", ErrManifest, e.Epoch))
			ok = false
		}
		if !ok {
			continue
		}
		q := 2*total/3 + 1
		if e.Total != total || e.Quorum != q || e.Faulty != total-q {
			r.fail(fmt.Errorf("%w: epoch %d claims W=%d Q=%d F=%d, weights give W=%d Q=%d F=%d", ErrArithmetic, e.Epoch, e.Total, e.Quorum, e.Faulty, total, q, total-q))
		}
		v.Total, v.Quorum, v.Faulty = total, q, total-q // from here on the recomputed values, never the claimed ones
		views[e.Epoch] = v
	}
	return views
}

// declared resolves the Byzantine names to member IDs and recomputes the assumption class: IN-BOUND exactly when the declared
// Byzantine weight is at most the faulty bound of every epoch.
func declared(b *Bundle, views map[uint64]*epochView, r *Report) map[string]bool {
	ids := map[string]bool{}
	for _, name := range b.Byzantine {
		found := false
		for _, v := range views {
			for id, m := range v.by {
				if m.Name == name {
					found, ids[id] = true, true
				}
			}
		}
		if !found {
			r.fail(fmt.Errorf("%w: %q", ErrByzantineName, name))
		}
	}
	class := InBound
	for _, v := range views {
		var w uint64
		for id, m := range v.by {
			if ids[id] {
				w += m.Weight
			}
		}
		if w > v.Faulty {
			class = OutsideAssumptions
		}
	}
	r.ComputedClass = class
	if b.Class != class {
		r.fail(fmt.Errorf("%w: claims %s, Byzantine weight gives %s", ErrClass, b.Class, class))
	}
	return ids
}

type decision struct {
	author string
	epoch  uint64
	round  uint64
	kind   string
}

func checkTrace(b *Bundle, views map[uint64]*epochView, byzantine map[string]bool, r *Report) {
	attempts := map[uint64]Event{}
	outcome := map[uint64]bool{}
	statements := map[decision]map[string]bool{}
	var malformedErrs []error
	for _, ev := range b.Events {
		switch ev.Kind {
		case "attempt":
			r.Attempts++
			if _, dup := attempts[ev.SendID]; dup {
				r.fail(fmt.Errorf("%w: %d", ErrDuplicateSend, ev.SendID))
				continue
			}
			attempts[ev.SendID] = ev
			if ev.Class != "vote" && ev.Class != "timeout" && ev.Class != "proposal" {
				r.Other++ // state sync, change requests and the like: no signed round statement to verify, only its accounting above
				continue
			}
			if len(ev.Raw) == 0 {
				r.fail(fmt.Errorf("%w: send %d", ErrNoRaw, ev.SendID))
				continue
			}
			if d, stmt, err := checkMessage(ev, views, r); err != nil {
				if malformed(err) {
					r.Malformed = append(r.Malformed, fmt.Sprintf("send %d: %v", ev.SendID, err))
					malformedErrs = append(malformedErrs, fmt.Errorf("send %d: %w", ev.SendID, err))
				} else {
					r.fail(fmt.Errorf("send %d: %w", ev.SendID, err))
				}
			} else if d.kind == "vote" || d.kind == "timeout" {
				if statements[d] == nil {
					statements[d] = map[string]bool{}
				}
				statements[d][string(stmt)] = true
			}
		case "deliver", "drop", "hold", "offline", "discard":
			at, ok := attempts[ev.SendID]
			if !ok {
				r.fail(fmt.Errorf("%w: %d", ErrNoAttempt, ev.SendID))
				continue
			}
			if ev.Kind == "deliver" {
				r.Deliveries++
				if !bytes.Equal(ev.Raw, at.Raw) {
					r.fail(fmt.Errorf("%w: %d", ErrTampered, ev.SendID))
				}
			}
			if ev.Kind != "hold" {
				outcome[ev.SendID] = true
			}
		}
	}
	for id := range attempts {
		if !outcome[id] {
			r.fail(fmt.Errorf("%w: %d", ErrNoOutcome, id))
		}
	}

	if len(r.Malformed) != b.Injected {
		r.fail(fmt.Errorf("%w: %d flagged, %d declared: %w", ErrMalformedCount, len(r.Malformed), b.Injected, errors.Join(malformedErrs...)))
	}

	// equivocation: two different verified statements for one (author, epoch, round, kind)
	r.Equivocated = map[string][]string{}
	for d, set := range statements {
		if len(set) < 2 {
			continue
		}
		name := d.author
		if m := views[d.epoch].by[d.author]; m != nil {
			name = m.Name
		}
		r.Equivocated[name] = append(r.Equivocated[name], fmt.Sprintf("%s e%d r%d", d.kind, d.epoch, d.round))
		if !byzantine[d.author] {
			r.fail(fmt.Errorf("%w: %s %s round %d", ErrHonestDoubleSig, name, d.kind, d.round))
		}
	}
	for _, ds := range r.Equivocated {
		sort.Strings(ds)
	}
	if len(r.Equivocated) == 0 {
		r.Equivocated = nil
	}
	// A declared Byzantine member that never equivocated is not an error (it may only have withheld); an equivocator outside the
	// declared set is the honest double sign above. The exact-set claim is made by ExpectEquivocators.
}

// malformed says whether a per-message error is the message's own defect (what an injected forgery looks like) rather than a defect
// of the bundle.
func malformed(err error) bool {
	for _, target := range []error{ErrSignature, ErrStatement, ErrDecode, ErrClaim, ErrUnknownAuthor, ErrProposalRound, ErrCertificate} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// ExpectEquivocators fails unless the bundle's recomputed equivocators are exactly the named members.
func (r *Report) ExpectEquivocators(names ...string) error {
	var got []string
	for n := range r.Equivocated {
		got = append(got, n)
	}
	sort.Strings(got)
	want := slices.Clone(names)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		return fmt.Errorf("%w: found %v, declared %v", ErrEquivocator, got, want)
	}
	return nil
}

// checkMessage recomputes the claims of one attempt from its bytes and verifies its signature. It returns the decision key and the
// signed statement of a vote or timeout.
func checkMessage(ev Event, views map[uint64]*epochView, r *Report) (decision, []byte, error) {
	switch ev.Class {
	case "vote":
		var v abdrc.VoteMsg
		if err := types.Cbor.Unmarshal(ev.Raw, &v); err != nil || v.VoteInfo == nil || v.LedgerCommitInfo == nil {
			return decision{}, nil, fmt.Errorf("%w: vote", ErrDecode)
		}
		if err := claim(ev, "vote", v.VoteInfo.Epoch, v.VoteInfo.RoundNumber, v.Author); err != nil {
			return decision{}, nil, err
		}
		view, m, err := author(views, v.VoteInfo.Epoch, v.Author)
		if err != nil {
			return decision{}, nil, err
		}
		var stmt []byte
		if v.Scheme == votesig.SchemeDomainBound {
			cfg, err := config(view)
			if err != nil {
				return decision{}, nil, err
			}
			stmt, _, _, err = drctypes.DomainBoundStatement(cfg, v.VoteInfo, v.LedgerCommitInfo, len(v.SealSignature) != 0)
			if err != nil {
				return decision{}, nil, fmt.Errorf("%w: %w", ErrStatement, err)
			}
		} else {
			h, err := v.VoteInfo.Hash(crypto.SHA256)
			if err != nil || !bytes.Equal(h, v.LedgerCommitInfo.PreviousHash) {
				return decision{}, nil, fmt.Errorf("%w: the seal does not sign the vote info the vote carries", ErrStatement)
			}
			if stmt, err = v.LedgerCommitInfo.SigBytes(); err != nil {
				return decision{}, nil, fmt.Errorf("%w: %w", ErrStatement, err)
			}
		}
		if err := m.verifier.VerifyBytes(v.Signature, stmt); err != nil {
			return decision{}, nil, fmt.Errorf("%w: %s", ErrSignature, m.Name)
		}
		r.Signed++
		return decision{v.Author, v.VoteInfo.Epoch, v.VoteInfo.RoundNumber, "vote"}, stmt, nil
	case "timeout":
		var v abdrc.TimeoutMsg
		if err := types.Cbor.Unmarshal(ev.Raw, &v); err != nil || v.Timeout == nil {
			return decision{}, nil, fmt.Errorf("%w: timeout", ErrDecode)
		}
		if err := claim(ev, "timeout", v.Timeout.Epoch, v.Timeout.Round, v.Author); err != nil {
			return decision{}, nil, err
		}
		view, m, err := author(views, v.Timeout.Epoch, v.Author)
		if err != nil {
			return decision{}, nil, err
		}
		var stmt []byte
		if v.Scheme == votesig.SchemeDomainBound {
			cfg, err := config(view)
			if err != nil {
				return decision{}, nil, err
			}
			if stmt, err = v.Preimage(cfg); err != nil {
				return decision{}, nil, fmt.Errorf("%w: %w", ErrStatement, err)
			}
		} else {
			stmt = v.Bytes()
		}
		if err := m.verifier.VerifyBytes(v.Signature, stmt); err != nil {
			return decision{}, nil, fmt.Errorf("%w: %s", ErrSignature, m.Name)
		}
		r.Signed++
		return decision{v.Author, v.Timeout.Epoch, v.Timeout.Round, "timeout"}, stmt, nil
	case "proposal":
		var p abdrc.ProposalMsg
		if err := types.Cbor.Unmarshal(ev.Raw, &p); err != nil || p.Block == nil {
			return decision{}, nil, fmt.Errorf("%w: proposal", ErrDecode)
		}
		if err := claim(ev, "proposal", p.Block.Epoch, p.Block.Round, p.Block.Author); err != nil {
			return decision{}, nil, err
		}
		_, m, err := author(views, p.Block.Epoch, p.Block.Author)
		if err != nil {
			return decision{}, nil, err
		}
		bb, err := p.Block.Bytes()
		if err != nil {
			return decision{}, nil, fmt.Errorf("%w: %w", ErrStatement, err)
		}
		if err := m.verifier.VerifyBytes(p.Signature, bb); err != nil {
			return decision{}, nil, fmt.Errorf("%w: %s", ErrSignature, m.Name)
		}
		var tcRound uint64
		if p.LastRoundTc != nil && p.LastRoundTc.Timeout != nil {
			tcRound = p.LastRoundTc.Timeout.Round
		}
		if p.Block.Round-1 != max(p.Block.GetParentRound(), tcRound) {
			return decision{}, nil, fmt.Errorf("%w: round %d", ErrProposalRound, p.Block.Round)
		}
		r.Proposals++
		if qc := p.Block.Qc; qc != nil && qc.VoteInfo != nil {
			if err := certificate(qc, views, r); err != nil {
				return decision{}, nil, err
			}
		}
		return decision{p.Block.Author, p.Block.Epoch, p.Block.Round, "proposal"}, nil, nil
	}
	return decision{}, nil, nil
}

// certificate weighs a carried QC under its own epoch: every signer a distinct member, the weight at least that epoch's quorum. The
// signatures themselves are not re-verified here (a scheme 2 QC carries the PV signatures, whose statement needs the full round
// data), so this is the weight check only and the report says how many certificates it covered.
func certificate(qc *drctypes.QuorumCert, views map[uint64]*epochView, r *Report) error {
	view, ok := views[qc.VoteInfo.Epoch]
	if !ok || len(qc.Signatures) == 0 {
		r.Unchecked++
		return nil
	}
	var w uint64
	for id := range qc.Signatures { // a map cannot hold a signer twice
		m := view.by[id]
		if m == nil {
			return fmt.Errorf("%w: signer %s", ErrCertificate, id)
		}
		w += m.Weight
	}
	if w < view.Quorum {
		return fmt.Errorf("%w: %d of %d", ErrCertificate, w, view.Quorum)
	}
	r.Certificates++
	return nil
}

func claim(ev Event, class string, epoch, round uint64, author string) error {
	if ev.Class != class || ev.Epoch != epoch || ev.Round != round || ev.Author != author {
		return fmt.Errorf("%w: claims %s e%d r%d by %s, bytes say %s e%d r%d by %s", ErrClaim, ev.Class, ev.Epoch, ev.Round, ev.Author, class, epoch, round, author)
	}
	return nil
}

func author(views map[uint64]*epochView, epoch uint64, id string) (*epochView, *member, error) {
	view, ok := views[epoch]
	if !ok {
		return nil, nil, fmt.Errorf("%w: %d", ErrUnknownEpoch, epoch)
	}
	m := view.by[id]
	if m == nil {
		return nil, nil, fmt.Errorf("%w: %s in epoch %d", ErrUnknownAuthor, id, epoch)
	}
	return view, m, nil
}

func config(v *epochView) (votesig.Config, error) {
	var g [32]byte
	copy(g[:], v.Genesis)
	cfg := votesig.Config{Scheme: v.Scheme, Network: v.Network, Genesis: g}
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("%w: %w", ErrStatement, err)
	}
	return cfg, nil
}

// checkChains: no two nodes committed different blocks for one round, every pair of nodes shares a committed round, and a block
// extends a lower round.
func checkChains(b *Bundle, r *Report) {
	for _, c := range b.Chains {
		for _, blk := range c.Blocks {
			if blk.Parent >= blk.Round {
				r.fail(fmt.Errorf("%w: %s round %d parent %d", ErrChainParent, c.Node, blk.Round, blk.Parent))
			}
		}
	}
	for i, a := range b.Chains {
		for _, o := range b.Chains[i+1:] {
			have := map[uint64][]byte{}
			for _, blk := range a.Blocks {
				have[blk.Round] = blk.Hash
			}
			shared := 0
			for _, blk := range o.Blocks {
				if h, ok := have[blk.Round]; ok {
					shared++
					if !bytes.Equal(h, blk.Hash) {
						r.fail(fmt.Errorf("%w: round %d, %s and %s", ErrChainConflict, blk.Round, a.Node, o.Node))
					}
				}
			}
			if shared == 0 {
				r.fail(fmt.Errorf("%w: %s and %s", ErrChainShared, a.Node, o.Node))
			}
		}
	}
}

// checkWindows judges the recorded commit times against the frozen bounds: a progress window needs MinCommits ordinary commits per
// node within the frozen deadline (and no gap above the frozen maximum); a stall window needs none.
func checkWindows(b *Bundle, r *Report) {
	obs := map[string][]Observe{}
	for _, c := range b.Chains {
		obs[c.Node] = c.Observed
	}
	for _, w := range b.Windows {
		res := WindowResult{Name: w.Name, Expect: w.Expect}
		if len(w.Nodes) == 0 {
			r.fail(fmt.Errorf("%w: %q names no node", ErrWindow, w.Name))
			continue
		}
		switch w.Expect {
		case "progress":
			if w.MinCommits <= 0 || b.Frozen.DeadlineMs <= 0 {
				r.fail(fmt.Errorf("%w: %q needs minCommits and a frozen deadline", ErrWindow, w.Name))
				continue
			}
			end := w.StartMs + b.Frozen.DeadlineMs
			for _, n := range w.Nodes {
				var in []int64
				for _, o := range obs[n] {
					if o.AtMs >= w.StartMs && o.AtMs <= end {
						in = append(in, o.AtMs)
					}
				}
				sort.Slice(in, func(i, j int) bool { return in[i] < in[j] })
				if len(in) < w.MinCommits {
					r.fail(fmt.Errorf("%w: window %q node %s has %d of %d", ErrNoProgress, w.Name, n, len(in), w.MinCommits))
					continue
				}
				res.CommitsInWin += len(in)
				res.FirstMs = max(res.FirstMs, in[0]-w.StartMs)
				res.LastNthMs = max(res.LastNthMs, in[w.MinCommits-1]-w.StartMs)
				prev := w.StartMs
				for _, at := range in {
					res.MaxGapMs = max(res.MaxGapMs, at-prev)
					prev = at
				}
				if b.Frozen.MaxCommitGapMs > 0 && res.MaxGapMs > b.Frozen.MaxCommitGapMs {
					r.fail(fmt.Errorf("%w: window %q node %s gap %dms > %dms", ErrCommitGap, w.Name, n, res.MaxGapMs, b.Frozen.MaxCommitGapMs))
				}
			}
		case "stall":
			if w.EndMs <= w.StartMs {
				r.fail(fmt.Errorf("%w: %q has no span", ErrWindow, w.Name))
				continue
			}
			for _, n := range w.Nodes {
				for _, o := range obs[n] {
					if o.AtMs >= w.StartMs && o.AtMs <= w.EndMs {
						res.CommitsInWin++
						r.fail(fmt.Errorf("%w: window %q node %s committed round %d", ErrStalled, w.Name, n, o.Round))
					}
				}
			}
		default:
			r.fail(fmt.Errorf("%w: %q expects %q", ErrWindow, w.Name, w.Expect))
			continue
		}
		r.Windows = append(r.Windows, res)
	}
}
