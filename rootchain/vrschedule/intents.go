// Package vrschedule is the root side of the validator-registry (VR) handoff protocol (VT-05b, ristik/bft-core#1159; design section
// 5.3): it observes VR's published outputs at the EVM blocks the committed root chain certifies (stage 0), derives the intent the
// executor judges HandoffView and Freeze v5 against (storage.VRIntents, over vrhandoff), and holds the root's protocol state.
package vrschedule

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/vrstate"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// ErrUnavailable reports an intent this root cannot derive yet because an off-consensus input is missing: R's committed source or VR's
// output at the latest certified EVM block has not been observed. It is unavailable, never false: the executor does not vote.
var ErrUnavailable = errors.New("vrschedule: intent input not observed yet")

// Intents is storage.VRIntents over the observed sources and outputs (vrhandoff.NewIntent).
//
// A Freeze v5 query derives the intent from committed history and the VR proof at P alone: the output state is the Freeze's own witness,
// verified here against P's certified state root, the members and changes are the certified candidate's (hash-verified against that
// proof), and the candidate must be exactly the derived unsigned candidate plus valid possession proofs. Only the source (stage 0) is
// read from the observed history. Any other query (a HandoffView, the committed opening) reads VR's output at the latest certified EVM
// block from the observer's cache.
type Intents struct {
	Deployment vradmit.Deployment
	Pins       vrstate.Pins
	// Config is the chain's Q3 protocol configuration: its Genesis is the intent's genesis, and the successor body carries it.
	Config  func() (q3format.ProtocolConfig, error)
	Sources *Sources
	Outputs *Outputs
	// Fetch reads VR's open output at a certified EVM block the cache does not hold (a HandoffView judged over an executed, uncommitted
	// parent): verified against the state root, then cached. Nil leaves an uncached state unavailable.
	Fetch func(blockHash, stateRoot [32]byte) (*vrhandoff.Output, error)
	// MissingSource is told that a derivation lacked the source of a result this root never observed (it joined or restarted after R's
	// publication): the node asks its peers for it (FetchSource), never blocking the derivation. Nil leaves it unavailable.
	MissingSource func(r vrschema.Word)
}

func (p *Intents) Intent(q storage.VRIntentQuery) (storage.VRIntent, bool, error) {
	d, ok, err := p.Derive(q)
	if err != nil || !ok {
		return storage.VRIntent{}, ok, err
	}
	return d.VRIntent, true, nil
}

// Derived is everything one derivation yields: the executor's view (digest, anchor and, for a Freeze, the body and trust base), the intent
// itself, and the context a successor body of it is derived over.
type Derived struct {
	storage.VRIntent
	Intent    vrhandoff.Intent
	RootEpoch uint64
	Body      vrhandoff.BodyContext
}

// Derive is Intent with the intent itself.
func (p *Intents) Derive(q storage.VRIntentQuery) (Derived, bool, error) { return p.derive(q, true) }

// DeriveCached is Derive from the observer's cache only: an uncached output is unavailable, never fetched (a leader's own checks, which
// must not wait on the execution client).
func (p *Intents) DeriveCached(q storage.VRIntentQuery) (Derived, bool, error) {
	return p.derive(q, false)
}

func (p *Intents) derive(q storage.VRIntentQuery, fetch bool) (Derived, bool, error) {
	var none Derived
	if q.Control == nil || q.Root == nil || p.Config == nil || p.Sources == nil {
		return none, false, fmt.Errorf("%w: no context", ErrUnavailable)
	}
	state, err := vradmit.DecodeRootState(q.Control.VR)
	if err != nil {
		return none, false, err
	}
	b := q.Backoff
	if b.Epoch != q.Epoch {
		return none, false, nil // the epoch's first attempt opens at the end of its first block
	}
	var out vrhandoff.Output
	if q.Candidate != nil {
		c, err := vrschema.DecodeCandidateV6(q.Candidate)
		if err != nil || len(c.SourceRef) != 32 {
			return none, false, nil
		}
		r := vrschema.Word(c.SourceRef)
		s, err := vrstate.VerifyOutput(q.Witness, q.LatestEVMRoot, p.Pins, r)
		if err != nil {
			return none, false, nil // admission refuses the witness; no intent rests on it
		}
		changes := append([]vrschema.RegistryChange(nil), c.RegistryChanges...)
		for i := range changes {
			changes[i].Verdict = 0
		}
		out = vrhandoff.Output{State: s, Members: c.Identities, Changes: changes}
	} else {
		if !q.LatestEVMOK || p.Outputs == nil {
			return none, false, nil
		}
		o, ok := p.Outputs.At(q.LatestEVMRoot)
		if !ok && fetch && p.Fetch != nil && len(q.LatestEVMBlock) == 32 {
			fetched, err := p.Fetch([32]byte(q.LatestEVMBlock), q.LatestEVMRoot)
			if err == nil {
				p.Outputs.Put(q.LatestEVMRoot, fetched)
				o, ok = fetched, true
			}
		}
		if !ok {
			return none, false, fmt.Errorf("%w: VR at the certified EVM state %x", ErrUnavailable, q.LatestEVMRoot[:8])
		}
		if o == nil {
			return none, false, nil // no open Published output there
		}
		out = *o
	}
	r := out.State.ResultID
	src, ok := p.Sources.Get(r)
	if !ok {
		if p.MissingSource != nil {
			p.MissingSource(r)
		}
		return none, false, fmt.Errorf("%w: the source of %x", ErrUnavailable, r[:8])
	}
	facts, err := q.Root()
	if err != nil {
		return none, false, err
	}
	cfg, err := p.Config()
	if err != nil {
		return none, false, err
	}
	// the predecessor every record of the epoch names is the authority's (the control state carries zero at the genesis epoch)
	predecessor := facts.Predecessor
	if predecessor == nil {
		predecessor = q.Control.PredecessorBodyID
	}
	if len(predecessor) != 32 {
		return none, false, fmt.Errorf("%w: predecessor", ErrUnavailable)
	}
	rc := vrhandoff.RootContext{Deployment: p.Deployment, Genesis: cfg.Genesis, RootEpoch: q.Epoch, Predecessor: [32]byte(predecessor),
		Attempt: b.Attempt, AttemptOpenRound: state.AttemptOpenRound, Installed: facts.Installed, Lifecycle: facts.Lifecycle, Fold: facts.Fold}
	in, d, err := vrhandoff.NewIntent(rc, src.Source, out)
	if errors.Is(err, vrhandoff.ErrIntent) {
		return none, false, nil
	}
	if err != nil {
		return none, false, err
	}
	v := Derived{VRIntent: storage.VRIntent{Digest: d, AnchorRound: in.AnchorRound, AnchorUCTime: AnchorUCTime(src, state)}, Intent: in, RootEpoch: q.Epoch,
		Body: vrhandoff.BodyContext{PredecessorLink: facts.Link, Config: cfg}}
	if q.Candidate == nil {
		return v, true, nil
	}
	if _, err := vrhandoff.VerifyAssembly(in, vrhandoff.Assembly{IntentDigest: d[:], Candidate: q.Candidate}); err != nil {
		return none, false, nil
	}
	if v.VRIntent.Body, err = vrhandoff.DeriveBody(in, q.Epoch, sha256.Sum256(q.Candidate), v.Body); err != nil {
		return none, false, nil
	}
	if _, v.TrustBase, err = vrhandoff.TrustBase(in, q.Epoch); err != nil {
		return none, false, nil
	}
	return v, true, nil
}

// AnchorUCTime is openTime(0): the committed UC time of the anchor block, which is the source's certifying block or the block that opened
// the attempt, whichever is later.
func AnchorUCTime(src SourceEntry, state vradmit.RootState) uint64 {
	if src.CertRootRound >= state.AttemptOpenRound {
		return src.CertUCTime
	}
	return state.AttemptOpenUCTime
}
