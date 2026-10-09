package q3format

import (
	"bytes"
	"errors"
	"fmt"
)

var (
	// ErrEnvelope is returned for an envelope that is well formed CBOR but not a valid lineage segment: links that repeat or skip
	// an epoch, or an inconsistent claim.
	ErrEnvelope = errors.New("q3format: invalid proof envelope")
	// ErrConflict is returned when an envelope link names an epoch the history already holds, differently.
	ErrConflict = errors.New("q3format: envelope conflicts with the verified history")
)

// The proposed transport limits (briefs/q3-design-v2.md section 2), to be checked against maximum-size valid fixtures before
// they are frozen: a longer history travels in consecutive segments, and nothing is ever omitted to fit.
const (
	EnvelopeVersion  = 1
	MaxLinks         = 64
	MaxEnvelopeBytes = 16 << 20
	MaxTransitions   = 64
	envelopeDomain   = "UNICITY_Q3_EXECUTION_PROOF"
	maxRootInput     = 1 << 20
	maxTransition    = 64 << 10
	maxEvidence      = maxField
	digestLen        = 32
)

// Envelope is Q3ExecutionProofV1: the canonical root input and compact transitions an execution job rests on, the target EVM
// parent (and the block, for an import or replay), and an ordered lineage segment. The root-genesis anchor and the execution
// genesis are pinned locally and never supplied by an envelope. The first two fields are opaque here; their authentication
// against the verified context is the Ureth verifier's work (slice C2).
type Envelope struct {
	RootInput    []byte
	Transitions  [][]byte
	TargetParent []byte
	BlockID      []byte // empty for a build job
	Links        []Link
}

func evidenceItems(e Evidence) []any { return []any{e.Summary, e.FrozenParent, e.CandidateDigest} }

func (c Claim) items() []any {
	return []any{c.Epoch, c.Start, c.BodyID[:], c.CommitID[:], c.PriorVersion, c.PriorID[:]}
}

// Encode is the canonical envelope. It refuses whatever DecodeEnvelope would (counts, sizes, bodies, epoch order), so a sender
// cannot emit an envelope that a receiver cannot read, or one that omits proof to fit.
func (e Envelope) Encode() ([]byte, error) {
	trans := make([]any, len(e.Transitions))
	for i, t := range e.Transitions {
		trans[i] = t
	}
	links := make([]any, len(e.Links))
	for i, l := range e.Links {
		preimage := l.Preimage
		if preimage == nil {
			preimage = []byte{} // an absent preimage is the empty byte string, never null
		}
		links[i] = []any{l.Body.Encode(), l.Claim.items(), evidenceItems(l.Evidence), preimage, l.Proof, receiptItems(l.Receipts)}
	}
	var block any
	if len(e.BlockID) != 0 {
		block = e.BlockID
	}
	raw := enc(envelopeDomain, uint64(EnvelopeVersion), e.RootInput, trans, e.TargetParent, block, links)
	if _, err := DecodeEnvelope(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// DecodeEnvelope parses a canonical envelope within the limits, checking every count and length before it is used. It
// refuses an unknown version, noncanonical or truncated bytes, an invalid embedded body, and links that are not strictly
// consecutive epochs, which also excludes duplicate and conflicting entries.
func DecodeEnvelope(raw []byte) (Envelope, error) {
	r, err := parse(raw, MaxEnvelopeBytes)
	if err != nil {
		return Envelope{}, err
	}
	r.expect(envelopeDomain)
	if v := r.uint(); r.err == nil && v != EnvelopeVersion {
		return Envelope{}, fmt.Errorf("%w: envelope version %d", ErrVersion, v)
	}
	var e Envelope
	e.RootInput = r.bytes(-1, maxRootInput)
	trans := r.array(MaxTransitions)
	for i := 0; i < trans.len() && trans.err == nil; i++ {
		e.Transitions = append(e.Transitions, trans.bytes(-1, maxTransition))
	}
	e.TargetParent = r.bytes(digestLen, 0)
	e.BlockID = r.optBytes(digestLen)
	links := r.array(MaxLinks)
	for i := 0; i < links.len() && links.err == nil; i++ {
		l, err := readLink(links.sub(6))
		if err != nil {
			return Envelope{}, err
		}
		if i > 0 && l.Body.Epoch != e.Links[i-1].Body.Epoch+1 {
			return Envelope{}, fmt.Errorf("%w: links must be consecutive epochs", ErrEnvelope)
		}
		e.Links = append(e.Links, l)
	}
	for _, rd := range []*reader{trans, links, r} {
		if rd.err != nil {
			return Envelope{}, rd.err
		}
	}
	if err := r.done(); err != nil {
		return Envelope{}, err
	}
	if len(e.BlockID) != 0 && len(e.BlockID) != digestLen {
		return Envelope{}, fmt.Errorf("%w: block identity of %d bytes", ErrFormat, len(e.BlockID))
	}
	return e, nil
}

func readLink(f *reader) (Link, error) {
	var l Link
	body := f.bytes(-1, MaxEnvelopeBytes) // DecodeBody bounds it
	c := f.sub(6)
	l.Claim.Epoch, l.Claim.Start = c.uint(), c.uint()
	copy(l.Claim.BodyID[:], c.bytes(digestLen, 0))
	copy(l.Claim.CommitID[:], c.bytes(digestLen, 0))
	l.Claim.PriorVersion = c.uint()
	copy(l.Claim.PriorID[:], c.bytes(digestLen, 0))
	ev := f.sub(3)
	l.Evidence = Evidence{Summary: ev.bytes(-1, maxEvidence), FrozenParent: ev.bytes(-1, maxEvidence), CandidateDigest: ev.bytes(-1, maxEvidence)}
	l.Preimage = f.bytes(-1, maxPreimage)
	l.Proof = f.bytes(-1, MaxOldCommitProof)
	var err error
	if l.Receipts, err = readReceipts(f); f.err == nil && err != nil {
		f.err = err
	}
	for _, rd := range []*reader{c, ev} {
		if rd.err != nil {
			return Link{}, rd.err
		}
	}
	if f.err != nil {
		return Link{}, f.err
	}
	if l.Body, err = DecodeBody(body); err != nil {
		return Link{}, err
	}
	return l, nil
}

// retained checks a link for an epoch e the history already holds, after prior. It is a reference to the verified entry, not a second
// verification, so nothing the link carries may differ from it: the claim, the recomputed identity of the supplied canonical
// body (a claim alone never names the body), and the committed record, candidate evidence and receipts the link presents. Any
// difference is ErrConflict; conflicting evidence is never ignored because the claim happens to match. The supplied commit
// proof is authenticated in full under the retained predecessor's committee (the record id does not commit to the signatures
// or the inclusion path), exactly as a fresh activation would be: a forged proof that names the right record is a conflict.
func (h *History) retained(e, prior Entry, l Link) error {
	conflict := func(what string) error { return fmt.Errorf("%w: epoch %d: %s", ErrConflict, l.Body.Epoch, what) }
	if e.claim() != l.Claim {
		return conflict("claim")
	}
	if id := l.Body.Identity(); id != e.bodyID || id != l.Claim.BodyID {
		return conflict("body identity")
	}
	p, err := decodeProof(l.Proof)
	if err != nil {
		return err
	}
	v, err := h.verifyCommit(prior, p)
	if err != nil {
		return errors.Join(ErrConflict, ErrActivation, err)
	}
	if v.RecordID != e.commitID || !bytes.Equal(p.Record.ID(), e.commitID[:]) { // the record id commits to its body, boundary, attempt and rounds
		return conflict("committed record")
	}
	if err := bindCandidate(l.Body, p.Record, l.Evidence); err != nil {
		return errors.Join(ErrConflict, err)
	}
	if !bytes.Equal(l.Preimage, e.preimage) {
		return conflict("candidate preimage")
	}
	if err := readiness(l.Body, p.Record.Attempt, l.Evidence, l.Preimage, prior.preimage, l.Receipts); err != nil {
		return errors.Join(ErrConflict, err)
	}
	return nil
}

// VerifyEnvelope extends h with the envelope's lineage and returns the extended history, leaving h untouched. A link for an
// epoch h already holds is a reference to a retained verified entry: it must be that entry exactly (ErrConflict otherwise).
// Any other link must extend the tip and passes WithV3; an epoch the history lacks, with nothing supplied before it, is
// ErrMissingHistory. The envelope's claim for each link must equal the derived activation field for field. The result is
// rooted in h's genesis: no segment becomes a trust anchor.
func (h *History) VerifyEnvelope(e Envelope) (*History, error) {
	cur := h
	for _, l := range e.Links {
		if have, err := cur.ForEpoch(l.Body.Epoch); err == nil {
			prior, perr := cur.ForEpoch(l.Body.Epoch - 1)
			if l.Body.Epoch == 0 || perr != nil {
				return nil, fmt.Errorf("%w: epoch %d has no retained predecessor to authenticate the proof", ErrConflict, l.Body.Epoch)
			}
			if err := cur.retained(have, prior, l); err != nil {
				return nil, err
			}
			continue
		}
		next, err := cur.WithV3(l)
		if err != nil {
			return nil, err
		}
		if next.Tip().claim() != l.Claim {
			return nil, fmt.Errorf("%w: claim for epoch %d differs from the derived activation", ErrBinding, l.Body.Epoch)
		}
		cur = next
	}
	return cur, nil
}
