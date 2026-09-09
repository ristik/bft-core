package shardnode

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

/*
The provider half of authenticated anchor recovery: what a node has to RETAIN so that it can serve
the evidence chain `VerifyAnchorEvidence` consumes.

WHY THIS EXISTS. Nothing in this repository retains it today, and an earlier revision of the design
record wrongly assumed otherwise. `continuityState` keeps an anchor, a covered round and the next
assignment — no certificates at all. `FileStore.SaveLUC` keeps exactly one certificate and
atomically overwrites it. So a peer can VERIFY the chain of
docs/design/f6b-quiet-tail-anchor-recovery.md §2 and cannot SERVE it, which makes the recommended
recovery path (§6, peer evidence retrieval) unimplementable until this exists. This file is §6.1.

WHAT IT IS, AND IS NOT. It is a bounded, in-memory ring of `(UC, TechnicalRecord)` pairs in
observation order, plus the assembly that cuts a requested window out of it. There is no transport
here and nothing calls it from the round loop: those are separate PRs, deliberately, because the
serving policy is decidable now and the wire format and the requester's application rules are not.
It persists nothing — a restart erases a node's serving capacity entirely, which is an availability
property and is stated rather than engineered around (§6.1, "why in-memory is enough for now").

WHAT IT NEVER DOES. It never synthesises a proof. Every refusal below returns a NAMED unavailable
outcome and no bundle at all; there is no path that trims a chain, substitutes a nearer source, or
answers a request it cannot answer exactly. That matters because the far end refuses a short chain
anyway (§2.2) — serving one would just spend a round trip to arrive at the same place, and would
hide from the requester the one thing it needs to know, which is that it should ask somebody else.
*/

// EvidenceBufferLimits bounds what one node retains for serving. Both bounds are needed: entry count
// bounds the assembly work and the served chain, bytes bound the memory, and neither implies the
// other once validator-set size (which drives per-certificate size) is allowed to vary.
type EvidenceBufferLimits struct {
	MaxEntries int
	MaxBytes   int
}

// DefaultEvidenceBufferLimits retains at most as many certificates as a requester will accept in one
// bundle (DefaultAnchorEvidenceLimits.MaxCertificates), so an assembled chain can never be refused
// by the far end for a length this side chose. The byte bound is four times the requester's, because
// this one covers the whole retained interval rather than a single served window.
var DefaultEvidenceBufferLimits = EvidenceBufferLimits{
	MaxEntries: DefaultAnchorEvidenceLimits.MaxCertificates,
	MaxBytes:   4 << 20,
}

// Named provider outcomes. None of them is a verification failure: they say this provider cannot
// answer THIS request, and the requester's correct response to every one of them is to ask another
// provider (docs/design/f6b-quiet-tail-anchor-recovery.md §4.1 — a provider's inability is never
// evidence about the shard's history).
var (
	ErrProviderNotReady = errors.New("evidence buffer: no certified block has been observed since this process started")
	ErrProviderEvicted  = errors.New("evidence buffer: the requested round, or the source it needs, has been evicted")
	ErrProviderBehind   = errors.New("evidence buffer: this provider has not itself reached the requested round")
	ErrProviderMismatch = errors.New("evidence buffer: this provider's certificate for the requested round is not the one the requester holds")

	// ErrObservationRejected marks an observation the buffer refused to retain. It is a defect on
	// THIS node's own delivery path, not a statement about a peer, and it is separate from the
	// outcomes above for exactly that reason.
	ErrObservationRejected = errors.New("evidence buffer: refused to retain an observation")
)

// EvidenceRequest pins a request to the certificate the REQUESTER holds — not to a round number
// alone. HeldIdentity is that certificate's InputRecord.Bytes(): the canonical encoding the root
// chain's signatures cover, and the same identity the predicate binds to at the far end (§2.2).
//
// Pinning matters on both sides. It stops a provider answering a differently-certified round that
// happens to share a number, and it turns "we disagree about this round" into an explicit
// ErrProviderMismatch here, one round trip earlier than the requester would have found it.
type EvidenceRequest struct {
	HeldRound    uint64
	HeldIdentity []byte
}

type bufferEntry struct {
	uc *types.UnicityCertificate
	tr *certification.TechnicalRecord

	round        uint64 // partition round
	rootRound    uint64
	assignedNext uint64 // this certificate's TechnicalRecord.Round
	nonQuiet     bool
	identity     []byte // InputRecord.Bytes()
	size         int    // encoded size of the pair, for the byte bound
}

/*
EvidenceBuffer retains what this node has observed, so it can serve it.

Contiguity, epochs and repeats are handled at OBSERVATION time rather than at assembly time, so that
the ring is at all times a single unbroken same-epoch interval, one entry per partition round, each
carrying the latest assignment for that round. Assembly then reduces to choosing a window, which is
what makes "never synthesise a proof" checkable by reading one function.
*/
type EvidenceBuffer struct {
	mu     sync.Mutex
	limits EvidenceBufferLimits

	entries []bufferEntry // oldest first; a contiguous chain by assigned round
	bytes   int
	epoch   uint64 // the shard epoch every retained entry is in
	haveAny bool

	// evicted records whether anything has ever been dropped for want of room. It is what
	// distinguishes "this provider has not seen a certified block yet" (not-ready, ordinary after a
	// restart) from "it had one and no longer has it" (evicted). Both are refusals; they tell an
	// operator different things.
	evicted bool
}

func NewEvidenceBuffer(limits EvidenceBufferLimits) (*EvidenceBuffer, error) {
	if limits.MaxEntries <= 0 || limits.MaxBytes <= 0 {
		return nil, fmt.Errorf("evidence buffer: both bounds must be positive, got MaxEntries=%d MaxBytes=%d",
			limits.MaxEntries, limits.MaxBytes)
	}
	return &EvidenceBuffer{limits: limits}, nil
}

/*
Observe retains one certificate and the technical record bound to it.

THE CALLER MUST ALREADY HAVE AUTHENTICATED uc — against its own trust base, for its own partition,
shard and configuration. This buffer decides where a certificate sits in the sequence and nothing
about whether it is genuine, exactly as continuityState.observe does; the difference is that what
this one retains will later be handed to somebody else, so it re-checks the ONE binding that would
otherwise let a local bug become a served chain: that the technical record is the one the
certificate commits to. The assignment in that record is what contiguity is judged against, here and
at the far end.

Out-of-sequence input is not an error to report upwards, because there is nothing upstream to fix:
it means this node missed certified history, and the honest response is to stop claiming an interval
it cannot prove. The buffer therefore RESETS to the new certificate and reports itself unable to
serve until a certified block arrives again. A returned error means the observation was malformed or
unbound — a defect on this node's delivery path.
*/
func (b *EvidenceBuffer) Observe(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	if uc == nil || uc.InputRecord == nil || tr == nil {
		return fmt.Errorf("%w: nil certificate, input record or technical record", ErrObservationRejected)
	}
	trHash, err := tr.Hash()
	if err != nil {
		return fmt.Errorf("%w: hashing technical record: %w", ErrObservationRejected, err)
	}
	if !bytes.Equal(trHash, uc.TRHash) {
		return fmt.Errorf("%w: the technical record is not the one this certificate commits to", ErrObservationRejected)
	}
	identity, err := uc.InputRecord.Bytes()
	if err != nil {
		return fmt.Errorf("%w: encoding input record: %w", ErrObservationRejected, err)
	}
	// Copy before retaining. The caller keeps its own reference to uc and may reuse or mutate it;
	// what this buffer will hand to a peer must not depend on that.
	ucCopy, trCopy, size, err := copyPair(uc, tr)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrObservationRejected, err)
	}

	e := bufferEntry{
		uc: ucCopy, tr: trCopy,
		round:        uc.InputRecord.RoundNumber,
		rootRound:    uc.GetRootRoundNumber(),
		assignedNext: tr.Round,
		nonQuiet:     len(uc.InputRecord.BlockHash) > 0,
		identity:     identity,
		size:         size,
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// A pair that alone exceeds MaxBytes can never be retained within the bound, so it is refused
	// rather than kept in violation of it. This is a CONFIGURATION outcome, not malformed input: the
	// certificate may be perfectly genuine and simply larger than this node was configured to hold,
	// and the actionable response is to raise MaxBytes. The interval is abandoned with it, because
	// a round this node cannot retain is a round it can no longer prove the interval across, and
	// the alternative — serving a chain with a hole where this certificate should be — is precisely
	// what the far end must refuse.
	if e.size > b.limits.MaxBytes {
		b.reset()
		return fmt.Errorf("%w: round %d encodes to %d bytes with its technical record, which alone exceeds MaxBytes=%d",
			ErrObservationRejected, e.round, e.size, b.limits.MaxBytes)
	}

	// A shard epoch change moves the validator set and the configuration with it, and the predicate
	// refuses a chain that crosses one (§3.1). Retaining across the boundary could therefore only
	// produce chains nobody may use, so the interval restarts in the new epoch. Keeping this scope
	// explicit is deliberate: recovery across an epoch transition is open work, not something this
	// buffer quietly half-supports.
	if b.haveAny && uc.InputRecord.Epoch != b.epoch {
		b.reset()
	}
	b.epoch = uc.InputRecord.Epoch
	b.haveAny = true

	if len(b.entries) == 0 {
		b.append(e)
		return nil
	}

	last := &b.entries[len(b.entries)-1]
	if e.round == last.round {
		switch {
		case bytes.Equal(e.identity, last.identity) && e.rootRound == last.rootRound &&
			bytes.Equal(e.uc.TRHash, last.uc.TRHash):
			// A duplicate delivery of a certificate already retained. Delivery retries make these
			// ordinary — the quiet-tail measurement saw 168 deliveries over 20 distinct rounds — so
			// they must be idempotent rather than either appended or refused.
			//
			// The TRHash comparison is what makes this a duplicate rather than merely a look-alike:
			// two certificates can carry the same input record at the same root round and still
			// commit to DIFFERENT assignments, and that is not a retransmission, it is a
			// contradiction — handled by the default branch below.
			return nil
		case bytes.Equal(e.identity, last.identity) && e.rootRound > last.rootRound:
			// A repeat: the same round re-certified at a later root round after a timeout, carrying
			// a NEW assignment. Normalised in place, so the ring stays one entry per round holding
			// the latest assignment. The predicate accepts either form; serving the normalised one
			// keeps the chain shorter and its contiguity check trivial.
			b.bytes += e.size - last.size
			last.uc, last.tr, last.size = e.uc, e.tr, e.size
			last.rootRound, last.assignedNext = e.rootRound, e.assignedNext
			b.evict()
			return nil
		default:
			// Two authenticated certificates for one round that disagree — about the input record,
			// or about the assignment at the same root round — or a repeat that does not advance
			// the root round. Retaining either would let this node serve a chain it cannot stand
			// behind, so the interval is abandoned and rebuilt from this certificate.
			//
			// Rebuilt, not merely emptied: the newest observation is still something this node
			// received and authenticated, and it is the only thing here with any claim to describe
			// the present. Whether a shard node should ALSO raise equivocation from this is #93's
			// taxonomy and not decided here; what is decided is that the interval before it can no
			// longer be proved, so it is not served.
			b.reset()
			b.append(e)
			return nil
		}
	}

	if e.round != last.assignedNext {
		// The round the previous certificate ASSIGNED is the only one that may follow it — never
		// last.round+1, because the root chain abandons rounds (§2.1). Anything else means this
		// node missed certified history and can no longer prove the interval.
		b.reset()
		b.append(e)
		return nil
	}

	// QUIET MEANS QUIET AT THE INTERVAL'S STATE, not merely "names no block". The predicate requires
	// every certificate after the source to satisfy `BlockHash empty AND Hash == PreviousHash ==
	// the source's state` (ErrEvidenceNotQuiet), and the source's state is carried forward by each
	// quiet round in turn. Classifying on the block hash alone was weaker than that at this end, so
	// a certificate that named no block but moved the state was retained as an ordinary quiet link
	// and served inside a window — a chain this buffer assembled successfully and the far end then
	// refused. A provider must never spend a requester's attempt on evidence it could see was
	// unusable, so the two ends classify identically and the interval is abandoned here instead.
	if !e.nonQuiet {
		state := last.uc.InputRecord.Hash
		if !bytes.Equal(e.uc.InputRecord.Hash, state) || !bytes.Equal(e.uc.InputRecord.PreviousHash, state) {
			b.reset()
			b.append(e)
			return nil
		}
	}

	b.append(e)
	return nil
}

// append adds an entry and then trims to the bounds. Eviction is plain oldest-first: a source that
// falls out is not special-cased, because assembly asks a sharper question anyway — whether a source
// survives at or before the round being requested (§6.1, "older sources, not just the latest one").
func (b *EvidenceBuffer) append(e bufferEntry) {
	b.entries = append(b.entries, e)
	b.bytes += e.size
	b.evict()
}

// evict trims to the bounds. BOTH bounds are hard: there is no "keep at least one entry" floor,
// because a floor would let retention exceed MaxBytes by the size of one certificate — a bound that
// can be exceeded is not a bound, and the one place it would be exceeded is exactly the place the
// certificates are largest. Nothing is retained beyond MaxBytes; Observe refuses a pair that cannot
// fit at all, so this loop always terminates at one entry or more rather than emptying the ring.
func (b *EvidenceBuffer) evict() {
	for len(b.entries) > 0 && (len(b.entries) > b.limits.MaxEntries || b.bytes > b.limits.MaxBytes) {
		b.bytes -= b.entries[0].size
		b.entries = b.entries[1:]
		b.evicted = true
	}
}

func (b *EvidenceBuffer) reset() {
	if len(b.entries) > 0 {
		b.evicted = true
	}
	b.entries = nil
	b.bytes = 0
}

/*
Assemble cuts the window [source … req.HeldRound] out of the retained interval, or says exactly why
it cannot.

The source is the LATEST non-quiet entry at or before the requested round — not the latest one the
buffer holds. Once a newer block is certified, the newer source cannot answer a request pinned
behind it: the window would start after the round it is supposed to explain. This is the correction
that a single "latest source" pointer gets wrong, and it is why non-quiet entries live in the ring
like any other rather than being tracked separately.

Everything is decided under the same lock that Observe appends under, and the result is a deep copy,
so a certificate arriving mid-assembly can neither lengthen nor truncate an answer, and two callers
never share mutable state.
*/
func (b *EvidenceBuffer) Assemble(req EvidenceRequest) (AnchorEvidence, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.entries) == 0 {
		if b.evicted {
			return AnchorEvidence{}, fmt.Errorf("%w: the retained interval is empty", ErrProviderEvicted)
		}
		return AnchorEvidence{}, fmt.Errorf("%w: nothing retained", ErrProviderNotReady)
	}

	newest := b.entries[len(b.entries)-1]
	if req.HeldRound > newest.round {
		return AnchorEvidence{}, fmt.Errorf("%w: requested round %d, this provider is at %d",
			ErrProviderBehind, req.HeldRound, newest.round)
	}

	held := -1
	for i := range b.entries {
		if b.entries[i].round == req.HeldRound {
			held = i
			break
		}
	}
	if held < 0 {
		// Below the oldest retained round, or a round this provider never saw certified inside the
		// interval it holds. Either way it is gone from here, and the requester should ask a
		// provider with a longer memory.
		return AnchorEvidence{}, fmt.Errorf("%w: round %d is not in the retained interval [%d..%d]",
			ErrProviderEvicted, req.HeldRound, b.entries[0].round, newest.round)
	}
	if !bytes.Equal(b.entries[held].identity, req.HeldIdentity) {
		// This provider's certificate for that round is not the requester's. Serving anything here
		// would be serving a chain to a node that will refuse it as a conflict, one round trip
		// later; saying so now is both cheaper and more informative.
		return AnchorEvidence{}, fmt.Errorf("%w: round %d", ErrProviderMismatch, req.HeldRound)
	}

	source := -1
	for i := held; i >= 0; i-- {
		if b.entries[i].nonQuiet {
			source = i
			break
		}
	}
	if source < 0 {
		if b.evicted {
			return AnchorEvidence{}, fmt.Errorf("%w: no certified block remains at or before round %d",
				ErrProviderEvicted, req.HeldRound)
		}
		// The ordinary state of a node that restarted into a quiet shard: it has certificates, none
		// of which names a block, so it has nothing that could anchor anybody. This is the same
		// shape of gap the whole design exists for, seen from the serving side.
		return AnchorEvidence{}, fmt.Errorf("%w: no certified block at or before round %d",
			ErrProviderNotReady, req.HeldRound)
	}

	src, srcTR, _, err := copyPair(b.entries[source].uc, b.entries[source].tr)
	if err != nil {
		return AnchorEvidence{}, err
	}
	out := AnchorEvidence{Source: src, SourceTechnical: srcTR}
	for i := source + 1; i <= held; i++ {
		uc, tr, _, err := copyPair(b.entries[i].uc, b.entries[i].tr)
		if err != nil {
			return AnchorEvidence{}, err
		}
		out.Tail = append(out.Tail, EvidenceLink{UC: uc, Technical: tr})
	}
	return out, nil
}

// Ready reports whether this provider could answer a request for its own latest round. It is a
// coarse health signal for logging and for a future transport's advertisement; a request still gets
// the precise outcome from Assemble, because readiness is per-round, not global.
func (b *EvidenceBuffer) Ready() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := len(b.entries) - 1; i >= 0; i-- {
		if b.entries[i].nonQuiet {
			return true
		}
	}
	return false
}

// Retained reports the interval this provider currently holds, for diagnostics: the number of
// entries and the inclusive round range. A zero count means nothing is retained.
func (b *EvidenceBuffer) Retained() (count int, from, to uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.entries) == 0 {
		return 0, 0, 0
	}
	return len(b.entries), b.entries[0].round, b.entries[len(b.entries)-1].round
}

// copyPair returns an independent deep copy of a certificate and its technical record, together with
// the encoded size of the pair.
//
// The copy is made by re-decoding the canonical encoding rather than by walking the structs: it
// cannot miss a field that either type grows later, and it produces the size measurement in the same
// pass. Both matter more than the marshalling cost, which is paid once per observation and once per
// served entry.
func copyPair(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) (*types.UnicityCertificate, *certification.TechnicalRecord, int, error) {
	ucBytes, err := types.Cbor.Marshal(uc)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("encoding certificate: %w", err)
	}
	trBytes, err := types.Cbor.Marshal(tr)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("encoding technical record: %w", err)
	}
	ucCopy := &types.UnicityCertificate{}
	if err := types.Cbor.Unmarshal(ucBytes, ucCopy); err != nil {
		return nil, nil, 0, fmt.Errorf("decoding certificate copy: %w", err)
	}
	trCopy := &certification.TechnicalRecord{}
	if err := types.Cbor.Unmarshal(trBytes, trCopy); err != nil {
		return nil, nil, 0, fmt.Errorf("decoding technical record copy: %w", err)
	}
	return ucCopy, trCopy, len(ucBytes) + len(trBytes), nil
}
