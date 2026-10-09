package q3format

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

var (
	// ErrHistory is returned for a link that does not extend the verified history, or a history that cannot be started.
	ErrHistory = errors.New("q3format: invalid or inconsistent trust history")
	// ErrMissingHistory is returned for a link that skips an epoch the verified history does not hold; the sender must supply it.
	ErrMissingHistory = errors.New("q3format: required trust history is missing")
	// ErrUnknownEpoch is returned for an epoch or round the verified history does not cover. It never means scheme 1.
	ErrUnknownEpoch = errors.New("q3format: epoch outside the verified history")
	// ErrOutsideInterval is returned for ordinary work outside the epoch's [A*, next A*) interval.
	ErrOutsideInterval = errors.New("q3format: round outside the epoch's active interval")
	// ErrNetwork is returned when a body or tuple names a network other than the history authority's.
	ErrNetwork = errors.New("q3format: network differs from the history authority")
	// ErrGenesis is returned when a tuple names a root genesis other than the history's.
	ErrGenesis = errors.New("q3format: root genesis differs from the history authority")
	// ErrActivation is returned when the committed record that would activate a body is not authenticated by the previous
	// epoch's committee. It wraps the verifier's own refusal.
	ErrActivation = errors.New("q3format: activation is not authenticated by a committed record")
	// ErrBinding is returned when an authenticated record does not bind the body, predecessor, boundary or candidate it is
	// presented with.
	ErrBinding = errors.New("q3format: committed record does not bind the presented body or candidate")
	// ErrScheme is returned when the previous epoch's signing scheme has no verifier here yet; there is no fallback to scheme 1.
	ErrScheme = errors.New("q3format: no verifier for the previous epoch's signing scheme")
)

// MaxOldCommitProof bounds one old-commit proof, as trustactivation does.
const MaxOldCommitProof = 1 << 20

// Entry is one verified epoch of the history. It can be built only by NewHistory or WithV3, each of which authenticates it; a
// caller cannot construct an activation.
type Entry struct {
	epoch, start, version, scheme uint64
	earliest                      uint64 // the body's A_min
	priorVersion                  uint64
	config                        *ProtocolConfig
	bodyID, commitID, anchorID    [32]byte
	priorID                       [32]byte
	tb                            *types.RootTrustBaseV1 // verifier projection of this epoch's committee
	// handoff and genesis are what the old committee's verified commit derived, kept for a V3 entry so that an installer takes
	// them from the verified history and never from a caller-built record.
	handoff *evmroot.VerifiedHandoff
	genesis *evmroot.EpochGenesis
	// rootOnly is true when the candidate digest the committed record binds is the operator candidate recomputed from the body's own
	// members: no EVM assignment preimage is committed, so none can be omitted.
	rootOnly bool
	// body is the canonical encoding of the V3 body the committed record names: SHA-256 of it is the committed NextBodyID.
	body []byte
	// preimage is the canonical candidate preimage the committed digest names (empty for a root-only entry). The next link's recovery
	// exemption chains to it: a recovery replaces exactly this primary.
	preimage []byte
}

// RootOnly reports whether the committed record binds exactly the root-only operator candidate of this entry's members. It is
// derived from the authenticated record when the entry is minted; an entry whose committed candidate is anything else (an EVM
// assignment) is not root-only, however its candidate bytes are presented later.
func (e Entry) RootOnly() bool { return e.rootOnly }

func (e Entry) Epoch() uint64 { return e.epoch }
func (e Entry) Start() uint64 { return e.start } // the actual activation boundary A*

// EarliestActivation is the body's A_min, the lower bound A* had to meet.
func (e Entry) EarliestActivation() uint64 { return e.earliest }
func (e Entry) Version() uint64            { return e.version }

// Scheme is the explicit signing scheme of the epoch: 1 for every legacy epoch, the tuple's for a V3 epoch.
func (e Entry) Scheme() uint64               { return e.scheme }
func (e Entry) BodyID() [32]byte             { return e.bodyID }
func (e Entry) ActivationCommitID() [32]byte { return e.commitID }
func (e Entry) AnchorID() [32]byte           { return e.anchorID }
func (e Entry) Config() (ProtocolConfig, bool) {
	if e.config == nil {
		return ProtocolConfig{}, false
	}
	return *e.config, true
}

// Anchor is the epoch-qualified coordinate the successor's first ordinary work is anchored at: (E, A*-1).
func (e Entry) Anchor() (epoch, round uint64) {
	if e.start == 0 {
		return e.epoch, 0 // the genesis epoch has no predecessor to anchor on
	}
	return e.epoch, e.start - 1
}

// Projection is a private copy of the epoch's verifier projection (members, exact weights, threshold, start). For a V3 entry it
// carries the body's state summary and change-record hash. It is a derived view: it is never the configuration identity.
func (e Entry) Projection() *types.RootTrustBaseV1 { return cloneTrustBase(e.tb) }

// Handoff is the verified old-committee commit this V3 entry was activated by and the epoch genesis derived from it. It is
// false for a legacy entry. The values are copies.
func (e Entry) Handoff() (evmroot.VerifiedHandoff, evmroot.EpochGenesis, bool) {
	if e.handoff == nil || e.genesis == nil {
		return evmroot.VerifiedHandoff{}, evmroot.EpochGenesis{}, false
	}
	v, g := *e.handoff, *e.genesis
	v.RecordID, v.Root, v.ControlDigest = bytes.Clone(v.RecordID), bytes.Clone(v.Root), bytes.Clone(v.ControlDigest)
	v.Record.PredecessorBodyID, v.Record.FrozenID = bytes.Clone(v.Record.PredecessorBodyID), bytes.Clone(v.Record.FrozenID)
	v.Record.NextBodyID, v.Record.SuccessorTRHash = bytes.Clone(v.Record.NextBodyID), bytes.Clone(v.Record.SuccessorTRHash)
	g.NextBodyID, g.RecordID, g.Root, g.ControlDigest = bytes.Clone(g.NextBodyID), bytes.Clone(g.RecordID), bytes.Clone(g.Root), bytes.Clone(g.ControlDigest)
	g.FrozenID, g.SuccessorTRHash = bytes.Clone(g.FrozenID), bytes.Clone(g.SuccessorTRHash)
	return v, g, true
}

// BodyEncoding is a copy of the canonical V3 body bytes this activation's identity is the hash of; nil for a legacy entry. A consumer
// that retains the body for derivation (the root's candidate-bearing install) takes it from here, never from the caller.
func (e Entry) BodyEncoding() []byte { return bytes.Clone(e.body) }

// Claim is what an envelope asserts about an entry; the verifier derives the same value and compares every field.
type Claim struct {
	Epoch, Start     uint64
	BodyID, CommitID [32]byte
	PriorVersion     uint64
	PriorID          [32]byte
}

func (e Entry) claim() Claim {
	return Claim{e.epoch, e.start, e.bodyID, e.commitID, e.priorVersion, e.priorID}
}

// Claim is the committed record's identity for this verified entry: what a durable install journal binds itself to.
func (e Entry) Claim() Claim { return e.claim() }

// History is the explicit, ordered, verified chain of epochs from the root genesis. Its network and genesis identity are the
// authority every later body is checked against. It is immutable: the With methods return an extended copy.
type History struct {
	network uint64
	genesis [32]byte
	entries []Entry
}

// NewHistory starts a history at the deployment's genesis trust base: epoch 1, self-signed by a unit committee. Its network is the
// authority's, and the root-genesis identity is its hash including signatures. No later bootstrap anchor exists.
func NewHistory(genesis *types.RootTrustBaseV1) (*History, error) {
	if err := weightvalidation.RootTrustBase(genesis, weightvalidation.ModeUnit); err != nil {
		return nil, errors.Join(ErrHistory, err)
	}
	if err := quorumweight.VerifyTrustBase(genesis, nil); err != nil {
		return nil, errors.Join(ErrHistory, err)
	}
	id, err := genesis.Hash(crypto.SHA256)
	if err != nil {
		return nil, errors.Join(ErrHistory, err)
	}
	owned := cloneTrustBase(genesis) // the history is the owner of its authority: a later change by the caller must not alter it
	h := &History{network: uint64(genesis.NetworkID)}
	copy(h.genesis[:], id)
	e := Entry{epoch: 1, start: genesis.EpochStart, version: 1, scheme: 1, bodyID: h.genesis, tb: owned}
	h.entries = []Entry{e}
	return h, nil
}

// cloneTrustBase is a deep copy: new node records (not copies of a NodeInfo, which carries a sync.Once), keys, hashes and signatures.
func cloneTrustBase(tb *types.RootTrustBaseV1) *types.RootTrustBaseV1 {
	c := *tb
	c.RootNodes = make([]*types.NodeInfo, len(tb.RootNodes))
	for i, n := range tb.RootNodes {
		if n != nil {
			c.RootNodes[i] = &types.NodeInfo{NodeID: n.NodeID, SigKey: bytes.Clone(n.SigKey), Stake: n.Stake}
		}
	}
	c.StateHash, c.ChangeRecordHash, c.PreviousEntryHash = bytes.Clone(tb.StateHash), bytes.Clone(tb.ChangeRecordHash), bytes.Clone(tb.PreviousEntryHash)
	if tb.Signatures != nil {
		c.Signatures = make(map[string]hex.Bytes, len(tb.Signatures))
		for k, v := range tb.Signatures {
			c.Signatures[k] = bytes.Clone(v)
		}
	}
	return &c
}

// Network and Genesis are the authority a body's network and tuple are checked against.
func (h *History) Network() uint64   { return h.network }
func (h *History) Genesis() [32]byte { return h.genesis }
func (h *History) Tip() Entry        { return h.entries[len(h.entries)-1] }

// ForEpoch is the verified entry of an epoch, or ErrUnknownEpoch. An absent epoch is never a legacy default.
func (h *History) ForEpoch(epoch uint64) (Entry, error) {
	for _, e := range h.entries {
		if e.epoch == epoch {
			return e, nil
		}
	}
	return Entry{}, fmt.Errorf("%w: epoch %d", ErrUnknownEpoch, epoch)
}

// Signing is the explicit signing configuration of an epoch's messages: scheme 1 for a verified legacy epoch, the tuple's scheme
// and the chain's genesis identity for a verified V3 epoch. An epoch the history does not hold is ErrUnknownEpoch, never scheme 1.
func (h *History) Signing(epoch uint64) (votesig.Config, error) {
	e, err := h.ForEpoch(epoch)
	if err != nil {
		return votesig.Config{}, err
	}
	if e.config == nil {
		return votesig.Config{Scheme: votesig.SchemeLegacy, Network: h.network}, nil
	}
	return votesig.Config{Scheme: e.config.SigningScheme, Network: e.config.Network, Genesis: e.config.Genesis}, nil
}

// LeaderPolicy is the leader selection policy of an epoch's rounds: "legacy" for a verified legacy epoch, the tuple's policy for a
// verified V3 epoch. An epoch the history does not hold is ErrUnknownEpoch, never "legacy".
func (h *History) LeaderPolicy(epoch uint64) (string, error) {
	e, err := h.ForEpoch(epoch)
	if err != nil {
		return "", err
	}
	if e.config == nil {
		return LeaderPolicyLegacy, nil
	}
	return e.config.LeaderPolicy, nil
}

// ForRound is the entry whose interval [A*, next A*) holds round.
func (h *History) ForRound(round uint64) (Entry, error) {
	for i := len(h.entries) - 1; i >= 0; i-- {
		if round >= h.entries[i].start {
			return h.entries[i], nil
		}
	}
	return Entry{}, fmt.Errorf("%w: round %d", ErrUnknownEpoch, round)
}

// Ordinary admits ordinary work at (epoch, round) only inside the epoch's own interval. Old suffix certificates beyond A*
// are old handoff evidence, authenticated by the commit-proof verifier, never ordinary old work. Bare rounds are never
// compared across epochs.
func (h *History) Ordinary(epoch, round uint64) error {
	e, err := h.ForEpoch(epoch)
	if err != nil {
		return err
	}
	if round < e.start {
		return fmt.Errorf("%w: round %d before A*=%d of epoch %d", ErrOutsideInterval, round, e.start, epoch)
	}
	if next, err := h.ForEpoch(epoch + 1); err == nil && round >= next.start {
		return fmt.Errorf("%w: round %d at or after the boundary %d", ErrOutsideInterval, round, next.start)
	}
	return nil
}

func (h *History) extend(e Entry) *History {
	return &History{network: h.network, genesis: h.genesis, entries: append(append([]Entry(nil), h.entries...), e)}
}

// Evidence is the frozen-state input the committed record binds: the pre-freeze summary, the frozen EVM parent and the
// candidate digest.
type Evidence struct {
	Summary, FrozenParent, CandidateDigest []byte
}

// Link is everything one V3 activation needs beyond the history: the body, the evidence its candidate rests on, the canonical
// candidate preimage (empty for a root-only change; it selects the readiness evidence, see readiness), the old committee's commit
// proof (canonical OldCommitProof bytes), the readiness receipts of every successor member (none for a verified exact recovery),
// and the claim the sender makes about the result.
type Link struct {
	Body     BodyV3
	Evidence Evidence
	Preimage []byte
	Proof    []byte
	Receipts []Receipt
	Claim    Claim
}

func decodeProof(proof []byte) (p handoff.OldCommitProof, err error) {
	if len(proof) == 0 || len(proof) > MaxOldCommitProof {
		return p, fmt.Errorf("%w: proof of %d bytes", ErrTooLarge, len(proof))
	}
	if err := types.Cbor.Unmarshal(proof, &p); err != nil {
		return p, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if again, err := types.Cbor.Marshal(p); err != nil || !bytes.Equal(again, proof) {
		return p, fmt.Errorf("%w: proof is not canonical", ErrFormat)
	}
	return p, nil
}

func projection(members evmroot.WeightSet, network, epoch, start, threshold uint64) (*types.RootTrustBaseV1, error) {
	nodes := make([]*types.NodeInfo, len(members))
	for i, m := range members {
		nodes[i] = &types.NodeInfo{NodeID: m.NodeID, SigKey: bytes.Clone(m.ConsensusKey), Stake: m.Weight}
	}
	return quorumweight.NewTrustBase(types.NetworkID(network), nodes, types.WithEpoch(epoch), types.WithEpochStart(start), types.WithQuorumThreshold(threshold))
}

// verifyCommit verifies the commit proof of an activation of the epoch after prior under prior's own rule: its committee, weights
// and threshold from the verified entry, and its signing scheme from the history's explicit record of that epoch (scheme 1 for the
// genesis epoch, the tuple's scheme for an activated one). An epoch whose scheme has no verifier is ErrScheme, never scheme 1.
func (h *History) verifyCommit(prior Entry, p handoff.OldCommitProof) (handoff.VerifiedRecord, error) {
	cfg, err := h.Signing(prior.epoch)
	if err != nil {
		return handoff.VerifiedRecord{}, err
	}
	if cfg.Scheme != votesig.SchemeLegacy && cfg.Scheme != votesig.SchemeDomainBound {
		return handoff.VerifiedRecord{}, fmt.Errorf("%w: scheme %d", ErrScheme, cfg.Scheme)
	}
	return handoff.VerifyOldCommitProofSigning(p, prior.tb, cfg)
}

// WithV3 appends one V3 epoch. An activation is minted only from a record the previous epoch's committee committed: the
// previous epoch's keys, weights and scheme come solely from this history, the commit proof and its control leaf are verified
// under them, and only then are the record's body, predecessor, boundary and candidate compared with the presented link. The
// body's network and tuple are checked against the history authority, never against the link's own claim.
func (h *History) WithV3(l Link) (*History, error) {
	tip, b := h.Tip(), l.Body
	if err := b.Validate(); err != nil {
		return nil, err
	}
	if b.Network != h.network { // the tuple's network is the body's: Validate has checked it
		return nil, fmt.Errorf("%w: body %d, authority %d", ErrNetwork, b.Network, h.network)
	}
	if b.Config.Genesis != h.genesis {
		return nil, ErrGenesis
	}
	switch {
	case b.Epoch > tip.epoch+1:
		return nil, fmt.Errorf("%w: epoch %d after %d", ErrMissingHistory, b.Epoch, tip.epoch)
	case b.Epoch != tip.epoch+1:
		return nil, fmt.Errorf("%w: epoch %d does not follow %d", ErrHistory, b.Epoch, tip.epoch)
	}
	prior := Prior{Network: h.network, Epoch: tip.epoch, BodyVersion: tip.version, Identity: tip.bodyID[:]}
	if want, err := prior.Hash(); err != nil || !bytes.Equal(want, b.PredecessorHash) {
		return nil, fmt.Errorf("%w: body predecessor is not the tip's", ErrPrior)
	}
	p, err := decodeProof(l.Proof)
	if err != nil {
		return nil, err
	}
	v, err := h.verifyCommit(tip, p)
	if err != nil {
		return nil, errors.Join(ErrActivation, err)
	}
	r, id := p.Record, b.Identity()
	switch {
	case !bytes.Equal(r.NextBodyID, id[:]):
		return nil, fmt.Errorf("%w: record names another body", ErrBinding)
	case !bytes.Equal(r.PredecessorBodyID, tip.bodyID[:]):
		return nil, fmt.Errorf("%w: record names another predecessor", ErrBinding)
	case r.ActivationRound < b.EarliestActivation:
		return nil, fmt.Errorf("%w: A*=%d before A_min=%d", ErrBinding, r.ActivationRound, b.EarliestActivation)
	case r.ActivationRound <= tip.start:
		return nil, fmt.Errorf("%w: A*=%d does not follow the epoch start %d", ErrBinding, r.ActivationRound, tip.start)
	}
	if err := bindCandidate(b, r, l.Evidence); err != nil {
		return nil, err
	}
	if err := readiness(b, r.Attempt, l.Evidence, l.Preimage, tip.preimage, l.Receipts); err != nil {
		return nil, err
	}
	operator, err := evmroot.D4OperatorCandidateDigest(b.Members)
	if err != nil {
		return nil, errors.Join(ErrBody, err)
	}
	rootOnly := bytes.Equal(l.Evidence.CandidateDigest, operator[:]) // bound into the committed FrozenID and the body's change-record hash above
	tb, err := projection(b.Members, b.Network, b.Epoch, r.ActivationRound, b.RootThreshold)
	if err != nil {
		return nil, errors.Join(ErrBody, err)
	}
	tb.StateHash, tb.ChangeRecordHash = bytes.Clone(b.StateSummary), bytes.Clone(b.ChangeRecordHash)
	cfg := b.Config
	anchor := evmroot.EpochGenesis{Network: b.Network, Epoch: b.Epoch, Start: r.ActivationRound, OrderedRound: r.OrderedRound, NextBodyID: id[:],
		RecordID: v.RecordID[:], Root: v.StateRoot[:], ControlDigest: v.ControlDigest[:], FrozenID: r.FrozenID, SuccessorTRHash: r.SuccessorTRHash}
	verified := evmroot.VerifiedHandoff{RecordID: bytes.Clone(v.RecordID[:]), Root: bytes.Clone(v.StateRoot[:]), ControlDigest: bytes.Clone(v.ControlDigest[:]),
		OrderRound: v.OrderRound, CommitSealRound: v.CommitSealRound, Epoch: v.SignerEpoch, Record: r}
	e := Entry{epoch: b.Epoch, start: r.ActivationRound, earliest: b.EarliestActivation, version: BodyVersion, scheme: cfg.SigningScheme, priorVersion: tip.version, priorID: tip.bodyID,
		config: &cfg, bodyID: id, commitID: v.RecordID, tb: tb, handoff: &verified, genesis: &anchor, rootOnly: rootOnly, body: b.Encode(), preimage: bytes.Clone(l.Preimage)}
	copy(e.anchorID[:], anchor.ID())
	return h.extend(e), nil
}

// bindCandidate checks that the committed record's frozen identity and the body's change-record hash are those of the
// evidence: the same candidate, attempt, predecessor and boundary bound before the old committee ordered the commit.
func bindCandidate(b BodyV3, r evmroot.OrderedHandoffRecord, ev Evidence) error {
	if len(ev.CandidateDigest) != 32 || len(ev.Summary) == 0 || len(ev.FrozenParent) == 0 || len(ev.Summary) > maxField || len(ev.FrozenParent) > maxField {
		return fmt.Errorf("%w: incomplete or oversize evidence", ErrBinding)
	}
	id := b.Identity()
	if !bytes.Equal(evmroot.D4FrozenID(id[:], ev.Summary, ev.FrozenParent, ev.CandidateDigest, r.Attempt, r.PredecessorBodyID), r.FrozenID) {
		return fmt.Errorf("%w: frozen identity", ErrBinding)
	}
	if !bytes.Equal(evmroot.D4CandidateContextHash(r.Network, r.PredecessorBodyID, r.Attempt, ev.CandidateDigest, b.EarliestActivation), b.ChangeRecordHash) {
		return fmt.Errorf("%w: candidate context", ErrBinding)
	}
	return nil
}
