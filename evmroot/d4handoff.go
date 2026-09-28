package evmroot

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"sort"

	abhash "github.com/unicitynetwork/bft-go-base/hash"
	"github.com/unicitynetwork/bft-go-base/tree/imt"
	base "github.com/unicitynetwork/bft-go-base/types"
)

// D4 is an executable protocol model. The wire profile is reserved here; no
// runtime consensus path imports this model.
const D4Profile uint64 = 2
const D4ControlPartition base.PartitionID = 0xffffffff
const PipelineDepth uint64 = 3 // scheduling margin, never a vote fence

var (
	ErrD4Phase          = errors.New("d4: invalid phase")
	ErrD4Record         = errors.New("d4: invalid ordered record")
	ErrD4Control        = errors.New("d4: invalid control leaf")
	ErrD4Proof          = errors.New("d4: invalid old commit proof")
	ErrD4Quorum         = errors.New("d4: insufficient distinct signed weight")
	ErrD4Snapshot       = errors.New("d4: invalid full snapshot")
	ErrD4Anchor         = errors.New("d4: invalid epoch anchor")
	ErrD4Suffix         = errors.New("d4: nonempty or state-changing old suffix")
	ErrD4CommitAnchor   = errors.New("d4: anchor cannot be committed")
	ErrD4Epoch          = errors.New("d4: epoch authority violation")
	ErrD4TerminalRepeat = errors.New("d4: terminal old certificate is historical")
	ErrD4Unready        = errors.New("d4: transition evidence unavailable")
)

type Phase uint8

const (
	PhaseIdle Phase = iota
	PhasePrepared
	PhaseFrozen
	PhaseEndorsed
	PhaseCommitted
	PhaseActivated
	PhaseAcknowledged
	PhaseAborted
)

func (p Phase) String() string {
	return [...]string{"idle", "prepared", "frozen", "endorsed", "committed", "activated", "acknowledged", "aborted"}[p]
}

type Candidate struct {
	Network, OldEpoch, NextEpoch, Attempt, MinActivation uint64
	PredecessorHash, CandidateHash                       []byte
}
type Handoff struct {
	Phase                           Phase
	Candidate                       Candidate
	Body                            TrustBaseBodyV2
	BodyID, FrozenID, LastEVMParent []byte
	Endorsement                     SigDomain
	Record                          OrderedHandoffRecord
	Proof                           *HandoffProof
	Verified                        *VerifiedHandoff
	Anchor                          *EpochGenesis
	AckEVMRound                     uint64
}
type SigDomain struct {
	Network, Epoch, Attempt, MinActivation uint64
	Predecessor, FrozenID                  []byte
	ActivationRound                        uint64
	SuccessorTRHash                        []byte
}

func FieldsAreKnown(d SigDomain) bool {
	return len(d.FrozenID) == 32 && d.ActivationRound == 0 && len(d.SuccessorTRHash) == 0
}

// The record payload omits its ID, signatures and proof. OrderedRound is in
// the ID, even when a later empty suffix supplies the commit seal.
type OrderedHandoffRecord struct {
	Network, Epoch, Attempt, OrderedRound, ActivationRound   uint64
	PredecessorBodyID, FrozenID, NextBodyID, SuccessorTRHash []byte
	Kind                                                     string
}

func (r OrderedHandoffRecord) payload() cArray {
	return cArray{cBytes(r.FrozenID), cBytes(r.NextBodyID), cUint(r.ActivationRound), cBytes(r.SuccessorTRHash)}
}
func (r OrderedHandoffRecord) Bytes() []byte {
	return marshalCBOR(cArray{cText("UNICITY_ORDERED_HANDOFF_RECORD"), cUint(1), cUint(r.Network), cUint(r.Epoch), cBytes(r.PredecessorBodyID), cUint(r.Attempt), cText(r.Kind), cUint(r.OrderedRound), r.payload()})
}
func (r OrderedHandoffRecord) ID() []byte { h := sha256.Sum256(r.Bytes()); return h[:] }
func (r OrderedHandoffRecord) Valid() bool {
	return r.Kind == "commit" && r.OrderedRound > 0 && r.ActivationRound >= r.OrderedRound && r.ActivationRound-r.OrderedRound >= PipelineDepth && len(r.PredecessorBodyID) == 32 && len(r.FrozenID) == 32 && len(r.NextBodyID) == 32 && len(r.SuccessorTRHash) == 32
}

type ControlState struct {
	Network, Epoch, Attempt, OrderedRound uint64
	PredecessorBodyID                     []byte
	Phase                                 string
	RecordBytes, PreviousDigest           []byte
}

func (s ControlState) Bytes() []byte {
	return marshalCBOR(cArray{cText("UNICITY_ROOT_HANDOFF_STATE"), cUint(1), cUint(s.Network), cUint(s.Epoch), cBytes(s.PredecessorBodyID), cUint(s.Attempt), cText(s.Phase), cUint(s.OrderedRound), cBytes(s.RecordBytes), cBytes(s.PreviousDigest)})
}
func (s ControlState) Digest() []byte { h := sha256.Sum256(s.Bytes()); return h[:] }
func (s ControlState) Matches(r OrderedHandoffRecord) bool {
	return s.Phase == "committed" && s.Network == r.Network && s.Epoch == r.Epoch && s.Attempt == r.Attempt && s.OrderedRound == r.OrderedRound && bytes.Equal(s.PredecessorBodyID, r.PredecessorBodyID) && bytes.Equal(s.RecordBytes, r.Bytes())
}

type ShardSnapshot struct {
	Partition                                                           base.PartitionID
	Root, InputRecord, TechnicalRecord, LastCR, PendingConfig, FeeStats []byte
}

func (s ShardSnapshot) CalculatedRoot() []byte {
	h := sha256.Sum256(marshalCBOR(cArray{cText("UNICITY_D4_SHARD_CHECKPOINT"), cUint(1), cUint(uint64(s.Partition)), cBytes(s.InputRecord), cBytes(s.TechnicalRecord), cBytes(s.LastCR), cBytes(s.PendingConfig), cBytes(s.FeeStats)}))
	return h[:]
}

type FullSnapshot struct {
	Control ControlState
	Shards  []ShardSnapshot
}

func (s FullSnapshot) Leaves() ([]*base.UnicityTreeData, error) {
	if s.Control.Phase != "committed" {
		return nil, ErrD4Control
	}
	out := []*base.UnicityTreeData{{Partition: D4ControlPartition, ShardTreeRoot: s.Control.Digest()}}
	seen := map[base.PartitionID]bool{D4ControlPartition: true}
	for _, v := range s.Shards {
		if seen[v.Partition] || len(v.Root) != 32 || !bytes.Equal(v.Root, v.CalculatedRoot()) {
			return nil, ErrD4Snapshot
		}
		seen[v.Partition] = true
		out = append(out, &base.UnicityTreeData{Partition: v.Partition, ShardTreeRoot: bytes.Clone(v.Root)})
	}
	return out, nil
}
func (s FullSnapshot) Tree() (*base.UnicityTree, error) {
	leaves, err := s.Leaves()
	if err != nil {
		return nil, err
	}
	return base.NewUnicityTree(crypto.SHA256, leaves)
}
func (s FullSnapshot) Root() ([]byte, error) {
	t, e := s.Tree()
	if e != nil {
		return nil, e
	}
	return t.RootHash(), nil
}
func (s FullSnapshot) ControlPath() (*base.UnicityTreeCertificate, error) {
	t, e := s.Tree()
	if e != nil {
		return nil, e
	}
	return t.Certificate(D4ControlPartition)
}

// The model signs the same relationship as the root QC: PreviousHash is
// Hash(VoteInfo); LedgerCommitInfo names the parent's round, epoch and root.
type D4VoteInfo struct {
	Round, Epoch, ParentRound, Timestamp uint64
	CurrentRoot                          []byte
}

func (v D4VoteInfo) Bytes() []byte {
	return marshalCBOR(cTag{39007, cArray{cUint(1), cUint(v.Round), cUint(v.Epoch), cUint(v.Timestamp), cUint(v.ParentRound), cBytes(v.CurrentRoot)}})
}
func (v D4VoteInfo) Hash() []byte { h := sha256.Sum256(v.Bytes()); return h[:] }

type D4LedgerCommitInfo struct {
	Network, Round, Epoch, Timestamp uint64
	Root                             []byte
}

func (l D4LedgerCommitInfo) Bytes(previousHash []byte) []byte {
	return marshalCBOR(cTag{39005, cArray{cUint(1), cUint(l.Network), cUint(l.Round), cUint(l.Epoch), cUint(l.Timestamp), cBytes(previousHash), optBytes(l.Root), cNull{}}})
}

type D4Seal struct {
	PreviousHash []byte
	Commit       D4LedgerCommitInfo
}

func (s D4Seal) Bytes() []byte {
	return s.Commit.Bytes(s.PreviousHash)
}

type D4Member struct {
	ID     string
	Weight uint64
	Public ed25519.PublicKey
}
type D4TrustBase struct {
	Network, Epoch, Threshold uint64
	Members                   []D4Member
}

func (tb D4TrustBase) Validate() error {
	seen := map[string]bool{}
	var total uint64
	for _, m := range tb.Members {
		if m.ID == "" || seen[m.ID] || m.Weight == 0 || len(m.Public) != ed25519.PublicKeySize || math.MaxUint64-total < m.Weight {
			return ErrD4Proof
		}
		seen[m.ID] = true
		total += m.Weight
	}
	if total == 0 || total > math.MaxUint64/2 || tb.Threshold != total*2/3+1 {
		return ErrD4Proof
	}
	return nil
}

func (tb D4TrustBase) member(id string) (D4Member, bool) {
	for _, m := range tb.Members {
		if m.ID == id {
			return m, true
		}
	}
	return D4Member{}, false
}

type D4QC struct {
	Vote       D4VoteInfo
	Seal       D4Seal
	Signatures map[string][]byte
}

func (qc D4QC) ID() []byte {
	ids := make([]string, 0, len(qc.Signatures))
	for id := range qc.Signatures {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	sigs := make(cArray, len(ids))
	for i, id := range ids {
		sigs[i] = cArray{cText(id), cBytes(qc.Signatures[id])}
	}
	h := sha256.Sum256(marshalCBOR(cArray{cText("UNICITY_D4_QC_ID"), cUint(2), cBytes(qc.Vote.Bytes()), cBytes(qc.Seal.Bytes()), sigs}))
	return h[:]
}

func (qc D4QC) Verify(tb D4TrustBase) error {
	if err := tb.Validate(); err != nil {
		return err
	}
	if qc.Vote.Epoch != tb.Epoch || qc.Vote.Round == 0 || qc.Vote.Timestamp == 0 || (qc.Vote.Round > 1 && qc.Vote.ParentRound == 0) || qc.Vote.ParentRound >= qc.Vote.Round || len(qc.Vote.CurrentRoot) != 32 || !bytes.Equal(qc.Seal.PreviousHash, qc.Vote.Hash()) {
		return ErrD4Proof
	}
	if qc.Seal.Commit.Round > 0 && (qc.Seal.Commit.Network != tb.Network || qc.Seal.Commit.Epoch != tb.Epoch || qc.Seal.Commit.Round != qc.Vote.ParentRound || qc.Seal.Commit.Timestamp < base.GenesisTime || qc.Seal.Commit.Timestamp > qc.Vote.Timestamp || len(qc.Seal.Commit.Root) != 32) {
		return ErrD4Proof
	}
	var weight uint64
	for id, sig := range qc.Signatures {
		m, ok := tb.member(id)
		if !ok || len(m.Public) != ed25519.PublicKeySize || !ed25519.Verify(m.Public, qc.Seal.Bytes(), sig) || math.MaxUint64-weight < m.Weight {
			return ErrD4Proof
		}
		weight += m.Weight
	}
	if weight < tb.Threshold || tb.Threshold == 0 {
		return ErrD4Quorum
	}
	return nil
}

// A deterministic key fixture is for the executable model only.
func D4FixtureTrustBase(epoch uint64, weights map[string]uint64) (D4TrustBase, map[string]ed25519.PrivateKey) {
	ids := make([]string, 0, len(weights))
	for id := range weights {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	tb := D4TrustBase{Network: 3, Epoch: epoch}
	keys := make(map[string]ed25519.PrivateKey)
	var total uint64
	for _, id := range ids {
		seed := sha256.Sum256([]byte(fmt.Sprintf("d4-model/%d/%s", epoch, id)))
		key := ed25519.NewKeyFromSeed(seed[:])
		keys[id] = key
		tb.Members = append(tb.Members, D4Member{id, weights[id], key.Public().(ed25519.PublicKey)})
		total += weights[id]
	}
	tb.Threshold = total*2/3 + 1
	return tb, keys
}
func D4SignQC(qc *D4QC, keys map[string]ed25519.PrivateKey, ids ...string) {
	qc.Seal.PreviousHash = qc.Vote.Hash()
	qc.Signatures = map[string][]byte{}
	for _, id := range ids {
		qc.Signatures[id] = ed25519.Sign(keys[id], qc.Seal.Bytes())
	}
}

type HandoffProof struct {
	Profile     uint64
	Record      OrderedHandoffRecord
	Control     ControlState
	ControlPath *base.UnicityTreeCertificate
	CommitQC    D4QC // QC(c+1), seal commits c
	OptionalQC  *D4QC
	Snapshot    FullSnapshot
}
type VerifiedHandoff struct {
	RecordID, Root, ControlDigest      []byte
	OrderRound, CommitSealRound, Epoch uint64
	Record                             OrderedHandoffRecord
	Snapshot                           FullSnapshot
}

func VerifyHandoff(p HandoffProof, old D4TrustBase) (VerifiedHandoff, error) {
	r := p.Record
	if p.Profile != D4Profile || !r.Valid() || r.Network != old.Network || r.Epoch != old.Epoch || !p.Control.Matches(r) {
		return VerifiedHandoff{}, ErrD4Record
	}
	if p.ControlPath == nil || p.ControlPath.Partition != D4ControlPartition || p.ControlPath.Version != 1 {
		return VerifiedHandoff{}, ErrD4Control
	}
	// Fix both the leaf key and IndexTreeOutput selector; a supplied shard key
	// must never choose the control leaf's position.
	digest := p.Control.Digest()
	hasher := abhash.New(crypto.SHA256.New())
	hasher.Write(digest)
	dataHash, e := hasher.Sum()
	if e != nil {
		return VerifiedHandoff{}, ErrD4Control
	}
	path := []*imt.PathItem{imt.NewPathItem(D4ControlPartition.Bytes(), dataHash)}
	for _, step := range p.ControlPath.HashSteps {
		if step == nil || step.Key == D4ControlPartition {
			return VerifiedHandoff{}, ErrD4Control
		}
		path = append(path, step.ToIMTPathItem())
	}
	root, e := imt.IndexTreeOutput(path, D4ControlPartition.Bytes(), crypto.SHA256)
	if e != nil {
		return VerifiedHandoff{}, ErrD4Control
	}
	c := p.CommitQC.Seal.Commit.Round
	if c == 0 || c < r.OrderedRound || c == math.MaxUint64 || p.CommitQC.Vote.Round != c+1 || p.CommitQC.Vote.Epoch != r.Epoch || p.CommitQC.Vote.ParentRound != c || p.CommitQC.Seal.Commit.Network != r.Network || p.CommitQC.Seal.Commit.Epoch != r.Epoch || !bytes.Equal(p.CommitQC.Seal.Commit.Root, root) || !bytes.Equal(p.CommitQC.Vote.CurrentRoot, root) {
		return VerifiedHandoff{}, ErrD4Proof
	}
	if e = p.CommitQC.Verify(old); e != nil {
		return VerifiedHandoff{}, e
	}
	if p.OptionalQC != nil {
		if p.OptionalQC.Vote.Round != c || p.OptionalQC.Vote.Epoch != r.Epoch || !bytes.Equal(p.OptionalQC.Vote.CurrentRoot, root) {
			return VerifiedHandoff{}, ErrD4Proof
		}
		if e = p.OptionalQC.Verify(old); e != nil {
			return VerifiedHandoff{}, e
		}
	}
	if !p.Snapshot.Control.Matches(r) || !bytes.Equal(p.Snapshot.Control.Digest(), digest) {
		return VerifiedHandoff{}, ErrD4Snapshot
	}
	full, e := p.Snapshot.Root()
	if e != nil || !bytes.Equal(full, root) {
		return VerifiedHandoff{}, ErrD4Snapshot
	}
	return VerifiedHandoff{r.ID(), root, digest, r.OrderedRound, c, r.Epoch, r, p.Snapshot}, nil
}

// G is a typed checkpoint, not an old block, QC or UC subject.
type EpochGenesis struct {
	Network, Epoch, Start, OrderedRound                                  uint64
	NextBodyID, RecordID, Root, ControlDigest, FrozenID, SuccessorTRHash []byte
}

func (g EpochGenesis) Bytes() []byte {
	return marshalCBOR(cArray{cText("UNICITY_EPOCH_GENESIS"), cUint(1), cUint(g.Network), cUint(g.Epoch), cBytes(g.NextBodyID), cUint(g.Start), cBytes(g.RecordID), cUint(g.OrderedRound), cBytes(g.Root), cBytes(g.ControlDigest), cBytes(g.FrozenID), cBytes(g.SuccessorTRHash)})
}
func (g EpochGenesis) ID() []byte { h := sha256.Sum256(g.Bytes()); return h[:] }
func DeriveEpochGenesis(v VerifiedHandoff, next TrustBaseBodyV2) (EpochGenesis, error) {
	r := v.Record
	id := next.Identity()
	if r.Epoch == math.MaxUint64 || next.Epoch != r.Epoch+1 || next.NetworkID != r.Network || !bytes.Equal(id[:], r.NextBodyID) || next.EarliestActivation > r.ActivationRound {
		return EpochGenesis{}, ErrD4Anchor
	}
	predecessorID := r.PredecessorBodyID
	if r.Epoch == 1 {
		var err error
		predecessorID, err = FirstV2PredecessorHash(V1Anchor{Version: 1, NetworkID: r.Network, Epoch: r.Epoch, HashIncludingSigs: r.PredecessorBodyID})
		if err != nil {
			return EpochGenesis{}, ErrD4Anchor
		}
	}
	if !bytes.Equal(next.PredecessorHash, predecessorID) {
		return EpochGenesis{}, ErrD4Anchor
	}
	if e := next.Validate(); e != nil {
		return EpochGenesis{}, ErrD4Anchor
	}
	return EpochGenesis{r.Network, next.Epoch, r.ActivationRound, r.OrderedRound, bytes.Clone(r.NextBodyID), bytes.Clone(v.RecordID), bytes.Clone(v.Root), bytes.Clone(v.ControlDigest), bytes.Clone(r.FrozenID), bytes.Clone(r.SuccessorTRHash)}, nil
}

type D4ParentKind uint8

const (
	D4AnchorParent D4ParentKind = iota + 1
	D4OrdinaryParent
)

type D4Parent struct {
	Kind         D4ParentKind
	GenesisID    []byte
	Epoch, Round uint64
	QC           *D4QC
}
type D4Bootstrap struct {
	Anchor               EpochGenesis
	NewTrust             D4TrustBase
	Installed            bool
	Snapshot             FullSnapshot
	HighestQC            D4Parent
	LastVoted, LockRound uint64
	Committed            []uint64
}

func CanBootstrapNew(v VerifiedHandoff, g EpochGenesis, s FullSnapshot) error {
	root, e := s.Root()
	if e != nil || !bytes.Equal(root, v.Root) || !bytes.Equal(g.Root, v.Root) || !bytes.Equal(g.RecordID, v.RecordID) || g.Epoch != v.Epoch+1 || g.Start != v.Record.ActivationRound || !bytes.Equal(s.Control.Digest(), v.ControlDigest) {
		return ErrD4Anchor
	}
	return nil
}
func (b *D4Bootstrap) Install(v VerifiedHandoff, g EpochGenesis, s FullSnapshot, newTrust D4TrustBase) error {
	if e := CanBootstrapNew(v, g, s); e != nil {
		return e
	}
	if e := newTrust.Validate(); e != nil || newTrust.Epoch != g.Epoch || newTrust.Network != g.Network {
		return ErrD4Anchor
	}
	if b.Installed {
		if !bytes.Equal(b.Anchor.ID(), g.ID()) {
			return ErrD4Anchor
		}
		return nil
	}
	b.Anchor = g
	b.NewTrust = newTrust
	b.Snapshot = s
	b.Installed = true
	b.HighestQC = D4Parent{Kind: D4AnchorParent, GenesisID: g.ID(), Epoch: g.Epoch, Round: g.Start - 1}
	return nil
}
func (b *D4Bootstrap) CanVote(round uint64, parent D4Parent) error {
	if !b.Installed || round < b.Anchor.Start || round <= b.LastVoted || parent.Epoch != b.Anchor.Epoch {
		return ErrD4Epoch
	}
	if parent.Kind == D4AnchorParent {
		if !bytes.Equal(parent.GenesisID, b.Anchor.ID()) || parent.Round != b.Anchor.Start-1 || b.HighestQC.Kind == D4OrdinaryParent {
			return ErrD4Anchor
		}
	} else if parent.Kind != D4OrdinaryParent || parent.QC == nil || parent.Round < b.Anchor.Start || parent.Round >= round || parent.Round < b.LockRound {
		return ErrD4Proof
	} else if parent.QC.Vote.Round != parent.Round || parent.QC.Vote.Epoch != b.Anchor.Epoch || parent.QC.Verify(b.NewTrust) != nil {
		return ErrD4Proof
	}
	return nil
}
func (b *D4Bootstrap) Vote(round uint64, parent D4Parent) error {
	if e := b.CanVote(round, parent); e != nil {
		return e
	}
	b.LastVoted = round
	if parent.Kind == D4OrdinaryParent && parent.Round > b.LockRound {
		b.LockRound = parent.Round
		b.HighestQC = parent
	}
	return nil
}

// The typed anchor occupies a slot for pacemaker ordering, but has no
// commit subject. This models isCommitCandidate before any QC aggregation.
func (b *D4Bootstrap) voteCommitSubject(round uint64, parent D4Parent, timestamp uint64) D4LedgerCommitInfo {
	if parent.Kind == D4AnchorParent {
		return D4LedgerCommitInfo{}
	}
	if round != parent.Round+1 {
		return D4LedgerCommitInfo{}
	}
	root := b.Anchor.Root
	if parent.QC != nil {
		root, timestamp = parent.QC.Vote.CurrentRoot, parent.QC.Vote.Timestamp
	}
	return D4LedgerCommitInfo{Network: b.NewTrust.Network, Round: parent.Round, Epoch: b.Anchor.Epoch, Timestamp: timestamp, Root: bytes.Clone(root)}
}

func (b *D4Bootstrap) BuildVoteQC(round uint64, parent D4Parent, root []byte, timestamp uint64) (D4QC, error) {
	if len(root) != 32 || timestamp == 0 {
		return D4QC{}, ErrD4Proof
	}
	if e := b.CanVote(round, parent); e != nil {
		return D4QC{}, e
	}
	commit := b.voteCommitSubject(round, parent, timestamp)
	if e := b.Vote(round, parent); e != nil {
		return D4QC{}, e
	}
	qc := D4QC{Vote: D4VoteInfo{Round: round, Epoch: b.Anchor.Epoch, ParentRound: parent.Round, Timestamp: timestamp, CurrentRoot: bytes.Clone(root)}, Seal: D4Seal{Commit: commit}}
	qc.Seal.PreviousHash = qc.Vote.Hash()
	return qc, nil
}
func (b *D4Bootstrap) Commit(parent D4Parent, child D4QC) error {
	if parent.Kind == D4AnchorParent {
		return ErrD4CommitAnchor
	}
	if !b.Installed || parent.Kind != D4OrdinaryParent || parent.QC == nil || parent.Epoch != b.Anchor.Epoch || parent.Round < b.Anchor.Start || parent.Round == math.MaxUint64 || child.Vote.Round != parent.Round+1 || child.Vote.ParentRound != parent.Round || child.Seal.Commit.Round != parent.Round || child.Seal.Commit.Epoch != b.Anchor.Epoch || !bytes.Equal(child.Seal.Commit.Root, parent.QC.Vote.CurrentRoot) || parent.QC.Vote.Round != parent.Round || parent.QC.Verify(b.NewTrust) != nil || child.Verify(b.NewTrust) != nil {
		return ErrD4Proof
	}
	b.Committed = append(b.Committed, parent.Round)
	return nil
}
func (b *D4Bootstrap) Restart() D4Bootstrap { return *b }

func NewHandoff(c Candidate, _ uint64) *Handoff { return &Handoff{Candidate: c} }
func (h *Handoff) Prepare() error {
	if h.Phase != PhaseIdle {
		return ErrD4Phase
	}
	h.Phase = PhasePrepared
	return nil
}
func (h *Handoff) Freeze(summary, parent []byte, body TrustBaseBodyV2) error {
	if h.Phase != PhasePrepared {
		return ErrD4Phase
	}
	if e := body.Validate(); e != nil {
		return e
	}
	if body.EarliestActivation != h.Candidate.MinActivation || !bytes.Equal(body.PredecessorHash, h.Candidate.PredecessorHash) || len(summary) == 0 || len(parent) == 0 {
		return ErrD4Record
	}
	id := body.Identity()
	h.Body = body
	h.BodyID = id[:]
	h.LastEVMParent = bytes.Clone(parent)
	h.FrozenID = frozenID(id[:], summary, parent, h.Candidate.CandidateHash, h.Candidate.Attempt, h.Candidate.PredecessorHash)
	h.Phase = PhaseFrozen
	return nil
}
func frozenID(body, summary, parent, candidate []byte, attempt uint64, predecessor []byte) []byte {
	x := sha256.Sum256(marshalCBOR(cArray{cText("UNICITY_HANDOFF_FROZEN"), cBytes(body), cBytes(summary), cBytes(parent), cBytes(candidate), cUint(attempt), cBytes(predecessor)}))
	return x[:]
}

func D4PreFreezeSummary(network uint64, predecessor []byte, attempt, round uint64, root, lastParent []byte) []byte {
	h := sha256.Sum256(marshalCBOR(cArray{cText("UNICITY_HANDOFF_PREFREEZE_STATE"), cUint(1), cUint(network), cBytes(predecessor), cUint(attempt), cUint(round), cBytes(root), cBytes(lastParent)}))
	return h[:]
}

func D4CandidateContextHash(network uint64, predecessor []byte, attempt uint64, candidate []byte, aMin uint64) []byte {
	h := sha256.Sum256(marshalCBOR(cArray{cText("UNICITY_HANDOFF_CANDIDATE_CONTEXT"), cUint(1), cUint(network), cBytes(predecessor), cUint(attempt), cBytes(candidate), cUint(aMin)}))
	return h[:]
}
func (h *Handoff) Endorse(weight, threshold uint64) error {
	if h.Phase != PhaseFrozen {
		return ErrD4Phase
	}
	if threshold == 0 || weight < threshold {
		return ErrD4Quorum
	}
	h.Endorsement = SigDomain{Network: h.Candidate.Network, Epoch: h.Candidate.OldEpoch, Attempt: h.Candidate.Attempt, MinActivation: h.Candidate.MinActivation, Predecessor: h.Candidate.PredecessorHash, FrozenID: h.FrozenID}
	h.Phase = PhaseEndorsed
	return nil
}
func (h *Handoff) Commit(order, start uint64, tr []byte) error {
	if h.Phase != PhaseEndorsed {
		return ErrD4Phase
	}
	if order == 0 || order > math.MaxUint64-PipelineDepth || start < h.Candidate.MinActivation || start < order+PipelineDepth || len(tr) != 32 {
		return ErrD4Record
	}
	h.Record = OrderedHandoffRecord{Network: h.Candidate.Network, Epoch: h.Candidate.OldEpoch, Attempt: h.Candidate.Attempt, OrderedRound: order, ActivationRound: start, PredecessorBodyID: bytes.Clone(h.Candidate.PredecessorHash), FrozenID: bytes.Clone(h.FrozenID), NextBodyID: bytes.Clone(h.BodyID), SuccessorTRHash: bytes.Clone(tr), Kind: "commit"}
	h.Phase = PhaseCommitted
	return nil
}
func (h *Handoff) Finalize(p HandoffProof, old D4TrustBase) error {
	if h.Phase != PhaseCommitted {
		return ErrD4Phase
	}
	if p.Profile == 0 {
		return ErrD4Proof
	}
	v, e := VerifyHandoff(p, old)
	if e != nil {
		return e
	}
	if !bytes.Equal(v.RecordID, h.Record.ID()) {
		return ErrD4Record
	}
	h.Proof = &p
	h.Verified = &v
	return nil
}
func (h *Handoff) Activate(g EpochGenesis, s FullSnapshot) error {
	if h.Phase != PhaseCommitted {
		return ErrD4Phase
	}
	if h.Verified == nil {
		return ErrD4Proof
	}
	if e := CanBootstrapNew(*h.Verified, g, s); e != nil {
		return e
	}
	h.Anchor = &g
	h.Phase = PhaseActivated
	return nil
}
func (h *Handoff) Acknowledge(round uint64) error {
	if h.Phase != PhaseActivated {
		return ErrD4Phase
	}
	h.AckEVMRound = round
	h.Phase = PhaseAcknowledged
	return nil
}
func (h *Handoff) Abort() error {
	if h.Phase < PhasePrepared || h.Phase >= PhaseCommitted {
		return ErrD4Phase
	}
	h.Phase = PhaseAborted
	return nil
}

// Timeout votes bind the tagged highQC, including the anchor's identity and
// slot. The new trust base signs these bytes; an old TC cannot advance it.
type D4TimeoutCertificate struct {
	Epoch, Round uint64
	HighQC       D4Parent
	Signatures   map[string][]byte
}

func (tc D4TimeoutCertificate) Bytes() []byte {
	tag := uint64(tc.HighQC.Kind)
	var qcID []byte
	if tc.HighQC.QC != nil {
		qcID = tc.HighQC.QC.ID()
	}
	return marshalCBOR(cArray{cText("UNICITY_D4_TIMEOUT"), cUint(2), cUint(tc.Epoch), cUint(tc.Round), cUint(tag), cBytes(tc.HighQC.GenesisID), cUint(tc.HighQC.Epoch), cUint(tc.HighQC.Round), cBytes(qcID)})
}
func D4SignTC(tc *D4TimeoutCertificate, keys map[string]ed25519.PrivateKey, ids ...string) {
	tc.Signatures = map[string][]byte{}
	for _, id := range ids {
		tc.Signatures[id] = ed25519.Sign(keys[id], tc.Bytes())
	}
}
func (tc D4TimeoutCertificate) Verify(tb D4TrustBase, g EpochGenesis) error {
	if err := tb.Validate(); err != nil {
		return err
	}
	if tc.Epoch != tb.Epoch || tc.Epoch != g.Epoch || tc.Round < g.Start || tc.HighQC.Epoch != g.Epoch {
		return ErrD4Epoch
	}
	if tc.HighQC.Kind == D4AnchorParent {
		if !bytes.Equal(tc.HighQC.GenesisID, g.ID()) || tc.HighQC.Round != g.Start-1 {
			return ErrD4Anchor
		}
	} else if tc.HighQC.Kind == D4OrdinaryParent {
		if tc.HighQC.QC == nil || tc.HighQC.Round < g.Start || tc.HighQC.Round >= tc.Round || tc.HighQC.QC.Vote.Round != tc.HighQC.Round {
			return ErrD4Proof
		}
		if e := tc.HighQC.QC.Verify(tb); e != nil {
			return e
		}
	} else {
		return ErrD4Proof
	}
	var weight uint64
	for id, sig := range tc.Signatures {
		m, ok := tb.member(id)
		if !ok || !ed25519.Verify(m.Public, tc.Bytes(), sig) || math.MaxUint64-weight < m.Weight {
			return ErrD4Proof
		}
		weight += m.Weight
	}
	if weight < tb.Threshold || tb.Threshold == 0 {
		return ErrD4Quorum
	}
	return nil
}
func (b *D4Bootstrap) ApplyTC(tc D4TimeoutCertificate) error {
	if !b.Installed {
		return ErrD4Anchor
	}
	if e := tc.Verify(b.NewTrust, b.Anchor); e != nil {
		return e
	}
	if tc.HighQC.Kind == D4OrdinaryParent && (b.HighestQC.Kind == D4AnchorParent || tc.HighQC.Round > b.HighestQC.Round) {
		b.HighestQC = tc.HighQC
	}
	return nil
}

type D4RecoveryHead struct {
	Parent       D4Parent
	Proof        *HandoffProof
	Snapshot     *FullSnapshot
	QC, CommitQC *D4QC
}

func (h D4RecoveryHead) Verify(old, newTB D4TrustBase, g EpochGenesis) error {
	if e := newTB.Validate(); e != nil || newTB.Epoch != g.Epoch || newTB.Network != g.Network {
		return ErrD4Epoch
	}
	if h.Parent.Kind == D4AnchorParent {
		if h.Proof == nil || h.Snapshot == nil || h.QC != nil || h.CommitQC != nil {
			return ErrD4Anchor
		}
		v, e := VerifyHandoff(*h.Proof, old)
		if e != nil {
			return e
		}
		if e = CanBootstrapNew(v, g, *h.Snapshot); e != nil {
			return e
		}
		if !bytes.Equal(h.Parent.GenesisID, g.ID()) || h.Parent.Epoch != g.Epoch || h.Parent.Round != g.Start-1 {
			return ErrD4Anchor
		}
		return nil
	}
	if h.Parent.Kind != D4OrdinaryParent || h.QC == nil || h.CommitQC == nil || h.Proof != nil || h.Snapshot != nil || h.Parent.Epoch != g.Epoch || h.Parent.Round < g.Start || h.QC.Vote.Round != h.Parent.Round || h.CommitQC.Vote.Round != h.Parent.Round+1 || h.CommitQC.Vote.ParentRound != h.Parent.Round || h.CommitQC.Seal.Commit.Round != h.Parent.Round || !bytes.Equal(h.CommitQC.Seal.Commit.Root, h.QC.Vote.CurrentRoot) {
		return ErrD4Proof
	}
	if e := h.QC.Verify(newTB); e != nil {
		return e
	}
	if e := h.CommitQC.Verify(newTB); e != nil {
		return e
	}
	return nil
}
func D4FallbackLeader(g EpochGenesis, members []string, round uint64) (string, error) {
	if round < g.Start || len(members) == 0 {
		return "", ErrD4Epoch
	}
	ordered := append([]string(nil), members...)
	sort.Strings(ordered)
	return ordered[(round-g.Start)%uint64(len(ordered))], nil
}

// Ordinary interval selection is separate from the typed old-suffix proof
// path. An old QC at c>=A* can prove H but cannot authorize ordinary work.
func D4VerifyOrdinaryQC(qc D4QC, tb D4TrustBase, start, end uint64) error {
	if qc.Vote.Epoch != tb.Epoch || qc.Vote.Round < start || (end != 0 && qc.Vote.Round >= end) {
		return ErrD4Epoch
	}
	return qc.Verify(tb)
}
