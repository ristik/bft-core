// Package frontierclient strictly verifies and groups signed root frontier
// replies. It is an inert evidence collector: it performs no I/O and grants no
// bootstrap, cut, receipt, readiness, or signing authority. Collector is
// single-owner and not safe for concurrent Add/Snapshot calls.
package frontierclient

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"slices"
	"sort"

	"github.com/fxamacker/cbor/v2"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/internal/frontiercodec"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

var (
	ErrProfile     = errors.New("frontier client profile invalid")
	ErrBudget      = errors.New("frontier collector byte budget exhausted")
	ErrMalformed   = errors.New("frontier reply malformed or non-canonical")
	ErrUnauthentic = errors.New("frontier evidence unauthenticated")
	ErrUnsupported = errors.New("frontier evidence authenticated but unsupported")
)

const maxAggregate = 1 << 20

type Profile struct {
	TrustBase             *types.RootTrustBaseV1
	NetworkID             types.NetworkID
	PartitionID           types.PartitionID
	ShardID               types.ShardID
	FullShardConfHash     []byte
	RootEpoch             uint64
	GenesisOriginIdentity []byte
	Nonce                 []byte
	// Signing is the signing configuration of RootEpoch: the wire form of the QCs the collector accepts. The zero value is the legacy scheme.
	Signing votesig.Config
}

type Status uint8

const (
	Rejected Status = iota
	Counted
	Duplicate
	OrdinaryObserved
	UnsupportedObserved
)

type AddResult struct {
	Status Status
	Err    error
}

type PairEvidence struct {
	pair    []byte
	id      [32]byte
	binding [32]byte
}

func (e PairEvidence) CanonicalPair() []byte        { return bytes.Clone(e.pair) }
func (e PairEvidence) Identity() [32]byte           { return e.id }
func (e PairEvidence) Valid() bool                  { return len(e.pair) != 0 }
func (e PairEvidence) AcquisitionBinding() [32]byte { return e.binding }

// CertificateAndTechnical returns owned decoded evidence. Callers must still
// authenticate it at their own authority boundary; this accessor grants none.
func (e PairEvidence) CertificateAndTechnical() (*types.UnicityCertificate, *certification.TechnicalRecord, error) {
	if !e.Valid() {
		return nil, nil, ErrMalformed
	}
	var pair frontiercodec.Pair
	if err := strictDecode(e.pair, &pair, 2, true); err != nil || pair.UC == nil || pair.TR == nil {
		return nil, nil, ErrMalformed
	}
	b, err := types.Cbor.Marshal(pair)
	if err != nil {
		return nil, nil, err
	}
	var owned frontiercodec.Pair
	if err = types.Cbor.Unmarshal(b, &owned); err != nil {
		return nil, nil, err
	}
	return owned.UC, owned.TR, nil
}

// Candidate is quorum evidence that still requires an independently verified
// committed cut at or above Floor. It is never a bootstrap receipt.
type Candidate struct {
	pair    []byte
	qc      []byte
	id      [32]byte
	floor   uint64
	authors []string
	binding [32]byte
}

func (c Candidate) Valid() bool                  { return len(c.pair) != 0 }
func (c Candidate) CanonicalPair() []byte        { return bytes.Clone(c.pair) }
func (c Candidate) CanonicalQC() []byte          { return bytes.Clone(c.qc) }
func (c Candidate) PairIdentity() [32]byte       { return c.id }
func (c Candidate) Floor() uint64                { return c.floor }
func (c Candidate) Authors() []string            { return slices.Clone(c.authors) }
func (c Candidate) AcquisitionBinding() [32]byte { return c.binding }

// Snapshot is diagnostic evidence at one instant. A future receipt handoff
// must re-read the live Collector so an older snapshot cannot bypass later
// exhaustion, ordinary evidence, or unsupported evidence.
type Snapshot struct {
	used              uint64
	exhausted         bool
	ordinary          bool
	unsupported       bool
	ordinaryFirst     PairEvidence
	ordinaryLatest    PairEvidence
	unsupportedFirst  PairEvidence
	unsupportedLatest PairEvidence
	candidate         Candidate
	cut               VerifiedCut
}

func (s Snapshot) UsedBytes() uint64                      { return s.used }
func (s Snapshot) Exhausted() bool                        { return s.exhausted }
func (s Snapshot) Ordinary() bool                         { return s.ordinary }
func (s Snapshot) Unsupported() bool                      { return s.unsupported }
func (s Snapshot) FirstOrdinary() PairEvidence            { return cloneEvidence(s.ordinaryFirst) }
func (s Snapshot) LatestOrdinaryArrival() PairEvidence    { return cloneEvidence(s.ordinaryLatest) }
func (s Snapshot) FirstUnsupported() PairEvidence         { return cloneEvidence(s.unsupportedFirst) }
func (s Snapshot) LatestUnsupportedArrival() PairEvidence { return cloneEvidence(s.unsupportedLatest) }
func (s Snapshot) Candidate() Candidate                   { return cloneCandidate(s.candidate) }
func (s Snapshot) VerifiedCut() VerifiedCut               { return cloneVerifiedCut(s.cut) }

// VerifiedCut is diagnostic proof evidence for the Collector's current live
// candidate and acquisition binding. It is never a bootstrap receipt.
type VerifiedCut struct {
	raw     []byte
	round   uint64
	root    []byte
	pairID  [32]byte
	binding [32]byte
}

func (v VerifiedCut) Valid() bool                  { return len(v.raw) != 0 }
func (v VerifiedCut) CanonicalBytes() []byte       { return bytes.Clone(v.raw) }
func (v VerifiedCut) CommittedRound() uint64       { return v.round }
func (v VerifiedCut) RootHash() []byte             { return bytes.Clone(v.root) }
func (v VerifiedCut) PairIdentity() [32]byte       { return v.pairID }
func (v VerifiedCut) AcquisitionBinding() [32]byte { return v.binding }

type group struct {
	pair    []byte
	id      [32]byte
	floor   uint64
	qc      []byte
	authors []string
	weight  uint64
}

type Collector struct {
	trust             *types.RootTrustBaseV1
	signing           votesig.Config
	verifiers         map[string]abcrypto.Verifier
	context           frontiercodec.Context
	nonce             []byte
	partition         types.PartitionID
	shard             types.ShardID
	conf              []byte
	quorum            uint64
	used              uint64
	exhausted         bool
	authors           map[string]struct{}
	groups            map[[32]byte]*group
	ordinary          bool
	unsupported       bool
	ordinaryFirst     PairEvidence
	ordinaryLatest    PairEvidence
	unsupportedFirst  PairEvidence
	unsupportedLatest PairEvidence
	candidate         Candidate
	binding           [32]byte
	cut               VerifiedCut
}

// AcquisitionBinding identifies the owned request and trust profile. It is
// metadata for comparing evidence and grants no authority.
func (c *Collector) AcquisitionBinding() [32]byte {
	if c == nil {
		return [32]byte{}
	}
	return c.binding
}

func NewCollector(p Profile) (*Collector, error) {
	if p.TrustBase == nil || p.NetworkID == 0 || p.PartitionID == 0 || p.RootEpoch == 0 || len(p.FullShardConfHash) != sha256.Size || len(p.GenesisOriginIdentity) != sha256.Size || len(p.Nonce) != sha256.Size || p.ShardID.Length() > 4096 {
		return nil, ErrProfile
	}
	if p.TrustBase.Version != 1 || len(p.TrustBase.RootNodes) == 0 || len(p.TrustBase.RootNodes) > 64 || p.TrustBase.NetworkID != p.NetworkID || p.TrustBase.Epoch != p.RootEpoch {
		return nil, ErrProfile
	}
	if len(p.TrustBase.Signatures) > 64 || len(p.TrustBase.StateHash)+len(p.TrustBase.ChangeRecordHash)+len(p.TrustBase.PreviousEntryHash) > frontiercodec.MaxReply {
		return nil, ErrProfile
	}
	total := len(p.TrustBase.StateHash) + len(p.TrustBase.ChangeRecordHash) + len(p.TrustBase.PreviousEntryHash)
	for _, n := range p.TrustBase.RootNodes {
		if n == nil || n.Stake != 1 || len(n.NodeID) == 0 || len(n.NodeID) > frontiercodec.MaxAuthor || len(n.SigKey) == 0 || len(n.SigKey) > frontiercodec.MaxAuthor || len(n.NodeID) > frontiercodec.MaxPart-total || len(n.SigKey) > frontiercodec.MaxPart-total-len(n.NodeID) {
			return nil, ErrProfile
		}
		total += len(n.NodeID) + len(n.SigKey)
	}
	for author, sig := range p.TrustBase.Signatures {
		if len(author) == 0 || len(author) > frontiercodec.MaxAuthor || len(sig) > frontiercodec.MaxSignature || len(author) > frontiercodec.MaxPart-total || len(sig) > frontiercodec.MaxPart-total-len(author) {
			return nil, ErrProfile
		}
		total += len(author) + len(sig)
	}
	b, err := types.Cbor.Marshal(p.TrustBase)
	if err != nil || len(b) > frontiercodec.MaxReply {
		return nil, ErrProfile
	}
	var trust types.RootTrustBaseV1
	if err := types.Cbor.Unmarshal(b, &trust); err != nil {
		return nil, ErrProfile
	}
	slices.SortFunc(trust.RootNodes, func(a, b *types.NodeInfo) int { return bytes.Compare([]byte(a.NodeID), []byte(b.NodeID)) })
	verifiers := make(map[string]abcrypto.Verifier, len(trust.RootNodes))
	for _, n := range trust.RootNodes {
		if n == nil || n.Stake != 1 || len(n.NodeID) == 0 || len(n.NodeID) > frontiercodec.MaxAuthor || len(n.SigKey) == 0 || len(n.SigKey) > frontiercodec.MaxAuthor {
			return nil, ErrProfile
		}
		if _, exists := verifiers[n.NodeID]; exists {
			return nil, ErrProfile
		}
		v, err := abcrypto.NewVerifierSecp256k1(bytes.Clone(n.SigKey))
		if err != nil {
			return nil, ErrProfile
		}
		verifiers[n.NodeID] = v
	}
	n, err := quorumweight.TotalWeight(trust.RootNodes)
	if err != nil {
		return nil, ErrProfile
	}
	if min, err := quorumweight.Threshold(n); err != nil || trust.QuorumThreshold < min || trust.QuorumThreshold > n {
		return nil, ErrProfile
	}
	shardBytes, err := types.Cbor.Marshal(p.ShardID)
	if err != nil || len(shardBytes) > frontiercodec.MaxPart {
		return nil, ErrProfile
	}
	var shard types.ShardID
	if err := types.Cbor.Unmarshal(shardBytes, &shard); err != nil {
		return nil, ErrProfile
	}
	context := frontiercodec.Context{NetworkID: p.NetworkID, PartitionID: p.PartitionID, CanonicalShardBytes: bytes.Clone(shard.Bytes()), FullShardConfHash: bytes.Clone(p.FullShardConfHash), RootEpoch: p.RootEpoch, GenesisOriginIdentity: bytes.Clone(p.GenesisOriginIdentity)}
	ownedTrust, err := types.Cbor.Marshal(&trust)
	if err != nil || len(ownedTrust) > frontiercodec.MaxReply {
		return nil, ErrProfile
	}
	trustFingerprint := sha256.Sum256(ownedTrust)
	binding, err := frontiercodec.AcquisitionBinding(context, p.Nonce, trustFingerprint[:])
	if err != nil {
		return nil, ErrProfile
	}
	return &Collector{trust: &trust, signing: p.Signing, verifiers: verifiers, context: context, nonce: bytes.Clone(p.Nonce), partition: p.PartitionID, shard: shard, conf: bytes.Clone(p.FullShardConfHash), quorum: trust.QuorumThreshold, authors: make(map[string]struct{}, len(verifiers)), groups: make(map[[32]byte]*group), binding: binding}, nil
}

// stakeOf is the weight of a trust-base member; the quorum over replies is a weight, not an author count.
func (c *Collector) stakeOf(author string) (uint64, bool) {
	for _, n := range c.trust.RootNodes {
		if n.NodeID == author {
			return n.Stake, true
		}
	}
	return 0, false
}

func (c *Collector) Add(raw []byte) AddResult {
	return c.add(raw, "")
}

// AddFrom verifies that an eligible positive response author matches the
// locally configured peer identity. Negative pair evidence remains retained
// independently of outer author eligibility.
func (c *Collector) AddFrom(raw []byte, expectedAuthor string) AddResult {
	if expectedAuthor == "" {
		return AddResult{Err: ErrProfile}
	}
	return c.add(raw, expectedAuthor)
}

func (c *Collector) add(raw []byte, expectedAuthor string) AddResult {
	if c == nil {
		return AddResult{Err: ErrProfile}
	}
	if err := c.charge(raw); err != nil {
		return AddResult{Err: err}
	}
	if len(raw) == 0 || len(raw) > frontiercodec.MaxReply {
		return AddResult{Err: ErrMalformed}
	}
	var reply frontiercodec.Reply
	if err := strictDecode(raw, &reply, 5, false); err != nil || len(reply.Author) > frontiercodec.MaxAuthor || len(reply.Pair) == 0 || len(reply.Pair) > frontiercodec.MaxPart || len(reply.QC) > frontiercodec.MaxPart || len(reply.Signature) > frontiercodec.MaxSignature {
		return AddResult{Err: ErrMalformed}
	}
	var pair frontiercodec.Pair
	if err := strictDecode(reply.Pair, &pair, 2, true); err != nil {
		return AddResult{Err: ErrMalformed}
	}
	pairID, class, strictSeal, err := c.authenticatePair(pair)
	if err != nil {
		return AddResult{Err: err}
	}
	evidence := PairEvidence{pair: bytes.Clone(reply.Pair), id: pairID, binding: c.binding}
	if class != pairInitial {
		c.retainNegative(evidence, class == pairOrdinary)
		status := UnsupportedObserved
		err := ErrUnsupported
		if class == pairOrdinary {
			status, err = OrdinaryObserved, nil
		}
		// Extra bad/unknown seal signatures prevent positive counting but cannot
		// erase the independently authenticated negative observation.
		_ = strictSeal
		return AddResult{Status: status, Err: err}
	}
	if strictSeal != nil {
		return AddResult{Err: strictSeal}
	}
	if reply.Version != frontiercodec.Version || len(reply.Author) == 0 || len(reply.QC) == 0 || len(reply.Signature) == 0 {
		return AddResult{Err: ErrMalformed}
	}
	var qc drctypes.QuorumCert
	if err := strictDecode(reply.QC, &qc, 3, true); err != nil {
		return AddResult{Err: ErrMalformed}
	}
	if err := c.verifyQC(&qc); err != nil {
		return AddResult{Err: err}
	}
	verifier := c.verifiers[reply.Author]
	if verifier == nil {
		return AddResult{Err: ErrUnauthentic}
	}
	if expectedAuthor != "" && reply.Author != expectedAuthor {
		return AddResult{Err: ErrUnauthentic}
	}
	qcDigest := sha256.Sum256(reply.QC)
	preimage, err := types.Cbor.Marshal(frontiercodec.SigningPreimage{Domain: frontiercodec.SigningDomain, Version: frontiercodec.Version, Context: c.context, Nonce: c.nonce, Author: reply.Author, PairID: pairID[:], QCDigest: qcDigest[:]})
	if err != nil || verifier.VerifyBytes(reply.Signature, preimage) != nil {
		return AddResult{Err: ErrUnauthentic}
	}
	if _, duplicate := c.authors[reply.Author]; duplicate {
		return AddResult{Status: Duplicate}
	}
	stake, ok := c.stakeOf(reply.Author)
	if !ok {
		return AddResult{Err: ErrUnauthentic}
	}
	g := c.groups[pairID]
	if g != nil {
		if _, err := quorumweight.Add(g.weight, stake); err != nil {
			return AddResult{Err: ErrUnauthentic}
		}
	}
	c.authors[reply.Author] = struct{}{}
	g = c.groups[pairID]
	if g == nil {
		g = &group{pair: bytes.Clone(reply.Pair), id: pairID}
		c.groups[pairID] = g
	}
	g.authors = append(g.authors, reply.Author)
	g.weight += stake // cannot overflow: checked above
	if round := qc.VoteInfo.RoundNumber; round > g.floor {
		g.floor, g.qc = round, bytes.Clone(reply.QC)
	}
	if quorumweight.Reached(g.weight, c.quorum) && !c.ordinary && !c.unsupported && !c.exhausted {
		authors := slices.Clone(g.authors)
		sort.Strings(authors)
		c.candidate = Candidate{pair: bytes.Clone(g.pair), qc: bytes.Clone(g.qc), id: g.id, floor: g.floor, authors: authors, binding: c.binding}
	}
	c.cut = VerifiedCut{}
	return AddResult{Status: Counted}
}

func (c *Collector) charge(raw []byte) error {
	n := uint64(len(raw))
	if c.exhausted || n > maxAggregate-c.used {
		c.exhausted = true
		c.used = maxAggregate
		c.candidate = Candidate{}
		c.cut = VerifiedCut{}
		return ErrBudget
	}
	c.used += n
	return nil
}

// AddCut verifies a canonical committed-root membership proof against the
// Collector's current live candidate. The same aggregate byte budget covers
// signed replies, malformed cuts, duplicates, and successful cuts.
func (c *Collector) AddCut(raw []byte) (VerifiedCut, error) {
	if c == nil {
		return VerifiedCut{}, ErrProfile
	}
	if err := c.charge(raw); err != nil {
		return VerifiedCut{}, err
	}
	if len(raw) == 0 || len(raw) > frontiercodec.MaxReply {
		return VerifiedCut{}, ErrMalformed
	}
	var proof frontiercodec.CutProof
	if err := strictDecode(raw, &proof, 9, false); err != nil || len(proof.AcquisitionBinding) > sha256.Size || len(proof.RootHash) > sha256.Size || len(proof.CommitQC) > frontiercodec.MaxPart || len(proof.Pair) == 0 || len(proof.Pair) > frontiercodec.MaxPart || len(proof.ShardCertificate) > frontiercodec.MaxPart || len(proof.UnicityCertificate) > frontiercodec.MaxPart {
		return VerifiedCut{}, ErrMalformed
	}
	var pair frontiercodec.Pair
	if err := strictDecode(proof.Pair, &pair, 2, true); err != nil {
		return VerifiedCut{}, ErrMalformed
	}
	pairID, class, strictSeal, err := c.authenticatePair(pair)
	if err != nil {
		return VerifiedCut{}, err
	}
	if class != pairInitial {
		c.retainNegative(PairEvidence{pair: bytes.Clone(proof.Pair), id: pairID, binding: c.binding}, class == pairOrdinary)
		return VerifiedCut{}, ErrUnsupported
	}
	if c.exhausted || c.ordinary || c.unsupported || !c.candidate.Valid() {
		return VerifiedCut{}, ErrUnsupported
	}
	if proof.Version != frontiercodec.Version || len(proof.AcquisitionBinding) != sha256.Size || len(proof.RootHash) != sha256.Size || proof.RootRound == 0 || proof.RootEpoch == 0 || len(proof.CommitQC) == 0 || len(proof.ShardCertificate) == 0 || len(proof.UnicityCertificate) == 0 {
		return VerifiedCut{}, ErrMalformed
	}
	if strictSeal != nil || pairID != c.candidate.id {
		return VerifiedCut{}, ErrUnauthentic
	}
	if !bytes.Equal(proof.AcquisitionBinding, c.binding[:]) || proof.RootEpoch != c.context.RootEpoch {
		return VerifiedCut{}, ErrUnauthentic
	}
	var qc drctypes.QuorumCert
	if err := strictDecode(proof.CommitQC, &qc, 3, true); err != nil {
		return VerifiedCut{}, ErrMalformed
	}
	if err := c.verifyQC(&qc); err != nil || qc.LedgerCommitInfo.RootChainRoundNumber != proof.RootRound || qc.LedgerCommitInfo.Epoch != proof.RootEpoch || qc.LedgerCommitInfo.NetworkID != c.context.NetworkID || !bytes.Equal(qc.LedgerCommitInfo.Hash, proof.RootHash) || proof.RootRound < c.candidate.floor {
		return VerifiedCut{}, ErrUnauthentic
	}
	var shardCert types.ShardTreeCertificate
	if err := strictCanonicalDecode(proof.ShardCertificate, &shardCert, true); err != nil || shardCertificateBounds(shardCert) != nil || shardCert.IsValid(c.shard) != nil {
		return VerifiedCut{}, ErrMalformed
	}
	var unicityCert types.UnicityTreeCertificate
	if err := strictCanonicalDecode(proof.UnicityCertificate, &unicityCert, true); err != nil || unicityCertificateBounds(&unicityCert) != nil || unicityCert.IsValid(c.partition) != nil {
		return VerifiedCut{}, ErrMalformed
	}
	trHash, err := pair.TR.Hash()
	if err != nil || !bytes.Equal(trHash, pair.UC.TRHash) {
		return VerifiedCut{}, ErrUnauthentic
	}
	shardRoot, err := shardCert.ComputeCertificateHash(pair.UC.InputRecord, trHash, c.conf, crypto.SHA256)
	if err != nil {
		return VerifiedCut{}, ErrUnauthentic
	}
	cutRoot, err := unicityCert.EvalAuthPath(shardRoot, crypto.SHA256)
	if err != nil || !bytes.Equal(cutRoot, proof.RootHash) {
		return VerifiedCut{}, ErrUnauthentic
	}
	v := VerifiedCut{raw: bytes.Clone(raw), round: proof.RootRound, root: bytes.Clone(proof.RootHash), pairID: pairID, binding: c.binding}
	c.cut = cloneVerifiedCut(v)
	return v, nil
}

type pairClass uint8

const (
	pairInitial pairClass = iota + 1
	pairOrdinary
	pairUnsupported
)

func (c *Collector) authenticatePair(pair frontiercodec.Pair) ([32]byte, pairClass, error, error) {
	if pair.UC == nil || pair.TR == nil || pair.UC.InputRecord == nil || pair.UC.UnicitySeal == nil {
		return [32]byte{}, 0, nil, ErrUnauthentic
	}
	if membershipBounds(pair.UC) != nil {
		return [32]byte{}, 0, nil, ErrUnauthentic
	}
	if signatureBounds(pair.UC.UnicitySeal.Signatures) != nil {
		return [32]byte{}, 0, nil, ErrUnauthentic
	}
	if err := pair.TR.IsValid(); err != nil || pair.TR.HashMatches(pair.UC.TRHash) != nil || pair.UC.Verify(quorumweight.Checked(c.trust), crypto.SHA256, c.partition, c.shard, c.conf) != nil {
		return [32]byte{}, 0, nil, ErrUnauthentic
	}
	seal := pair.UC.UnicitySeal
	if seal.NetworkID != c.context.NetworkID {
		return [32]byte{}, 0, nil, ErrUnauthentic
	}
	if seal.Epoch != c.context.RootEpoch {
		id, err := frontiercodec.PairIdentity(pair, c.context)
		if err != nil {
			return [32]byte{}, 0, nil, ErrUnauthentic
		}
		return id, pairUnsupported, strictSignatures(c.trust, seal.Signatures, mustSealBytes(seal)), nil
	}
	// The collector is bound to one assignment's configuration hash (c.conf), so the shard epochs are
	// authenticated by that binding rather than fixed at zero. The certified epoch never exceeds the
	// authorized one, and the authorized round still strictly advances the certified one.
	if pair.UC.InputRecord.Epoch > pair.TR.Epoch || pair.TR.Round == 0 || pair.TR.Round <= pair.UC.InputRecord.RoundNumber {
		id, err := frontiercodec.PairIdentity(pair, c.context)
		if err != nil {
			return [32]byte{}, 0, nil, ErrUnauthentic
		}
		return id, pairUnsupported, strictSignatures(c.trust, seal.Signatures, mustSealBytes(seal)), nil
	}
	id, err := frontiercodec.PairIdentity(pair, c.context)
	if err != nil {
		return [32]byte{}, 0, nil, ErrUnauthentic
	}
	strict := strictSignatures(c.trust, seal.Signatures, mustSealBytes(seal))
	initialBytes, _ := (&types.InputRecord{Version: 1}).Bytes()
	irBytes, _ := pair.UC.InputRecord.Bytes()
	if bytes.Equal(irBytes, initialBytes) {
		return id, pairInitial, strict, nil
	}
	if pair.UC.InputRecord.RoundNumber == 0 {
		return id, pairUnsupported, strict, nil
	}
	ir := pair.UC.InputRecord
	origin := evmroot.RootOriginV2{
		NetworkID: uint64(seal.NetworkID), RootRound: seal.RootChainRoundNumber, RootEpoch: seal.Epoch,
		ReferenceTime: seal.Timestamp, UnicityTreeRoot: seal.Hash, InputVersion: uint64(ir.Version),
		IR:     evmroot.ShardInputRecord{Round: ir.RoundNumber, Epoch: ir.Epoch, PreviousHash: ir.PreviousHash, Hash: ir.Hash, Timestamp: ir.Timestamp, BlockHash: ir.BlockHash},
		TRHash: pair.UC.TRHash, ShardConfHash: pair.UC.ShardConfHash,
	}
	class, err := origin.Class()
	if err != nil || (class != evmroot.OriginFirstCertifiedV2 && class != evmroot.OriginOrdinaryV2) {
		return id, pairUnsupported, strict, nil
	}
	return id, pairOrdinary, strict, nil
}

func membershipBounds(uc *types.UnicityCertificate) error {
	if uc == nil || uc.UnicityTreeCertificate == nil || len(uc.UnicityTreeCertificate.HashSteps) > 1024 || len(uc.ShardTreeCertificate.SiblingHashes) > 4096 {
		return ErrUnauthentic
	}
	if unicityCertificateBounds(uc.UnicityTreeCertificate) != nil || shardCertificateBounds(uc.ShardTreeCertificate) != nil {
		return ErrUnauthentic
	}
	return nil
}

func shardCertificateBounds(cert types.ShardTreeCertificate) error {
	if len(cert.SiblingHashes) > 4096 {
		return ErrMalformed
	}
	for _, hash := range cert.SiblingHashes {
		if len(hash) != sha256.Size {
			return ErrMalformed
		}
	}
	return nil
}

func unicityCertificateBounds(cert *types.UnicityTreeCertificate) error {
	if cert == nil || len(cert.HashSteps) > 1024 {
		return ErrMalformed
	}
	for _, step := range cert.HashSteps {
		if step == nil || len(step.Hash) != sha256.Size {
			return ErrMalformed
		}
	}
	return nil
}

func mustSealBytes(seal *types.UnicitySeal) []byte {
	b, _ := seal.SigBytes()
	return b
}

func strictSignatures(trust *types.RootTrustBaseV1, signatures map[string]hex.Bytes, data []byte) error {
	if signatureBounds(signatures) != nil || len(data) == 0 {
		return ErrUnauthentic
	}
	for author, sig := range signatures {
		if len(author) == 0 || len(author) > frontiercodec.MaxAuthor || len(sig) == 0 || len(sig) > frontiercodec.MaxSignature {
			return ErrUnauthentic
		}
	}
	if _, err := quorumweight.VerifySignedStrict(trust, data, signatures); err != nil {
		return ErrUnauthentic
	}
	return nil
}

func signatureBounds(signatures map[string]hex.Bytes) error {
	if len(signatures) == 0 || len(signatures) > 64 {
		return ErrUnauthentic
	}
	for author, sig := range signatures {
		if len(author) == 0 || len(author) > frontiercodec.MaxAuthor || len(sig) == 0 || len(sig) > frontiercodec.MaxSignature {
			return ErrUnauthentic
		}
	}
	return nil
}

func (c *Collector) verifyQC(qc *drctypes.QuorumCert) error {
	if qc == nil || qc.VoteInfo == nil || qc.LedgerCommitInfo == nil {
		return ErrUnauthentic
	}
	if signatureBounds(qc.Signatures) != nil {
		return ErrUnauthentic
	}
	vote, parent, commit := qc.VoteInfo.RoundNumber, qc.VoteInfo.ParentRoundNumber, qc.LedgerCommitInfo.RootChainRoundNumber
	if vote == drctypes.GenesisRootRound || parent == 0 || commit == 0 || vote == ^uint64(0) || vote != parent+1 || commit != parent || qc.VoteInfo.Epoch != c.context.RootEpoch || qc.LedgerCommitInfo.Epoch != c.context.RootEpoch || qc.LedgerCommitInfo.NetworkID != c.context.NetworkID {
		return ErrUnauthentic
	}
	if err := qc.VerifyScheme(c.trust, c.signing); err != nil {
		return ErrUnauthentic
	}
	if c.signing.Scheme == votesig.SchemeDomainBound {
		// VerifyScheme checked both signature maps of the scheme 2 certificate strictly; only the bounds of the second map remain
		if len(qc.SealSignatures) != 0 && signatureBounds(qc.SealSignatures) != nil {
			return ErrUnauthentic
		}
		return nil
	}
	b, err := qc.LedgerCommitInfo.SigBytes()
	if err != nil {
		return ErrUnauthentic
	}
	return strictSignatures(c.trust, qc.Signatures, b)
}

func (c *Collector) retainNegative(e PairEvidence, ordinary bool) {
	if ordinary {
		if !c.ordinaryFirst.Valid() {
			c.ordinaryFirst = cloneEvidence(e)
		}
		c.ordinaryLatest = cloneEvidence(e)
		c.ordinary = true
	} else {
		if !c.unsupportedFirst.Valid() {
			c.unsupportedFirst = cloneEvidence(e)
		}
		c.unsupportedLatest = cloneEvidence(e)
		c.unsupported = true
	}
	c.candidate = Candidate{}
	c.cut = VerifiedCut{}
}

func (c *Collector) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{}
	}
	s := Snapshot{used: c.used, exhausted: c.exhausted, ordinary: c.ordinary, unsupported: c.unsupported, ordinaryFirst: cloneEvidence(c.ordinaryFirst), ordinaryLatest: cloneEvidence(c.ordinaryLatest), unsupportedFirst: cloneEvidence(c.unsupportedFirst), unsupportedLatest: cloneEvidence(c.unsupportedLatest)}
	if !c.exhausted && !c.ordinary && !c.unsupported {
		s.candidate = cloneCandidate(c.candidate)
		s.cut = cloneVerifiedCut(c.cut)
	}
	return s
}

func cloneEvidence(e PairEvidence) PairEvidence { e.pair = bytes.Clone(e.pair); return e }
func cloneCandidate(c Candidate) Candidate {
	c.pair = bytes.Clone(c.pair)
	c.qc = bytes.Clone(c.qc)
	c.authors = slices.Clone(c.authors)
	return c
}
func cloneVerifiedCut(v VerifiedCut) VerifiedCut {
	v.raw = bytes.Clone(v.raw)
	v.root = bytes.Clone(v.root)
	return v
}

func strictMode(tags cbor.TagsMode) cbor.DecMode {
	dm, err := (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden, TagsMd: tags, MaxNestedLevels: 32, MaxArrayElements: 8192, MaxMapPairs: 128, ExtraReturnErrors: cbor.ExtraDecErrorUnknownField}).DecMode()
	if err != nil {
		panic(err)
	}
	return dm
}

func strictDecode(raw []byte, target any, expectedArray int, allowTags bool) error {
	tags := cbor.TagsForbidden
	if allowTags {
		tags = cbor.TagsAllowed
	}
	dm := strictMode(tags)
	var generic any
	if err := dm.Unmarshal(raw, &generic); err != nil {
		return err
	}
	arr, ok := generic.([]any)
	if !ok || len(arr) != expectedArray {
		return ErrMalformed
	}
	canonical, err := types.Cbor.Marshal(generic)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrMalformed
	}
	if err := dm.Unmarshal(raw, target); err != nil {
		return err
	}
	reencoded, err := types.Cbor.Marshal(target)
	if err != nil || !bytes.Equal(reencoded, raw) {
		return ErrMalformed
	}
	return nil
}

func strictCanonicalDecode(raw []byte, target any, allowTags bool) error {
	tags := cbor.TagsForbidden
	if allowTags {
		tags = cbor.TagsAllowed
	}
	dm := strictMode(tags)
	var generic any
	if err := dm.Unmarshal(raw, &generic); err != nil {
		return err
	}
	canonical, err := types.Cbor.Marshal(generic)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrMalformed
	}
	if err := dm.Unmarshal(raw, target); err != nil {
		return err
	}
	reencoded, err := types.Cbor.Marshal(target)
	if err != nil || !bytes.Equal(reencoded, raw) {
		return ErrMalformed
	}
	return nil
}
