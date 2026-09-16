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
	"github.com/unicitynetwork/bft-core/rootchain/consensus/internal/frontiercodec"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
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

type group struct {
	pair    []byte
	id      [32]byte
	floor   uint64
	qc      []byte
	authors []string
}

type Collector struct {
	trust             *types.RootTrustBaseV1
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
	n := uint64(len(trust.RootNodes))
	if trust.QuorumThreshold <= 2*n/3 || trust.QuorumThreshold > n {
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
	return &Collector{trust: &trust, verifiers: verifiers, context: context, nonce: bytes.Clone(p.Nonce), partition: p.PartitionID, shard: shard, conf: bytes.Clone(p.FullShardConfHash), quorum: trust.QuorumThreshold, authors: make(map[string]struct{}, len(verifiers)), groups: make(map[[32]byte]*group), binding: binding}, nil
}

func (c *Collector) Add(raw []byte) AddResult {
	if c == nil {
		return AddResult{Err: ErrProfile}
	}
	n := uint64(len(raw))
	if c.exhausted || n > maxAggregate-c.used {
		c.exhausted = true
		c.used = maxAggregate
		c.candidate = Candidate{}
		return AddResult{Err: ErrBudget}
	}
	c.used += n
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
	qcDigest := sha256.Sum256(reply.QC)
	preimage, err := types.Cbor.Marshal(frontiercodec.SigningPreimage{Domain: frontiercodec.SigningDomain, Version: frontiercodec.Version, Context: c.context, Nonce: c.nonce, Author: reply.Author, PairID: pairID[:], QCDigest: qcDigest[:]})
	if err != nil || verifier.VerifyBytes(reply.Signature, preimage) != nil {
		return AddResult{Err: ErrUnauthentic}
	}
	if _, duplicate := c.authors[reply.Author]; duplicate {
		return AddResult{Status: Duplicate}
	}
	c.authors[reply.Author] = struct{}{}
	g := c.groups[pairID]
	if g == nil {
		g = &group{pair: bytes.Clone(reply.Pair), id: pairID}
		c.groups[pairID] = g
	}
	g.authors = append(g.authors, reply.Author)
	if round := qc.VoteInfo.RoundNumber; round > g.floor {
		g.floor, g.qc = round, bytes.Clone(reply.QC)
	}
	if uint64(len(g.authors)) >= c.quorum && !c.ordinary && !c.unsupported && !c.exhausted {
		authors := slices.Clone(g.authors)
		sort.Strings(authors)
		c.candidate = Candidate{pair: bytes.Clone(g.pair), qc: bytes.Clone(g.qc), id: g.id, floor: g.floor, authors: authors, binding: c.binding}
	}
	return AddResult{Status: Counted}
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
	if signatureBounds(pair.UC.UnicitySeal.Signatures) != nil {
		return [32]byte{}, 0, nil, ErrUnauthentic
	}
	if err := pair.TR.IsValid(); err != nil || pair.TR.HashMatches(pair.UC.TRHash) != nil || pair.UC.Verify(c.trust, crypto.SHA256, c.partition, c.shard, c.conf) != nil {
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
	if pair.UC.InputRecord.Epoch != 0 || pair.TR.Epoch != 0 || pair.TR.Round == 0 || pair.TR.Round <= pair.UC.InputRecord.RoundNumber {
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

func mustSealBytes(seal *types.UnicitySeal) []byte {
	b, _ := seal.SigBytes()
	return b
}

func strictSignatures(trust *types.RootTrustBaseV1, signatures map[string]hex.Bytes, data []byte) error {
	if signatureBounds(signatures) != nil || len(data) == 0 {
		return ErrUnauthentic
	}
	var votes uint64
	for author, sig := range signatures {
		if len(author) == 0 || len(author) > frontiercodec.MaxAuthor || len(sig) == 0 || len(sig) > frontiercodec.MaxSignature {
			return ErrUnauthentic
		}
		stake, err := trust.VerifySignature(data, sig, author)
		if err != nil || votes > ^uint64(0)-stake {
			return ErrUnauthentic
		}
		votes += stake
	}
	if votes < trust.QuorumThreshold {
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
	if err := qc.Verify(c.trust); err != nil {
		return ErrUnauthentic
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
}

func (c *Collector) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{}
	}
	s := Snapshot{used: c.used, exhausted: c.exhausted, ordinary: c.ordinary, unsupported: c.unsupported, ordinaryFirst: cloneEvidence(c.ordinaryFirst), ordinaryLatest: cloneEvidence(c.ordinaryLatest), unsupportedFirst: cloneEvidence(c.unsupportedFirst), unsupportedLatest: cloneEvidence(c.unsupportedLatest)}
	if !c.exhausted && !c.ordinary && !c.unsupported {
		s.candidate = cloneCandidate(c.candidate)
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
