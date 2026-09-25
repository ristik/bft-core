package configuredprogress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/frontier"
	bfttypes "github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
)

const journalFrontierKind uint64 = 6
const journalFloorKind uint64 = 8

var journalFrontierKey = []byte("journal/frontier")
var journalFloorKey = []byte("journal/floor")
var journalCoveragePrefix = []byte("journal/coverage/")

// The frontier, its certified anchor and every covered request live in the
// journal's Bolt bucket. The separate file Store in frontier is never opened.
type journalFrontierWire struct {
	_          struct{} `cbor:",toarray"`
	Version    uint64
	Descriptor []byte
	Frontier   []byte
	Anchor     []byte
}

type journalFloorWire struct {
	_          struct{} `cbor:",toarray"`
	Version    uint64
	Descriptor []byte
	Sequence   uint64
	Round      uint64
	Height     uint64
}

type FrontierSnapshot struct {
	Anchor      *frontier.Record
	Record      *archive.Record
	ResultingUC *bfttypes.UnicityCertificate
	Floor       uint64
}

func coverageKey(height uint64) []byte {
	k := make([]byte, len(journalCoveragePrefix)+8)
	copy(k, journalCoveragePrefix)
	binary.BigEndian.PutUint64(k[len(journalCoveragePrefix):], height)
	return k
}

func encodeFrontierState(w journalFrontierWire) ([]byte, error) {
	p, err := marshal(w)
	if err != nil {
		return nil, err
	}
	return encodeEnvelope(journalFrontierKind, p, archive.MaxWireBytes+frontier.MaxBytes+4096)
}

func encodeFloor(w journalFloorWire) ([]byte, error) {
	p, err := marshal(w)
	if err != nil {
		return nil, err
	}
	return encodeEnvelope(journalFloorKind, p, 4096)
}

func sameFrontierContext(c Context, p frontier.Policy) bool {
	r, pc := c.Origin.Record(), c.Origin.ProofContext()
	a := p.Context
	return a.NetworkID == bfttypes.NetworkID(r.NetworkID) && a.PartitionID == bfttypes.PartitionID(r.PartitionID) && bytes.Equal(a.ShardID.Bytes(), r.ShardID) &&
		a.ShardEpoch == pc.ShardEpoch && a.RootEpoch == pc.RootEpoch && bytes.Equal(a.FullShardConfHash[:], c.Origin.FullShardConfHash().Bytes()) &&
		bytes.Equal(a.RegistryAddress[:], pc.RegistryAddress[:]) && bytes.Equal(a.RegistryCodeHash[:], pc.RegistryCodeHash[:]) &&
		bytes.Equal(a.GenesisCommitment[:], pc.GenesisCommitment[:]) && bytes.Equal(a.EVMGenesisHash[:], pc.EVMGenesisHash[:]) &&
		len(a.ExecutionIdentity) != 0 && sha256.Sum256(a.ExecutionIdentity) == c.ExecutionConfigV2
}

// EnableFrontier checks the exact configured subject and both replica names
// before activating pruning. The local anchor is authenticated against the
// certified journal; replica availability is checked only before advancement.
func (s *Store) EnableFrontier(ctx context.Context, c Context, limits JournalLimits, p frontier.Policy) error {
	if !s.journal || p.Binding == nil || p.Availability == nil || !sameFrontierContext(c, p) || p.Replicas[0] == "" || p.Replicas[1] == "" || p.Replicas[0] == p.Replicas[1] {
		return ErrContext
	}
	if err := limits.check(); err != nil {
		return err
	}
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return err
	}
	p.Context.ExecutionIdentity = bytes.Clone(p.Context.ExecutionIdentity)
	s.frontier = &p
	err = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if err := readJournalMeta(b, state.i.descriptorDigest, limits); err != nil {
			return err
		}
		_, err := readFrontier(b, state.i.descriptorDigest, p)
		return err
	})
	if err != nil {
		s.frontier = nil
		return err
	}
	_, err = s.LoadJournal(ctx, c, limits)
	if err != nil {
		s.frontier = nil
	}
	return err
}

func readFrontier(b *bolt.Bucket, dd [32]byte, policy frontier.Policy) (FrontierSnapshot, error) {
	var out FrontierSnapshot
	if b == nil {
		return out, ErrUnavailable
	}
	var floor journalFloorWire
	if raw := b.Get(journalFloorKey); raw != nil {
		p, err := decodeEnvelope(raw, journalFloorKind, 4096)
		if err != nil {
			return out, err
		}
		if err = decodePayload(p, &floor); err != nil {
			return out, err
		}
		if floor.Version != journalVersion || !bytes.Equal(floor.Descriptor, dd[:]) || floor.Sequence == 0 || floor.Round == 0 || floor.Height == 0 {
			return out, frontier.ErrStale
		}
		out.Floor = floor.Height
	}
	raw := b.Get(journalFrontierKey)
	if raw == nil {
		if floor.Sequence != 0 {
			return out, frontier.ErrStale
		}
		return out, nil
	}
	payload, err := decodeEnvelope(raw, journalFrontierKind, archive.MaxWireBytes+frontier.MaxBytes+4096)
	if err != nil {
		return out, err
	}
	var w journalFrontierWire
	if err = decodePayload(payload, &w); err != nil {
		return out, err
	}
	if w.Version != journalVersion || !bytes.Equal(w.Descriptor, dd[:]) {
		return out, frontier.ErrContext
	}
	policy.MinimumSequence = floor.Sequence
	r, err := frontier.Decode(w.Frontier, policy)
	if err != nil {
		return out, err
	}
	if floor.Sequence > r.Sequence || floor.Round > r.Round || floor.Height > r.Height {
		return out, frontier.ErrStale
	}
	if !bytes.Equal(b.Get(coverageKey(r.Height)), w.Frontier) {
		return out, frontier.ErrInvalid
	}
	response, err := archive.DecodeFor(r.Subject, w.Anchor)
	if err != nil || response.Outcome != archive.OK || response.Record == nil {
		return out, frontier.ErrInvalid
	}
	digest, err := archive.ManifestDigest(r.Subject, response.Record)
	if err != nil || digest != r.Acks[0].ManifestDigest || digest != r.Acks[1].ManifestDigest || policy.Binding.VerifyCertified(r, response.Record) != nil {
		return out, frontier.ErrInvalid
	}
	out.Anchor, out.Record = &r, response.Record
	return out, nil
}

func (s *Store) LoadFrontier(ctx context.Context, c Context, limits JournalLimits) (FrontierSnapshot, error) {
	if s.frontier == nil {
		return FrontierSnapshot{}, ErrSettings
	}
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return FrontierSnapshot{}, err
	}
	var out FrontierSnapshot
	err = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if err := readJournalMeta(b, state.i.descriptorDigest, limits); err != nil {
			return err
		}
		out, err = readFrontier(b, state.i.descriptorDigest, *s.frontier)
		return err
	})
	return out, err
}

// VerifyFrontierCopies refuses an advance while a previously promised anchor
// has lost either independently configured replica copy.
func (s *Store) VerifyFrontierCopies(ctx context.Context, c Context, limits JournalLimits) error {
	f, err := s.LoadFrontier(ctx, c, limits)
	if err != nil || f.Anchor == nil {
		return err
	}
	for _, ack := range f.Anchor.Acks {
		if err := s.frontier.Availability.VerifyAvailable(ack.Replica, f.Anchor.Subject, ack.ManifestDigest); err != nil {
			return fmt.Errorf("%w: %v", frontier.ErrUnavailable, err)
		}
	}
	return nil
}

// LoadCoverage returns a bounded page of committed archive promises for paced
// audits. The cursor is an EVM height, not a journal entry index.
func (s *Store) LoadCoverage(ctx context.Context, c Context, limits JournalLimits, after uint64, max int) ([]frontier.Record, error) {
	if s.frontier == nil || max < 1 || max > 64 {
		return nil, ErrSettings
	}
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return nil, err
	}
	var out []frontier.Record
	err = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if err := readJournalMeta(b, state.i.descriptorDigest, limits); err != nil {
			return err
		}
		f, err := readFrontier(b, state.i.descriptorDigest, *s.frontier)
		if err != nil || f.Anchor == nil {
			return err
		}
		if after >= f.Anchor.Height {
			return nil
		}
		for h := after + 1; h <= f.Anchor.Height && len(out) < max; h++ {
			raw := b.Get(coverageKey(h))
			if raw == nil {
				return frontier.ErrInvalid
			}
			r, err := frontier.Decode(raw, *s.frontier)
			if err != nil || r.Height != h {
				return frontier.ErrInvalid
			}
			out = append(out, r)
		}
		return nil
	})
	return out, err
}

// VerifyCoveredArchive licenses repair of a pruned record only when the
// journal committed its exact request and manifest before deletion.
func (s *Store) VerifyCoveredArchive(ctx context.Context, c Context, limits JournalLimits, q archive.Request, rec *archive.Record) error {
	if s.frontier == nil || rec == nil {
		return frontier.ErrUnavailable
	}
	var header gethtypes.Header
	if rlp.DecodeBytes(rec.Header, &header) != nil || header.Number == nil {
		return frontier.ErrInvalid
	}
	h := header.Number.Uint64()
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return err
	}
	return s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if err := readJournalMeta(b, state.i.descriptorDigest, limits); err != nil {
			return err
		}
		f, err := readFrontier(b, state.i.descriptorDigest, *s.frontier)
		if err != nil {
			return err
		}
		if f.Anchor == nil || h > f.Anchor.Height {
			return frontier.ErrUnavailable
		}
		raw := b.Get(coverageKey(h))
		if raw == nil {
			return frontier.ErrUnavailable
		}
		r, err := frontier.Decode(raw, *s.frontier)
		if err != nil || r.Subject.BlockHash != q.BlockHash || !sameCoverageSubject(r.Subject, q) {
			return frontier.ErrInvalid
		}
		digest, err := archive.ManifestDigest(q, rec)
		if err != nil || digest != r.Acks[0].ManifestDigest || digest != r.Acks[1].ManifestDigest || s.frontier.Binding.VerifyCertified(r, rec) != nil {
			return frontier.ErrInvalid
		}
		return nil
	})
}

func sameCoverageSubject(a, b archive.Request) bool {
	x, ex := archive.EncodeRequest(a)
	y, ey := archive.EncodeRequest(b)
	return ex == nil && ey == nil && bytes.Equal(x, y)
}

// AdvanceFrontier plans against live replica read-backs before the transaction.
// The transaction then rechecks every covered certified journal association,
// all local obligations and the previous frontier before committing the new
// frontier, anchor material and covered-range evidence together.
func (s *Store) AdvanceFrontier(ctx context.Context, c Context, limits JournalLimits, covered []frontier.Coverage) error {
	if s.frontier == nil || len(covered) == 0 {
		return ErrSettings
	}
	image, err := s.LoadJournal(ctx, c, limits)
	if err != nil {
		return err
	}
	current, err := s.LoadFrontier(ctx, c, limits)
	if err != nil {
		return err
	}
	next := covered[len(covered)-1].Anchor
	if covered[len(covered)-1].Material == nil {
		return frontier.ErrInvalid
	}
	nextUC, _, err := verifiedPairBytes(ctx, c, covered[len(covered)-1].Material.ResultingUC, covered[len(covered)-1].Material.ResultingTR)
	if err != nil {
		return fmt.Errorf("%w: resulting certificate: %v", frontier.ErrInvalid, err)
	}
	if nextUC.GetRootRoundNumber() != next.Round {
		return frontier.ErrInvalid
	}
	obligations := journalObligations(image)
	if _, err = frontier.PlanAdvance(current.Anchor, next, *s.frontier, covered, obligations); err != nil {
		return err
	}
	parent := common.Hash(c.Origin.BlockHash())
	if current.Anchor != nil {
		parent = common.Hash(current.Anchor.Subject.BlockHash)
	}
	for _, item := range covered {
		var header gethtypes.Header
		if item.Material == nil || rlp.DecodeBytes(item.Material.Header, &header) != nil || header.ParentHash != parent {
			return frontier.ErrInvalid
		}
		parent = common.Hash(item.Anchor.Subject.BlockHash)
	}
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return err
	}
	encoded := make([][]byte, len(covered))
	for i, item := range covered {
		encoded[i], err = frontier.Encode(item.Anchor, *s.frontier)
		if err != nil {
			return err
		}
	}
	anchorWire, err := archive.EncodeResponse(archive.Response{Request: next.Subject, Outcome: archive.OK, Record: covered[len(covered)-1].Material})
	if err != nil {
		return err
	}
	frontierWire, err := encodeFrontierState(journalFrontierWire{Version: journalVersion, Descriptor: state.i.descriptorDigest[:], Frontier: encoded[len(encoded)-1], Anchor: anchorWire})
	if err != nil {
		return err
	}
	if err := s.at("before-frontier-transaction"); err != nil {
		return err
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if !imageMatches(b, state.i) {
			return ErrStale
		}
		if err := readJournalMeta(b, state.i.descriptorDigest, limits); err != nil {
			return err
		}
		prior, err := readFrontier(b, state.i.descriptorDigest, *s.frontier)
		if err != nil {
			return err
		}
		if prior.Anchor == nil && current.Anchor != nil || prior.Anchor != nil && current.Anchor == nil || prior.Anchor != nil && prior.Anchor.Sequence != current.Anchor.Sequence {
			return frontier.ErrStale
		}
		for _, item := range covered {
			if err := checkCoveredCandidate(b, ctx, c, item); err != nil {
				return err
			}
		}
		if err := checkPruneObligations(b, next.Round); err != nil {
			return err
		}
		for i, item := range covered {
			if err := b.Put(coverageKey(item.Anchor.Height), encoded[i]); err != nil {
				return err
			}
		}
		if err := s.at("before-frontier-commit"); err != nil {
			return err
		}
		return b.Put(journalFrontierKey, frontierWire)
	})
	if err != nil {
		return err
	}
	return s.at("after-frontier-transaction")
}

func checkCoveredCandidate(b *bolt.Bucket, ctx context.Context, c Context, item frontier.Coverage) error {
	r := item.Anchor
	raw := b.Get(journalCandidateKey(r.Subject.BlockHash[:]))
	if raw == nil {
		return frontier.ErrUnavailable
	}
	w, err := decodeCandidate(raw)
	if err != nil {
		return err
	}
	if w.Status != 1 || w.Number != r.Height || !bytes.Equal(w.Hash, r.Subject.BlockHash[:]) || !bytes.Equal(w.StateRoot, r.StateRoot[:]) ||
		!bytes.Equal(w.AuthorizingUC, item.Material.OriginalUC) || !bytes.Equal(w.AuthorizingTR, item.Material.OriginalTR) || !bytes.Equal(w.ResultingUC, item.Material.ResultingUC) || !bytes.Equal(w.ResultingTR, item.Material.ResultingTR) {
		return frontier.ErrInvalid
	}
	resultUC, _, err := verifiedPairBytes(ctx, c, w.ResultingUC, w.ResultingTR)
	if err != nil {
		return fmt.Errorf("%w: %v", frontier.ErrInvalid, err)
	}
	if resultUC.GetRootRoundNumber() != r.Round || resultUC.InputRecord.RoundNumber != w.Round {
		return frontier.ErrInvalid
	}
	return nil
}

func journalObligations(image JournalSnapshot) []frontier.Obligation {
	var out []frontier.Obligation
	for _, o := range image.Observations {
		if o.Unresolved {
			out = append(out, frontier.Obligation{Round: o.UC.GetRootRoundNumber(), UnresolvedBody: true})
		}
	}
	return out
}

// A different certified block at or above either coordinate makes this body
// impossible to certify. The independent signing authority retains this
// node's vote record; the journal body is not that safety record.
func supersededCandidate(number, round, certifiedHeight, certifiedRound uint64) bool {
	return number <= certifiedHeight || round <= certifiedRound
}

func checkPruneObligations(b *bolt.Bucket, throughRoot uint64) error {
	curs := b.Cursor()
	for k, raw := curs.Seek(journalObservationPrefix); k != nil && bytes.HasPrefix(k, journalObservationPrefix); k, raw = curs.Next() {
		w, err := decodeObservation(raw)
		if err != nil {
			return err
		}
		if w.RootRound <= throughRoot && w.Unresolved {
			return frontier.ErrObligation
		}
	}
	return nil
}

// PruneFrontier is a second Bolt transaction. The deletion and floor advance
// are atomic. Repeating it after a crash is safe.
func (s *Store) PruneFrontier(ctx context.Context, c Context, limits JournalLimits) error {
	if s.frontier == nil {
		return ErrSettings
	}
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if !imageMatches(b, state.i) {
			return ErrStale
		}
		if err := readJournalMeta(b, state.i.descriptorDigest, limits); err != nil {
			return err
		}
		f, err := readFrontier(b, state.i.descriptorDigest, *s.frontier)
		if err != nil || f.Anchor == nil {
			if err != nil {
				return err
			}
			return frontier.ErrUnavailable
		}
		if f.Floor == f.Anchor.Height {
			return nil
		}
		anchorUC, _, err := verifiedPairBytes(ctx, c, f.Record.ResultingUC, f.Record.ResultingTR)
		if err != nil {
			return err
		}
		if err := checkPruneObligations(b, f.Anchor.Round); err != nil {
			return err
		}
		curs := b.Cursor()
		for k, raw := curs.Seek(journalCandidatePrefix); k != nil && bytes.HasPrefix(k, journalCandidatePrefix); k, raw = curs.Next() {
			w, e := decodeCandidate(raw)
			if e != nil {
				return e
			}
			if w.Status == 1 && w.Number <= f.Anchor.Height || w.Status != 1 && supersededCandidate(w.Number, w.Round, f.Anchor.Height, anchorUC.InputRecord.RoundNumber) {
				if w.Status == 1 {
					covered := b.Get(coverageKey(w.Number))
					if covered == nil {
						return frontier.ErrObligation
					}
					claimed, e := frontier.Decode(covered, *s.frontier)
					if e != nil || !bytes.Equal(claimed.Subject.BlockHash[:], w.Hash) {
						return frontier.ErrObligation
					}
				}
				if err := curs.Delete(); err != nil {
					return err
				}
				if err := s.at("mid-prune"); err != nil {
					return err
				}
			}
		}
		for k, raw := curs.Seek(journalObservationPrefix); k != nil && bytes.HasPrefix(k, journalObservationPrefix); k, raw = curs.Next() {
			w, e := decodeObservation(raw)
			if e != nil {
				return e
			}
			if w.Round <= anchorUC.InputRecord.RoundNumber && w.RootRound <= f.Anchor.Round {
				if err := curs.Delete(); err != nil {
					return err
				}
				if err := s.at("mid-prune"); err != nil {
					return err
				}
			}
		}
		floor, err := encodeFloor(journalFloorWire{Version: journalVersion, Descriptor: state.i.descriptorDigest[:], Sequence: f.Anchor.Sequence, Round: f.Anchor.Round, Height: f.Anchor.Height})
		if err != nil {
			return err
		}
		if err := s.at("before-prune-commit"); err != nil {
			return err
		}
		return b.Put(journalFloorKey, floor)
	})
}

func (s *Store) frontierPresent() (bool, error) {
	var present bool
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		present = b != nil && (b.Get(journalFrontierKey) != nil || b.Get(journalFloorKey) != nil)
		return nil
	})
	return present, err
}

func (s *Store) requireFrontierPolicy(b *bolt.Bucket) error {
	if s.frontier == nil && (b.Get(journalFrontierKey) != nil || b.Get(journalFloorKey) != nil) {
		return fmt.Errorf("%w: pruned journal requires authenticated frontier policy", ErrSettings)
	}
	return nil
}
