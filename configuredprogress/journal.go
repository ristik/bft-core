package configuredprogress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
)

// The journal shares the configured-progress transaction domain. A resulting certificate and
// its candidate association are published by CommitObservation's single Bolt transaction, before
// configured admission can deliver the certificate to a round or advance the live LUC.
const journalVersion uint64 = 1
const (
	journalCandidateKind   uint64 = 3
	journalObservationKind uint64 = 4
	journalMetaKind        uint64 = 5
	MaxCandidateBytes             = 8 << 20
	MaxJournalCandidates          = 4096
	MaxJournalObservations        = 8192
	MaxJournalBytes               = 128 << 20
)

var (
	// ErrLocalProposalConflict identifies the safe-to-decline case where a
	// leader already retained different bytes for this exact authorization.
	ErrLocalProposalConflict = errors.New("configured progress: local proposal already retained")
	journalMetaKey           = []byte("journal/meta")
	journalCandidatePrefix   = []byte("journal/c/")
	journalObservationPrefix = []byte("journal/o/")
)

type JournalLimits struct {
	Candidates   int
	Observations int
	Bytes        int64
}

func (l JournalLimits) check() error {
	if l.Candidates < 1 || l.Candidates > MaxJournalCandidates || l.Observations < 1 || l.Observations > MaxJournalObservations || l.Bytes < MaxCandidateBytes || l.Bytes > MaxJournalBytes {
		return fmt.Errorf("%w: journal limits outside candidates 1..%d, observations 1..%d, bytes %d..%d", ErrSettings, MaxJournalCandidates, MaxJournalObservations, MaxCandidateBytes, MaxJournalBytes)
	}
	return nil
}

type journalMetaWire struct {
	_            struct{} `cbor:",toarray"`
	Version      uint64
	Descriptor   []byte
	Candidates   uint64
	Observations uint64
	Bytes        uint64
}
type journalCandidateWire struct {
	_                                             struct{} `cbor:",toarray"`
	Version                                       uint64
	Descriptor                                    []byte
	Status                                        uint64 // 0 candidate, 1 certified
	Round, Number, ParentNumber                   uint64
	Hash, StateRoot, ParentHash, ParentState, Raw []byte
	BlockSize, StateSize                          uint64
	LocallyBuilt                                  bool
	AuthorizingUC, AuthorizingTR                  []byte
	ResultingUC, ResultingTR                      []byte
}
type journalObservationWire struct {
	_                struct{} `cbor:",toarray"`
	Version          uint64
	Descriptor       []byte
	Round, RootRound uint64
	TargetHash       []byte // nil for a quiet or bootstrap certificate
	Unresolved       bool
	UC, TR           []byte
}

// JournalCandidate retains the executor's exact dissemination bytes and its original authorizing
// pair. The resulting certificate is a different pair and is filled only by admission.
type JournalCandidate struct {
	Round, Number, ParentNumber                   uint64
	Hash, StateRoot, ParentHash, ParentState, Raw []byte
	BlockSize, StateSize                          uint64
	LocallyBuilt                                  bool
	AuthorizingUC                                 *types.UnicityCertificate
	AuthorizingTR                                 *certification.TechnicalRecord
}
type JournalEntry struct {
	Candidate   JournalCandidate
	Certified   bool
	ResultingUC *types.UnicityCertificate
	ResultingTR *certification.TechnicalRecord
}
type JournalObservation struct {
	UC         *types.UnicityCertificate
	TR         *certification.TechnicalRecord
	TargetHash []byte
	Unresolved bool
}
type JournalSnapshot struct {
	Candidates   []JournalEntry
	Observations []JournalObservation
	Bytes        int64
	Frontier     *FrontierSnapshot
	Restored     *RestoreAnchor
}

func journalCandidateKey(hash []byte) []byte {
	return append(bytes.Clone(journalCandidatePrefix), hash...)
}
func journalObservationKey(root, round uint64) []byte {
	k := make([]byte, len(journalObservationPrefix)+16)
	copy(k, journalObservationPrefix)
	binary.BigEndian.PutUint64(k[len(journalObservationPrefix):], root)
	binary.BigEndian.PutUint64(k[len(journalObservationPrefix)+8:], round)
	return k
}

func journalEpochObservationKey(epoch, root, round uint64) []byte {
	k := make([]byte, len(journalObservationPrefix)+24)
	copy(k, journalObservationPrefix)
	binary.BigEndian.PutUint64(k[len(journalObservationPrefix):], epoch)
	binary.BigEndian.PutUint64(k[len(journalObservationPrefix)+8:], root)
	binary.BigEndian.PutUint64(k[len(journalObservationPrefix)+16:], round)
	return k
}

// EnableJournal requires an initialized, fresh configured-origin v2 store. There is no implicit
// migration from a legacy LUC/record or from an already advanced configured-progress database.
// Reopening requires the identical limits and descriptor; no history is discarded at capacity.
func (s *Store) EnableJournal(ctx context.Context, c Context, limits JournalLimits) error {
	if err := limits.check(); err != nil {
		return err
	}
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return err
	}
	dd := state.i.descriptorDigest
	meta := journalMetaWire{Version: journalVersion, Descriptor: dd[:], Candidates: uint64(limits.Candidates), Observations: uint64(limits.Observations), Bytes: uint64(limits.Bytes)}
	p, err := marshal(meta)
	if err != nil {
		return err
	}
	raw, err := encodeEnvelope(journalMetaKind, p, MaxDescriptorBytes)
	if err != nil {
		return err
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if !imageMatches(b, state.i) {
			return ErrStale
		}
		old := b.Get(journalMetaKey)
		if old != nil {
			if !bytes.Equal(old, raw) {
				return fmt.Errorf("%w: journal version, origin or limits changed", ErrContext)
			}
			return nil
		}
		if state.i.control.Revision != 0 {
			return fmt.Errorf("%w: existing progress lacks a complete proposal history; use fresh D2 lane state", ErrVersion)
		}
		return b.Put(journalMetaKey, raw)
	})
	if err != nil {
		return err
	}
	s.journal = true
	if present, err := s.frontierPresent(); err != nil {
		return err
	} else if present {
		return nil // EnableFrontier must authenticate the anchor before a reader starts.
	}
	_, err = s.LoadJournal(ctx, c, limits)
	return err
}

func readJournalMeta(b *bolt.Bucket, dd [32]byte, limits JournalLimits) error {
	if b == nil {
		return ErrUnavailable
	}
	raw := b.Get(journalMetaKey)
	if raw == nil {
		return fmt.Errorf("%w: journal marker absent", ErrUnavailable)
	}
	p, err := decodeEnvelope(raw, journalMetaKind, MaxDescriptorBytes)
	if err != nil {
		return err
	}
	var m journalMetaWire
	if err := decodePayload(p, &m); err != nil {
		return err
	}
	if m.Version != journalVersion {
		return ErrVersion
	}
	if !bytes.Equal(m.Descriptor, dd[:]) || m.Candidates != uint64(limits.Candidates) || m.Observations != uint64(limits.Observations) || m.Bytes != uint64(limits.Bytes) {
		return ErrContext
	}
	return nil
}

func journalCount(b *bolt.Bucket) (candidates, observations int, n int64, err error) {
	c := b.Cursor()
	for k, v := c.Seek(journalCandidatePrefix); k != nil && bytes.HasPrefix(k, journalCandidatePrefix); k, v = c.Next() {
		candidates++
		n += int64(len(k) + len(v))
		if candidates > MaxJournalCandidates || n > MaxJournalBytes {
			return 0, 0, 0, ErrBounds
		}
	}
	for k, v := c.Seek(journalObservationPrefix); k != nil && bytes.HasPrefix(k, journalObservationPrefix); k, v = c.Next() {
		observations++
		n += int64(len(k) + len(v))
		if observations > MaxJournalObservations || n > MaxJournalBytes {
			return 0, 0, 0, ErrBounds
		}
	}
	return
}

func encodeCandidate(w journalCandidateWire) ([]byte, error) {
	p, err := marshal(w)
	if err != nil {
		return nil, err
	}
	return encodeEnvelope(journalCandidateKind, p, MaxCandidateBytes+MaxPairBytes*3)
}
func decodeCandidate(raw []byte) (journalCandidateWire, error) {
	p, err := decodeEnvelope(raw, journalCandidateKind, MaxCandidateBytes+MaxPairBytes*3)
	if err != nil {
		return journalCandidateWire{}, err
	}
	var w journalCandidateWire
	err = decodePayload(p, &w)
	return w, err
}
func encodeObservation(w journalObservationWire) ([]byte, error) {
	p, err := marshal(w)
	if err != nil {
		return nil, err
	}
	return encodeEnvelope(journalObservationKind, p, MaxPairBytes*2+4096)
}
func decodeObservation(raw []byte) (journalObservationWire, error) {
	p, err := decodeEnvelope(raw, journalObservationKind, MaxPairBytes*2+4096)
	if err != nil {
		return journalObservationWire{}, err
	}
	var w journalObservationWire
	err = decodePayload(p, &w)
	return w, err
}
func pairBytes(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) ([]byte, []byte, error) {
	u, err := types.Cbor.Marshal(uc)
	if err != nil {
		return nil, nil, err
	}
	t, err := types.Cbor.Marshal(tr)
	if err != nil {
		return nil, nil, err
	}
	if len(u) == 0 || len(t) == 0 || len(u)+len(t) > MaxPairBytes {
		return nil, nil, ErrBounds
	}
	return u, t, nil
}
func verifiedPairBytes(ctx context.Context, c Context, u, t []byte) (*types.UnicityCertificate, *certification.TechnicalRecord, error) {
	if len(u) == 0 || len(t) == 0 || len(u)+len(t) > MaxPairBytes {
		return nil, nil, ErrBounds
	}
	var uc types.UnicityCertificate
	var tr certification.TechnicalRecord
	if err := types.Cbor.Unmarshal(u, &uc); err != nil {
		return nil, nil, err
	}
	if err := types.Cbor.Unmarshal(t, &tr); err != nil {
		return nil, nil, err
	}
	if _, err := rootinput.AuthenticateHistoricalObservationV2(ctx, c.Observation, &uc, &tr); err != nil {
		return nil, nil, err
	}
	return &uc, &tr, nil
}

// PutJournalCandidate is the fsync barrier before publication or signing. It also resolves a
// previously durable UC whose body arrived later. Repeated identical candidates are idempotent;
// a hash reused for different bytes is a conflict. The configured origin is checked on every call.
func (s *Store) PutJournalCandidate(ctx context.Context, c Context, limits JournalLimits, v JournalCandidate) error {
	return s.putJournalCandidate(ctx, c, limits, v, false)
}

// PutHistoricalJournalCandidate retains a peer-recovered body whose original
// authorization was signed before the installed root epoch. This grants no
// current admission authority; the caller must verify the resulting certificate
// and the block binding before retaining the body.
func (s *Store) PutHistoricalJournalCandidate(ctx context.Context, c Context, limits JournalLimits, v JournalCandidate) error {
	return s.putJournalCandidate(ctx, c, limits, v, true)
}

func (s *Store) putJournalCandidate(ctx context.Context, c Context, limits JournalLimits, v JournalCandidate, historical bool) error {
	if !s.journal {
		return fmt.Errorf("%w: journal not enabled", ErrSettings)
	}
	if err := limits.check(); err != nil {
		return err
	}
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return err
	}
	if len(v.Hash) != sha256.Size || len(v.StateRoot) != sha256.Size || len(v.ParentHash) != sha256.Size || len(v.ParentState) != sha256.Size || len(v.Raw) == 0 || len(v.Raw) > MaxCandidateBytes || v.Number == 0 || v.Round == 0 || v.Number != v.ParentNumber+1 {
		return ErrBounds
	}
	if v.AuthorizingUC == nil || v.AuthorizingTR == nil {
		return ErrUntrusted
	}
	authenticate := rootinput.AuthenticateObservationV2
	if historical {
		authenticate = rootinput.AuthenticateHistoricalObservationV2
	}
	if _, err := authenticate(ctx, c.Observation, v.AuthorizingUC, v.AuthorizingTR); err != nil {
		return err
	}
	if v.AuthorizingTR.Round != v.Round {
		return fmt.Errorf("%w: candidate round differs from authorizing TR", ErrConflict)
	}
	u, t, err := pairBytes(v.AuthorizingUC, v.AuthorizingTR)
	if err != nil {
		return err
	}
	w := journalCandidateWire{Version: journalVersion, Descriptor: state.i.descriptorDigest[:], Round: v.Round, Number: v.Number, ParentNumber: v.ParentNumber, Hash: bytes.Clone(v.Hash), StateRoot: bytes.Clone(v.StateRoot), ParentHash: bytes.Clone(v.ParentHash), ParentState: bytes.Clone(v.ParentState), Raw: bytes.Clone(v.Raw), BlockSize: v.BlockSize, StateSize: v.StateSize, LocallyBuilt: v.LocallyBuilt, AuthorizingUC: u, AuthorizingTR: t}
	key := journalCandidateKey(v.Hash)
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if !imageMatches(b, state.i) {
			return ErrStale
		}
		if err := readJournalMeta(b, state.i.descriptorDigest, limits); err != nil {
			return err
		}
		if s.frontier != nil {
			frontierImage, e := readFrontier(b, state.i.descriptorDigest, *s.frontier)
			if e != nil {
				return e
			}
			if frontierImage.Anchor != nil {
				anchorUC, _, e := verifiedPairBytes(ctx, c, frontierImage.Record.ResultingUC, frontierImage.Record.ResultingTR)
				if e != nil {
					return e
				}
				if supersededCandidate(v.Number, v.Round, frontierImage.Anchor.Height, anchorUC.InputRecord.RoundNumber) {
					return fmt.Errorf("%w: candidate was superseded by the certified frontier", ErrConflict)
				}
			}
		}
		if old := b.Get(key); old != nil {
			prior, e := decodeCandidate(old)
			if e != nil {
				return e
			}
			w.Status, w.ResultingUC, w.ResultingTR = prior.Status, prior.ResultingUC, prior.ResultingTR
			// LocallyBuilt records that this node authored the proposal. A peer
			// may later return the same certified body during catch-up; that
			// source does not change its original provenance.
			w.LocallyBuilt = w.LocallyBuilt || prior.LocallyBuilt
			raw, e := encodeCandidate(w)
			if e != nil {
				return e
			}
			if !bytes.Equal(old, raw) {
				return fmt.Errorf("%w: same candidate hash has different bytes", ErrConflict)
			}
			return nil
		}
		if v.LocallyBuilt {
			cursor := b.Cursor()
			for k, raw := cursor.Seek(journalCandidatePrefix); k != nil && bytes.HasPrefix(k, journalCandidatePrefix); k, raw = cursor.Next() {
				prior, e := decodeCandidate(raw)
				if e != nil {
					return e
				}
				if !prior.LocallyBuilt || prior.Round != v.Round {
					continue
				}
				pu, _, e := verifiedPairBytes(ctx, c, prior.AuthorizingUC, prior.AuthorizingTR)
				if e != nil {
					return e
				}
				if pu.GetRootEpoch() == v.AuthorizingUC.GetRootEpoch() && pu.GetRootRoundNumber() == v.AuthorizingUC.GetRootRoundNumber() && pu.GetRoundNumber() == v.AuthorizingUC.GetRoundNumber() {
					return fmt.Errorf("%w: %w: a different local proposal was already retained for this authorization; refusing publication after restart", ErrConflict, ErrLocalProposalConflict)
				}
			}
		}
		// A root certificate may be durable before its candidate body arrives.
		cursor := b.Cursor()
		for k, raw := cursor.Seek(journalObservationPrefix); k != nil && bytes.HasPrefix(k, journalObservationPrefix); k, raw = cursor.Next() {
			o, e := decodeObservation(raw)
			if e != nil {
				return e
			}
			if !bytes.Equal(o.TargetHash, v.Hash) {
				continue
			}
			if o.Round != v.Round {
				return fmt.Errorf("%w: certificate round and candidate round differ", ErrConflict)
			}
			result, _, e := verifiedPairBytes(ctx, c, o.UC, o.TR)
			if e != nil || !bytes.Equal(result.InputRecord.Hash, v.StateRoot) {
				return fmt.Errorf("%w: resulting certificate state differs from candidate: %v", ErrConflict, e)
			}
			if w.Status == 0 {
				w.Status, w.ResultingUC, w.ResultingTR = 1, bytes.Clone(o.UC), bytes.Clone(o.TR)
			}
			o.Unresolved = false
			updated, e := encodeObservation(o)
			if e != nil {
				return e
			}
			if e = b.Put(k, updated); e != nil {
				return e
			}
		}
		raw, err := encodeCandidate(w)
		if err != nil {
			return err
		}
		count, observed, n, err := journalCount(b)
		if err != nil {
			return err
		}
		if count >= limits.Candidates || observed > limits.Observations || n+int64(len(key)+len(raw)) > limits.Bytes {
			return fmt.Errorf("%w: full-history journal capacity reached", ErrBounds)
		}
		if err := s.at("before-candidate-put"); err != nil {
			return err
		}
		if err := b.Put(key, raw); err != nil {
			return err
		}
		return s.at("before-candidate-commit")
	})
}

func (s *Store) appendJournalObservation(tx *bolt.Tx, pair *verifiedPair, dd [32]byte) error {
	b := tx.Bucket(bucketName)
	if pair == nil {
		return ErrUntrusted
	}
	// Limits are stored in the durable marker, so a changed process setting cannot silently relax it.
	metaRaw := b.Get(journalMetaKey)
	if metaRaw == nil {
		return ErrUnavailable
	}
	mp, err := decodeEnvelope(metaRaw, journalMetaKind, MaxDescriptorBytes)
	if err != nil {
		return err
	}
	var meta journalMetaWire
	if err = decodePayload(mp, &meta); err != nil {
		return err
	}
	if meta.Version != journalVersion || !bytes.Equal(meta.Descriptor, dd[:]) || meta.Candidates > math.MaxInt || meta.Observations > math.MaxInt || meta.Bytes > math.MaxInt64 {
		return ErrContext
	}
	limits := JournalLimits{Candidates: int(meta.Candidates), Observations: int(meta.Observations), Bytes: int64(meta.Bytes)}
	if err = limits.check(); err != nil {
		return err
	}
	uc, tr := pair.observation.Certificate(), pair.observation.TechnicalRecord()
	u, t, err := pairBytes(uc, tr)
	if err != nil {
		return err
	}
	ir := uc.InputRecord
	target := bytes.Clone(ir.BlockHash)
	if len(target) != 0 && len(target) != sha256.Size {
		return ErrUntrusted
	}
	w := journalObservationWire{Version: journalVersion, Descriptor: dd[:], Round: ir.RoundNumber, RootRound: uc.GetRootRoundNumber(), TargetHash: target, UC: u, TR: t}
	key := journalEpochObservationKey(uc.GetRootEpoch(), w.RootRound, w.Round)
	// A journal written before epoch-qualified keys may already hold this
	// exact observation under the legacy coordinate.
	if old := b.Get(journalObservationKey(w.RootRound, w.Round)); old != nil {
		ow, e := decodeObservation(old)
		if e != nil {
			return e
		}
		if bytes.Equal(ow.UC, u) && bytes.Equal(ow.TR, t) {
			return nil
		}
	}
	if old := b.Get(key); old != nil {
		ow, e := decodeObservation(old)
		if e != nil {
			return e
		}
		if !bytes.Equal(ow.UC, u) || !bytes.Equal(ow.TR, t) {
			return fmt.Errorf("%w: resulting certificate differs at same root/partition round", ErrConflict)
		}
		return nil
	}
	if len(target) > 0 {
		ck := journalCandidateKey(target)
		if raw := b.Get(ck); raw != nil {
			cw, e := decodeCandidate(raw)
			if e != nil {
				return e
			}
			if cw.Round != w.Round || !bytes.Equal(cw.StateRoot, ir.Hash) {
				return fmt.Errorf("%w: resulting certificate disagrees with candidate", ErrConflict)
			}
			if cw.Status == 0 {
				cw.Status, cw.ResultingUC, cw.ResultingTR = 1, bytes.Clone(u), bytes.Clone(t)
				updated, e := encodeCandidate(cw)
				if e != nil {
					return e
				}
				if e = b.Put(ck, updated); e != nil {
					return e
				}
			}
		} else {
			w.Unresolved = true
		}
	}
	raw, err := encodeObservation(w)
	if err != nil {
		return err
	}
	count, observed, n, err := journalCount(b)
	if err != nil {
		return err
	}
	if count > limits.Candidates || observed >= limits.Observations || n+int64(len(key)+len(raw)) > limits.Bytes {
		return fmt.Errorf("%w: full-history journal capacity reached", ErrBounds)
	}
	if err = s.at("before-journal-observation-put"); err != nil {
		return err
	}
	if err = b.Put(key, raw); err != nil {
		return err
	}
	return s.at("before-journal-observation-commit")
}

// BackfillJournalObservation admits an independently authenticated historical
// certificate for a fetched body without moving the monotonic live progress
// cursor backwards. The caller must have checked and executed that body first.
// The candidate association and observation are one Bolt transaction.
func (s *Store) BackfillJournalObservation(ctx context.Context, c Context, limits JournalLimits, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	if !s.journal {
		return ErrSettings
	}
	if err := limits.check(); err != nil {
		return err
	}
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return err
	}
	o, err := rootinput.AuthenticateHistoricalObservationV2(ctx, c.Observation, uc, tr)
	if err != nil {
		return err
	}
	pair, err := authenticateHandle(ctx, c, o)
	if err != nil {
		return err
	}
	if state.i.observed == nil {
		return fmt.Errorf("%w: no current observation for historical backfill", ErrUnavailable)
	}
	rel, err := compareCumulativeObservations(o, state.i.observed.observation)
	if err != nil || rel != relationAdvance && rel != relationDuplicate && rel != relationRepeat {
		return fmt.Errorf("%w: historical certificate conflicts with current progress: %v", ErrConflict, err)
	}
	target := uc.InputRecord.BlockHash
	if len(target) != sha256.Size {
		return fmt.Errorf("%w: backfill needs a non-quiet target hash", ErrUntrusted)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if !imageMatches(b, state.i) {
			return ErrStale
		}
		candidate := b.Get(journalCandidateKey(target))
		if candidate == nil {
			return fmt.Errorf("%w: backfill body %x is missing", ErrUnavailable, target)
		}
		cw, e := decodeCandidate(candidate)
		if e != nil {
			return e
		}
		if cw.Round != uc.InputRecord.RoundNumber || !bytes.Equal(cw.StateRoot, uc.InputRecord.Hash) {
			return fmt.Errorf("%w: backfill body differs from certificate", ErrConflict)
		}
		return s.appendJournalObservation(tx, pair, state.i.descriptorDigest)
	})
}

// LoadJournal verifies every retained byte against the caller's configured origin and root trust.
// It is intentionally a capped full-history scan for the private D2 lane, never a readiness grant.
func (s *Store) LoadJournal(ctx context.Context, c Context, limits JournalLimits) (JournalSnapshot, error) {
	if err := limits.check(); err != nil {
		return JournalSnapshot{}, err
	}
	// Progress and journal are read in separate Bolt transactions because progress
	// verification runs outside a transaction. A certificate can commit between
	// those reads. Retry that moving snapshot instead of treating it as damage.
	for attempt := 0; attempt < 3; attempt++ {
		image, token, err := s.loadJournalOnce(ctx, c, limits)
		if token.t == nil || s.Unchanged(token) {
			return image, err
		}
	}
	return JournalSnapshot{}, ErrStale
}

func (s *Store) loadJournalOnce(ctx context.Context, c Context, limits JournalLimits) (JournalSnapshot, ProgressToken, error) {
	state, token, err := s.Load(ctx, c)
	if err != nil {
		return JournalSnapshot{}, ProgressToken{}, err
	}
	if err := s.at("after-journal-progress-load"); err != nil {
		return JournalSnapshot{}, token, err
	}
	var out JournalSnapshot
	err = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if err := readJournalMeta(b, state.i.descriptorDigest, limits); err != nil {
			return err
		}
		if err := s.requireFrontierPolicy(b); err != nil {
			return err
		}
		var anchorUC *types.UnicityCertificate
		if s.frontier != nil {
			frontierImage, e := readFrontier(b, state.i.descriptorDigest, *s.frontier)
			if e != nil {
				return e
			}
			if frontierImage.Anchor != nil {
				out.Frontier = &frontierImage
				anchorUC, _, e = verifiedPairBytes(ctx, c, frontierImage.Record.ResultingUC, frontierImage.Record.ResultingTR)
				if e != nil {
					return e
				}
				out.Frontier.ResultingUC = anchorUC
			}
		}
		count, observed, n, err := journalCount(b)
		if err != nil {
			return err
		}
		if count > limits.Candidates || observed > limits.Observations || n > limits.Bytes {
			return ErrBounds
		}
		out.Bytes = n
		curs := b.Cursor()
		for k, raw := curs.Seek(journalCandidatePrefix); k != nil && bytes.HasPrefix(k, journalCandidatePrefix); k, raw = curs.Next() {
			w, e := decodeCandidate(raw)
			if e != nil {
				return e
			}
			if w.Version != journalVersion || !bytes.Equal(w.Descriptor, state.i.descriptorDigest[:]) {
				return ErrContext
			}
			if len(k) != len(journalCandidatePrefix)+sha256.Size || !bytes.Equal(k[len(journalCandidatePrefix):], w.Hash) || len(w.Hash) != sha256.Size || len(w.StateRoot) != sha256.Size || len(w.ParentHash) != sha256.Size || len(w.ParentState) != sha256.Size || len(w.Raw) == 0 || len(w.Raw) > MaxCandidateBytes || w.Number == 0 || w.Number != w.ParentNumber+1 || w.Round == 0 {
				return ErrUntrusted
			}
			uc, tr, e := verifiedPairBytes(ctx, c, w.AuthorizingUC, w.AuthorizingTR)
			if e != nil {
				return e
			}
			if tr.Round != w.Round {
				return ErrConflict
			}
			entry := JournalEntry{Candidate: JournalCandidate{Round: w.Round, Number: w.Number, ParentNumber: w.ParentNumber, Hash: bytes.Clone(w.Hash), StateRoot: bytes.Clone(w.StateRoot), ParentHash: bytes.Clone(w.ParentHash), ParentState: bytes.Clone(w.ParentState), Raw: bytes.Clone(w.Raw), BlockSize: w.BlockSize, StateSize: w.StateSize, LocallyBuilt: w.LocallyBuilt, AuthorizingUC: uc, AuthorizingTR: tr}}
			if w.Status == 1 {
				resultUC, resultTR, e := verifiedPairBytes(ctx, c, w.ResultingUC, w.ResultingTR)
				if e != nil {
					return e
				}
				if resultUC.InputRecord.RoundNumber != w.Round || !bytes.Equal(resultUC.InputRecord.BlockHash, w.Hash) || !bytes.Equal(resultUC.InputRecord.Hash, w.StateRoot) {
					return ErrConflict
				}
				entry.Certified, entry.ResultingUC, entry.ResultingTR = true, resultUC, resultTR
			} else if w.Status != 0 || len(w.ResultingUC) != 0 || len(w.ResultingTR) != 0 {
				return ErrUntrusted
			}
			out.Candidates = append(out.Candidates, entry)
		}
		for k, raw := curs.Seek(journalObservationPrefix); k != nil && bytes.HasPrefix(k, journalObservationPrefix); k, raw = curs.Next() {
			w, e := decodeObservation(raw)
			if e != nil {
				return e
			}
			if w.Version != journalVersion || !bytes.Equal(w.Descriptor, state.i.descriptorDigest[:]) {
				return ErrContext
			}
			uc, tr, e := verifiedPairBytes(ctx, c, w.UC, w.TR)
			if e != nil {
				return e
			}
			if !bytes.Equal(k, journalObservationKey(w.RootRound, w.Round)) && !bytes.Equal(k, journalEpochObservationKey(uc.GetRootEpoch(), w.RootRound, w.Round)) {
				return ErrContext
			}
			if w.Round != uc.GetRoundNumber() || w.RootRound != uc.GetRootRoundNumber() || !bytes.Equal(w.TargetHash, uc.InputRecord.BlockHash) {
				return ErrUntrusted
			}
			if len(w.TargetHash) > 0 {
				cr := b.Get(journalCandidateKey(w.TargetHash))
				coveredByFrontier := cr == nil && !w.Unresolved && anchorUC != nil &&
					(uc.GetRootEpoch() < anchorUC.GetRootEpoch() || uc.GetRootEpoch() == anchorUC.GetRootEpoch() && uc.GetRootRoundNumber() <= anchorUC.GetRootRoundNumber()) &&
					uc.InputRecord.RoundNumber <= anchorUC.InputRecord.RoundNumber
				// Pruning may retain an older authenticated observation because
				// it authorizes a hot local candidate, while deleting that
				// observation's own covered body. The contiguous frontier is
				// then the proof that the body was previously resolved.
				if w.Unresolved != (cr == nil) && !coveredByFrontier {
					return ErrUntrusted
				}
				if cr != nil {
					cw, e := decodeCandidate(cr)
					if e != nil {
						return e
					}
					if cw.Status != 1 || cw.Round != w.Round || !bytes.Equal(cw.StateRoot, uc.InputRecord.Hash) {
						return ErrConflict
					}
				}
			} else if w.Unresolved {
				return ErrUntrusted
			}
			out.Observations = append(out.Observations, JournalObservation{UC: uc, TR: tr, TargetHash: bytes.Clone(w.TargetHash), Unresolved: w.Unresolved})
		}
		sort.Slice(out.Observations, func(i, j int) bool {
			a, b := out.Observations[i].UC, out.Observations[j].UC
			if a.GetRootEpoch() != b.GetRootEpoch() {
				return a.GetRootEpoch() < b.GetRootEpoch()
			}
			if a.GetRootRoundNumber() != b.GetRootRoundNumber() {
				return a.GetRootRoundNumber() < b.GetRootRoundNumber()
			}
			return a.GetRoundNumber() < b.GetRoundNumber()
		})
		out.Restored, err = readRestoreAnchor(b, state.i.descriptorDigest, out)
		if err != nil {
			return err
		}
		if state.i.observed == nil && len(out.Observations) != 0 || state.i.observed != nil && len(out.Observations) == 0 && anchorUC == nil {
			return fmt.Errorf("%w: journal and progress observation count disagree", ErrUntrusted)
		}
		if state.i.observed != nil {
			var lu, lt []byte
			var e error
			if len(out.Observations) != 0 && (anchorUC == nil || out.Observations[len(out.Observations)-1].UC.GetRootEpoch() > anchorUC.GetRootEpoch() || out.Observations[len(out.Observations)-1].UC.GetRootEpoch() == anchorUC.GetRootEpoch() && out.Observations[len(out.Observations)-1].UC.GetRootRoundNumber() > anchorUC.GetRootRoundNumber()) {
				latest := out.Observations[len(out.Observations)-1]
				lu, lt, e = pairBytes(latest.UC, latest.TR)
			} else {
				lu, lt = out.Frontier.Record.ResultingUC, out.Frontier.Record.ResultingTR
			}
			if e != nil || !bytes.Equal(lu, state.i.observed.wire.UC) || !bytes.Equal(lt, state.i.observed.wire.TR) {
				return fmt.Errorf("%w: latest journal certificate differs from durable progress", ErrUntrusted)
			}
		}
		localAuthorizations := make(map[[4]uint64]struct{})
		for _, candidate := range out.Candidates {
			if candidate.Candidate.LocallyBuilt {
				key := [4]uint64{candidate.Candidate.AuthorizingUC.GetRootEpoch(), candidate.Candidate.AuthorizingUC.GetRootRoundNumber(), candidate.Candidate.AuthorizingUC.GetRoundNumber(), candidate.Candidate.Round}
				if _, repeated := localAuthorizations[key]; repeated {
					return fmt.Errorf("%w: two local proposals for one authorization", ErrConflict)
				}
				localAuthorizations[key] = struct{}{}
			}
			foundAuthorization, foundResult := false, !candidate.Certified
			for _, observed := range out.Observations {
				if candidate.Candidate.AuthorizingUC.GetRootEpoch() == observed.UC.GetRootEpoch() && candidate.Candidate.AuthorizingUC.GetRootRoundNumber() == observed.UC.GetRootRoundNumber() && candidate.Candidate.AuthorizingUC.GetRoundNumber() == observed.UC.GetRoundNumber() && candidate.Candidate.AuthorizingTR.Round == observed.TR.Round {
					foundAuthorization = true
				}
				if candidate.Certified && candidate.Candidate.Round == observed.UC.InputRecord.RoundNumber && bytes.Equal(candidate.Candidate.Hash, observed.TargetHash) && bytes.Equal(candidate.Candidate.StateRoot, observed.UC.InputRecord.Hash) {
					foundResult = true
				}
			}
			if anchorUC != nil && candidate.Candidate.AuthorizingUC.GetRootEpoch() == anchorUC.GetRootEpoch() && candidate.Candidate.AuthorizingUC.GetRootRoundNumber() == anchorUC.GetRootRoundNumber() && candidate.Candidate.AuthorizingUC.GetRoundNumber() == anchorUC.GetRoundNumber() {
				foundAuthorization = true
			}
			if anchorUC != nil && candidate.Certified && candidate.ResultingUC.GetRootEpoch() == anchorUC.GetRootEpoch() && candidate.ResultingUC.GetRootRoundNumber() == anchorUC.GetRootRoundNumber() && candidate.ResultingUC.GetRoundNumber() == anchorUC.GetRoundNumber() && bytes.Equal(candidate.Candidate.Hash, anchorUC.InputRecord.BlockHash) {
				// Pruning removes the anchor body's authorizing observation while
				// retaining the body itself. The frontier transaction checked the
				// exact original and resulting pairs against this candidate.
				originalUC, originalTR, originalErr := pairBytes(candidate.Candidate.AuthorizingUC, candidate.Candidate.AuthorizingTR)
				resultUC, resultTR, resultErr := pairBytes(candidate.ResultingUC, candidate.ResultingTR)
				if originalErr == nil && resultErr == nil &&
					bytes.Equal(originalUC, out.Frontier.Record.OriginalUC) && bytes.Equal(originalTR, out.Frontier.Record.OriginalTR) &&
					bytes.Equal(resultUC, out.Frontier.Record.ResultingUC) && bytes.Equal(resultTR, out.Frontier.Record.ResultingTR) {
					foundAuthorization = true
					foundResult = true
				}
			}
			if !foundResult && candidate.Certified && out.Frontier != nil && candidate.Candidate.Number < out.Frontier.Anchor.Height {
				// A repeat certificate can keep an older covered body hot after
				// its resulting observation is pruned. Coverage was committed
				// with the frontier after checking this exact candidate and both
				// replica acknowledgments. Recheck every certified coordinate.
				if raw := b.Get(coverageKey(candidate.Candidate.Number)); raw != nil {
					covered, e := frontier.Decode(raw, *s.frontier)
					if e == nil && covered.Height == candidate.Candidate.Number && (covered.Epoch == candidate.ResultingUC.GetRootEpoch() || covered.Epoch == 0 && candidate.ResultingUC.GetRootEpoch() == c.Observation.RootEpoch) && covered.Round == candidate.ResultingUC.GetRootRoundNumber() &&
						covered.Sequence < out.Frontier.Anchor.Sequence && bytes.Equal(covered.Subject.BlockHash[:], candidate.Candidate.Hash) &&
						bytes.Equal(covered.StateRoot[:], candidate.Candidate.StateRoot) {
						foundResult = true
					}
				}
			}
			// A returning follower may retain a later proposal before it has
			// fetched the authorizing certificate's own body/observation. The
			// pair above was independently authenticated; only locally built
			// proposals require it to have been observed here already.
			if candidate.Candidate.LocallyBuilt && !foundAuthorization || !foundResult {
				anchorHeight, anchorRound := uint64(0), uint64(0)
				if out.Frontier != nil {
					anchorHeight, anchorRound = out.Frontier.Anchor.Height, out.Frontier.Anchor.Round
				}
				return fmt.Errorf("%w: candidate lacks its retained authorizing or resulting certificate: height=%d round=%d local=%t certified=%t auth=(%d,%d) authorization=%t result=%t frontier=(%d,%d)",
					ErrUntrusted, candidate.Candidate.Number, candidate.Candidate.Round, candidate.Candidate.LocallyBuilt, candidate.Certified,
					candidate.Candidate.AuthorizingUC.GetRootRoundNumber(), candidate.Candidate.AuthorizingUC.GetRoundNumber(), foundAuthorization, foundResult, anchorHeight, anchorRound)
			}
		}
		return nil
	})
	return out, token, err
}
