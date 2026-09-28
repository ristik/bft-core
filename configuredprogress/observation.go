package configuredprogress

import (
	"bytes"
	"context"
	"fmt"
	"math"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
)

type relation uint8

const (
	relationAdvance relation = iota
	relationRepeat
	relationDuplicate
	relationStale
)

// ObservationOutcome distinguishes a durable advance from a verified no-op.
type ObservationOutcome uint8

const (
	ObservationAdvanced ObservationOutcome = iota
	ObservationRepeated
	ObservationDuplicate
	ObservationStale
)

func pairFromObservation(o rootinput.VerifiedObservationV2) (pairWire, []byte, error) {
	if !o.Valid() {
		return pairWire{}, nil, fmt.Errorf("%w: invalid observation handle", ErrContext)
	}
	u := o.Certificate()
	t := o.TechnicalRecord()
	ub, err := types.Cbor.Marshal(u)
	if err != nil {
		return pairWire{}, nil, err
	}
	tb, err := types.Cbor.Marshal(t)
	if err != nil {
		return pairWire{}, nil, err
	}
	p := pairWire{UC: ub, TR: tb}
	raw, err := marshal(p)
	if err != nil {
		return pairWire{}, nil, err
	}
	if len(raw) > MaxPairBytes {
		return pairWire{}, nil, fmt.Errorf("%w: pair is %d bytes", ErrBounds, len(raw))
	}
	return p, raw, nil
}

func verifyPair(ctx context.Context, c Context, p pairWire) (*verifiedPair, error) {
	raw, err := marshal(p)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxPairBytes {
		return nil, fmt.Errorf("%w: pair is %d bytes", ErrBounds, len(raw))
	}
	if err = innerDec.Valid(p.UC); err != nil {
		return nil, fmt.Errorf("%w: certificate bounds/shape: %v", ErrUntrusted, err)
	}
	if err = innerDec.Valid(p.TR); err != nil {
		return nil, fmt.Errorf("%w: technical-record bounds/shape: %v", ErrUntrusted, err)
	}
	var u types.UnicityCertificate
	if err = types.Cbor.Unmarshal(p.UC, &u); err != nil {
		return nil, fmt.Errorf("%w: certificate: %v", ErrUntrusted, err)
	}
	technical := newTechnical()
	if err = types.Cbor.Unmarshal(p.TR, technical); err != nil {
		return nil, fmt.Errorf("%w: technical record: %v", ErrUntrusted, err)
	}
	ucAgain, _ := types.Cbor.Marshal(&u)
	trAgain, _ := types.Cbor.Marshal(technical)
	if !bytes.Equal(ucAgain, p.UC) || !bytes.Equal(trAgain, p.TR) {
		return nil, fmt.Errorf("%w: non-canonical pair member", ErrUntrusted)
	}
	o, err := rootinput.AuthenticateHistoricalObservationV2(ctx, c.Observation, &u, technical)
	if err != nil {
		return nil, err
	}
	return &verifiedPair{wire: p, raw: raw, observation: o}, nil
}

// newTechnical is split out to keep pair decoding explicit without accepting interface-shaped CBOR.
func newTechnical() *certification.TechnicalRecord { return &certification.TechnicalRecord{} }

func authenticateHandle(ctx context.Context, c Context, o rootinput.VerifiedObservationV2) (*verifiedPair, error) {
	p, _, err := pairFromObservation(o)
	if err != nil {
		return nil, err
	}
	v, err := verifyPair(ctx, c, p)
	if err != nil {
		return nil, err
	}
	if v.observation.OriginIdentity() != o.OriginIdentity() || v.observation.Class() != o.Class() {
		return nil, fmt.Errorf("%w: observation handle changed identity", ErrContext)
	}
	return v, nil
}

func canonicalIR(u *types.UnicityCertificate) ([]byte, error) {
	if u == nil || u.InputRecord == nil {
		return nil, fmt.Errorf("%w: input record missing", ErrConflict)
	}
	return u.InputRecord.Bytes()
}

func sameRootStatement(a, b *types.UnicityCertificate, at, bt *certification.TechnicalRecord) (bool, error) {
	if a.UnicitySeal == nil || b.UnicitySeal == nil {
		return false, ErrConflict
	}
	as, err := a.UnicitySeal.SigBytes()
	if err != nil {
		return false, err
	}
	bs, err := b.UnicitySeal.SigBytes()
	if err != nil {
		return false, err
	}
	atr, err := types.Cbor.Marshal(at)
	if err != nil {
		return false, err
	}
	btr, err := types.Cbor.Marshal(bt)
	if err != nil {
		return false, err
	}
	return bytes.Equal(as, bs) && bytes.Equal(atr, btr), nil
}

func compareObservations(current, next rootinput.VerifiedObservationV2) (relation, error) {
	a, b := current.Certificate(), next.Certificate()
	if a == nil || b == nil {
		return relationAdvance, ErrConflict
	}
	apr, bpr := a.GetRoundNumber(), b.GetRoundNumber()
	arr, brr := a.GetRootRoundNumber(), b.GetRootRoundNumber()
	ae, be := a.GetRootEpoch(), b.GetRootEpoch()
	if be > ae && be != ae+1 {
		return relationAdvance, fmt.Errorf("%w: root epoch skipped from %d to %d", ErrConflict, ae, be)
	}
	order := 0
	if be < ae || be == ae && brr < arr {
		order = -1
	} else if be > ae || be == ae && brr > arr {
		order = 1
	}
	if apr == bpr {
		ai, e := canonicalIR(a)
		if e != nil {
			return relationAdvance, e
		}
		bi, e := canonicalIR(b)
		if e != nil {
			return relationAdvance, e
		}
		if !bytes.Equal(ai, bi) {
			return relationAdvance, fmt.Errorf("%w: different input records at partition round %d", ErrConflict, apr)
		}
		switch {
		case order == 0:
			same, e := sameRootStatement(a, b, current.TechnicalRecord(), next.TechnicalRecord())
			if e != nil {
				return relationAdvance, e
			}
			if !same {
				return relationAdvance, fmt.Errorf("%w: same root/partition round has another signed seal statement or TR", ErrConflict)
			}
			return relationDuplicate, nil
		case order < 0:
			return relationStale, nil
		default:
			return relationRepeat, nil
		}
	}
	if bpr < apr {
		if order >= 0 {
			return relationAdvance, fmt.Errorf("%w: earlier partition round at later root round", ErrConflict)
		}
		return relationStale, nil
	}
	if order <= 0 {
		return relationAdvance, fmt.Errorf("%w: later partition round at earlier root round", ErrConflict)
	}
	// The shared helper still compares scalar root rounds. For a proven
	// cross-epoch successor, neutralize only that precondition on local copies;
	// its shard-state and block-hash continuity checks remain in force.
	if be > ae {
		oldCopy, newCopy := *a, *b
		oldSeal, newSeal := *a.UnicitySeal, *b.UnicitySeal
		oldSeal.RootChainRoundNumber, newSeal.RootChainRoundNumber = 0, 0
		oldCopy.UnicitySeal, newCopy.UnicitySeal = &oldSeal, &newSeal
		a, b = &oldCopy, &newCopy
	}
	if err := types.CheckNonEquivocatingCertificates(a, b); err != nil {
		return relationAdvance, fmt.Errorf("%w: %v", ErrConflict, err)
	}
	return relationAdvance, nil
}

// PreparedObservation binds an authenticated candidate and its outcome to one exact durable image.
type PreparedObservation struct{ p *preparedObservation }
type preparedObservation struct {
	store   *Store
	before  *durableImage
	next    []byte
	outcome ObservationOutcome
	current *verifiedPair
	mutates bool
}

func (s *Store) PrepareObservation(ctx context.Context, c Context, o rootinput.VerifiedObservationV2) (PreparedObservation, ObservationOutcome, error) {
	var ownErr error
	c, ownErr = ownContext(c)
	if ownErr != nil {
		return PreparedObservation{}, 0, ownErr
	}
	// A historical handle can prove old bytes during replay but cannot grant
	// current admission after the installed epoch advances.
	current, err := rootinput.AuthenticateObservationV2(ctx, c.Observation, o.Certificate(), o.TechnicalRecord())
	if err != nil || current.OriginIdentity() != o.OriginIdentity() {
		if err != nil {
			return PreparedObservation{}, 0, err
		}
		return PreparedObservation{}, 0, ErrContext
	}
	st, _, err := s.Load(ctx, c)
	if err != nil {
		return PreparedObservation{}, 0, err
	}
	candidate, err := authenticateHandle(ctx, c, o)
	if err != nil {
		return PreparedObservation{}, 0, err
	}
	i := st.i
	if i.observed == nil {
		if i.control.Revision != 0 {
			return PreparedObservation{}, 0, fmt.Errorf("%w: missing observed", ErrUntrusted)
		}
		if s.journal && candidate.observation.Class() != evmroot.OriginBootstrapV2 {
			return PreparedObservation{}, 0, fmt.Errorf("%w: a fresh execution journal must begin with the configured bootstrap certificate", ErrUnavailable)
		}
		return s.prepareObservationMutation(i, candidate, ObservationAdvanced)
	}
	rel, err := compareObservations(i.observed.observation, candidate.observation)
	if err != nil {
		return PreparedObservation{}, 0, err
	}
	switch rel {
	case relationDuplicate:
		return PreparedObservation{p: &preparedObservation{store: s, before: i, outcome: ObservationDuplicate, current: i.observed}}, ObservationDuplicate, nil
	case relationStale:
		return PreparedObservation{p: &preparedObservation{store: s, before: i, outcome: ObservationStale, current: i.observed}}, ObservationStale, nil
	case relationRepeat:
		return s.prepareObservationMutation(i, candidate, ObservationRepeated)
	default:
		return s.prepareObservationMutation(i, candidate, ObservationAdvanced)
	}
}

func (s *Store) prepareObservationMutation(i *durableImage, candidate *verifiedPair, out ObservationOutcome) (PreparedObservation, ObservationOutcome, error) {
	if i.control.Revision == math.MaxUint64 {
		return PreparedObservation{}, 0, fmt.Errorf("%w: revision overflow", ErrBounds)
	}
	cw := i.control
	cw.Revision++
	cw.Observed = &candidate.wire
	if candidate.observation.Class() != evmroot.OriginBootstrapV2 && cw.First == nil {
		p := candidate.wire
		cw.First = &p
	}
	if cw.First != nil && candidate.observation.Class() == evmroot.OriginBootstrapV2 {
		return PreparedObservation{}, 0, fmt.Errorf("%w: bootstrap cannot replace ordinary progress", ErrConflict)
	}
	payload, err := marshal(cw)
	if err != nil {
		return PreparedObservation{}, 0, err
	}
	raw, err := encodeEnvelope(kindControl, payload, MaxControlBytes)
	if err != nil {
		return PreparedObservation{}, 0, err
	}
	return PreparedObservation{p: &preparedObservation{store: s, before: i, next: raw, outcome: out, current: candidate, mutates: true}}, out, nil
}

func imageMatches(b *bolt.Bucket, i *durableImage) bool {
	if b == nil || !bytes.Equal(b.Get(descriptorKey), i.descriptor) || !bytes.Equal(b.Get(controlKey), i.controlRaw) {
		return false
	}
	if i.headName == nil {
		return i.headRaw == nil
	}
	return bytes.Equal(b.Get(i.headName), i.headRaw)
}

// CommitObservation rechecks exact CAS bytes even for duplicate/stale no-ops. It returns the current
// durably accepted observation, never the stale incoming pair.
func (s *Store) CommitObservation(p PreparedObservation) (rootinput.VerifiedObservationV2, ObservationOutcome, error) {
	if p.p == nil || p.p.store != s {
		return rootinput.VerifiedObservationV2{}, 0, ErrStale
	}
	pr := p.p
	if !pr.mutates {
		err := s.db.View(func(tx *bolt.Tx) error {
			if !imageMatches(tx.Bucket(bucketName), pr.before) {
				return ErrStale
			}
			return nil
		})
		if err != nil {
			return rootinput.VerifiedObservationV2{}, 0, err
		}
		return pr.current.observation, pr.outcome, nil
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if !imageMatches(b, pr.before) {
			return ErrStale
		}
		if err := b.Put(controlKey, pr.next); err != nil {
			return err
		}
		// Once a journal marker exists, no caller can bypass the atomic association merely by
		// reopening Store without calling EnableJournal. The marker, not process memory, governs
		// the durable observation contract.
		if b.Get(journalMetaKey) != nil {
			if err := s.appendJournalObservation(tx, pr.current, pr.before.descriptorDigest); err != nil {
				return err
			}
		} else if s.journal {
			return fmt.Errorf("%w: enabled journal marker missing", ErrUnavailable)
		}
		return s.at("before-observation-commit")
	})
	if err != nil {
		return rootinput.VerifiedObservationV2{}, 0, err
	}
	return pr.current.observation, pr.outcome, nil
}

func reownObservation(o rootinput.VerifiedObservationV2) rootinput.VerifiedObservationV2 { return o }
