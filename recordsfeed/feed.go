// Package recordsfeed is the shard-side authenticated route to the root's P85 record log.
//
// A paired EVM node must derive, from the authenticated root origin it consumes, the exact next prefix of the root's source log. The
// root's control state (which carries the canonical source state: progress tracker, closed epochs, and the log's length and tip) is a
// leaf of the unicity tree, whose root the origin's certificate already authenticates. The route therefore has two parts:
//
//   - a cut: the control state of the committed origin block and its path in that block's unicity tree. Verified against the origin's
//     tree root it yields the cursor (progress, UC time, log length and tip) and the closed epochs;
//   - the records: fetched from any root, verified link by link from the last verified record, and retained only once the chain
//     they extend ends at the tip the cut authenticated.
//
// A root can withhold (the answer is unavailable, never an empty feed) but cannot substitute: nothing it serves is believed unless it
// hashes into the authenticated tip.
package recordsfeed

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

const (
	// MaxBatch is the most records one request returns.
	MaxBatch = 256
	// MaxCutBytes and MaxBatchBytes bound a response.
	MaxCutBytes   = 4 << 20
	MaxBatchBytes = 1 << 20
)

var (
	// ErrUnavailable reports a cut or a record no asked root could provide.
	ErrUnavailable = errors.New("recordsfeed: the root log is unavailable")
	// ErrAuth reports a cut that does not lead to the origin's tree root, a state that is not the canonical source state, or records
	// that do not extend to the authenticated tip.
	ErrAuth = errors.New("recordsfeed: not authenticated by the origin")
	// ErrWire reports a malformed exchange.
	ErrWire = errors.New("recordsfeed: malformed exchange")
)

// Cut is the control state of one committed root block and the path of its leaf in that block's unicity tree.
type Cut struct {
	_       struct{} `cbor:",toarray"`
	Control *evmroot.ControlState
	Path    *types.UnicityTreeCertificate
}

// CutKey names the committed root block a cut belongs to as the origin the shard holds does: network, root epoch, root round and the
// root of the block's unicity tree. Rounds overlap across epochs, so a round alone is no request.
type CutKey struct {
	Network, Epoch, Round uint64
	TreeRoot              [32]byte
}

// KeyOf derives the cut key from an authenticated origin.
func KeyOf(origin evmroot.RootOriginV2) (CutKey, error) {
	if len(origin.UnicityTreeRoot) != 32 {
		return CutKey{}, fmt.Errorf("%w: origin tree root width", ErrAuth)
	}
	key := CutKey{Network: origin.NetworkID, Epoch: origin.RootEpoch, Round: origin.RootRound}
	copy(key.TreeRoot[:], origin.UnicityTreeRoot)
	return key, nil
}

// Remote is a root, or several, that serve cuts and records.
type Remote interface {
	// Cut returns the cut of the committed root block the key names.
	Cut(ctx context.Context, key CutKey) (Cut, error)
	// Records returns up to max records from the given index (fewer at the end of the log).
	Records(ctx context.Context, from uint64, max int) ([]rootrecords.Record, error)
}

// VerifyCut checks the cut against the origin and returns the source state it commits and the cursor of the origin: the progress
// at the origin's round, the origin's UC time, and the length and tip of the complete source log.
func VerifyCut(cut Cut, origin evmroot.RootOriginV2) (rootrecords.State, rootrecords.Cursor, error) {
	if cut.Control == nil || cut.Path == nil || len(origin.UnicityTreeRoot) == 0 {
		return rootrecords.State{}, rootrecords.Cursor{}, fmt.Errorf("%w: no control state or path", ErrAuth)
	}
	root, err := handoff.ControlRoot(cut.Control, cut.Path)
	if err != nil || !bytes.Equal(root, origin.UnicityTreeRoot) {
		return rootrecords.State{}, rootrecords.Cursor{}, fmt.Errorf("%w: the control leaf does not lead to the origin's tree root", ErrAuth)
	}
	if cut.Control.Network != origin.NetworkID {
		return rootrecords.State{}, rootrecords.Cursor{}, fmt.Errorf("%w: the control state belongs to network %d, the origin to %d", ErrAuth, cut.Control.Network, origin.NetworkID)
	}
	if len(cut.Control.Pos) == 0 {
		return rootrecords.State{}, rootrecords.Cursor{}, fmt.Errorf("%w: the control state carries no source state", ErrAuth)
	}
	state, err := rootrecords.DecodeState(cut.Control.Pos)
	if err != nil {
		return rootrecords.State{}, rootrecords.Cursor{}, errors.Join(ErrAuth, err)
	}
	progress, err := state.Progress(origin.RootRound)
	if err != nil {
		return rootrecords.State{}, rootrecords.Cursor{}, errors.Join(ErrAuth, err)
	}
	if origin.ReferenceTime < state.LastTime {
		return rootrecords.State{}, rootrecords.Cursor{}, fmt.Errorf("%w: the origin's UC time precedes the log's last record", ErrAuth)
	}
	return state, rootrecords.Cursor{Progress: progress, UCTime: origin.ReferenceTime, TargetCount: state.Count, TargetTip: state.Tip}, nil
}

// Source is the verified view of the root's record log of one pair: a rootinput.RecordsSource.
type Source struct {
	remotes []Remote

	mu  sync.Mutex
	log []rootrecords.Record
	// cuts retains the cuts this source verified, bounded (oldest dropped first), so that the node can mirror them to non-active
	// followers (ServerSource) without their asking a root.
	cuts     map[CutKey]Cut
	cutOrder []CutKey
	// store, when set, retains every verified cut durably, so that this node can serve a historical cut long after it left the bounded
	// in-memory cache and across restarts: the mirror's retention guarantee for root-free historical recovery is "every cut it verified".
	store CutStore
	// checked is how many leading records of log have had every served field authenticated by a cut in this process. Records loaded from
	// the durable store are chain-verified at load (VerifyAfter), but a Closure's closed-epoch field is not covered by its identifier: until
	// a cut re-authenticates it, such a record is mirrored (the follower authenticates it itself) but not used by this node.
	checked int
	// persistErr is the first durable-retention failure; once set, this source no longer promises historical availability.
	persistErr   error
	onPersistErr func(error)
}

// CutStore durably retains verified cuts and the verified record log.
type CutStore interface {
	PutCut(key CutKey, cut Cut) error
	GetCut(key CutKey) (Cut, bool, error)
	// AppendRecords stores records that continue the stored log at their own indexes; LoadRecords returns the stored log in order.
	AppendRecords(records []rootrecords.Record) error
	LoadRecords() ([]rootrecords.Record, error)
}

// SetCutStore attaches durable retention and restores the verified record log from it (chain-verified from index 0). Call before use.
// A store whose log does not verify is refused: nothing from it is mirrored.
func (s *Source) SetCutStore(store CutStore) error {
	records, err := store.LoadRecords()
	if err != nil {
		return fmt.Errorf("%w: loading the retained record log: %v", ErrUnavailable, err)
	}
	if err := rootrecords.VerifyAfter(nil, records); err != nil {
		return errors.Join(ErrAuth, fmt.Errorf("the retained record log does not verify: %w", err))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store, s.log, s.checked = store, records, 0
	return nil
}

// OnPersistError installs a hook for durable-retention failures (logging, status).
func (s *Source) OnPersistError(f func(error)) { s.onPersistErr = f }

// PersistenceError reports the first durable-retention failure, nil while every verified cut and record was retained.
func (s *Source) PersistenceError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.persistErr
}

// persistFailed records a retention failure (s.mu not held).
func (s *Source) persistFailed(err error) {
	s.mu.Lock()
	first := s.persistErr == nil
	if first {
		s.persistErr = err
	}
	hook := s.onPersistErr
	s.mu.Unlock()
	if hook != nil {
		hook(err)
	}
}

// maxMirroredCuts bounds the verified cuts a source keeps in memory; older ones are served from the durable store (SetCutStore).
var maxMirroredCuts = 4096

// ControlCut serves a cut this source has verified (ServerSource). An unverified cut is unavailable: a mirror never relays unchecked bytes,
// and the follower verifies it again against its own origin.
func (s *Source) ControlCut(key CutKey) (Cut, error) {
	s.mu.Lock()
	cut, ok := s.cuts[key]
	store := s.store
	s.mu.Unlock()
	if ok {
		return cut, nil
	}
	if store != nil {
		if cut, ok, err := store.GetCut(key); err == nil && ok {
			return cut, nil
		}
	}
	return Cut{}, fmt.Errorf("%w: cut not verified here", ErrUnavailable)
}

// Records serves the verified log (ServerSource).
func (s *Source) Records(from uint64, max int) ([]rootrecords.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if from >= uint64(len(s.log)) || max <= 0 {
		return nil, fmt.Errorf("%w: record %d", ErrUnavailable, from)
	}
	end := min(uint64(len(s.log)), from+uint64(max))
	return append([]rootrecords.Record(nil), s.log[from:end]...), nil
}

func (s *Source) retainCut(key CutKey, cut Cut) {
	if s.store != nil {
		if err := s.store.PutCut(key, cut); err != nil {
			s.persistFailed(fmt.Errorf("retaining the cut of %+v: %w", key, err))
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cuts == nil {
		s.cuts = map[CutKey]Cut{}
	}
	if _, ok := s.cuts[key]; ok {
		return
	}
	s.cuts[key] = cut
	s.cutOrder = append(s.cutOrder, key)
	if len(s.cutOrder) > maxMirroredCuts {
		delete(s.cuts, s.cutOrder[0])
		s.cutOrder = s.cutOrder[1:]
	}
}

// NewSource returns a source that fetches from the remotes in order and retains every record it has verified.
func NewSource(remotes ...Remote) *Source { return &Source{remotes: remotes} }

// Cursor fetches and verifies the cut of the origin's committed block and extends the verified log to the length it authenticates. A
// remote that withholds, or serves what the origin does not authenticate, is skipped for the next; the cursor is returned only from a
// remote whose cut and records both verified, and every failure is reported when none did.
func (s *Source) Cursor(ctx context.Context, origin evmroot.RootOriginV2) (rootrecords.Cursor, error) {
	var errs []error
	for _, remote := range s.remotes {
		cursor, err := s.cursorFrom(ctx, remote, origin)
		if err == nil {
			return cursor, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	if len(errs) == 0 {
		errs = append(errs, ErrUnavailable)
	}
	return rootrecords.Cursor{}, errors.Join(errs...)
}

func (s *Source) cursorFrom(ctx context.Context, remote Remote, origin evmroot.RootOriginV2) (rootrecords.Cursor, error) {
	key, err := KeyOf(origin)
	if err != nil {
		return rootrecords.Cursor{}, err
	}
	cut, err := remote.Cut(ctx, key)
	if err != nil {
		return rootrecords.Cursor{}, errors.Join(ErrUnavailable, err)
	}
	state, cursor, err := VerifyCut(cut, origin)
	if err != nil {
		return rootrecords.Cursor{}, err
	}
	if err := s.extend(ctx, remote, state); err != nil {
		return rootrecords.Cursor{}, err
	}
	s.retainCut(key, cut)
	return cursor, nil
}

// Record returns a record of the verified log; a record that has not been verified is unavailable.
func (s *Source) Record(index uint64) (rootrecords.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index >= uint64(s.checked) {
		return rootrecords.Record{}, fmt.Errorf("%w: record %d", ErrUnavailable, index)
	}
	return s.log[index], nil
}

// extend verifies the records up to the state's length against its tip and retains them.
func (s *Source) extend(ctx context.Context, remote Remote, state rootrecords.State) error {
	// A retention failure is recorded under the lock, with the extension published atomically; the external hook runs after the unlock
	// (the deferred calls run in reverse: unlock first, then the report).
	var report error
	var hook func(error)
	defer func() {
		if report != nil && hook != nil {
			hook(report)
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	if state.Count == 0 {
		return nil
	}
	if uint64(len(s.log)) >= state.Count {
		if s.log[state.Count-1].ID != state.Tip {
			return fmt.Errorf("%w: the verified log differs from the log the origin authenticates", ErrAuth)
		}
		// the tip binds the covered prefix: its loaded records become usable once their closed epochs check
		if err := s.checkLoaded(state, state.Count); err != nil {
			return err
		}
		s.checked = max(s.checked, int(state.Count))
		return nil
	}
	// the whole loaded log is covered; it becomes usable only once the suffix below joins it and ends at the tip
	if err := s.checkLoaded(state, uint64(len(s.log))); err != nil {
		return err
	}
	var prev *rootrecords.Record
	if n := len(s.log); n > 0 {
		prev = &s.log[n-1]
	}
	var staged []rootrecords.Record
	for next := uint64(len(s.log)); next < state.Count; {
		want := min(state.Count-next, MaxBatch)
		batch, err := remote.Records(ctx, next, int(want))
		if err != nil {
			return errors.Join(ErrUnavailable, err)
		}
		if uint64(len(batch)) == 0 || uint64(len(batch)) > want {
			return fmt.Errorf("%w: %d records for a request of %d", ErrUnavailable, len(batch), want)
		}
		if err := rootrecords.VerifyAfter(prev, batch); err != nil {
			return errors.Join(ErrAuth, err)
		}
		for i := range batch {
			if err := authenticateClosedEpoch(batch[i], state); err != nil {
				return err
			}
		}
		staged = append(staged, batch...)
		prev = &staged[len(staged)-1]
		next += uint64(len(batch))
	}
	if staged[len(staged)-1].ID != state.Tip {
		return fmt.Errorf("%w: the records end at another tip than the origin's", ErrAuth)
	}
	if s.store != nil {
		if err := s.store.AppendRecords(staged); err != nil {
			report = fmt.Errorf("retaining records %d..: %w", staged[0].Index, err)
			if s.persistErr == nil {
				s.persistErr = report
			}
			hook = s.onPersistErr
		}
	}
	s.log = append(s.log, staged...)
	s.checked = len(s.log)
	return nil
}

// checkLoaded authenticates the closed-epoch field of the not yet usable loaded records below end (s.mu held). It changes nothing: the
// caller makes them usable only once the chain they belong to binds to the cut's tip.
func (s *Source) checkLoaded(state rootrecords.State, end uint64) error {
	for i := uint64(s.checked); i < end; i++ {
		if err := authenticateClosedEpoch(s.log[i], state); err != nil {
			return err
		}
	}
	return nil
}

// authenticateClosedEpoch checks the one field of a served record that its identifier does not cover: the epoch a Closure closed. The
// source state lists the H round every closed epoch closed at, and a Closure names its H round.
func authenticateClosedEpoch(r rootrecords.Record, state rootrecords.State) error {
	if r.Kind != rootrecords.KindClosure {
		return nil
	}
	hRound := uint64(0)
	for _, b := range r.Data[56:64] {
		hRound = hRound<<8 | uint64(b)
	}
	epoch, ok := state.ClosedEpochOf(hRound)
	if !ok || epoch != r.ClosedEpoch {
		return fmt.Errorf("%w: closure %d names closed epoch %d, the origin's state says %d (found %t)", ErrAuth, r.Index, r.ClosedEpoch, epoch, ok)
	}
	return nil
}
