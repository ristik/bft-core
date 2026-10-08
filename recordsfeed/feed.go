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
	return cursor, nil
}

// Record returns a record of the verified log; a record that has not been verified is unavailable.
func (s *Source) Record(index uint64) (rootrecords.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index >= uint64(len(s.log)) {
		return rootrecords.Record{}, fmt.Errorf("%w: record %d", ErrUnavailable, index)
	}
	return s.log[index], nil
}

// extend verifies the records up to the state's length against its tip and retains them.
func (s *Source) extend(ctx context.Context, remote Remote, state rootrecords.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state.Count == 0 {
		return nil
	}
	if uint64(len(s.log)) >= state.Count {
		if s.log[state.Count-1].ID != state.Tip {
			return fmt.Errorf("%w: the verified log differs from the log the origin authenticates", ErrAuth)
		}
		return nil
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
	s.log = append(s.log, staged...)
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
