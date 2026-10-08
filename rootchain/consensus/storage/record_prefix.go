package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

var (
	// ErrRecordPrefixMissing reports an installed checkpoint whose source log this root does not retain and could not obtain.
	ErrRecordPrefixMissing = errors.New("P85 record log: the retained prefix is shorter than the checkpoint's and could not be fetched")
	// ErrRecordPrefixConflict reports a retained log that differs from the one the checkpoint's source state commits.
	ErrRecordPrefixConflict = errors.New("P85 record log: the retained log is not the one the checkpoint commits")
)

// RecordFetcher is where a root that joins without the log gets it: the verified records of another root, in bounded pages.
type RecordFetcher interface {
	Records(ctx context.Context, from uint64, max int) ([]rootrecords.Record, error)
}

const (
	prefixPage    = 256
	prefixTimeout = 30 * time.Second
)

// SetRecordFetcher names where the missing prefix of the source log is fetched from when a checkpoint is installed.
func (x *BlockStore) SetRecordFetcher(f RecordFetcher) {
	x.lock.Lock()
	defer x.lock.Unlock()
	x.prefixSource = f
}

// ensureRetainedPrefix checks the installed checkpoint's source state (the length and tip of the log it commits) against the retained
// log before the successor consensus starts. A longer or equal retained log must carry the committed tip at the committed length; a
// shorter one is completed from the fetcher, each record verified link by link from the last retained one and the closed epochs
// authenticated by the checkpoint's state, and only a prefix that ends at exactly the committed tip is retained. A checkpoint whose
// cursor is valid but whose log is missing is not enough to start.
func (x *BlockStore) ensureRetainedPrefix(control *evmroot.ControlState) error {
	if control == nil || len(control.Pos) == 0 {
		return nil
	}
	state, err := rootrecords.DecodeState(control.Pos)
	if err != nil {
		return fmt.Errorf("the checkpoint's source state: %w", err)
	}
	if state.Count == 0 {
		return nil
	}
	store, ok := x.storage.(RecordStore)
	if !ok {
		return ErrNoRecordStore
	}
	have, err := store.RecordCount()
	if err != nil {
		return err
	}
	if have >= state.Count {
		tip, err := store.Records(state.Count-1, 1)
		if err != nil || len(tip) != 1 || tip[0].ID != state.Tip {
			return errors.Join(ErrRecordPrefixConflict, err)
		}
		return nil
	}
	if x.prefixSource == nil {
		return fmt.Errorf("%w: %d of %d records retained", ErrRecordPrefixMissing, have, state.Count)
	}
	ctx, cancel := context.WithTimeout(context.Background(), prefixTimeout)
	defer cancel()
	var prev *rootrecords.Record
	if have > 0 {
		last, err := store.Records(have-1, 1)
		if err != nil || len(last) != 1 {
			return errors.Join(ErrRecordPrefixConflict, err)
		}
		prev = &last[0]
	}
	var staged []rootrecords.Record
	for next := have; next < state.Count; {
		want := min(state.Count-next, prefixPage)
		batch, err := x.prefixSource.Records(ctx, next, int(want))
		if err != nil {
			return errors.Join(ErrRecordPrefixMissing, err)
		}
		if len(batch) == 0 || uint64(len(batch)) > want {
			return fmt.Errorf("%w: %d records for a request of %d", ErrRecordPrefixMissing, len(batch), want)
		}
		if err := rootrecords.VerifyAfter(prev, batch); err != nil {
			return errors.Join(ErrRecordPrefixConflict, err)
		}
		for _, r := range batch {
			if err := closedEpochMatches(r, state); err != nil {
				return err
			}
		}
		staged = append(staged, batch...)
		prev = &staged[len(staged)-1]
		next += uint64(len(batch))
	}
	if staged[len(staged)-1].ID != state.Tip {
		return fmt.Errorf("%w: the fetched records end at another tip", ErrRecordPrefixConflict)
	}
	return store.AppendRecords(staged)
}

// closedEpochMatches is the one field of a served Closure that its identifier does not cover: the epoch it closed, which the source
// state lists by H round.
func closedEpochMatches(r rootrecords.Record, state rootrecords.State) error {
	if r.Kind != rootrecords.KindClosure {
		return nil
	}
	if len(r.Data) < 64 {
		return fmt.Errorf("%w: closure %d is malformed", ErrRecordPrefixConflict, r.Index)
	}
	hRound := uint64(0)
	for _, b := range r.Data[56:64] {
		hRound = hRound<<8 | uint64(b)
	}
	epoch, ok := state.ClosedEpochOf(hRound)
	if !ok || epoch != r.ClosedEpoch {
		return fmt.Errorf("%w: closure %d names closed epoch %d, the checkpoint says %d (found %t)", ErrRecordPrefixConflict, r.Index, r.ClosedEpoch, epoch, ok)
	}
	return nil
}
