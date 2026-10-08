package rootrecords

import (
	"fmt"
)

// Registry is what the EVM registry holds in the parent state that the next import is judged against: the imported count and tip, the
// progress and UC time of the last import, the length and tip of the source log as of it, and the anchors of the last imported
// record (nil while nothing is imported).
type Registry struct {
	Count, Progress, UCTime, TargetCount uint64
	Tip, TargetTip                       [32]byte
	Last                                 *Record
}

// Cursor is the authenticated state of the source log at the chosen root origin: the current progress and UC time, and the length and
// tip of the complete log as of that origin's block. Records committed after the origin are not part of it (no future-origin records).
type Cursor struct {
	Progress, UCTime, TargetCount uint64
	TargetTip                     [32]byte
}

// Source returns the retained source log's records by index.
type Source interface {
	Record(index uint64) (Record, error)
}

// BuildImport derives the import owed by a block whose parent registry is reg, as of the origin cursor: exactly the next
// min(MaxImport, TargetCount - Count) records of the source log, with the cursor's anchors and target. A relayer supplies nothing; a
// second paired node derives identical bytes from the same inputs.
func BuildImport(src Source, cur Cursor, reg Registry) (Import, error) {
	if reg.Count > cur.TargetCount {
		return Import{}, fmt.Errorf("%w: the registry holds %d records, the source log had %d at the origin", ErrImport, reg.Count, cur.TargetCount)
	}
	n := min(cur.TargetCount-reg.Count, MaxImport)
	imp := Import{Progress: cur.Progress, UCTime: cur.UCTime, TargetCount: cur.TargetCount, TargetTip: cur.TargetTip}
	for i := reg.Count; i < reg.Count+n; i++ {
		r, err := src.Record(i)
		if err != nil {
			return Import{}, fmt.Errorf("%w: source record %d: %v", ErrImport, i, err)
		}
		if r.Index != i {
			return Import{}, fmt.Errorf("%w: source record %d carries index %d", ErrImport, i, r.Index)
		}
		imp.Entries = append(imp.Entries, ImportEntry{Record: r, ClosedEpoch: r.ClosedEpoch})
	}
	if err := imp.CheckNext(reg); err != nil {
		return Import{}, err
	}
	return imp, nil
}

// CheckNext is the registry's own acceptance rule for importRootRecords as a second implementation: the batch is exactly the required
// prefix, indices and links continue the registry's log, identifiers are content-derived, anchors never decrease and never exceed the
// supplied current ones, the supplied current anchors and target never decrease, an unchanged target keeps its tip, a zero target has a
// zero tip, and a caught-up batch ends at the target tip. It needs only the registry words and the last imported record's anchors.
func (i Import) CheckNext(reg Registry) error {
	if err := i.shapeValid(); err != nil {
		return err
	}
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrImport}, a...)...)
	}
	if i.Progress < reg.Progress || i.UCTime < reg.UCTime || i.TargetCount < reg.TargetCount {
		return bad("current progress, UC time or target decreased")
	}
	if i.TargetCount < reg.Count || uint64(len(i.Entries)) != min(i.TargetCount-reg.Count, MaxImport) {
		return bad("%d entries are not the required prefix of %d records after %d", len(i.Entries), i.TargetCount, reg.Count)
	}
	if i.TargetCount == reg.TargetCount && i.TargetTip != reg.TargetTip {
		return bad("an unchanged target changed its tip")
	}
	tip, lastProgress, lastTime := reg.Tip, uint64(0), uint64(0)
	if reg.Last != nil {
		lastProgress, lastTime = reg.Last.Progress, reg.Last.UCTime
	}
	for k, e := range i.Entries {
		r := e.Record
		if r.Index != reg.Count+uint64(k) || r.Predecessor != tip {
			return bad("entry %d does not continue the registry's log", k)
		}
		if r.Progress < lastProgress || r.UCTime < lastTime || r.Progress > i.Progress || r.UCTime > i.UCTime {
			return bad("entry %d has an anchor outside [previous, current]", k)
		}
		if r.ID != RecordID(r.Index, r.Predecessor, r.Kind, r.Progress, r.UCTime, r.Data) {
			return bad("entry %d is not content-derived", k)
		}
		tip, lastProgress, lastTime = r.ID, r.Progress, r.UCTime
	}
	if reg.Count+uint64(len(i.Entries)) == i.TargetCount && tip != i.TargetTip {
		return bad("the caught-up tail is not the target tip")
	}
	return nil
}
