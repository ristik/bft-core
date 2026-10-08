package rootrecords

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
)

// MaxImport is the largest record batch one EVM block imports (the registry's importRootRecords bound).
const MaxImport = 32

const importDomain = "UNICITY_P85_RECORD_IMPORT"

// ErrImport reports an import companion that is not the canonical, well-formed batch of the next required prefix.
var ErrImport = errors.New("rootrecords: invalid record import")

// ImportEntry is one record with the closed root epoch of a Closure (zero for every other kind).
type ImportEntry struct {
	Record      Record
	ClosedEpoch uint64
}

// Import is the mandatory record import of one EVM block: the authenticated current progress and UC time, the length and tip of the
// complete source log, and the next min(MaxImport, TargetCount - registry count) records. Its canonical CBOR is the companion the
// root input commits by hash (rootRecordsHash), so every paired node derives and checks identical bytes.
type Import struct {
	Progress, UCTime, TargetCount uint64
	TargetTip                     [32]byte
	Entries                       []ImportEntry
}

func (i Import) shapeValid() error {
	if len(i.Entries) > MaxImport {
		return fmt.Errorf("%w: %d entries", ErrImport, len(i.Entries))
	}
	if i.TargetCount == 0 && i.TargetTip != ([32]byte{}) {
		return fmt.Errorf("%w: a zero target has a tip", ErrImport)
	}
	for k, e := range i.Entries {
		if err := checkPayload(e.Record.Kind, e.Record.Data); err != nil {
			return fmt.Errorf("%w: entry %d: %v", ErrImport, k, err)
		}
		if e.Record.Kind != KindClosure && e.ClosedEpoch != 0 {
			return fmt.Errorf("%w: entry %d: only a closure names a closed epoch", ErrImport, k)
		}
	}
	return nil
}

// Encode checks the shape only: at most MaxImport entries, the exact payload width of each kind, a closed epoch only on a closure and a
// zero tip for a zero target. It does not check indices, links, record identifiers or the uint64 payload words; a producer derives the
// batch from its own log (ImportBatch) and every verifier recomputes it and compares the bytes, and the registry checks the rest.
//
// Encode is the canonical CBOR ["UNICITY_P85_RECORD_IMPORT", p, t, targetCount, targetTip, entries] with entries
// [index, recordID, predecessor, kind, progress, ucTime, data, closedEpoch].
func (i Import) Encode() ([]byte, error) {
	if err := i.shapeValid(); err != nil {
		return nil, err
	}
	entries := make([]any, 0, len(i.Entries))
	for _, e := range i.Entries {
		r := e.Record
		entries = append(entries, []any{r.Index, r.ID[:], r.Predecessor[:], uint64(r.Kind), r.Progress, r.UCTime, r.Data, e.ClosedEpoch})
	}
	return types.Cbor.Marshal([]any{importDomain, i.Progress, i.UCTime, i.TargetCount, i.TargetTip[:], entries})
}

// Hash is SHA-256 of the canonical encoding: the rootRecordsHash the root input commits.
func (i Import) Hash() ([32]byte, error) {
	b, err := i.Encode()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

func u64(v any) (uint64, bool) { x, ok := v.(uint64); return x, ok }

func b32(v any) (a [32]byte, ok bool) {
	b, ok := v.([]byte)
	if !ok || len(b) != 32 {
		return a, false
	}
	copy(a[:], b)
	return a, true
}

// DecodeImport parses a companion and refuses anything that is not the exact canonical encoding of the value it decodes to (a
// non-shortest integer or an indefinite-length array decodes to the same value and is refused). Like Encode it checks shape only.
func DecodeImport(data []byte) (Import, error) {
	var out Import
	var raw []any
	if err := types.Cbor.Unmarshal(data, &raw); err != nil || len(raw) != 6 {
		return out, fmt.Errorf("%w: shape", ErrImport)
	}
	if d, ok := raw[0].(string); !ok || d != importDomain {
		return out, fmt.Errorf("%w: domain", ErrImport)
	}
	var ok [4]bool
	out.Progress, ok[0] = u64(raw[1])
	out.UCTime, ok[1] = u64(raw[2])
	out.TargetCount, ok[2] = u64(raw[3])
	out.TargetTip, ok[3] = b32(raw[4])
	if !ok[0] || !ok[1] || !ok[2] || !ok[3] {
		return Import{}, fmt.Errorf("%w: header", ErrImport)
	}
	entries, isArr := raw[5].([]any)
	if !isArr {
		return Import{}, fmt.Errorf("%w: entries", ErrImport)
	}
	for _, ev := range entries {
		f, isArr := ev.([]any)
		if !isArr || len(f) != 8 {
			return Import{}, fmt.Errorf("%w: entry shape", ErrImport)
		}
		var e ImportEntry
		var good [8]bool
		e.Record.Index, good[0] = u64(f[0])
		e.Record.ID, good[1] = b32(f[1])
		e.Record.Predecessor, good[2] = b32(f[2])
		kind, kindOK := u64(f[3])
		good[3] = kindOK && kind <= 0xff
		e.Record.Kind = Kind(kind)
		e.Record.Progress, good[4] = u64(f[4])
		e.Record.UCTime, good[5] = u64(f[5])
		e.Record.Data, good[6] = f[6].([]byte)
		e.ClosedEpoch, good[7] = u64(f[7])
		for _, g := range good {
			if !g {
				return Import{}, fmt.Errorf("%w: entry field", ErrImport)
			}
		}
		out.Entries = append(out.Entries, e)
	}
	again, err := out.Encode()
	if err != nil || !bytes.Equal(again, data) {
		return Import{}, fmt.Errorf("%w: not canonical", ErrImport)
	}
	return out, nil
}

// ImportBatch is the import a block owes given the registry's imported count: the next min(MaxImport, count of the source log - have)
// records, the log's tip as the target, and the current progress and UC time. Everything is derived from the projector's own log and
// anchors; a relayer supplies nothing. have beyond the log is refused.
func (p *Projector) ImportBatch(have uint64) (Import, error) {
	total := p.Log.Len()
	if have > total {
		return Import{}, fmt.Errorf("%w: registry holds %d of %d records", ErrImport, have, total)
	}
	n := min(total-have, MaxImport)
	imp := Import{Progress: p.Anchor().Progress, UCTime: p.Anchor().UCTime, TargetCount: total}
	if total > 0 {
		last, _ := p.Log.At(total - 1)
		imp.TargetTip = last.ID
	}
	for i := have; i < have+n; i++ {
		r, _ := p.Log.At(i)
		imp.Entries = append(imp.Entries, ImportEntry{Record: r, ClosedEpoch: p.closedEpochs[i]})
	}
	return imp, nil
}

// The metered admission of an import companion, mirrored in ureth (records.rs): the byte cap precedes every charge, the scan charge
// 2000+16*C_R is reserved before the structural scan, and the entry charge 1000*N before any entry is decoded. Both sides are checked
// against the same vectors; the priced figures are admission prices subject to the maximum-work acceptance gate, not measured costs.
const (
	MaxImportBytes = 16384
	ScanBaseGas    = 2000
	ScanByteGas    = 16
	EntryGas       = 1000
)

// ErrImportBudget reports an import companion whose admission charge does not fit the system budget that remains.
var ErrImportBudget = errors.New("rootrecords: import admission exceeds the system budget")

// ScanGas is G_R_scan for a companion of n bytes.
func ScanGas(n int) uint64 { return ScanBaseGas + ScanByteGas*uint64(n) }

// AdmissionGas is G_R_admit = G_R_scan + 1000*N for a companion of n bytes with entries entries.
func AdmissionGas(n, entries int) uint64 { return ScanGas(n) + EntryGas*uint64(entries) }

// AdmitImport admits a companion against the remaining system budget in the staged order the design fixes, returning the decoded value
// and G_R_admit.
func AdmitImport(raw []byte, budget uint64) (Import, uint64, error) {
	if len(raw) > MaxImportBytes {
		return Import{}, 0, fmt.Errorf("%w: %d bytes", ErrImport, len(raw))
	}
	scan := ScanGas(len(raw))
	if scan > budget {
		return Import{}, 0, fmt.Errorf("%w: scan charge %d of %d", ErrImportBudget, scan, budget)
	}
	imp, err := DecodeImport(raw)
	if err != nil {
		return Import{}, 0, err
	}
	entries := EntryGas * uint64(len(imp.Entries))
	if entries > budget-scan {
		return Import{}, 0, fmt.Errorf("%w: entry charge %d of %d", ErrImportBudget, entries, budget-scan)
	}
	return imp, scan + entries, nil
}
