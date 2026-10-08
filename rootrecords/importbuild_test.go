package rootrecords

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type logSource struct {
	records []Record
	missing map[uint64]bool
	lie     map[uint64]uint64
}

func (l logSource) Record(i uint64) (Record, error) {
	if l.missing[i] || i >= uint64(len(l.records)) {
		return Record{}, errors.New("not retained")
	}
	r := l.records[i]
	if v, ok := l.lie[i]; ok {
		r.Index = v
	}
	return r, nil
}

func cursorOf(p *Projector) Cursor {
	a := p.Anchor()
	c := Cursor{Progress: a.Progress, UCTime: a.UCTime, TargetCount: p.Log.Len()}
	if n := p.Log.Len(); n > 0 {
		last, _ := p.Log.At(n - 1)
		c.TargetTip = last.ID
	}
	return c
}

func registryAfter(p *Projector, have uint64, prior Cursor) Registry {
	reg := Registry{Count: have, Progress: prior.Progress, UCTime: prior.UCTime, TargetCount: prior.TargetCount, TargetTip: prior.TargetTip}
	if have > 0 {
		last, _ := p.Log.At(have - 1)
		reg.Tip, reg.Last = last.ID, &last
	}
	return reg
}

func TestBuildImportIsTheProjectorsBatchForEveryRegistryCount(t *testing.T) {
	p := backlog(t, 40)
	src := logSource{records: p.Log.Records()}
	cur := cursorOf(p)
	for have := uint64(0); have <= 40; have++ {
		want, err := p.ImportBatch(have)
		require.NoError(t, err)
		got, err := BuildImport(src, cur, registryAfter(p, have, Cursor{}))
		require.NoError(t, err, have)
		require.Equal(t, want, got, "registry count %d", have)
		a, _ := want.Encode()
		b, _ := got.Encode()
		require.Equal(t, a, b)
	}
}

func TestBuildImportIsBoundedByTheOriginNotByTheLiveLog(t *testing.T) {
	p := backlog(t, 10)
	src := logSource{records: p.Log.Records()}
	// the origin saw only the first six records; the log has grown since: nothing past the origin is imported
	at6 := Cursor{Progress: 3, UCTime: 1_005, TargetCount: 6}
	tip, _ := p.Log.At(5)
	at6.TargetTip = tip.ID
	imp, err := BuildImport(src, at6, Registry{})
	require.NoError(t, err)
	require.Len(t, imp.Entries, 6)
	require.EqualValues(t, 6, imp.TargetCount)
	// the registry already holds more than the origin's log: the node is ahead of the origin it was handed
	_, err = BuildImport(src, at6, Registry{Count: 7})
	require.ErrorIs(t, err, ErrImport)
}

func TestBuildImportRefusesASourceThatCannotServeTheRecords(t *testing.T) {
	p := backlog(t, 5)
	cur := cursorOf(p)
	_, err := BuildImport(logSource{records: p.Log.Records(), missing: map[uint64]bool{3: true}}, cur, Registry{})
	require.ErrorIs(t, err, ErrImport, "an unretained record is unavailable, not skipped")
	_, err = BuildImport(logSource{records: p.Log.Records(), lie: map[uint64]uint64{2: 9}}, cur, Registry{})
	require.ErrorIs(t, err, ErrImport, "a source record under the wrong index")
}

func TestBuildImportRefusesARegistryAheadOfTheOriginsLog(t *testing.T) {
	p := backlog(t, 5)
	cur := cursorOf(p)
	// an in-range source would otherwise happily serve records past the target
	_, err := BuildImport(logSource{records: p.Log.Records()}, cur, Registry{Count: 6})
	require.ErrorIs(t, err, ErrImport)
	_, err = BuildImport(logSource{records: p.Log.Records()}, cur, Registry{Count: 5, Tip: cur.TargetTip})
	require.NoError(t, err, "caught up is an empty batch, not an error")
}

func TestCheckNextIsTheRegistrysRuleOneMutationAtATime(t *testing.T) {
	p := newProj(t)
	require.NoError(t, p.Tracker.Observe(1, 20)) // records ordered at positive progress, so "above the current progress" is testable
	for i := 0; i < 40; i++ {
		_, err := p.SessionClosed(label("result/" + string(rune('A'+i%26)) + string(rune('a'+i/26))))
		require.NoError(t, err)
	}
	require.Positive(t, p.Anchor().Progress)
	src := logSource{records: p.Log.Records()}
	cur := cursorOf(p)
	prior := Cursor{Progress: 0, UCTime: 900, TargetCount: 10, TargetTip: label("old-tip")}
	reg := registryAfter(p, 6, prior)
	good, err := BuildImport(src, cur, reg)
	require.NoError(t, err)
	require.Len(t, good.Entries, 32)
	require.NoError(t, good.CheckNext(reg))

	clone := func() Import {
		out := good
		out.Entries = append([]ImportEntry(nil), good.Entries...)
		for i := range out.Entries {
			out.Entries[i].Record.Data = append([]byte(nil), out.Entries[i].Record.Data...)
		}
		return out
	}
	regCases := map[string]func(r *Registry){
		"current progress below the registry's": func(r *Registry) { r.Progress = good.Progress + 1 },
		"current UC time below the registry's":  func(r *Registry) { r.UCTime = good.UCTime + 1 },
		"the target below the registry's":       func(r *Registry) { r.TargetCount = good.TargetCount + 1 },
		"another registry tip":                  func(r *Registry) { r.Tip[0] ^= 1 },
		"an unchanged target with another tip":  func(r *Registry) { r.TargetCount, r.TargetTip = good.TargetCount, label("another") },
		"a registry ahead of the batch":         func(r *Registry) { r.Count = 7 },
		"a last record newer than the first":    func(r *Registry) { l := *r.Last; l.UCTime = good.Entries[0].Record.UCTime + 1; r.Last = &l },
		"a last record with greater progress":   func(r *Registry) { l := *r.Last; l.Progress = good.Entries[0].Record.Progress + 1; r.Last = &l },
	}
	for name, mut := range regCases {
		r := reg
		mut(&r)
		require.ErrorIs(t, good.CheckNext(r), ErrImport, name)
	}
	impCases := map[string]func(i *Import){
		"one entry too few":                    func(i *Import) { i.Entries = i.Entries[:31] },
		"one entry too many":                   func(i *Import) { i.Entries = append(i.Entries, i.Entries[0]) },
		"a skipped index":                      func(i *Import) { i.Entries[3].Record.Index++ },
		"a broken link":                        func(i *Import) { i.Entries[3].Record.Predecessor[0] ^= 1 },
		"an identifier that is not content":    func(i *Import) { i.Entries[31].Record.ID[0] ^= 1 }, // the last entry: no successor link to catch it, and the batch is not caught up
		"changed content":                      func(i *Import) { i.Entries[3].Record.Progress++ },
		"an anchor above the current progress": func(i *Import) { i.Progress = i.Entries[31].Record.Progress - 1 },
		"an anchor above the current time":     func(i *Import) { i.UCTime = i.Entries[31].Record.UCTime - 1 },
		"a closed epoch off a closure":         func(i *Import) { i.Entries[0].ClosedEpoch = 3 },
	}
	for name, mut := range impCases {
		i := clone()
		mut(&i)
		require.Error(t, i.CheckNext(reg), name)
	}
	// the caught-up batch must end at the target tip
	p2 := backlog(t, 3)
	cur2 := cursorOf(p2)
	imp2, err := BuildImport(logSource{records: p2.Log.Records()}, cur2, Registry{})
	require.NoError(t, err)
	imp2.TargetTip[0] ^= 1
	require.ErrorIs(t, imp2.CheckNext(Registry{}), ErrImport)
}

func TestAClosureCarriesItsClosedEpochIntoTheImport(t *testing.T) {
	s := mustCommit(t, NewState(1, 1), 100, 2, 101, true)
	s = mustBlock(t, s, 2, 105)
	n, rec, err := s.Close(1, closureData(1), 105, 1_500)
	require.NoError(t, err)
	require.EqualValues(t, 1, rec.ClosedEpoch)
	require.NoError(t, Verify([]Record{rec}))
	require.EqualValues(t, 1, n.Count)
	imp, err := BuildImport(logSource{records: []Record{rec}}, Cursor{Progress: rec.Progress, UCTime: rec.UCTime, TargetCount: 1, TargetTip: rec.ID}, Registry{})
	require.NoError(t, err)
	require.EqualValues(t, 1, imp.Entries[0].ClosedEpoch)
	enc, err := imp.Encode()
	require.NoError(t, err)
	dec, err := DecodeImport(enc)
	require.NoError(t, err)
	require.EqualValues(t, 1, dec.Entries[0].ClosedEpoch)

	bad := rec
	bad.Kind, bad.Data = KindSessionClosed, make([]byte, 32)
	bad.ID = RecordID(bad.Index, bad.Predecessor, bad.Kind, bad.Progress, bad.UCTime, bad.Data)
	require.ErrorIs(t, Verify([]Record{bad}), ErrClosedEpoch, "a closed epoch on a record that is not a closure")
}

func TestAdmitImportChargesInTheDesignedOrder(t *testing.T) {
	p := backlog(t, 5)
	imp, err := BuildImport(logSource{records: p.Log.Records()}, cursorOf(p), Registry{})
	require.NoError(t, err)
	raw, err := imp.Encode()
	require.NoError(t, err)
	scan := ScanGas(len(raw))
	require.EqualValues(t, 2000+16*len(raw), scan)
	got, gas, err := AdmitImport(raw, scan+5_000)
	require.NoError(t, err)
	require.Equal(t, imp, got)
	require.Equal(t, AdmissionGas(len(raw), 5), gas)
	require.EqualValues(t, scan+5_000, gas)

	_, _, err = AdmitImport(raw, scan-1)
	require.ErrorIs(t, err, ErrImportBudget)
	_, _, err = AdmitImport(raw, scan+4_999)
	require.ErrorIs(t, err, ErrImportBudget)
	// the scan charge is reserved before the content is looked at: garbage of the same length fails for budget first
	_, _, err = AdmitImport(make([]byte, len(raw)), scan-1)
	require.ErrorIs(t, err, ErrImportBudget)
	_, _, err = AdmitImport(make([]byte, len(raw)), scan)
	require.ErrorIs(t, err, ErrImport)
	require.NotErrorIs(t, err, ErrImportBudget)
	// the byte cap precedes every charge
	_, _, err = AdmitImport(make([]byte, MaxImportBytes+1), 1<<62)
	require.ErrorIs(t, err, ErrImport)
	require.NotErrorIs(t, err, ErrImportBudget)
	// non-canonical bytes are refused whatever the budget
	_, _, err = AdmitImport(append(append([]byte(nil), raw...), 0), 1<<62)
	require.ErrorIs(t, err, ErrImport)
}
