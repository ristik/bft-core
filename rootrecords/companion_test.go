package rootrecords

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

func backlog(t *testing.T, n int) *Projector {
	t.Helper()
	p := newProj(t)
	for i := 0; i < n; i++ {
		_, err := p.SessionClosed(label("result/" + string(rune('A'+i%26)) + string(rune('a'+i/26))))
		require.NoError(t, err)
	}
	return p
}

func TestImportRoundTripsCanonically(t *testing.T) {
	p := backlog(t, 3)
	imp, err := p.ImportBatch(0)
	require.NoError(t, err)
	enc, err := imp.Encode()
	require.NoError(t, err)
	got, err := DecodeImport(enc)
	require.NoError(t, err)
	require.Equal(t, imp, got)
	h, err := imp.Hash()
	require.NoError(t, err)
	again, _ := got.Hash()
	require.Equal(t, h, again)
}

func TestImportBatchIsTheNextPrefix(t *testing.T) {
	p := backlog(t, 40)
	first, err := p.ImportBatch(0)
	require.NoError(t, err)
	require.Len(t, first.Entries, 32)
	require.EqualValues(t, 40, first.TargetCount)
	rest, err := p.ImportBatch(32)
	require.NoError(t, err)
	require.Len(t, rest.Entries, 8)
	require.EqualValues(t, 32, rest.Entries[0].Record.Index)
	require.Equal(t, first.TargetTip, rest.TargetTip)
	done, err := p.ImportBatch(40)
	require.NoError(t, err)
	require.Empty(t, done.Entries, "caught up: the mandatory empty import")
	_, err = p.ImportBatch(41)
	require.ErrorIs(t, err, ErrImport)
	none, err := newProj(t).ImportBatch(0)
	require.NoError(t, err)
	require.Zero(t, none.TargetCount)
	require.Equal(t, [32]byte{}, none.TargetTip)
}

func TestImportBatchCarriesTheCurrentAnchors(t *testing.T) {
	p := backlog(t, 2)
	require.NoError(t, p.Tracker.Observe(1, 77))
	require.NoError(t, p.Import(origin(1, 20, 1_500)))
	imp, err := p.ImportBatch(0)
	require.NoError(t, err)
	require.EqualValues(t, 76, imp.Progress)
	require.EqualValues(t, 1_500, imp.UCTime)
	require.EqualValues(t, 1_000, imp.Entries[0].Record.UCTime, "a record keeps the anchor it was ordered at")
}

func TestImportEncodeRefusals(t *testing.T) {
	p := backlog(t, 34)
	base, _ := p.ImportBatch(0)
	cases := map[string]func(i *Import){
		"more than 32 entries":            func(i *Import) { i.Entries = append(i.Entries, i.Entries[0]) },
		"a zero target with a tip":        func(i *Import) { i.TargetCount, i.TargetTip, i.Entries = 0, [32]byte{1}, nil },
		"a closed epoch on a non-closure": func(i *Import) { i.Entries[0].ClosedEpoch = 1 },
		"a payload of the wrong width":    func(i *Import) { i.Entries[0].Record.Data = i.Entries[0].Record.Data[:31] },
		"an unknown kind":                 func(i *Import) { i.Entries[0].Record.Kind = Kind(9) },
	}
	for name, mutate := range cases {
		i := base
		i.Entries = append([]ImportEntry(nil), base.Entries...)
		mutate(&i)
		_, err := i.Encode()
		require.ErrorIs(t, err, ErrImport, name)
	}
}

func TestDecodeImportRefusals(t *testing.T) {
	p := backlog(t, 2)
	imp, _ := p.ImportBatch(0)
	enc, _ := imp.Encode()
	mk := func(v any) []byte { b, err := types.Cbor.Marshal(v); require.NoError(t, err); return b }
	entry := func(f ...any) any { return f }
	r := imp.Entries[0].Record
	good := []any{r.Index, r.ID[:], r.Predecessor[:], uint64(r.Kind), r.Progress, r.UCTime, r.Data, uint64(0)}
	hdr := []any{importDomain, imp.Progress, imp.UCTime, imp.TargetCount, imp.TargetTip[:]}
	cases := map[string][]byte{
		"trailing byte":  append(append([]byte(nil), enc...), 0),
		"truncated":      enc[:len(enc)-1],
		"empty":          nil,
		"another domain": mk(append([]any{"OTHER"}, append(hdr[1:], []any{good})...)),
		"five fields":    mk(append(hdr, nil)[:5]),
		"entry of seven": mk(append(append([]any(nil), hdr...), []any{good[:7]})),
		"entries a map":  mk(append(append([]any(nil), hdr...), map[string]any{})),
		"a short ID":     mk(append(append([]any(nil), hdr...), []any{entry(r.Index, []byte{1}, r.Predecessor[:], uint64(r.Kind), r.Progress, r.UCTime, r.Data, uint64(0))})),
		"a string for p": mk(append([]any{importDomain, "x"}, append(hdr[2:], []any{good})...)),
	}
	for name, data := range cases {
		_, err := DecodeImport(data)
		require.ErrorIs(t, err, ErrImport, name)
	}
}

func hx(b []byte) string { return "0x" + hex.EncodeToString(b) }

// import-vectors.json: the registry's importRootRecords calls the model owes, block by block, replayed by the contracts' tests.
const importVectorsPath = "testdata/import-vectors.json"

type importBlock struct {
	N           uint64        `json:"n"`
	Progress    uint64        `json:"progress"`
	UCTime      uint64        `json:"ucTime"`
	TargetCount uint64        `json:"targetCount"`
	TargetTip   string        `json:"targetTip"`
	Entries     []importEntry `json:"entries"`
	Companion   string        `json:"companion"`
	Hash        string        `json:"rootRecordsHash"`
}

type importEntry struct {
	vectorRecord
	ClosedEpoch uint64 `json:"closedEpoch"`
}

type importScenario struct {
	Name   string        `json:"name"`
	Blocks []importBlock `json:"blocks"`
}

func blockOf(t *testing.T, n uint64, imp Import) importBlock {
	t.Helper()
	enc, err := imp.Encode()
	require.NoError(t, err)
	h, err := imp.Hash()
	require.NoError(t, err)
	b := importBlock{N: n, Progress: imp.Progress, UCTime: imp.UCTime, TargetCount: imp.TargetCount, TargetTip: hx(imp.TargetTip[:]), Companion: hx(enc), Hash: hx(h[:])}
	for _, e := range imp.Entries {
		b.Entries = append(b.Entries, importEntry{toVector("", []Record{e.Record}).Records[0], e.ClosedEpoch})
	}
	return b
}

func buildImportVectors(t *testing.T) []importScenario {
	t.Helper()
	// a mixed log: a closure of epoch 1 and a retirement after a handoff, then a long backlog split over blocks
	p := newProj(t)
	_, err := p.Ack(label("result/J"), 100, 2, 101)
	require.NoError(t, err)
	require.NoError(t, p.Tracker.Observe(2, 151))
	require.NoError(t, p.Import(origin(1, 20, 1_200)))
	_, _, err = p.Close(ClosureKey{1, label("record/H"), 100}, Closure{label("assignment/genesis"), label("terminal-root"), label("exposure-digest"), label("key-history-digest")})
	require.NoError(t, err)
	_, err = p.Retire(1, 1, label("ref-digest"))
	require.NoError(t, err)
	first, err := p.ImportBatch(0)
	require.NoError(t, err)
	mixed := importScenario{Name: "mixed-kinds", Blocks: []importBlock{blockOf(t, 1, first)}}
	again, err := p.ImportBatch(3)
	require.NoError(t, err)
	mixed.Blocks = append(mixed.Blocks, blockOf(t, 2, again)) // caught up: the mandatory empty import

	long := backlog(t, 40)
	b1, err := long.ImportBatch(0)
	require.NoError(t, err)
	b2, err := long.ImportBatch(32)
	require.NoError(t, err)
	return []importScenario{mixed, {Name: "backlog-40", Blocks: []importBlock{blockOf(t, 1, b1), blockOf(t, 2, b2)}}}
}

func TestImportVectorsAreTheProjection(t *testing.T) {
	want, err := json.MarshalIndent(map[string]any{"format": "UNICITY_P85_RECORD_IMPORT/v1", "scenarios": buildImportVectors(t)}, "", "  ")
	require.NoError(t, err)
	want = append(want, '\n')
	if os.Getenv("ROOTRECORDS_UPDATE") == "1" {
		require.NoError(t, os.WriteFile(importVectorsPath, want, 0o644))
	}
	got, err := os.ReadFile(importVectorsPath)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got), "run with ROOTRECORDS_UPDATE=1 to regenerate")
}
