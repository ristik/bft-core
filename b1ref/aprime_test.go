package b1ref

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/unicitynetwork/bft-core/b1ref/b1gen"
)

const corpusSeed = "b1-any-age-v1"

func vectorByID(t *testing.T, m *b1gen.Manifest, id string) []byte {
	for _, v := range m.Vectors {
		if v.ID == id {
			raw, _ := hex.DecodeString(v.Request)
			return raw
		}
	}
	t.Fatalf("vector %s missing", id)
	return nil
}

func TestCallerScannerAllocatesNothing(t *testing.T) {
	m := b1gen.Build(corpusSeed)
	for _, id := range []string{"cert.single.ok", "cert.batch.max-16.ok", "quorum.max.all", "price.worst.k16"} {
		raw := vectorByID(t, m, id)
		var pl plan
		if err := scanBatch(raw, &pl, Standard); err != nil {
			t.Fatal(err)
		}
		if n := testing.AllocsPerRun(20, func() { scanBatch(raw, &pl, Standard) }); n != 0 {
			t.Fatalf("%s: %g allocations", id, n)
		}
	}
}

// TestGroupingParity: the oracle's scan finds exactly the generator's grouping on every structurally accepted vector.
func TestGroupingParity(t *testing.T) {
	m := b1gen.Build(corpusSeed)
	n := 0
	for _, v := range m.Vectors {
		g := v.Expected.Grouping
		if g == nil {
			continue
		}
		raw, _ := hex.DecodeString(v.Request)
		var pl plan
		if err := scanBatch(raw, &pl, Standard); err != nil {
			t.Fatalf("%s: %v", v.ID, err)
		}
		if pl.c != g.C || pl.k != g.K || pl.e != g.E || pl.s != g.S || pl.q != g.Q || pl.a != g.A || pl.p != g.P || pl.charge != v.Expected.Gas {
			t.Fatalf("%s: oracle %+v charge %d, generator %+v gas %d", v.ID, pl, pl.charge, *g, v.Expected.Gas)
		}
		n++
	}
	if n < 50 {
		t.Fatalf("only %d grouped vectors", n)
	}
}

func TestCallerScannerRejectsSignatureShape(t *testing.T) {
	m := b1gen.Build(corpusSeed)
	count := 0
	for _, v := range m.Vectors {
		if v.Expected.Sentinel != "ErrSigFormat" {
			continue
		}
		raw, _ := hex.DecodeString(v.Request)
		var pl plan
		if err := scanBatch(raw, &pl, Standard); !errors.Is(err, ErrSigFormat) {
			t.Fatalf("%s: %v", v.ID, err)
		}
		count++
	}
	if count < 6 {
		t.Fatal("missing signature format cases", count)
	}
}

// certFrame wraps one UC payload in a valid single-claim call frame. The UC is last, so slicing the frame with cap=len leaves the
// payload with no spare capacity: reads past its end panic instead of silently succeeding.
func certFrame(uc []byte) []byte {
	f := []byte{2, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0x80}
	f = append(f, make([]byte, 96)...)
	f = append(f, byte(len(uc)>>24), byte(len(uc)>>16), byte(len(uc)>>8), byte(len(uc)))
	f = append(f, uc...)
	return f[:len(f):len(f)]
}

func scanErr(in []byte) error { var pl plan; return scanBatch(in, &pl, Standard) }

func TestCallerScannerEmptyUC(t *testing.T) {
	if err := scanErr(certFrame(nil)); !errors.Is(err, ErrTruncated) {
		t.Fatal(err)
	}
}

func TestCallerScannerTightCapacityTruncation(t *testing.T) {
	for name, uc := range map[string][]byte{
		"bytes-inline":    {0x45, 1, 2, 3},
		"text-inline":     {0x65, 'a', 'b', 'c'},
		"bytes-no-body":   {0x58, 32},
		"text-no-body":    {0x78, 32},
		"bytes-one-short": {0x43, 1, 2},
	} {
		if err := scanErr(certFrame(uc)); !errors.Is(err, ErrTruncated) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestCallerScannerDuplicateBeforeDecode(t *testing.T) {
	// {1:0, 2:0, 1:0}: the later duplicate key is found by the allocation-free pass, before the shape reader or any decoder sees
	// the UC.
	uc := []byte{0xa3, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00}
	if err := scanErr(certFrame(uc)); !errors.Is(err, ErrDuplicateMapKey) {
		t.Fatal(err)
	}
}

// TestClaimConflictPredicate: the same-shard predicate on synthetic claims, since no real pair of different claims can both fold to
// one seal (contract section 7a.1).
func TestClaimConflictPredicate(t *testing.T) {
	claims := []claim{{partition: 1, shardBytes: []byte{0x80}}, {partition: 1, shardBytes: []byte{0x80}}, {partition: 1, shardBytes: []byte{0xc0}}, {partition: 2, shardBytes: []byte{0x80}}}
	pl := &plan{k: 4, occ: make([]occurrence, 4)}
	for i := range pl.occ[:4] {
		pl.occ[i] = occurrence{newClaim: true}
	}
	if !conflicts(claims, pl, 1) {
		t.Fatal("same partition and shard under one seal is a conflict")
	}
	if conflicts(claims, pl, 2) || conflicts(claims, pl, 3) {
		t.Fatal("another shard or partition is no conflict")
	}
	pl.occ[1].sealGroup = 1
	if conflicts(claims, pl, 1) {
		t.Fatal("the same shard under another seal is no conflict")
	}
	pl.occ[1].sealGroup, pl.occ[0].newClaim = 0, false
	if conflicts(claims, pl, 1) {
		t.Fatal("an exact repeat (not a new claim) is no conflict")
	}
}

// TestComposedLimits: the composition's anchor table is grouped under Composed. Seventeen occurrences of one claim exceed the
// standalone claim bound (ErrCount) but group under Composed into one claim, one seal and one epoch, with the occurrences counted.
func TestComposedLimits(t *testing.T) {
	single := vectorByID(t, b1gen.Build(corpusSeed), "cert.single.ok")
	one, err := GroupWith(single, Composed)
	if err != nil {
		t.Fatal(err)
	}
	in := []byte{2, 0, 0, 17}
	for i := 0; i < 17; i++ {
		in = append(in, single[4:]...)
	}
	if _, err := Group(in); !errors.Is(err, ErrCount) {
		t.Fatalf("standalone: %v", err)
	}
	g, err := GroupWith(in, Composed)
	if err != nil {
		t.Fatal(err)
	}
	if g.K != 17 || g.A != 1 || g.S != 1 || g.E != 1 || g.Q != one.Q || g.P != one.P {
		t.Fatalf("composed grouping %+v, single %+v", g, one)
	}
}
