package frontier

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/unicitynetwork/bft-core/archive"
)

var eligibleNames = []string{"replica-a", "replica-b", "replica-c"}

func eligiblePolicy(p Policy) Policy {
	p.Replicas = [2]string{}
	p.Eligible = append([]string(nil), eligibleNames...)
	p.PolicyDigest = [32]byte{9}
	return p
}

// pairRecord is a version 3 record acknowledged by eligibleNames[i] and [j].
func pairRecord(base Record, p Policy, i, j int) (Record, *archive.Record) {
	r := base
	r.Epoch = p.Context.RootEpoch
	r.PolicyDigest = p.PolicyDigest
	m := materialFor(r.Height)
	setSubject(&r, Policy{Replicas: [2]string{p.Eligible[i], p.Eligible[j]}})
	return r, m
}

// advance is the block after base, acknowledged by eligibleNames[i] and [j].
func advance(base Record, p Policy, i, j int) (Record, *archive.Record) {
	base.Sequence++
	base.Round++
	base.Height++
	return pairRecord(base, p, i, j)
}

func pairs() [][2]int { return [][2]int{{0, 1}, {0, 2}, {1, 2}} }

func eligibleFixture() (Record, Policy) {
	r, p := fixture()
	return r, eligiblePolicy(p)
}

func TestEligibleAnyTwoOfThreeRoundTripPlanAndRecover(t *testing.T) {
	base, p := eligibleFixture()
	for _, pr := range pairs() {
		r, m := pairRecord(base, p, pr[0], pr[1])
		raw, err := Encode(r, p)
		if err != nil {
			t.Fatalf("%v: %v", pr, err)
		}
		if raw[len(domain)] != policyVersion {
			t.Fatalf("%v: version %d", pr, raw[len(domain)])
		}
		got, err := Decode(raw, p)
		if err != nil || got.PolicyDigest != p.PolicyDigest || got.Acks[0].Replica != eligibleNames[pr[0]] || got.Acks[1].Replica != eligibleNames[pr[1]] {
			t.Fatalf("%v: decode %+v %v", pr, got, err)
		}
		if got.Migrated() {
			t.Fatalf("%v: current record reported migrated", pr)
		}
		// Any pair may follow any other pair.
		for _, then := range pairs() {
			n, nm := advance(r, p, then[0], then[1])
			plan, err := PlanAdvance(&r, n, p, []Coverage{{Anchor: n, Material: nm}}, nil)
			if err != nil || plan.PruneThrough != n.Round {
				t.Fatalf("%v then %v: plan %v", pr, then, err)
			}
		}
		if err := CheckRecovery(r, 0, p, Coverage{Anchor: r, Material: m}); err != nil {
			t.Fatalf("%v: recovery %v", pr, err)
		}
	}
}

// Availability is checked for the two replicas that acknowledged, and only those.
func TestEligiblePlanChecksOnlyTheAcknowledgingPair(t *testing.T) {
	base, p := eligibleFixture()
	for _, pr := range pairs() {
		prev, _ := pairRecord(base, p, 0, 1)
		r, m := advance(prev, p, pr[0], pr[1])
		cov := []Coverage{{Anchor: r, Material: m}}
		for k, name := range eligibleNames {
			p.Availability = availabilityTest{lost: name}
			_, err := PlanAdvance(&prev, r, p, cov, nil)
			if k == pr[0] || k == pr[1] {
				require(t, err, ErrAcknowledgment)
			} else if err != nil {
				t.Fatalf("pair %v, third replica %s lost: %v", pr, name, err)
			}
		}
	}
}

func TestEligibleRefusals(t *testing.T) {
	base, p := eligibleFixture()
	good, _ := pairRecord(base, p, 0, 2)
	mutate := func(f func(*Record, *Policy)) error {
		r, q := good, p
		q.Eligible = append([]string(nil), p.Eligible...)
		f(&r, &q)
		_, err := Encode(r, q)
		return err
	}
	retarget := func(r *Record, i int, name string) {
		r.Acks[i].Replica = name
	}
	for name, tc := range map[string]struct {
		f    func(*Record, *Policy)
		want error
	}{
		"reversed order":        {func(r *Record, _ *Policy) { r.Acks[0], r.Acks[1] = r.Acks[1], r.Acks[0] }, ErrContext},
		"same replica twice":    {func(r *Record, _ *Policy) { retarget(r, 1, eligibleNames[0]) }, ErrContext},
		"outside the policy":    {func(r *Record, _ *Policy) { retarget(r, 1, "replica-z") }, ErrContext},
		"first outside":         {func(r *Record, _ *Policy) { retarget(r, 0, "replica-z") }, ErrContext},
		"other policy digest":   {func(r *Record, _ *Policy) { r.PolicyDigest = [32]byte{8} }, ErrContext},
		"policy without digest": {func(_ *Record, q *Policy) { q.PolicyDigest = [32]byte{} }, ErrContext},
		"one eligible only":     {func(_ *Record, q *Policy) { q.Eligible = q.Eligible[:1] }, ErrContext},
		"four eligible":         {func(_ *Record, q *Policy) { q.Eligible = append(q.Eligible, "replica-d") }, ErrContext},
		"duplicate eligible":    {func(_ *Record, q *Policy) { q.Eligible[1] = q.Eligible[0] }, ErrContext},
		"empty eligible name":   {func(_ *Record, q *Policy) { q.Eligible[1] = "" }, ErrContext},
		"v3 under legacy pair":  {func(_ *Record, q *Policy) { q.Eligible, q.Replicas = nil, [2]string{"replica-a", "replica-c"} }, ErrContext},
		"split manifests":       {func(r *Record, _ *Policy) { r.Acks[1].ManifestDigest[0] ^= 1 }, ErrAcknowledgment},
		"epochless v3":          {func(r *Record, _ *Policy) { r.Epoch = 0 }, ErrInvalid},
	} {
		if err := mutate(tc.f); !errorsIs(err, tc.want) {
			t.Errorf("%s: got %v want %v", name, err, tc.want)
		}
	}
	if err := mutate(func(*Record, *Policy) {}); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func errorsIs(got, want error) bool { return got != nil && (got == want || errorsIsWrapped(got, want)) }

// A tampered but re-checksummed digest must fail the strict decode.
func TestEligibleDecodeBindsPolicyDigest(t *testing.T) {
	base, p := eligibleFixture()
	r, _ := pairRecord(base, p, 1, 2)
	raw, err := Encode(r, p)
	if err != nil {
		t.Fatal(err)
	}
	at := len(domain) + 1 + 8*4 // sequence, round, height, epoch
	raw[at] ^= 1
	sum := sha256.Sum256(raw[:len(raw)-32])
	copy(raw[len(raw)-32:], sum[:])
	_, err = Decode(raw, p)
	require(t, err, ErrContext)
	if _, err = DecodeMigrating(raw, p); err != nil {
		t.Fatalf("an earlier-policy record with a still eligible replica is historical: %v", err)
	}
}

func TestEligibleHistoricalRecords(t *testing.T) {
	base, p := eligibleFixture()
	// Earlier policy: replicas {a, z}; membership changed to {a, b, c}.
	older := p
	older.Eligible = []string{"replica-a", "replica-z"}
	older.PolicyDigest = [32]byte{7}
	r, _ := pairRecord(base, older, 0, 1)
	raw, err := Encode(r, older)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decode(raw, p)
	require(t, err, ErrContext)
	got, err := DecodeMigrating(raw, p)
	if err != nil || !got.Historical || !got.Migrated() {
		t.Fatalf("historical v3: %+v %v", got, err)
	}
	// No acknowledging replica remains eligible: refused even when migrating.
	disjoint := p
	disjoint.Eligible = []string{"replica-y", "replica-z"}
	disjoint.PolicyDigest = [32]byte{6}
	r, _ = pairRecord(base, disjoint, 0, 1)
	raw, err = Encode(r, disjoint)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeMigrating(raw, p)
	require(t, err, ErrContext)
}

// Version 1 and 2 records are historical two-replica evidence under an Eligible
// policy, even when both acknowledging replicas are still eligible: they are
// accepted only by DecodeMigrating, as Historical, and never encoded again.
func TestEligibleLegacyRecords(t *testing.T) {
	base, legacy := fixture()
	p := eligiblePolicy(legacy)
	for _, tc := range []struct {
		names     [2]string
		epoch     uint64
		migrating error
	}{
		{[2]string{"replica-a", "replica-b"}, 0, nil},
		{[2]string{"replica-c", "replica-a"}, 0, nil},
		{[2]string{"replica-b", "replica-c"}, 4, nil},
		{[2]string{"replica-a", "replica-z"}, 0, nil},
		{[2]string{"replica-z", "replica-c"}, 4, nil},
		{[2]string{"replica-y", "replica-z"}, 0, ErrContext},
	} {
		r := base
		r.Epoch = tc.epoch
		setSubject(&r, Policy{Replicas: tc.names})
		raw, err := encodeRecord(r)
		if err != nil {
			t.Fatal(err)
		}
		wantVersion := version
		if tc.epoch != 0 {
			wantVersion = epochVersion
		}
		if raw[len(domain)] != wantVersion {
			t.Fatalf("%v: version %d", tc.names, raw[len(domain)])
		}
		if _, err := Decode(raw, p); !errorsIs(err, ErrContext) {
			t.Fatalf("%v strict: %v", tc.names, err)
		}
		if _, err := Encode(r, p); !errorsIs(err, ErrContext) {
			t.Fatalf("%v encode: %v", tc.names, err)
		}
		got, err := DecodeMigrating(raw, p)
		if tc.migrating != nil {
			if !errorsIs(err, tc.migrating) {
				t.Fatalf("%v migrating: %v", tc.names, err)
			}
			continue
		}
		if err != nil || !got.Historical || !got.Migrated() {
			t.Fatalf("%v migrating: %+v %v", tc.names, got, err)
		}
	}
	// A legacy two-replica policy never accepts a version 3 record.
	r, p3 := eligibleFixture()
	v3, _ := pairRecord(r, p3, 0, 1)
	if _, err := Encode(v3, legacy); !errorsIs(err, ErrContext) {
		t.Fatalf("v3 under legacy policy: %v", err)
	}
}

// One replica named twice must never count as two acknowledgments, in any
// version and through every entry point.
func TestEligibleDuplicateAcknowledger(t *testing.T) {
	base, legacy := fixture()
	p := eligiblePolicy(legacy)
	for _, epoch := range []uint64{0, 4} {
		r := base
		r.Epoch = epoch
		setSubject(&r, Policy{Replicas: [2]string{"replica-a", "replica-a"}})
		raw, err := encodeRecord(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(raw, p); !errorsIs(err, ErrContext) {
			t.Fatalf("epoch %d strict: %v", epoch, err)
		}
		if _, err := DecodeMigrating(raw, p); !errorsIs(err, ErrContext) {
			t.Fatalf("epoch %d migrating: %v", epoch, err)
		}
		if _, err := Encode(r, p); !errorsIs(err, ErrContext) {
			t.Fatalf("epoch %d encode: %v", epoch, err)
		}
	}
	// A version 3 record of an earlier policy naming one replica twice.
	older := p
	older.PolicyDigest = [32]byte{7}
	r, _ := pairRecord(base, older, 0, 1)
	r.Acks[1].Replica = r.Acks[0].Replica
	raw, err := encodeRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeMigrating(raw, p); !errorsIs(err, ErrContext) {
		t.Fatalf("historical v3 duplicate: %v", err)
	}
}

func TestEligibleStoreRoundTripAndRegression(t *testing.T) {
	base, p := eligibleFixture()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, _ := pairRecord(base, p, 0, 1)
	if err := s.Save(first, p); err != nil {
		t.Fatal(err)
	}
	next := first
	next.Sequence++
	next.Round++
	next.Height++
	second, _ := pairRecord(next, p, 1, 2)
	if err := s.Save(second, p); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(p)
	if err != nil || got.Acks[0].Replica != "replica-b" || got.Acks[1].Replica != "replica-c" {
		t.Fatalf("load %+v %v", got, err)
	}
	require(t, s.Save(first, p), ErrStale)
}

func errorsIsWrapped(got, want error) bool { return errors.Is(got, want) }
