package frontier

import (
	"reflect"
	"strings"
	"testing"
)

func policyWith(p Policy, a, b string) Policy {
	p.Replicas = [2]string{a, b}
	return p
}

func TestDecodeMigratingDropsRetiredReplicaAcknowledgments(t *testing.T) {
	r, p := fixture()
	raw, err := Encode(r, p)
	if err != nil {
		t.Fatal(err)
	}
	replaced := policyWith(p, "replica-a", "replica-c")
	_, err = Decode(raw, replaced)
	require(t, err, ErrContext) // the strict decoder is unchanged
	got, err := DecodeMigrating(raw, replaced)
	if err != nil {
		t.Fatal(err)
	}
	if got.Acks[0].Replica != "replica-a" || !got.Acks[1].Dropped() || got.Retired[1] != "replica-b" || !got.Migrated() {
		t.Fatalf("slot 1 must be dropped and slot 0 kept: %+v", got)
	}
	if got.Acks[1].ManifestDigest != r.Acks[1].ManifestDigest || got.Acks[1].RequestDigest != r.Acks[1].RequestDigest {
		t.Fatal("a dropped acknowledgment keeps its digests")
	}
	if got.PersistedReplicas() != [2]string{"replica-a", "replica-b"} {
		t.Fatalf("persisted replicas %v", got.PersistedReplicas())
	}
	if got.Sequence != r.Sequence || got.Round != r.Round || got.Height != r.Height || got.Subject.BlockHash != r.Subject.BlockHash {
		t.Fatal("the durable position must be kept")
	}
	// The retained replica may also change slot when the operator lists it second.
	moved, err := DecodeMigrating(raw, policyWith(p, "replica-c", "replica-b"))
	if err != nil {
		t.Fatal(err)
	}
	if !moved.Acks[0].Dropped() || moved.Acks[1].Replica != "replica-b" || moved.Retired[0] != "replica-a" {
		t.Fatalf("slot 0 must be dropped and slot 1 kept: %+v", moved)
	}
	swapped, err := DecodeMigrating(raw, policyWith(p, "replica-c", "replica-a"))
	if err != nil {
		t.Fatal(err)
	}
	if swapped.Acks[1].Replica != "replica-a" || !swapped.Acks[0].Dropped() || swapped.Retired[0] != "replica-b" {
		t.Fatalf("the retained replica follows the policy's slot: %+v", swapped)
	}
}

func TestDecodeMigratingLeavesAnUnchangedPairExactlyAsDecode(t *testing.T) {
	r, p := fixture()
	raw, err := Encode(r, p)
	if err != nil {
		t.Fatal(err)
	}
	strict, err := Decode(raw, p)
	if err != nil {
		t.Fatal(err)
	}
	migrating, err := DecodeMigrating(raw, p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(migrating, strict) || migrating.Migrated() {
		t.Fatalf("an unchanged pair must decode identically: %+v %+v", migrating, strict)
	}
	// The same two replicas in another order stay refused, exactly as before.
	_, err = Decode(raw, policyWith(p, "replica-b", "replica-a"))
	require(t, err, ErrContext)
	_, err = DecodeMigrating(raw, policyWith(p, "replica-b", "replica-a"))
	require(t, err, ErrContext)
}

func TestDecodeMigratingRefusesMalformedPairChanges(t *testing.T) {
	r, p := fixture()
	raw, err := Encode(r, p)
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]Policy{
		"one replica only":          policyWith(p, "replica-a", ""),
		"duplicate replica":         policyWith(p, "replica-a", "replica-a"),
		"duplicate new replica":     policyWith(p, "replica-c", "replica-c"),
		"over-long replica name":    policyWith(p, "replica-a", strings.Repeat("x", 65)),
		"no replica at all":         policyWith(p, "", ""),
		"empty retained position 0": policyWith(p, "", "replica-b"),
	} {
		_, err := DecodeMigrating(raw, bad)
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		require(t, err, ErrContext)
	}
	// A record naming one replica twice is never a replacement candidate.
	dup := r
	dup.Acks[0].Replica, dup.Acks[1].Replica = "replica-x", "replica-x"
	raw, err = encodeRecord(dup)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeMigrating(raw, policyWith(p, "replica-a", "replica-c"))
	require(t, err, ErrContext)
}

func TestMigratedRecordCannotBeEncodedOrAcknowledgedByARetiredReplica(t *testing.T) {
	r, p := fixture()
	raw, err := Encode(r, p)
	if err != nil {
		t.Fatal(err)
	}
	np := policyWith(p, "replica-a", "replica-c")
	migrated, err := DecodeMigrating(raw, np)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Encode(migrated, np)
	require(t, err, ErrContext)
	// An acknowledgment from the retired replica is refused under the new policy.
	retired := r
	retired.Sequence, retired.Height, retired.Round = 2, 8, 11
	material := setSubject(&retired, p) // acknowledged by replica-a and the retired replica-b
	_, err = Encode(retired, np)
	require(t, err, ErrContext)
	_, err = PlanAdvance(&migrated, retired, np, []Coverage{{Anchor: retired, Material: material}}, nil)
	require(t, err, ErrContext)
}

func TestPlanAdvanceFromMigratedPositionNeedsTheNewPairToAcknowledge(t *testing.T) {
	r, p := fixture()
	raw, err := Encode(r, p)
	if err != nil {
		t.Fatal(err)
	}
	np := policyWith(p, "replica-a", "replica-c")
	migrated, err := DecodeMigrating(raw, np)
	if err != nil {
		t.Fatal(err)
	}
	next, item := nextOf(r, np) // acknowledged by the configured pair
	if _, err := PlanAdvance(&migrated, next, np, []Coverage{item}, nil); err != nil {
		t.Fatal(err)
	}
	np.Availability = availabilityTest{lost: "replica-c"}
	_, err = PlanAdvance(&migrated, next, np, []Coverage{item}, nil)
	require(t, err, ErrAcknowledgment)
}
