package frontier

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-go-base/types"
)

type bindingTest struct{}

func (bindingTest) VerifyCertified(r Record, material *archive.Record) error {
	if material == nil || !bytes.Equal(crypto.Keccak256(material.Header), r.Subject.BlockHash[:]) || r.StateRoot[0] != byte(r.Height-1) || r.Round != r.Height+3 {
		return ErrInvalid
	}
	return nil
}

type acceptBinding struct{}

func (acceptBinding) VerifyCertified(Record, *archive.Record) error { return nil }

type availabilityTest struct{ lost string }

func (a availabilityTest) VerifyAvailable(replica string, _ archive.Request, _ [32]byte) error {
	if replica == a.lost {
		return ErrUnavailable
	}
	return nil
}
func materialFor(height uint64) *archive.Record {
	return &archive.Record{Header: []byte{0xc1, byte(height)}, Body: []byte("body"), CanonicalRootInput: []byte("input"), OriginalUC: []byte("ouc"), OriginalTR: []byte("otr"), ResultingUC: []byte("ruc"), ResultingTR: []byte("rtr"), Companion: []byte("companion"), ParentAccounting: []byte("accounting")}
}
func setSubject(r *Record, p Policy) *archive.Record {
	m := materialFor(r.Height)
	copy(r.Subject.BlockHash[:], crypto.Keccak256(m.Header))
	r.StateRoot = [32]byte{}
	r.StateRoot[0] = byte(r.Height - 1)
	q, _ := archive.EncodeRequest(r.Subject)
	d := sha256.Sum256(q)
	md, _ := archive.ManifestDigest(r.Subject, m)
	for i := range r.Acks {
		r.Acks[i] = Acknowledgment{Replica: p.Replicas[i], RequestDigest: d, ManifestDigest: md}
	}
	return m
}
func fixture() (Record, Policy) {
	var shard types.ShardID
	if err := shard.UnmarshalText([]byte("0x0180")); err != nil {
		panic(err)
	}
	c := archive.Context{NetworkID: 1, PartitionID: 2, ShardID: shard, ShardEpoch: 3, RootEpoch: 4, ExecutionIdentity: []byte("identity-v1")}
	c.FullShardConfHash[0] = 1
	c.RegistryAddress[0] = 2
	c.RegistryCodeHash[0] = 3
	c.GenesisCommitment[0] = 4
	c.EVMGenesisHash[0] = 5
	r := Record{Sequence: 1, Round: 10, Height: 7, Subject: archive.Request{Context: c}}
	p := Policy{Context: c, Replicas: [2]string{"replica-a", "replica-b"}, Binding: bindingTest{}, Availability: availabilityTest{}}
	setSubject(&r, p)
	return r, p
}
func nextOf(base Record, p Policy) (Record, Coverage) {
	r := base
	r.Sequence++
	r.Round++
	r.Height++
	m := setSubject(&r, p)
	return r, Coverage{Anchor: r, Material: m}
}
func require(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
func TestAdvanceGates(t *testing.T) {
	base, p := fixture()
	next, covered := nextOf(base, p)
	cases := []struct {
		name   string
		mutate func(*Record, *Policy)
		want   error
	}{
		{"missing first ack", func(r *Record, _ *Policy) { r.Acks[0].RequestDigest = [32]byte{} }, ErrAcknowledgment},
		{"missing second ack", func(r *Record, _ *Policy) { r.Acks[1].ManifestDigest = [32]byte{} }, ErrAcknowledgment},
		{"mismatched manifests", func(r *Record, _ *Policy) { r.Acks[1].ManifestDigest[0] ^= 1 }, ErrAcknowledgment},
		{"wrong replica", func(r *Record, _ *Policy) { r.Acks[1].Replica = "replica-c" }, ErrContext},
		{"regression", func(r *Record, _ *Policy) { r.Round = base.Round }, ErrStale},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, p2 := next, p
			tc.mutate(&r, &p2)
			c := covered
			c.Anchor = r
			_, err := PlanAdvance(&base, r, p2, []Coverage{c}, nil)
			require(t, err, tc.want)
		})
	}
	for _, tc := range []struct {
		name string
		o    Obligation
	}{
		{"unresolved body", Obligation{Round: 11, UnresolvedBody: true}},
		{"pending authorization", Obligation{Round: 11, PendingAuthorization: true}},
		{"non-equivocation", Obligation{Round: 11, NonEquivocation: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PlanAdvance(&base, next, p, []Coverage{covered}, []Obligation{tc.o})
			require(t, err, ErrObligation)
		})
	}
	plan, err := PlanAdvance(&base, next, p, []Coverage{covered}, []Obligation{{Round: 12, UnresolvedBody: true}})
	if err != nil || plan.PruneThrough != 11 {
		t.Fatalf("plan: %+v %v", plan, err)
	}
}
func TestCodecVectorAndRefusals(t *testing.T) {
	r, p := fixture()
	wire, err := Encode(r, p)
	if err != nil {
		t.Fatal(err)
	}
	const vector = "f25807679c9911401db8cf9aae7971c9f039b95d85c8dc1f62f25aecac9e6b98"
	sum := sha256.Sum256(wire)
	if hex.EncodeToString(sum[:]) != vector {
		t.Fatalf("vector: %x", sum)
	}
	got, err := Decode(wire, p)
	if err != nil || got.Round != r.Round {
		t.Fatalf("decode: %v", err)
	}
	bad := bytes.Clone(wire)
	bad[len(bad)-1] ^= 1
	_, err = Decode(bad, p)
	require(t, err, ErrInvalid)
	bad = bytes.Clone(wire)
	bad[len(domain)]++
	checksum := sha256.Sum256(bad[:len(bad)-32])
	copy(bad[len(bad)-32:], checksum[:])
	_, err = Decode(bad, p)
	require(t, err, ErrVersion)
	bad = bytes.Clone(wire)
	bad[0] ^= 1
	checksum = sha256.Sum256(bad[:len(bad)-32])
	copy(bad[len(bad)-32:], checksum[:])
	_, err = Decode(bad, p)
	require(t, err, ErrInvalid)
	wrong := p
	wrong.Context.RootEpoch++
	_, err = Decode(wire, wrong)
	require(t, err, ErrContext)
	wrong = p
	wrong.MinimumSequence = 2
	_, err = Decode(wire, wrong)
	require(t, err, ErrStale)
	wrong = p
	wrong.Replicas[0] = "other"
	_, err = Decode(wire, wrong)
	require(t, err, ErrContext)
}
func TestStoreCrashSteps(t *testing.T) {
	first, p := fixture()
	next := first
	next.Sequence = 2
	next.Round = 11
	next.Height = 8
	for _, step := range []string{"after-create", "after-write", "after-file-sync", "after-close", "after-rename", "after-dir-sync"} {
		t.Run(step, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Save(first, p); err != nil {
				t.Fatal(err)
			}
			fault := errors.New("injected")
			s.Fault = func(at string) error {
				if at == step {
					return fault
				}
				return nil
			}
			require(t, s.Save(next, p), fault)
			reopened, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			got, err := reopened.Load(p)
			if err != nil {
				t.Fatal(err)
			}
			want := uint64(1)
			if step == "after-rename" || step == "after-dir-sync" {
				want = 2
			}
			if got.Sequence != want {
				t.Fatalf("sequence %d, want %d", got.Sequence, want)
			}
		})
	}
}
func TestStoreRejectsCorruptStaleCopiedAndRegression(t *testing.T) {
	r, p := fixture()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Save(r, p); err != nil {
		t.Fatal(err)
	}
	require(t, s.Save(r, p), ErrStale)
	p2 := p
	p2.MinimumSequence = 2
	_, err = s.Load(p2)
	require(t, err, ErrStale)
	p2 = p
	p2.Context.ExecutionIdentity = []byte("copied-identity")
	_, err = s.Load(p2)
	require(t, err, ErrContext)
	path := filepath.Join(s.dir, "frontier")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	_, err = s.Load(p)
	require(t, err, ErrInvalid)
}

func TestAdvanceIsolatedMonotonicAndCoverage(t *testing.T) {
	base, p := fixture()
	first, c1 := nextOf(base, p)
	last, c2 := nextOf(first, p)
	p.Binding = acceptBinding{}
	for _, tc := range []struct {
		name   string
		mutate func(*Record)
	}{
		{"sequence", func(r *Record) { r.Sequence = base.Sequence }},
		{"round", func(r *Record) { r.Round = base.Round }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := first
			tc.mutate(&r)
			c := c1
			c.Anchor = r
			_, err := PlanAdvance(&base, r, p, []Coverage{c}, nil)
			require(t, err, ErrStale)
		})
	}
	t.Run("height", func(t *testing.T) {
		r := base
		r.Sequence++
		r.Round++
		_, err := PlanAdvance(&base, r, p, nil, nil)
		require(t, err, ErrStale)
	})
	t.Run("missing-intermediate", func(t *testing.T) {
		_, err := PlanAdvance(&base, last, p, []Coverage{c2}, nil)
		require(t, err, ErrAcknowledgment)
	})
	t.Run("missing-all", func(t *testing.T) {
		_, err := PlanAdvance(&base, first, p, nil, nil)
		require(t, err, ErrAcknowledgment)
	})
	t.Run("covered-sequence", func(t *testing.T) {
		r := last
		r.Sequence = first.Sequence
		c := c2
		c.Anchor = r
		_, err := PlanAdvance(&base, r, p, []Coverage{c1, c}, nil)
		require(t, err, ErrAcknowledgment)
	})
	t.Run("covered-round", func(t *testing.T) {
		r := last
		r.Round = first.Round
		c := c2
		c.Anchor = r
		_, err := PlanAdvance(&base, r, p, []Coverage{c1, c}, nil)
		require(t, err, ErrAcknowledgment)
	})
	_, err := PlanAdvance(&base, last, p, []Coverage{c1, c2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("manifest-binding", func(t *testing.T) {
		wrong := c1
		wrong.Anchor.Acks[0].ManifestDigest[0] ^= 1
		wrong.Anchor.Acks[1].ManifestDigest = wrong.Anchor.Acks[0].ManifestDigest
		_, err := PlanAdvance(&base, last, p, []Coverage{wrong, c2}, nil)
		require(t, err, ErrAcknowledgment)
	})
	t.Run("certified-binding", func(t *testing.T) {
		q := p
		q.Binding = bindingTest{}
		wrong := c1
		wrong.Anchor.StateRoot[0] ^= 1
		_, err := PlanAdvance(&base, last, q, []Coverage{wrong, c2}, nil)
		require(t, err, ErrInvalid)
	})
	t.Run("replica-readback", func(t *testing.T) {
		q := p
		q.Availability = availabilityTest{lost: "replica-b"}
		_, err := PlanAdvance(&base, last, q, []Coverage{c1, c2}, nil)
		require(t, err, ErrAcknowledgment)
	})
}

func TestConfiguredReplicasAndNames(t *testing.T) {
	r, p := fixture()
	for _, n := range []int{0, 65} {
		name := "zero"
		if n == 65 {
			name = "65"
		}
		t.Run(name, func(t *testing.T) {
			q := p
			q.Replicas[0] = string(bytes.Repeat([]byte{'a'}, n))
			r2 := r
			r2.Acks[0].Replica = q.Replicas[0]
			_, err := Encode(r2, q)
			require(t, err, ErrContext)
		})
	}
	t.Run("duplicate", func(t *testing.T) {
		q := p
		q.Replicas[1] = q.Replicas[0]
		r.Acks[1].Replica = q.Replicas[1]
		_, err := Encode(r, q)
		require(t, err, ErrContext)
	})
}

func TestStoreIsolatedRegressionsAndUnloadable(t *testing.T) {
	base, p := fixture()
	next, _ := nextOf(base, p)
	for _, tc := range []struct {
		name   string
		mutate func(*Record)
	}{
		{"sequence", func(r *Record) { r.Sequence = base.Sequence }},
		{"round", func(r *Record) { r.Round = base.Round }},
		{"height", func(r *Record) { r.Height = base.Height }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := Open(t.TempDir())
			if e := s.Save(base, p); e != nil {
				t.Fatal(e)
			}
			r := next
			tc.mutate(&r)
			require(t, s.Save(r, p), ErrStale)
			got, e := s.Load(p)
			if e != nil || got.Sequence != base.Sequence {
				t.Fatalf("good frontier replaced: %v", e)
			}
		})
	}
	t.Run("unloadable", func(t *testing.T) {
		s, _ := Open(t.TempDir())
		if e := s.Save(base, p); e != nil {
			t.Fatal(e)
		}
		wire, e := Encode(next, p)
		if e != nil {
			t.Fatal(e)
		}
		wire[len(wire)-1] ^= 1
		require(t, s.saveEncoded(next, p, wire), ErrInvalid)
		good, e := s.Load(p)
		if e != nil || good.Sequence != base.Sequence {
			t.Fatalf("unloadable replacement: %v", e)
		}
	})
	s, _ := Open(t.TempDir())
	if e := s.Save(base, p); e != nil {
		t.Fatal(e)
	}
	var e error
	q := p
	q.Replicas[0] = string(bytes.Repeat([]byte{'x'}, 65))
	r := next
	r.Acks[0].Replica = q.Replicas[0]
	require(t, s.Save(r, q), ErrContext)
	got, e := s.Load(p)
	if e != nil || got.Sequence != base.Sequence {
		t.Fatalf("good frontier replaced: %v", e)
	}
}

func TestCodecTrailingAndNoncanonical(t *testing.T) {
	r, p := fixture()
	wire, e := Encode(r, p)
	if e != nil {
		t.Fatal(e)
	}
	fixSum := func(b []byte) { sum := sha256.Sum256(b[:len(b)-32]); copy(b[len(b)-32:], sum[:]) }
	t.Run("trailing", func(t *testing.T) {
		trailing := append(bytes.Clone(wire[:len(wire)-32]), 0x99)
		trailing = append(trailing, make([]byte, 32)...)
		fixSum(trailing)
		_, e := Decode(trailing, p)
		require(t, e, ErrInvalid)
	})
	t.Run("noncanonical", func(t *testing.T) {
		q, _ := archive.EncodeRequest(r.Subject)
		nameAt := len(domain) + 1 + 24 + 32 + 4 + len(q)
		bad := bytes.Clone(wire)
		nameEnd := nameAt + 1 + int(bad[nameAt])
		bad[nameAt]++
		bad = append(bad[:nameEnd], append([]byte{0}, bad[nameEnd:]...)...)
		fixSum(bad)
		_, e := Decode(bad, p)
		require(t, e, ErrInvalid)
	})
}

func TestRecoveryOrderingAndReplicaLoss(t *testing.T) {
	base, p := fixture()
	next, covered := nextOf(base, p)
	_, e := PlanAdvance(&base, next, p, []Coverage{covered}, nil)
	if e != nil {
		t.Fatal(e)
	} // both acks first
	s, _ := Open(t.TempDir())
	if e = s.Save(base, p); e != nil {
		t.Fatal(e)
	}
	// Crash after acknowledgements but before frontier write: old boundary remains.
	got, e := s.Load(p)
	if e != nil || got.Round != base.Round {
		t.Fatalf("frontier moved before write: %v", e)
	}
	if e = s.Save(next, p); e != nil {
		t.Fatal(e)
	}
	// Crash after frontier write but before prune: restart may prune idempotently.
	got, e = s.Load(p)
	if e != nil || got.Round != next.Round {
		t.Fatalf("frontier write absent: %v", e)
	}
	if e = CheckRecovery(got, base.Round, p, covered); e != nil {
		t.Fatal(e)
	}
	require(t, CheckRecovery(base, next.Round, p, Coverage{Anchor: base, Material: materialFor(base.Height)}), ErrStale)
	p.Availability = availabilityTest{lost: "replica-b"}
	require(t, CheckRecovery(got, next.Round, p, covered), ErrUnavailable)
}

func TestLoadRejectsOversizedFile(t *testing.T) {
	_, p := fixture()
	s, _ := Open(t.TempDir())
	if err := os.WriteFile(filepath.Join(s.dir, "frontier"), bytes.Repeat([]byte{1}, MaxBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Load(p)
	require(t, err, ErrInvalid)
}
