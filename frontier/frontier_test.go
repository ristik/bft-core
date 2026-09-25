package frontier

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-go-base/types"
)

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
	r.StateRoot[0] = 6
	r.Subject.BlockHash[0] = 7
	p := Policy{Context: c, Replicas: [2]string{"replica-a", "replica-b"}}
	q, _ := archive.EncodeRequest(r.Subject)
	d := sha256.Sum256(q)
	for i := range r.Acks {
		r.Acks[i] = Acknowledgment{Replica: p.Replicas[i], RequestDigest: d, ManifestDigest: sha256.Sum256([]byte("manifest"))}
	}
	return r, p
}
func require(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
func TestAdvanceGates(t *testing.T) {
	base, p := fixture()
	next := base
	next.Sequence = 2
	next.Round = 11
	next.Height = 8
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
			_, err := PlanAdvance(&base, r, p2, nil)
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
			_, err := PlanAdvance(&base, next, p, []Obligation{tc.o})
			require(t, err, ErrObligation)
		})
	}
	plan, err := PlanAdvance(&base, next, p, []Obligation{{Round: 12, UnresolvedBody: true}})
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
	const vector = "b0e6a8f028abc4abebf66995579481ec616248cc1811f118c56806ddda370459"
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
