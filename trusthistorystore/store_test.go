package trusthistorystore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/keyvaluedb/boltdb"
	"github.com/unicitynetwork/bft-core/m2contract"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

type proofVerifier struct{}

func (proofVerifier) VerifyActivation(_ context.Context, b evmroot.TrustBaseBodyV2, a evmroot.ActivatedTrustBase, p []byte) error {
	id := b.Identity()
	if !bytes.Equal(a.BodyIdentity, id[:]) || !bytes.Equal(p, []byte("finalized-proof")) {
		return errors.New("bad proof")
	}
	return nil
}
func anchor(t *testing.T) *types.RootTrustBaseV1 {
	t.Helper()
	s, err := abcrypto.NewInMemorySecp256K1Signer()
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Verifier()
	if err != nil {
		t.Fatal(err)
	}
	key, err := v.MarshalPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	tb, err := types.NewTrustBase(3, []*types.NodeInfo{{NodeID: "node-0", SigKey: key, Stake: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tb.Sign("node-0", s); err != nil {
		t.Fatal(err)
	}
	return tb
}
func body(t *testing.T, s *Store) m2contract.TrustInterval {
	t.Helper()
	p, err := evmroot.FirstV2PredecessorHash(s.history.Anchor)
	if err != nil {
		t.Fatal(err)
	}
	m := evmroot.WeightSet{{StakingID: "stake-0", NodeID: "node-0", ConsensusKey: bytes.Repeat([]byte{2}, 33), Weight: 1}}
	b := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: s.history.Anchor.NetworkID, Epoch: s.history.Anchor.Epoch + 1, EarliestActivation: 10, Members: m, RootThreshold: 1, StateSummary: bytes.Repeat([]byte{3}, 32), ChangeRecordHash: bytes.Repeat([]byte{4}, 32), PredecessorHash: p}
	id := b.Identity()
	return m2contract.TrustInterval{Body: b, Activation: evmroot.ActivatedTrustBase{BodyIdentity: id[:], EpochStart: 12, ActivationCommitID: bytes.Repeat([]byte{5}, 32)}, End: 0}
}
func openDB(t *testing.T, path string) *boltdb.BoltDB {
	t.Helper()
	db, err := boltdb.New(path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}
func TestStoreRestartEvictionAndRefusal(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "trust.db")
	tb := anchor(t)
	id := sha256.Sum256([]byte("execution-v2"))
	db := openDB(t, path)
	s, err := Open(ctx, db, tb, id, proofVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.ByRound(tb.GetEpochStart())
	if err != nil || first.V1 == nil {
		t.Fatalf("open anchor: %+v %v", first, err)
	}
	if _, err := s.ByEpoch(tb.GetEpoch() + 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown epoch: %v", err)
	}
	in := body(t, s)
	if err := s.AppendVerified(ctx, in, []byte("finalized-proof")); err != nil {
		t.Fatal(err)
	}
	second := in
	firstID := in.Body.Identity()
	second.Body.Epoch++
	second.Body.EarliestActivation = 20
	second.Body.PredecessorHash = bytes.Clone(firstID[:])
	secondID := second.Body.Identity()
	second.Activation.BodyIdentity = bytes.Clone(secondID[:])
	second.Activation.EpochStart = 22
	second.Activation.ActivationCommitID = bytes.Repeat([]byte{6}, 32)
	if err := s.AppendVerified(ctx, second, []byte("finalized-proof")); err != nil {
		t.Fatal(err)
	}
	cached, err := s.ByEpoch(in.Body.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	cached.V2.Members[0].ConsensusKey[0] ^= 0xff
	stable, err := s.ByEpoch(in.Body.Epoch)
	if err != nil || stable.BodyID != in.Body.Identity() {
		t.Fatalf("caller corrupted cache: %+v %v", stable, err)
	}
	s.Evict()
	after, err := s.ByRound(12)
	if err != nil || after.V2 == nil || after.Epoch != in.Body.Epoch {
		t.Fatalf("evicted lookup: %+v %v", after, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = openDB(t, path)
	s, err = Open(ctx, db, tb, id, proofVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	after, err = s.ByEpoch(second.Body.Epoch)
	if err != nil || after.V2 == nil {
		t.Fatalf("restart lookup: %+v %v", after, err)
	}
	if got, err := s.ByRound(11); err != nil || got.V1 == nil {
		t.Fatalf("before A*: %+v %v", got, err)
	}
	if got, err := s.ByRound(12); err != nil || got.V2 == nil || got.Epoch != in.Body.Epoch {
		t.Fatalf("at first A*: %+v %v", got, err)
	}
	if got, err := s.ByRound(22); err != nil || got.V2 == nil || got.Epoch != second.Body.Epoch {
		t.Fatalf("at second A*: %+v %v", got, err)
	}
	if _, err := Open(ctx, db, tb, sha256.Sum256([]byte("different")), proofVerifier{}); !errors.Is(err, ErrIdentity) {
		t.Fatalf("identity mismatch: %v", err)
	}
	if _, err := Open(ctx, db, tb, id, nil); !errors.Is(err, ErrProof) {
		t.Fatalf("missing verifier: %v", err)
	}
	other := anchor(t)
	if _, err := Open(ctx, db, other, id, proofVerifier{}); !errors.Is(err, ErrAnchor) {
		t.Fatalf("anchor mismatch: %v", err)
	}
	if err := s.AppendVerified(ctx, in, []byte("finalized-proof")); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate epoch: %v", err)
	}
	bad := second
	priorID := second.Body.Identity()
	bad.Body.Epoch++
	bad.Body.PredecessorHash = priorID[:]
	bad.Body.EarliestActivation = 19
	bad.Activation.EpochStart = 20
	badID := bad.Body.Identity()
	bad.Activation.BodyIdentity = badID[:]
	if err := s.AppendVerified(ctx, bad, []byte("bad")); !errors.Is(err, ErrProof) {
		t.Fatalf("bad proof: %v", err)
	}
}
func TestIncompatibleStoreRefused(t *testing.T) {
	ctx := context.Background()
	tb := anchor(t)
	id := sha256.Sum256([]byte("execution-v2"))
	db := openDB(t, filepath.Join(t.TempDir(), "old.db"))
	defer db.Close()
	if err := db.Write([]byte("legacy"), uint64(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, db, tb, id, proofVerifier{}); !errors.Is(err, ErrIncompatible) {
		t.Fatalf("legacy db: %v", err)
	}
}

func persistedFixture(t *testing.T) (string, *types.RootTrustBaseV1, [32]byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trust.db")
	tb := anchor(t)
	id := sha256.Sum256([]byte("execution-v2"))
	db := openDB(t, path)
	s, err := Open(context.Background(), db, tb, id, proofVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AppendVerified(context.Background(), body(t, s), []byte("finalized-proof")); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path, tb, id
}
func mutateStoredEntry(t *testing.T, path string, change func(*entryDisk)) {
	t.Helper()
	db := openDB(t, path)
	defer db.Close()
	var raw []byte
	ok, err := db.Read(uint64Key(2), &raw)
	if err != nil || !ok {
		t.Fatalf("read entry: %v %v", ok, err)
	}
	var e entryDisk
	if err := types.Cbor.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	change(&e)
	raw, err = types.Cbor.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Write(uint64Key(2), raw); err != nil {
		t.Fatal(err)
	}
}
func TestPersistedEntryRefusals(t *testing.T) {
	cases := []struct {
		name   string
		want   error
		detail error
		change func(*entryDisk)
	}{
		{"damaged encoding", ErrEncoding, nil, func(e *entryDisk) { e.Canonical[0] ^= 1 }},
		{"missing proof", ErrProof, nil, func(e *entryDisk) { e.Proof = nil }},
		{"nonunit member", ErrHistory, m2contract.ErrNonUnitWeight, func(e *entryDisk) {
			e.Body.Members[0].Weight = 2
			e.Body.RootThreshold = 2
			id := e.Body.Identity()
			e.Activation.BodyIdentity = bytes.Clone(id[:])
			in := m2contract.TrustInterval{Body: e.Body, Activation: e.Activation, End: e.End}
			var err error
			e.Canonical, err = in.Encode()
			if err != nil {
				panic(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, tb, id := persistedFixture(t)
			mutateStoredEntry(t, path, tc.change)
			db := openDB(t, path)
			defer db.Close()
			_, err := Open(context.Background(), db, tb, id, proofVerifier{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if tc.detail != nil && !errors.Is(err, tc.detail) {
				t.Fatalf("want detail %v, got %v", tc.detail, err)
			}
		})
	}
}

func TestSchemaAndAnchorEncodingRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		want   error
		mutate func(*testing.T, *boltdb.BoltDB)
	}{
		{"schema version", ErrIncompatible, func(t *testing.T, db *boltdb.BoltDB) {
			raw, err := types.Cbor.Marshal(uint64(2))
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Write(schemaKey, raw); err != nil {
				t.Fatal(err)
			}
		}},
		{"extra key", ErrIncompatible, func(t *testing.T, db *boltdb.BoltDB) {
			raw, err := types.Cbor.Marshal(uint64(1))
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Write([]byte("foreign"), raw); err != nil {
				t.Fatal(err)
			}
		}},
		{"anchor encoding", ErrEncoding, func(t *testing.T, db *boltdb.BoltDB) {
			var raw []byte
			ok, err := db.Read(anchorKey, &raw)
			if err != nil || !ok {
				t.Fatal(err)
			}
			var a anchorDisk
			if err := types.Cbor.Unmarshal(raw, &a); err != nil {
				t.Fatal(err)
			}
			a.Canonical[0] ^= 1
			raw, err = types.Cbor.Marshal(a)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Write(anchorKey, raw); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, tb, id := persistedFixture(t)
			db := openDB(t, path)
			tc.mutate(t, db)
			_, err := Open(context.Background(), db, tb, id, proofVerifier{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestAppendRefusesGappedEpoch(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "trust.db")
	tb := anchor(t)
	id := sha256.Sum256([]byte("execution-v2"))
	db := openDB(t, path)
	defer db.Close()
	s, err := Open(ctx, db, tb, id, proofVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	in := body(t, s)
	in.Body.Epoch++
	newID := in.Body.Identity()
	in.Activation.BodyIdentity = bytes.Clone(newID[:])
	err = s.AppendVerified(ctx, in, []byte("finalized-proof"))
	if !errors.Is(err, ErrHistory) || !errors.Is(err, m2contract.ErrEpochGap) {
		t.Fatalf("gapped append: %v", err)
	}
}
