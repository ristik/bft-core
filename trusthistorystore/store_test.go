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

type countingVerifier struct{ calls int }

func (v *countingVerifier) VerifyActivation(ctx context.Context, prior Record, in m2contract.TrustInterval, proof []byte) error {
	v.calls++
	return (proofVerifier{}).VerifyActivation(ctx, prior, in, proof)
}

func (proofVerifier) VerifyActivation(_ context.Context, prior Record, in m2contract.TrustInterval, p []byte) error {
	id := in.Body.Identity()
	if !bytes.Equal(in.Activation.BodyIdentity, id[:]) || !bytes.Equal(p, []byte("finalized-proof")) || prior.End != in.Activation.EpochStart || prior.Epoch+1 != in.Body.Epoch || (prior.V1 == nil && prior.V2 == nil) {
		return errors.New("bad proof")
	}
	if prior.V1 != nil && prior.V1.Epoch != prior.Epoch {
		return errors.New("wrong v1 trust base")
	}
	if prior.V2 != nil && prior.V2.Identity() != prior.BodyID {
		return errors.New("wrong v2 trust base")
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
	first, err := s.ByEpoch(tb.GetEpoch())
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
	after, err := s.ByEpoch(in.Body.Epoch)
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
	if got, err := s.ByEpoch(tb.GetEpoch()); err != nil || got.V1 == nil || got.End != in.Activation.EpochStart {
		t.Fatalf("old epoch after A*: %+v %v", got, err)
	}
	if got, err := s.ByEpoch(in.Body.Epoch); err != nil || got.V2 == nil || got.Start != in.Activation.EpochStart || got.End != second.Activation.EpochStart {
		t.Fatalf("first v2 epoch: %+v %v", got, err)
	}
	if got, err := s.ByEpoch(second.Body.Epoch); err != nil || got.V2 == nil || got.Start != second.Activation.EpochStart {
		t.Fatalf("second v2 epoch: %+v %v", got, err)
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
	bad.Body.EarliestActivation = 30
	bad.Activation.EpochStart = 32
	badID := bad.Body.Identity()
	bad.Activation.BodyIdentity = badID[:]
	if err := s.AppendVerified(ctx, bad, []byte("bad")); !errors.Is(err, ErrProof) {
		t.Fatalf("bad proof: %v", err)
	}
}

func TestSuffixUCSelectsSignerByEpoch(t *testing.T) {
	db := openDB(t, filepath.Join(t.TempDir(), "trust.db"))
	defer db.Close()
	tb := anchor(t)
	s, err := Open(context.Background(), db, tb, sha256.Sum256([]byte("execution-v2")), proofVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	in := body(t, s)
	if err := s.AppendVerified(context.Background(), in, []byte("finalized-proof")); err != nil {
		t.Fatal(err)
	}
	ucRootEpoch, ucRound := tb.GetEpoch(), in.Activation.EpochStart+1
	activeEpoch, err := s.history.At(ucRound)
	if err != nil || activeEpoch != in.Body.Epoch {
		t.Fatalf("active epoch at suffix round: %d, %v", activeEpoch, err)
	}
	signer, err := s.ByEpoch(ucRootEpoch)
	if err != nil || signer.V1 == nil || signer.Epoch != ucRootEpoch || signer.End != in.Activation.EpochStart {
		t.Fatalf("suffix UC signer: %+v %v", signer, err)
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

func TestAppendClearsCachedAnchorInterval(t *testing.T) {
	db := openDB(t, filepath.Join(t.TempDir(), "trust.db"))
	defer db.Close()
	tb := anchor(t)
	s, err := Open(context.Background(), db, tb, sha256.Sum256([]byte("execution-v2")), proofVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.ByEpoch(tb.GetEpoch())
	if err != nil || before.End != 0 {
		t.Fatalf("cached anchor before append: %+v %v", before, err)
	}
	in := body(t, s)
	if err := s.AppendVerified(context.Background(), in, []byte("finalized-proof")); err != nil {
		t.Fatal(err)
	}
	after, err := s.ByEpoch(tb.GetEpoch())
	if err != nil || after.End != in.Activation.EpochStart {
		t.Fatalf("cached anchor after append: %+v %v", after, err)
	}
}

func TestByEpochOwnsV1Anchor(t *testing.T) {
	db := openDB(t, filepath.Join(t.TempDir(), "trust.db"))
	defer db.Close()
	tb := anchor(t)
	s, err := Open(context.Background(), db, tb, sha256.Sum256([]byte("execution-v2")), proofVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.ByEpoch(tb.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	first.V1.RootNodes[0].SigKey[0] ^= 0xff
	for id, sig := range first.V1.Signatures {
		sig[0] ^= 0xff
		first.V1.Signatures[id] = sig
	}
	second, err := s.ByEpoch(tb.Epoch)
	if err != nil || !bytes.Equal(second.V1.RootNodes[0].SigKey, tb.RootNodes[0].SigKey) {
		t.Fatalf("mutable v1 key: %v", err)
	}
	for id, sig := range second.V1.Signatures {
		if !bytes.Equal(sig, tb.Signatures[id]) {
			t.Fatal("mutable v1 signature")
		}
	}
}

func TestOpenRefusesZeroExecutionIdentity(t *testing.T) {
	db := openDB(t, filepath.Join(t.TempDir(), "trust.db"))
	defer db.Close()
	_, err := Open(context.Background(), db, anchor(t), [32]byte{}, proofVerifier{})
	if !errors.Is(err, ErrIdentity) {
		t.Fatalf("zero execution identity: %v", err)
	}
}

func TestLoadPinsAnchorStart(t *testing.T) {
	path, tb, id := persistedFixture(t)
	db := openDB(t, path)
	var raw []byte
	if ok, err := db.Read(anchorKey, &raw); err != nil || !ok {
		t.Fatalf("anchor: %v %v", ok, err)
	}
	var a anchorDisk
	if err := types.Cbor.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	a.Start++
	var err error
	a.Canonical, err = (m2contract.V1AnchorRecord{Anchor: a.Anchor, Start: a.Start, End: a.End}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	raw, err = types.Cbor.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Write(anchorKey, raw); err != nil {
		t.Fatal(err)
	}
	_, err = Open(context.Background(), db, tb, id, proofVerifier{})
	if !errors.Is(err, ErrAnchor) {
		t.Fatalf("changed anchor start: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRejectsKeyBodyEpochMismatchBeforeHistory(t *testing.T) {
	path, tb, id := persistedFixture(t)
	mutateStoredEntry(t, path, func(e *entryDisk) {
		e.Body.Epoch++
		bodyID := e.Body.Identity()
		e.Activation.BodyIdentity = bytes.Clone(bodyID[:])
		var err error
		e.Canonical, err = (m2contract.TrustInterval{Body: e.Body, Activation: e.Activation, End: e.End}).Encode()
		if err != nil {
			panic(err)
		}
	})
	db := openDB(t, path)
	defer db.Close()
	_, err := Open(context.Background(), db, tb, id, proofVerifier{})
	if !errors.Is(err, ErrHistory) || errors.Is(err, m2contract.ErrEpochGap) {
		t.Fatalf("key/body epoch mismatch: %v", err)
	}
}

func TestAppendRequiresOpenNewInterval(t *testing.T) {
	db := openDB(t, filepath.Join(t.TempDir(), "trust.db"))
	defer db.Close()
	s, err := Open(context.Background(), db, anchor(t), sha256.Sum256([]byte("execution-v2")), proofVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	in := body(t, s)
	in.End = in.Activation.EpochStart + 1
	if err := s.AppendVerified(context.Background(), in, []byte("finalized-proof")); !errors.Is(err, ErrHistory) {
		t.Fatalf("closed new interval: %v", err)
	}
}

func TestLoadRequiresOpenFinalRecord(t *testing.T) {
	t.Run("v2 tail", func(t *testing.T) {
		path, tb, id := persistedFixture(t)
		mutateStoredEntry(t, path, func(e *entryDisk) {
			e.End = e.Activation.EpochStart + 1
			var err error
			e.Canonical, err = (m2contract.TrustInterval{Body: e.Body, Activation: e.Activation, End: e.End}).Encode()
			if err != nil {
				panic(err)
			}
		})
		db := openDB(t, path)
		defer db.Close()
		_, err := Open(context.Background(), db, tb, id, proofVerifier{})
		if !errors.Is(err, ErrHistory) {
			t.Fatalf("closed v2 tail: %v", err)
		}
	})
	t.Run("anchor tail", func(t *testing.T) {
		db := openDB(t, filepath.Join(t.TempDir(), "trust.db"))
		defer db.Close()
		tb := anchor(t)
		id := sha256.Sum256([]byte("execution-v2"))
		if _, err := Open(context.Background(), db, tb, id, proofVerifier{}); err != nil {
			t.Fatal(err)
		}
		var raw []byte
		if ok, err := db.Read(anchorKey, &raw); err != nil || !ok {
			t.Fatalf("anchor: %v %v", ok, err)
		}
		var a anchorDisk
		if err := types.Cbor.Unmarshal(raw, &a); err != nil {
			t.Fatal(err)
		}
		a.End = a.Start + 1
		var err error
		a.Canonical, err = (m2contract.V1AnchorRecord{Anchor: a.Anchor, Start: a.Start, End: a.End}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		raw, err = types.Cbor.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Write(anchorKey, raw); err != nil {
			t.Fatal(err)
		}
		_, err = Open(context.Background(), db, tb, id, proofVerifier{})
		if !errors.Is(err, ErrHistory) {
			t.Fatalf("closed anchor tail: %v", err)
		}
	})
}

func TestLoadValidatesHistoryBeforeVerifier(t *testing.T) {
	path, tb, id := persistedFixture(t)
	mutateStoredEntry(t, path, func(e *entryDisk) {
		e.Body.Members[0].Weight = 2
		e.Body.RootThreshold = 2
		bodyID := e.Body.Identity()
		e.Activation.BodyIdentity = bytes.Clone(bodyID[:])
		var err error
		e.Canonical, err = (m2contract.TrustInterval{Body: e.Body, Activation: e.Activation, End: e.End}).Encode()
		if err != nil {
			panic(err)
		}
	})
	db := openDB(t, path)
	defer db.Close()
	v := &countingVerifier{}
	_, err := Open(context.Background(), db, tb, id, v)
	if !errors.Is(err, ErrHistory) || v.calls != 0 {
		t.Fatalf("invalid history reached verifier: %v, calls %d", err, v.calls)
	}
}
