package configuredprogress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/rootinput"
	bolt "go.etcd.io/bbolt"
)

var (
	bucketName    = []byte("configured-progress/v2")
	descriptorKey = []byte("descriptor")
	controlKey    = []byte("control")
	legacyBucket  = []byte("certified-record/v1")
)

// MaxRetain is the implementation ceiling for ordinary records.
const MaxRetain = 1 << 16

type Settings struct{ Retain int }

func (s Settings) check() error {
	if s.Retain < 1 || s.Retain > MaxRetain {
		return fmt.Errorf("%w: Retain %d, want 1..%d", ErrSettings, s.Retain, MaxRetain)
	}
	return nil
}

// Context is independently checked local configuration used to distrust every stored byte.
type Context struct {
	Origin      registrygenesis.GenesisOrigin
	Observation rootinput.ObservationContextV2
	Record      certifiedstore.Context
}

func (c Context) check() error {
	if !c.Origin.Valid() {
		return ErrContext
	}
	r := c.Origin.Record()
	pc := c.Origin.ProofContext()
	if uint64(c.Observation.NetworkID) != r.NetworkID || uint64(c.Observation.PartitionID) != r.PartitionID || !bytes.Equal(c.Observation.ShardID.Bytes(), r.ShardID) || !bytes.Equal(c.Observation.ShardConfHash, c.Origin.FullShardConfHash().Bytes()) || c.Observation.RootEpoch != r.RootEpoch || c.Observation.TrustBases == nil {
		return ErrContext
	}
	if uint64(c.Record.NetworkID) != r.NetworkID || uint64(c.Record.PartitionID) != r.PartitionID || !bytes.Equal(c.Record.ShardID.Bytes(), r.ShardID) || !bytes.Equal(c.Record.FullShardConfHash, c.Origin.FullShardConfHash().Bytes()) || c.Record.Registry != pc || c.Record.TrustBases == nil {
		return ErrContext
	}
	return nil
}

type Store struct {
	db         *bolt.DB
	settings   Settings
	checkpoint func(string) error
}

// OpenConfiguredV2 opens an isolated v2 database without creating its bucket or initializing data.
func OpenConfiguredV2(path string, s Settings) (*Store, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: symbolic link", ErrSettings)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*Store, error) { _ = db.Close(); return nil, e }
	if db.NoSync {
		return fail(fmt.Errorf("%w: backend NoSync", ErrSettings))
	}
	err = db.View(func(tx *bolt.Tx) error {
		var names [][]byte
		err := tx.ForEach(func(n []byte, _ *bolt.Bucket) error { names = append(names, bytes.Clone(n)); return nil })
		if err != nil {
			return err
		}
		if len(names) > 1 {
			return fmt.Errorf("%w: mixed top-level buckets", ErrVersion)
		}
		if len(names) == 1 && !bytes.Equal(names[0], bucketName) {
			if bytes.Equal(names[0], legacyBucket) {
				return fmt.Errorf("%w: legacy certified-record/v1 database", ErrVersion)
			}
			return fmt.Errorf("%w: unknown top-level bucket %q", ErrVersion, names[0])
		}
		return nil
	})
	if err != nil {
		return fail(err)
	}
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		if err == nil {
			err = fmt.Errorf("mode %s", fi.Mode())
		}
		return fail(fmt.Errorf("%w: store path: %v", ErrSettings, err))
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fail(err)
	}
	err = d.Sync()
	closeErr := d.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return fail(err)
	}
	return &Store{db: db, settings: s}, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) at(n string) error {
	if s.checkpoint != nil {
		return s.checkpoint(n)
	}
	return nil
}

type durableImage struct {
	descriptor, controlRaw, headName, headRaw                        []byte
	descriptorDigest, descriptorRawDigest, controlDigest, headDigest [32]byte
	control                                                          controlWire
	first, observed                                                  *verifiedPair
	head                                                             certifiedstore.Loaded
	hasHead                                                          bool
}
type verifiedPair struct {
	wire        pairWire
	raw         []byte
	observation rootinput.VerifiedObservationV2
}

// State is a verified durable image. Accessors return owned evidence.
type State struct{ i *durableImage }

func (s State) Revision() uint64 {
	if s.i == nil {
		return 0
	}
	return s.i.control.Revision
}
func (s State) Ordinary() bool { return s.i != nil && s.i.first != nil }
func (s State) Observed() (rootinput.VerifiedObservationV2, bool) {
	if s.i == nil || s.i.observed == nil {
		return rootinput.VerifiedObservationV2{}, false
	}
	return reownObservation(s.i.observed.observation), true
}
func (s State) FirstOrdinary() (rootinput.VerifiedObservationV2, bool) {
	if s.i == nil || s.i.first == nil {
		return rootinput.VerifiedObservationV2{}, false
	}
	return reownObservation(s.i.first.observation), true
}
func (s State) Head() (certifiedstore.Loaded, bool) {
	if s.i == nil || !s.i.hasHead {
		return certifiedstore.Loaded{}, false
	}
	return s.i.head, true
}

// ProgressToken proves only that exact previously verified bytes remain current in this Store instance.
type ProgressToken struct{ t *progressToken }
type progressToken struct {
	store                                       *Store
	descriptorDigest, controlDigest, headDigest [32]byte
	headName                                    []byte
	revision                                    uint64
	observed                                    [32]byte
	hasObserved                                 bool
}

func tokenFor(s *Store, i *durableImage) ProgressToken {
	t := &progressToken{store: s, descriptorDigest: i.descriptorRawDigest, controlDigest: i.controlDigest, headDigest: i.headDigest, headName: bytes.Clone(i.headName), revision: i.control.Revision}
	if i.observed != nil {
		t.observed = i.observed.observation.OriginIdentity()
		t.hasObserved = true
	}
	return ProgressToken{t: t}
}

// Initialize atomically creates descriptor and revision-0 control. Existing state is verified, never reset.
func (s *Store) Initialize(ctx context.Context, c Context) (State, ProgressToken, error) {
	if err := c.check(); err != nil {
		return State{}, ProgressToken{}, err
	}
	if st, t, err := s.Load(ctx, c); err == nil {
		return st, t, nil
	} else if !errors.Is(err, ErrUnavailable) {
		return State{}, ProgressToken{}, err
	}
	desc, dd, err := encodeDescriptor(c.Origin)
	if err != nil {
		return State{}, ProgressToken{}, err
	}
	cw := controlWire{Version: FormatVersion, DescriptorDigest: dd[:], Revision: 0}
	cp, _ := marshal(cw)
	control, err := encodeEnvelope(kindControl, cp, MaxControlBytes)
	if err != nil {
		return State{}, ProgressToken{}, err
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		var count int
		if err := tx.ForEach(func([]byte, *bolt.Bucket) error { count++; return nil }); err != nil {
			return err
		}
		if count != 0 {
			return ErrStale
		}
		b, err := tx.CreateBucket(bucketName)
		if err != nil {
			return err
		}
		if err = b.Put(descriptorKey, desc); err != nil {
			return err
		}
		if err = b.Put(controlKey, control); err != nil {
			return err
		}
		return s.at("before-initialize-commit")
	})
	if err != nil {
		return State{}, ProgressToken{}, err
	}
	return s.Load(ctx, c)
}

func (s *Store) readRaw() (descriptor, control, headName, headRaw []byte, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return ErrUnavailable
		}
		d := b.Get(descriptorKey)
		c := b.Get(controlKey)
		if d == nil || c == nil {
			return ErrUnavailable
		}
		if len(d) > MaxDescriptorBytes || len(c) > MaxControlBytes {
			return ErrBounds
		}
		descriptor = bytes.Clone(d)
		control = bytes.Clone(c)
		cp, e := decodeEnvelope(c, kindControl, MaxControlBytes)
		if e != nil {
			return e
		}
		var cw controlWire
		if e = decodePayload(cp, &cw); e != nil {
			return e
		}
		if cw.HeadKey != nil {
			if !validRecordKey(cw.HeadKey) {
				return fmt.Errorf("%w: malformed head key", ErrUntrusted)
			}
			headName = bytes.Clone(cw.HeadKey)
			v := b.Get(cw.HeadKey)
			if v == nil {
				return ErrUnavailable
			}
			if len(v) > MaxOuterRecordBytes {
				return ErrBounds
			}
			headRaw = bytes.Clone(v)
		}
		return nil
	})
	return
}

// Load performs bounded verification of descriptor, control, referenced pairs and referenced head only.
func (s *Store) Load(ctx context.Context, c Context) (State, ProgressToken, error) {
	if err := c.check(); err != nil {
		return State{}, ProgressToken{}, err
	}
	desc, control, hn, hr, err := s.readRaw()
	if err != nil {
		return State{}, ProgressToken{}, err
	}
	dd, err := verifyDescriptor(desc, c.Origin)
	if err != nil {
		return State{}, ProgressToken{}, err
	}
	cp, err := decodeEnvelope(control, kindControl, MaxControlBytes)
	if err != nil {
		return State{}, ProgressToken{}, err
	}
	var cw controlWire
	if err = decodePayload(cp, &cw); err != nil {
		return State{}, ProgressToken{}, err
	}
	if cw.Version != FormatVersion || !bytes.Equal(cw.DescriptorDigest, dd[:]) {
		return State{}, ProgressToken{}, ErrContext
	}
	if cw.Revision == 0 && (cw.First != nil || cw.Observed != nil || cw.HeadKey != nil) {
		return State{}, ProgressToken{}, fmt.Errorf("%w: revision zero is not empty", ErrUntrusted)
	}
	if cw.Revision > 0 && cw.Observed == nil {
		return State{}, ProgressToken{}, fmt.Errorf("%w: mutated control lacks observed pair", ErrUntrusted)
	}
	i := &durableImage{descriptor: desc, controlRaw: control, headName: hn, headRaw: hr, descriptorDigest: dd, descriptorRawDigest: sha256.Sum256(desc), controlDigest: sha256.Sum256(control), control: cw}
	if cw.First != nil {
		i.first, err = verifyPair(ctx, c, *cw.First)
		if err != nil {
			return State{}, ProgressToken{}, err
		}
		if i.first.observation.Class() == evmroot.OriginBootstrapV2 {
			return State{}, ProgressToken{}, fmt.Errorf("%w: first ordinary is bootstrap", ErrUntrusted)
		}
	}
	if cw.Observed != nil {
		i.observed, err = verifyPair(ctx, c, *cw.Observed)
		if err != nil {
			return State{}, ProgressToken{}, err
		}
	}
	if i.first == nil && i.observed != nil && i.observed.observation.Class() != evmroot.OriginBootstrapV2 {
		return State{}, ProgressToken{}, fmt.Errorf("%w: ordinary observed without first evidence", ErrUntrusted)
	}
	if i.first != nil && (i.observed == nil || i.observed.observation.Class() == evmroot.OriginBootstrapV2) {
		return State{}, ProgressToken{}, fmt.Errorf("%w: ordinary supersession lost", ErrUntrusted)
	}
	if i.first != nil {
		rel, e := compareObservations(i.first.observation, i.observed.observation)
		if e != nil || rel == relationStale {
			return State{}, ProgressToken{}, fmt.Errorf("%w: first/observed ordering: %v", ErrUntrusted, e)
		}
	}
	if cw.HeadKey == nil {
		if hn != nil {
			return State{}, ProgressToken{}, fmt.Errorf("%w: unbound head key", ErrUntrusted)
		}
	} else if !bytes.Equal(cw.HeadKey, hn) {
		return State{}, ProgressToken{}, fmt.Errorf("%w: control/head key mismatch", ErrUntrusted)
	}
	if hn != nil {
		if i.first == nil || i.observed == nil || !validRecordKey(hn) {
			return State{}, ProgressToken{}, fmt.Errorf("%w: invalid ordinary head", ErrUntrusted)
		}
		i.head, err = verifyOuterRecord(ctx, c, dd, hn, hr)
		if err != nil {
			return State{}, ProgressToken{}, err
		}
		i.hasHead = true
		i.headDigest = sha256.Sum256(hr)
		hobs, err := observationFromLoaded(ctx, c, i.head)
		if err != nil {
			return State{}, ProgressToken{}, err
		}
		rel, e := compareObservations(hobs, i.observed.observation)
		if e != nil || rel == relationStale {
			return State{}, ProgressToken{}, fmt.Errorf("%w: head newer/conflicting with observed: %v", ErrUntrusted, e)
		}
	}
	return State{i: i}, tokenFor(s, i), nil
}

func (s *Store) Unchanged(t ProgressToken) bool {
	if t.t == nil || t.t.store != s {
		return false
	}
	d, c, h, hr, e := s.readRaw()
	if e != nil {
		return false
	}
	return sha256.Sum256(d) == t.t.descriptorDigest && sha256.Sum256(c) == t.t.controlDigest && bytes.Equal(h, t.t.headName) && ((h == nil && t.t.headName == nil) || (h != nil && sha256.Sum256(hr) == t.t.headDigest))
}
