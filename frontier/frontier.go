// Package frontier defines an inert durable certified frontier and prune planner.
// The configuredprogress journal remains the sole recovery owner.
package frontier

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/unicitynetwork/bft-core/archive"
)

var (
	ErrInvalid        = errors.New("frontier: invalid record")
	ErrVersion        = errors.New("frontier: unsupported version")
	ErrContext        = errors.New("frontier: wrong context or configured replicas")
	ErrStale          = errors.New("frontier: stale or regressing anchor")
	ErrAcknowledgment = errors.New("frontier: two durable acknowledgments required")
	ErrObligation     = errors.New("frontier: retained obligation blocks pruning")
	ErrUnavailable    = errors.New("frontier: record unavailable")
)

const version byte = 1
const domain = "M2FRONTIER"
const MaxBytes = archive.MaxRequestBytes + 512

type Acknowledgment struct {
	Replica        string
	RequestDigest  [32]byte
	ManifestDigest [32]byte
}
type Record struct {
	Sequence  uint64
	Round     uint64
	Height    uint64
	StateRoot [32]byte
	Subject   archive.Request
	Acks      [2]Acknowledgment
}
type Policy struct {
	Context         archive.Context
	Replicas        [2]string
	MinimumSequence uint64 // authenticated lower bound supplied by the recovery owner
	Binding         CertifiedBinding
	Availability    ReplicaAvailability
}

// CertifiedBinding checks the claimed round, height, state root and block hash
// against the header and resulting UC/TR in the canonical archive record.
// The wired adapter must obtain its trust base independently of this record.
type CertifiedBinding interface {
	VerifyCertified(Record, *archive.Record) error
}

// ReplicaAvailability re-reads and verifies the named replica's complete
// manifest and chunks for the exact request. It must compare the real manifest
// digest to expected before returning; the caller cannot mint an ack locally.
type ReplicaAvailability interface {
	VerifyAvailable(replica string, request archive.Request, expected [32]byte) error
}

type Coverage struct {
	Anchor   Record
	Material *archive.Record
}

func subjectBytes(r Record) ([]byte, error) { return archive.EncodeRequest(r.Subject) }
func equalContext(a, b archive.Context) bool {
	a.ExecutionIdentity = nil
	b.ExecutionIdentity = nil
	// The identity is checked separately because it is a byte slice.
	return reflect.DeepEqual(a, b)
}
func valid(r Record, p Policy) error {
	if r.Sequence == 0 || r.Round == 0 || r.Height == 0 || r.StateRoot == ([32]byte{}) {
		return ErrInvalid
	}
	q, err := subjectBytes(r)
	if err != nil {
		return ErrInvalid
	}
	if !equalContext(r.Subject.Context, p.Context) || !bytes.Equal(r.Subject.Context.ExecutionIdentity, p.Context.ExecutionIdentity) {
		return ErrContext
	}
	if len(p.Replicas[0]) == 0 || len(p.Replicas[0]) > 64 || len(p.Replicas[1]) == 0 || len(p.Replicas[1]) > 64 || p.Replicas[0] == p.Replicas[1] || r.Acks[0].Replica != p.Replicas[0] || r.Acks[1].Replica != p.Replicas[1] {
		return ErrContext
	}
	digest := sha256.Sum256(q)
	for _, a := range r.Acks {
		if a.RequestDigest != digest || a.ManifestDigest == ([32]byte{}) {
			return ErrAcknowledgment
		}
	}
	if r.Acks[0].ManifestDigest != r.Acks[1].ManifestDigest {
		return ErrAcknowledgment
	}
	if r.Sequence < p.MinimumSequence {
		return ErrStale
	}
	return nil
}
func putString(b *bytes.Buffer, s string) { b.WriteByte(byte(len(s))); b.WriteString(s) }
func Encode(r Record, p Policy) ([]byte, error) {
	if err := valid(r, p); err != nil {
		return nil, err
	}
	q, _ := subjectBytes(r)
	var b bytes.Buffer
	b.WriteString(domain)
	b.WriteByte(version)
	for _, v := range []uint64{r.Sequence, r.Round, r.Height} {
		_ = binary.Write(&b, binary.BigEndian, v)
	}
	b.Write(r.StateRoot[:])
	_ = binary.Write(&b, binary.BigEndian, uint32(len(q)))
	b.Write(q)
	for _, a := range r.Acks {
		putString(&b, a.Replica)
		b.Write(a.RequestDigest[:])
		b.Write(a.ManifestDigest[:])
	}
	sum := sha256.Sum256(b.Bytes())
	b.Write(sum[:])
	if b.Len() > MaxBytes {
		return nil, ErrInvalid
	}
	return b.Bytes(), nil
}
func Decode(raw []byte, p Policy) (Record, error) {
	var out Record
	if len(raw) > MaxBytes || len(raw) < len(domain)+1+24+32+4+2*(1+64)+32 {
		return out, ErrInvalid
	}
	if !bytes.Equal(raw[:len(domain)], []byte(domain)) {
		return out, ErrInvalid
	}
	if raw[len(domain)] != version {
		return out, ErrVersion
	}
	payload := raw[:len(raw)-32]
	sum := sha256.Sum256(payload)
	if !bytes.Equal(sum[:], raw[len(raw)-32:]) {
		return out, ErrInvalid
	}
	r := bytes.NewReader(payload[len(domain)+1:])
	for _, v := range []*uint64{&out.Sequence, &out.Round, &out.Height} {
		if binary.Read(r, binary.BigEndian, v) != nil {
			return Record{}, ErrInvalid
		}
	}
	if _, err := io.ReadFull(r, out.StateRoot[:]); err != nil {
		return Record{}, ErrInvalid
	}
	var n uint32
	if binary.Read(r, binary.BigEndian, &n) != nil || n > archive.MaxRequestBytes || uint64(n) > uint64(r.Len()) {
		return Record{}, ErrInvalid
	}
	qb := make([]byte, n)
	if _, err := io.ReadFull(r, qb); err != nil {
		return Record{}, ErrInvalid
	}
	var err error
	out.Subject, err = archive.DecodeRequest(qb)
	if err != nil {
		return Record{}, ErrInvalid
	}
	for i := range out.Acks {
		length, er := r.ReadByte()
		if er != nil || length == 0 || length > 64 || int(length)+64 > r.Len() {
			return Record{}, ErrInvalid
		}
		name := make([]byte, length)
		_, _ = io.ReadFull(r, name)
		if bytes.IndexByte(name, 0) >= 0 {
			return Record{}, ErrInvalid
		}
		out.Acks[i].Replica = string(name)
		_, _ = io.ReadFull(r, out.Acks[i].RequestDigest[:])
		_, _ = io.ReadFull(r, out.Acks[i].ManifestDigest[:])
	}
	remaining := r.Len()
	if remaining != 0 {
		return Record{}, ErrInvalid
	}
	if err = valid(out, p); err != nil {
		return Record{}, err
	}
	again, _ := Encode(out, p)
	if !bytes.Equal(payload[len(domain)+1:len(payload)-remaining], again[len(domain)+1:len(again)-32]) {
		return Record{}, ErrInvalid
	}
	return out, nil
}

type Obligation struct {
	Round                                                 uint64
	UnresolvedBody, PendingAuthorization, NonEquivocation bool
}
type Plan struct {
	Next         Record
	PruneThrough uint64
}

// PlanAdvance only returns a deletion boundary. The journal owner must perform
// any later transition atomically with its own certified progress state.
func PlanAdvance(current *Record, next Record, p Policy, covered []Coverage, obligations []Obligation) (Plan, error) {
	if err := valid(next, p); err != nil {
		return Plan{}, err
	}
	if current != nil {
		if err := valid(*current, p); err != nil {
			return Plan{}, err
		}
		if next.Sequence <= current.Sequence || next.Round <= current.Round || next.Height <= current.Height {
			return Plan{}, ErrStale
		}
	}
	if current == nil || p.Binding == nil || p.Availability == nil || (len(covered) == 0 && next.Height > current.Height) {
		return Plan{}, ErrAcknowledgment
	}
	previous := *current
	for _, item := range covered {
		r := item.Anchor
		if err := valid(r, p); err != nil {
			return Plan{}, err
		}
		if r.Height != previous.Height+1 || r.Round <= previous.Round || r.Sequence <= previous.Sequence {
			return Plan{}, ErrAcknowledgment
		}
		digest, err := archive.ManifestDigest(r.Subject, item.Material)
		if err != nil || digest != r.Acks[0].ManifestDigest || digest != r.Acks[1].ManifestDigest {
			return Plan{}, ErrAcknowledgment
		}
		if p.Binding.VerifyCertified(r, item.Material) != nil {
			return Plan{}, ErrInvalid
		}
		for _, ack := range r.Acks {
			if p.Availability.VerifyAvailable(ack.Replica, r.Subject, digest) != nil {
				return Plan{}, ErrAcknowledgment
			}
		}
		previous = r
	}
	if len(covered) > 0 && !reflect.DeepEqual(previous, next) {
		return Plan{}, ErrAcknowledgment
	}
	for _, o := range obligations {
		if o.Round <= next.Round && (o.UnresolvedBody || o.PendingAuthorization || o.NonEquivocation) {
			return Plan{}, ErrObligation
		}
	}
	return Plan{Next: next, PruneThrough: next.Round}, nil
}

// CheckRecovery refuses a rolled-back frontier and re-reads both replica
// copies. A wired journal supplies its prune floor from the same transaction
// that made pruning durable. Loss of either copy halts further advancement.
func CheckRecovery(durable Record, journalPrunedThrough uint64, p Policy, anchor Coverage) error {
	if durable.Round < journalPrunedThrough {
		return ErrStale
	}
	if err := valid(durable, p); err != nil {
		return err
	}
	if anchor.Anchor.Round != durable.Round || anchor.Anchor.Subject.BlockHash != durable.Subject.BlockHash || p.Binding == nil || p.Availability == nil {
		return ErrInvalid
	}
	digest, err := archive.ManifestDigest(durable.Subject, anchor.Material)
	if err != nil || digest != durable.Acks[0].ManifestDigest || digest != durable.Acks[1].ManifestDigest || p.Binding.VerifyCertified(durable, anchor.Material) != nil {
		return ErrInvalid
	}
	for _, ack := range durable.Acks {
		if p.Availability.VerifyAvailable(ack.Replica, durable.Subject, digest) != nil {
			return ErrUnavailable
		}
	}
	return nil
}

type Store struct {
	dir   string
	mu    sync.Mutex
	Fault func(string) error
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}
func (s *Store) at(step string) error {
	if s.Fault != nil {
		return s.Fault(step)
	}
	return nil
}
func (s *Store) Load(p Policy) (Record, error) {
	path := filepath.Join(s.dir, "frontier")
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, ErrUnavailable
	}
	if err != nil {
		return Record{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > MaxBytes {
		return Record{}, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil || len(raw) > MaxBytes {
		return Record{}, ErrInvalid
	}
	return Decode(raw, p)
}

// Save uses one same-directory rename. A fault after rename can report failure
// even though the new record is visible; callers must reload before retrying.
func (s *Store) Save(next Record, p Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := Encode(next, p)
	if err != nil {
		return err
	}
	return s.saveEncoded(next, p, raw)
}

// saveEncoded is split out so an unloadable encoder result can be fault-tested
// before it reaches the atomic replacement path. Caller holds s.mu.
func (s *Store) saveEncoded(next Record, p Policy, raw []byte) error {
	if _, err := Decode(raw, p); err != nil {
		return err
	}
	old, e := s.Load(p)
	if e == nil {
		if next.Sequence <= old.Sequence || next.Round <= old.Round || next.Height <= old.Height {
			return ErrStale
		}
	} else if !errors.Is(e, ErrUnavailable) {
		return e
	}
	f, err := os.CreateTemp(s.dir, ".frontier-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = s.at("after-create"); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = s.at("after-write"); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = s.at("after-file-sync"); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = s.at("after-close"); err != nil {
		return err
	}
	if err = os.Rename(tmp, filepath.Join(s.dir, "frontier")); err != nil {
		return err
	}
	if err = s.at("after-rename"); err != nil {
		return err
	}
	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	d.Close()
	if err != nil {
		return err
	}
	return s.at("after-dir-sync")
}
