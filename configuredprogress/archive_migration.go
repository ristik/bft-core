package configuredprogress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"sort"

	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/frontier"
	bolt "go.etcd.io/bbolt"
)

// The archive policy migration record (bft-core#1030). A writer's archive replicas follow the installed validator set, so a membership
// change switches its policy while durable coverage still names the replicas of earlier policies. Nothing durable is rewritten or
// deleted on a switch: the record says which policy is in force, which earlier replicas the coverage names (the lineage, accepted as
// historical acknowledgers), which of them still hold copies this writer promised and has not yet verified on the current replicas
// (retained holders, counted towards K until then), and how far that verification has come. Retained holders are released only when
// every promised position from the coverage base up to the switch has two verified copies on the current replicas.
const journalArchiveMigrationKind uint64 = 12
const archiveMigrationLimit = 1 << 16

var journalArchiveMigrationKey = []byte("journal/archive-migration")

type archiveMigrationWire struct {
	_          struct{} `cbor:",toarray"`
	Version    uint64
	Descriptor []byte
	Policy     []byte // the canonical encoding of the archive policy in force (archivepolicy.Policy.Encode); opaque here
	Replicas   []string
	Lineage    []string
	Retained   []string
	Since      uint64
	Through    uint64
}

// ArchiveMigration is the durable state of the archive policy in force.
type ArchiveMigration struct {
	Policy   []byte   // encoded policy; Digest is its SHA-256, the digest frontier records bind to
	Digest   [32]byte //
	Replicas []string // the policy's replicas, canonical order
	Lineage  []string // replicas of earlier policies named by durable coverage: accepted as historical acknowledgers, never as new ones
	Retained []string // earlier replicas still counted as holders of what this writer promised; empty once complete
	Since    uint64   // the frontier height when the policy was adopted: every later coverage record is acknowledged under it
	Through  uint64   // every promised position at or below this height has two verified copies on Replicas (or is below the coverage base)
}

// Complete reports whether no earlier replica is still a holder: every block position promised before the switch, and every retained
// activation bundle, was verified on two current replicas (or nothing earlier was retained at all).
func (m ArchiveMigration) Complete() bool { return len(m.Retained) == 0 }

// Backlog is the number of promised block positions still to verify on the current replicas.
func (m ArchiveMigration) Backlog() uint64 {
	if m.Complete() || m.Through >= m.Since {
		return 0
	}
	return m.Since - m.Through
}

func namesValid(names []string) bool {
	for _, n := range names {
		if n == "" || len(n) > 64 {
			return false
		}
	}
	return true
}

func encodeArchiveMigration(dd [32]byte, m ArchiveMigration) ([]byte, error) {
	p, err := marshal(archiveMigrationWire{Version: journalVersion, Descriptor: dd[:], Policy: m.Policy, Replicas: m.Replicas, Lineage: m.Lineage,
		Retained: m.Retained, Since: m.Since, Through: m.Through})
	if err != nil {
		return nil, err
	}
	return encodeEnvelope(journalArchiveMigrationKind, p, archiveMigrationLimit)
}

func readArchiveMigration(b *bolt.Bucket, dd [32]byte) (ArchiveMigration, bool, error) {
	raw := b.Get(journalArchiveMigrationKey)
	if raw == nil {
		return ArchiveMigration{}, false, nil
	}
	payload, err := decodeEnvelope(raw, journalArchiveMigrationKind, archiveMigrationLimit)
	if err != nil {
		return ArchiveMigration{}, false, err
	}
	var w archiveMigrationWire
	if err := decodePayload(payload, &w); err != nil {
		return ArchiveMigration{}, false, err
	}
	if w.Version != journalVersion || !bytes.Equal(w.Descriptor, dd[:]) || len(w.Policy) == 0 || len(w.Replicas) < 2 || len(w.Replicas) > 3 ||
		!namesValid(w.Replicas) || !namesValid(w.Lineage) || !namesValid(w.Retained) || w.Through > w.Since {
		return ArchiveMigration{}, false, fmt.Errorf("%w: archive policy migration record", ErrContext)
	}
	m := ArchiveMigration{Policy: w.Policy, Digest: sha256.Sum256(w.Policy), Replicas: w.Replicas, Lineage: w.Lineage, Retained: w.Retained, Since: w.Since, Through: w.Through}
	return m, true, nil
}

// LoadArchiveMigration returns the persisted archive policy migration record, if any.
func (s *Store) LoadArchiveMigration(ctx context.Context, c Context, limits JournalLimits) (ArchiveMigration, bool, error) {
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return ArchiveMigration{}, false, err
	}
	var m ArchiveMigration
	var ok bool
	err = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if err := readJournalMeta(b, state.i.descriptorDigest, limits); err != nil {
			return err
		}
		m, ok, err = readArchiveMigration(b, state.i.descriptorDigest)
		return err
	})
	return m, ok, err
}

// union returns the distinct names of the lists, sorted, without the excluded ones.
func union(exclude []string, lists ...[]string) []string {
	seen := map[string]bool{}
	for _, n := range exclude {
		seen[n] = true
	}
	var out []string
	for _, list := range lists {
		for _, n := range list {
			if n != "" && !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	return out
}

// frontierHeight is the height of the durable frontier anchor, zero without one. It reads the record without a policy: only its height
// is used.
func frontierHeight(b *bolt.Bucket, dd [32]byte) (uint64, error) {
	raw := b.Get(journalFrontierKey)
	if raw == nil {
		return 0, nil
	}
	payload, err := decodeEnvelope(raw, journalFrontierKind, archive.MaxWireBytes+frontier.MaxBytes+4096)
	if err != nil {
		return 0, err
	}
	var w journalFrontierWire
	if err := decodePayload(payload, &w); err != nil {
		return 0, err
	}
	if w.Version != journalVersion || !bytes.Equal(w.Descriptor, dd[:]) {
		return 0, frontier.ErrContext
	}
	r, err := frontier.DecodeUnchecked(w.Frontier)
	if err != nil {
		return 0, err
	}
	return r.Height, nil
}

// coverageAcknowledgers is every replica name the durable coverage records in (base, through] carry.
func coverageAcknowledgers(b *bolt.Bucket, base, through uint64) ([]string, error) {
	names := map[string]bool{}
	for h := base + 1; h <= through && h != 0; h++ {
		raw := b.Get(coverageKey(h))
		if raw == nil {
			return nil, fmt.Errorf("%w: no coverage record at height %d below the frontier", frontier.ErrInvalid, h)
		}
		r, err := frontier.DecodeUnchecked(raw)
		if err != nil || r.Height != h {
			return nil, fmt.Errorf("%w: the coverage record at height %d does not decode", frontier.ErrInvalid, h)
		}
		for _, a := range r.Acks {
			names[a.Replica] = true
		}
	}
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// AdoptArchivePolicy makes policy (its canonical encoding, with its replicas in canonical order) the archive policy in force, in one
// transaction, and returns the migration record. The same policy again returns the record unchanged. Otherwise the earlier replicas
// that may still hold promised copies become retained holders: the previous record's replicas, plus its retained holders if its own
// migration was not complete; without a previous record (a node that ran before policies were persisted) every replica the durable
// coverage names. The lineage keeps every earlier replica the coverage may name. The verification restarts at the coverage base,
// and is complete at once when no earlier replica is retained. A caller must not advance the frontier between adopting a policy and
// switching the frontier to it.
func (s *Store) AdoptArchivePolicy(ctx context.Context, c Context, limits JournalLimits, policy []byte, replicas []string) (ArchiveMigration, error) {
	if len(policy) == 0 || len(replicas) < 2 || len(replicas) > 3 || !namesValid(replicas) {
		return ArchiveMigration{}, ErrContext
	}
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return ArchiveMigration{}, err
	}
	digest := sha256.Sum256(policy)
	var out ArchiveMigration
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if !imageMatches(b, state.i) {
			return ErrStale
		}
		dd := state.i.descriptorDigest
		if err := readJournalMeta(b, dd, limits); err != nil {
			return err
		}
		previous, found, err := readArchiveMigration(b, dd)
		if err != nil {
			return err
		}
		if found && previous.Digest == digest {
			out = previous
			return nil
		}
		base, _, err := readCoverageBase(b, dd, [32]byte(c.Origin.BlockHash()))
		if err != nil {
			return err
		}
		since, err := frontierHeight(b, dd)
		if err != nil {
			return err
		}
		next := ArchiveMigration{Policy: bytes.Clone(policy), Digest: digest, Replicas: slices.Clone(replicas), Since: since, Through: base.Height}
		if found {
			next.Lineage = union(replicas, previous.Lineage, previous.Replicas, previous.Retained)
			if previous.Complete() {
				// every promise was verified on the previous replicas
				next.Retained = union(replicas, previous.Replicas)
			} else {
				next.Retained = union(replicas, previous.Replicas, previous.Retained)
			}
		} else {
			named, err := coverageAcknowledgers(b, base.Height, since)
			if err != nil {
				return err
			}
			next.Lineage = union(replicas, named)
			next.Retained = next.Lineage
		}
		if next.Since < next.Through {
			next.Since = next.Through
		}
		if len(next.Retained) == 0 {
			next.Retained, next.Through = nil, next.Since
		}
		raw, err := encodeArchiveMigration(dd, next)
		if err != nil {
			return err
		}
		if err := s.at("before-archive-policy-commit"); err != nil {
			return err
		}
		if err := b.Put(journalArchiveMigrationKey, raw); err != nil {
			return err
		}
		out = next
		return nil
	})
	return out, err
}

// AdvanceArchiveMigration records that every promised position at or below through has two verified copies on replicas, the replicas of
// the policy with this digest. It never moves backwards. release says the caller also verified every other retained obligation (the
// activation bundles) on two of them: only with it, and only at the switch height, is the migration complete and are the retained holders
// released. A record of another policy or replica set (a switch in between) is ErrStale: that verification belongs to a policy no longer
// in force.
func (s *Store) AdvanceArchiveMigration(ctx context.Context, c Context, limits JournalLimits, digest [32]byte, replicas []string, through uint64, release bool) (ArchiveMigration, error) {
	state, _, err := s.Load(ctx, c)
	if err != nil {
		return ArchiveMigration{}, err
	}
	var out ArchiveMigration
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if !imageMatches(b, state.i) {
			return ErrStale
		}
		dd := state.i.descriptorDigest
		if err := readJournalMeta(b, dd, limits); err != nil {
			return err
		}
		m, found, err := readArchiveMigration(b, dd)
		if err != nil {
			return err
		}
		if !found || m.Digest != digest || !slices.Equal(m.Replicas, replicas) {
			return fmt.Errorf("%w: the archive policy in force changed", ErrStale)
		}
		if through > m.Since {
			through = m.Since
		}
		if m.Complete() || through < m.Through || through == m.Through && !(release && through >= m.Since) {
			out = m
			return nil
		}
		m.Through = through
		if release && m.Through >= m.Since {
			m.Retained = nil
		}
		raw, err := encodeArchiveMigration(dd, m)
		if err != nil {
			return err
		}
		if err := s.at("before-archive-migration-commit"); err != nil {
			return err
		}
		if err := b.Put(journalArchiveMigrationKey, raw); err != nil {
			return err
		}
		out = m
		return nil
	})
	return out, err
}
