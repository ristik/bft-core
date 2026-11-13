package archivewiring

import (
	"slices"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/configuredprogress"
)

// ReplicaPolicy is the versioned archive replica policy a writer's archive consumers share (bft-core#1030): the publisher, the
// recovery source, the frontier worker, the operator status and the archive server's authorization each read one snapshot per pass,
// so a switch never mixes two policies inside one pass. Work planned under a replaced snapshot finishes against it or fails its checks
// and is retried under the new one; it is never relabeled.
//
// The node switches the policy when an installed assignment derives another replica set (after the startup replay and on every
// activation). The frontier worker owns its durable side: it adopts the switch in the journal, then publishes the earlier replicas that
// still hold promised copies (Retained) until the current replicas are verified to hold them. A retained holder is read from and counts
// towards K for promised positions; it is never published to and never acknowledges a new one, and it may use this node's archive
// service (not its journal, evidence or consensus services) until it is released.
type ReplicaPolicy struct {
	mu      sync.Mutex
	snap    ReplicaPolicySnapshot
	changed chan struct{}
}

// ReplicaPolicySnapshot is one version of the policy.
type ReplicaPolicySnapshot struct {
	Version  uint64
	Replicas []peer.ID // two or three, canonical order
	Digest   [32]byte  // the derived policy's digest; zero for an explicit (legacy) pair, which never switches
	Encoded  []byte    // the derived policy's canonical encoding (archivepolicy.Policy.Encode), persisted by the frontier worker
	Epoch    uint64    // the installed shard epoch the replicas were derived from (diagnostics)
	Retained []peer.ID // earlier replicas still holding promised copies not yet verified on Replicas
	// Migration is the durable migration state the frontier worker last applied, nil before (or without pruning).
	Migration *configuredprogress.ArchiveMigration
}

func (s ReplicaPolicySnapshot) clone() ReplicaPolicySnapshot {
	s.Replicas, s.Retained, s.Encoded = slices.Clone(s.Replicas), slices.Clone(s.Retained), slices.Clone(s.Encoded)
	if s.Migration != nil {
		m := *s.Migration
		s.Migration = &m
	}
	return s
}

// Readable is the replicas a promised record may be read from: the current ones, then the retained holders.
func (s ReplicaPolicySnapshot) Readable() []peer.ID {
	out := slices.Clone(s.Replicas)
	for _, id := range s.Retained {
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// NewReplicaPolicy starts at version 1 with the startup replicas.
func NewReplicaPolicy(replicas []peer.ID, digest [32]byte, encoded []byte, epoch uint64) (*ReplicaPolicy, error) {
	if !validReplicas(replicas) || digest != ([32]byte{}) && len(encoded) == 0 {
		return nil, ErrConfig
	}
	return &ReplicaPolicy{snap: ReplicaPolicySnapshot{Version: 1, Replicas: slices.Clone(replicas), Digest: digest, Encoded: slices.Clone(encoded), Epoch: epoch},
		changed: make(chan struct{})}, nil
}

// Snapshot returns the current version.
func (p *ReplicaPolicy) Snapshot() ReplicaPolicySnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.snap.clone()
}

// Changed is closed at the next version change.
func (p *ReplicaPolicy) Changed() <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.changed
}

func (p *ReplicaPolicy) bump() {
	p.snap.Version++
	close(p.changed)
	p.changed = make(chan struct{})
}

// Switch makes a derived policy current. It reports false, changing nothing, when the replicas are the current ones (another epoch
// or membership with the same replica set keeps the policy and its digest: no migration without a replica change) or when the current
// policy is an explicit pair. Retained holders and the migration state are the frontier worker's to publish for the new policy.
func (p *ReplicaPolicy) Switch(replicas []peer.ID, digest [32]byte, encoded []byte, epoch uint64) (bool, error) {
	if !validReplicas(replicas) || digest == ([32]byte{}) || len(encoded) == 0 {
		return false, ErrConfig
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.snap.Digest == ([32]byte{}) || slices.Equal(p.snap.Replicas, replicas) {
		return false, nil
	}
	// Until the worker adopts the switch, every earlier replica still counts as a holder: nothing is released by the switch itself.
	retained := p.snap.Readable()
	retained = slices.DeleteFunc(retained, func(id peer.ID) bool { return slices.Contains(replicas, id) })
	p.snap = ReplicaPolicySnapshot{Version: p.snap.Version, Replicas: slices.Clone(replicas), Digest: digest, Encoded: slices.Clone(encoded), Epoch: epoch, Retained: retained}
	p.bump()
	return true, nil
}

// adopt publishes the durable migration state of the policy with this digest; a state of a replaced policy is ignored.
func (p *ReplicaPolicy) adopt(digest [32]byte, m configuredprogress.ArchiveMigration) {
	retained := make([]peer.ID, 0, len(m.Retained))
	for _, name := range m.Retained {
		if id, err := peer.Decode(name); err == nil {
			retained = append(retained, id)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.snap.Digest != digest {
		return
	}
	same := slices.Equal(p.snap.Retained, retained) && p.snap.Migration != nil && p.snap.Migration.Since == m.Since && p.snap.Migration.Through == m.Through
	mm := m
	p.snap.Retained, p.snap.Migration = retained, &mm
	if !same {
		p.bump()
	}
}

// Holder reports whether id is a retained holder: an earlier replica this node still reads promised copies from. It authorizes the
// archive service only.
func (p *ReplicaPolicy) Holder(id peer.ID) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Contains(p.snap.Retained, id)
}

// Seed replaces the policy unconditionally with a persisted one (the policy a previous run adopted), before any consumer starts: a
// restart keeps the digest its durable records bind to instead of re-deriving it under a later epoch.
func (p *ReplicaPolicy) Seed(replicas []peer.ID, digest [32]byte, encoded []byte, epoch uint64) error {
	if !validReplicas(replicas) || digest == ([32]byte{}) || len(encoded) == 0 {
		return ErrConfig
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.snap = ReplicaPolicySnapshot{Version: p.snap.Version, Replicas: slices.Clone(replicas), Digest: digest, Encoded: slices.Clone(encoded), Epoch: epoch}
	p.bump()
	return nil
}
