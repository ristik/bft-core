package shardnode

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// ErrShardConfEpochUnknown refuses a certificate whose shard epoch has no installed configuration: its assignment's committed handoff
// has not been verified and installed here yet. It is retryable after the install, and it never falls back to another epoch's hash.
var ErrShardConfEpochUnknown = errors.New("shardnode: no installed shard configuration for the certificate's shard epoch")

// ErrShardConfConflict refuses to install a configuration hash for a shard epoch that already has a different one.
var ErrShardConfConflict = errors.New("shardnode: a different shard configuration is already installed for this shard epoch")

// ShardConfSet is what a node accepts certificates under: the shard configuration hash of each shard epoch, seeded with the genesis
// entry (epoch 0) and extended only from verified committed assignment steps. One set is shared by the certificate client, the
// persisted-certificate check, the configured admission and the evidence recovery, so they cannot disagree about it.
type ShardConfSet struct {
	mu      sync.RWMutex
	genesis []byte
	byEpoch map[uint64][]byte
}

// NewShardConfSet starts a set with the genesis configuration hash as the shard epoch 0 entry.
func NewShardConfSet(genesis []byte) (*ShardConfSet, error) {
	if err := validateShardConfHashWidth(genesis); err != nil {
		return nil, err
	}
	return &ShardConfSet{genesis: bytes.Clone(genesis), byEpoch: map[uint64][]byte{0: bytes.Clone(genesis)}}, nil
}

// Genesis is the deployment's genesis configuration hash: the identity pin, never replaced by an assignment.
func (s *ShardConfSet) Genesis() []byte { return bytes.Clone(s.genesis) }

// Install records the configuration hash in effect from the given shard epoch. The same hash again is a no-op; a different hash for an
// installed epoch (the genesis entry included) is ErrShardConfConflict.
func (s *ShardConfSet) Install(epoch uint64, hash []byte) error {
	if err := validateShardConfHashWidth(hash); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if have, ok := s.byEpoch[epoch]; ok {
		if !bytes.Equal(have, hash) {
			return fmt.Errorf("%w: shard epoch %d", ErrShardConfConflict, epoch)
		}
		return nil
	}
	s.byEpoch[epoch] = bytes.Clone(hash)
	return nil
}

// ForEpoch is the hash a certificate whose technical record names the given shard epoch must commit to.
func (s *ShardConfSet) ForEpoch(epoch uint64) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	conf, ok := s.byEpoch[epoch]
	if !ok {
		return nil, fmt.Errorf("%w: shard epoch %d", ErrShardConfEpochUnknown, epoch)
	}
	return bytes.Clone(conf), nil
}

// ForIREpoch is the set of hashes a certificate whose INPUT RECORD names the given shard epoch may carry: the configuration of that
// epoch, or of a later installed one, because a successor assignment is certified (its technical record and configuration advance) while
// the input record still names the epoch before it, until the acknowledgement. The configuration of an EARLIER epoch is never
// acceptable for a newer one. Used where only a certificate is at hand (a persisted last certificate, peer evidence).
func (s *ShardConfSet) ForIREpoch(irEpoch uint64) [][]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	epochs := make([]uint64, 0, len(s.byEpoch))
	for e := range s.byEpoch {
		if e >= irEpoch {
			epochs = append(epochs, e)
		}
	}
	sort.Slice(epochs, func(i, j int) bool { return epochs[i] < epochs[j] })
	out := make([][]byte, 0, len(epochs))
	for _, e := range epochs {
		out = append(out, bytes.Clone(s.byEpoch[e]))
	}
	return out
}
