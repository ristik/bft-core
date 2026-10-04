package trustbase

import (
	"errors"
	"fmt"
	"sort"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

var (
	// ErrSigningHistory is returned when the signing configuration of an epoch cannot be established from the authenticated
	// history: an unknown epoch, or an activation that does not fit the recorded ones.
	ErrSigningHistory = errors.New("signing configuration history")
)

// signingRegistry is the authenticated history of the epochs that activated the domain-bound scheme. The scheme is a
// property of the root epoch, so signing, verification and the epoch's weights change together at one epoch boundary; no
// wall-clock switch, flag or seal-version heuristic exists. An epoch with no activation at or below it is scheme 1.
//
// The registry is installed from the authenticated configuration history when the store is opened and when a successor
// epoch is installed. Nothing in production installs an activation yet, so every epoch resolves to scheme 1.
type signingRegistry struct {
	byEpoch map[uint64]votesig.Config
}

// ActivateSigning records that the given epoch is the first to sign with cfg (scheme 2). The epoch's trust base must be
// installed; the scheme never goes back (an activation below a recorded one is refused); installing the same record again
// is a no-op and a different record for the same epoch is refused.
func (s *TrustBaseStore) ActivateSigning(epoch uint64, cfg votesig.Config) error {
	if cfg.Scheme != votesig.SchemeDomainBound {
		return fmt.Errorf("%w: only scheme 2 is an activation, got %d", ErrSigningHistory, cfg.Scheme)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	tb, err := s.GetByEpoch(epoch)
	if err != nil {
		return fmt.Errorf("%w: epoch %d has no trust base: %w", ErrSigningHistory, epoch, err)
	}
	if cfg.Network != uint64(tb.NetworkID) {
		return fmt.Errorf("%w: configuration network %d differs from the trust base network %d", ErrSigningHistory, cfg.Network, tb.NetworkID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.signing.byEpoch == nil {
		s.signing.byEpoch = make(map[uint64]votesig.Config)
	}
	if prev, ok := s.signing.byEpoch[epoch]; ok {
		if prev != cfg {
			return fmt.Errorf("%w: epoch %d already activated with another configuration", ErrSigningHistory, epoch)
		}
		return nil
	}
	for e, prev := range s.signing.byEpoch {
		if e > epoch {
			return fmt.Errorf("%w: epoch %d is below the recorded activation at epoch %d", ErrSigningHistory, epoch, e)
		}
		if prev.Genesis != cfg.Genesis || prev.Network != cfg.Network {
			return fmt.Errorf("%w: the root-chain genesis identity changed at epoch %d", ErrSigningHistory, epoch)
		}
	}
	s.signing.byEpoch[epoch] = cfg
	return nil
}

// SigningConfig is the signing configuration of the epoch's messages: the activation record of the latest activated epoch
// at or below it (scheme 2), or the legacy configuration (scheme 1) when none is. It is an error for an epoch with no
// installed trust base: missing history is not an implicit legacy choice.
func (s *TrustBaseStore) SigningConfig(epoch uint64) (votesig.Config, error) {
	tb, err := s.GetByEpoch(epoch)
	if err != nil {
		return votesig.Config{}, fmt.Errorf("%w: epoch %d: %w", ErrSigningHistory, epoch, err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	epochs := make([]uint64, 0, len(s.signing.byEpoch))
	for e := range s.signing.byEpoch {
		epochs = append(epochs, e)
	}
	sort.Slice(epochs, func(i, j int) bool { return epochs[i] > epochs[j] })
	for _, e := range epochs {
		if e <= epoch {
			return s.signing.byEpoch[e], nil
		}
	}
	return votesig.Config{Scheme: votesig.SchemeLegacy, Network: uint64(tb.NetworkID)}, nil
}
