package cmd

import (
	"errors"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"
)

// errNoInstallPeers is returned when an install has no root peer to ask.
var errNoInstallPeers = errors.New("no bootstrap root peer to fetch from")

// fetchFromRootPeers asks the root peers in order and returns the first answer. When none answers it returns every peer's refusal, each
// with the peer id, so an install that cannot find its bundle says why instead of only that it failed.
func fetchFromRootPeers[B any](peers []peer.AddrInfo, request func(peer.ID) (B, error)) (B, error) {
	var zero B
	if len(peers) == 0 {
		return zero, errNoInstallPeers
	}
	var errs []error
	for _, root := range peers {
		b, err := request(root.ID)
		if err == nil {
			return b, nil
		}
		errs = append(errs, fmt.Errorf("peer %s: %w", root.ID, err))
	}
	return zero, errors.Join(errs...)
}
