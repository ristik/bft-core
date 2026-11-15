package cmd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// errNoInstallPeers is returned when an install has no root peer to ask.
var errNoInstallPeers = errors.New("no bootstrap root peer to fetch from")

// errInvalidPeerBundle marks a peer whose answer did not authenticate against this root's own history: the next peer is asked.
var errInvalidPeerBundle = errors.New("the served bundle does not authenticate")

// fetchFromRootPeers asks the root peers in order and returns the first answer that authenticates (accept, when given: a side-effect-free
// check against this root's installed history, so one peer serving a decodable but invalid bundle cannot mask a later honest one). Every
// request gets ctx, and no peer is asked once ctx has ended. When none answers it returns every peer's refusal, each with the peer id, so an
// install that cannot find its bundle says why instead of only that it failed.
func fetchFromRootPeers[B any](ctx context.Context, peers []peer.AddrInfo, request func(context.Context, peer.ID) (B, error), accept func(B) error) (B, error) {
	var zero B
	if len(peers) == 0 {
		return zero, errNoInstallPeers
	}
	var errs []error
	for _, root := range peers {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		b, err := request(ctx, root.ID)
		if err == nil && accept != nil {
			if aerr := accept(b); aerr != nil {
				err = fmt.Errorf("%w: %w", errInvalidPeerBundle, aerr)
			}
		}
		if err == nil {
			return b, nil
		}
		errs = append(errs, fmt.Errorf("peer %s: %w", root.ID, err))
	}
	return zero, errors.Join(errs...)
}

// Waiting for a root peer to serve the activation (#1080). A root started with --install-handoff-epoch that does not hold the committed
// checkpoint itself (it was stopped before its own copy of the old epoch committed it) asks its peers, and a peer serves the activation only
// once it has committed it too. The first root to restart used to find none and exit, and its container restart backoff (doubling up to
// ~13 s) then decided when it tried again: ~27 s per handoff. It now asks again in process, after a short capped backoff, until a peer
// serves it or the wait elapses. Nothing is trusted the sooner for it: whatever a peer serves is verified by the caller exactly as before.
const (
	installRetryFirst = 250 * time.Millisecond
	installRetryMax   = 2 * time.Second
	// installWaitDefault bounds the wait of --install-handoff-wait: an old committee short of the stopped root still commits within a few
	// round timeouts, so a root that has waited this long exits with every peer's refusal (and its supervisor decides what follows).
	installWaitDefault = 2 * time.Minute
)

// installRetry is the backoff of awaitFromRootPeers: the first delay, its cap and the whole wait (zero: ask every peer once).
type installRetry struct {
	first, max, wait time.Duration
}

func defaultInstallRetry(wait time.Duration) installRetry {
	return installRetry{first: installRetryFirst, max: installRetryMax, wait: wait}
}

// awaitFromRootPeers is fetchFromRootPeers asked again after each refusal, the delay doubling from r.first up to r.max, until a peer serves
// an answer that authenticates, r.wait has elapsed or ctx ends. The wait bounds the requests too: for a positive r.wait every request runs
// under a context that ends with it, no request starts after it and the backoff never outlasts it. A zero r.wait is one sweep under ctx.
// waiting (optional) is told of every refusal it waits after. Without peers it does not wait: none can come.
func awaitFromRootPeers[B any](ctx context.Context, r installRetry, peers []peer.AddrInfo, request func(context.Context, peer.ID) (B, error), accept func(B) error,
	waiting func(attempt int, err error)) (B, error) {
	if r.wait <= 0 {
		return fetchFromRootPeers(ctx, peers, request, accept)
	}
	ctx, cancel := context.WithTimeout(ctx, r.wait)
	defer cancel()
	delay := r.first
	for attempt := 1; ; attempt++ {
		b, err := fetchFromRootPeers(ctx, peers, request, accept)
		if err == nil || errors.Is(err, errNoInstallPeers) {
			return b, err
		}
		if ctx.Err() != nil {
			return b, fmt.Errorf("after %d attempts within %s: %w", attempt, r.wait, errors.Join(ctx.Err(), err))
		}
		if waiting != nil {
			waiting(attempt, err)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return b, fmt.Errorf("after %d attempts within %s: %w", attempt, r.wait, errors.Join(ctx.Err(), err))
		case <-timer.C:
		}
		delay = min(2*delay, r.max)
	}
}
