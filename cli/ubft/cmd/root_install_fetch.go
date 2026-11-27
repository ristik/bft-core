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
// request gets ctx; no peer is asked, no answer authenticated and none chosen once ctx has ended (its error is kept). When none answers it returns every peer's refusal, each with the peer id, so an
// install that cannot find its bundle says why instead of only that it failed.
func fetchFromRootPeers[B any](ctx context.Context, peers []peer.AddrInfo, request func(context.Context, peer.ID) (B, error), accept func(B) error) (B, error) {
	var zero B
	if len(peers) == 0 {
		return zero, errNoInstallPeers
	}
	refusals := make([]error, len(peers))
	b, ok, _, ended := sweepRootPeers(ctx, peers, request, accept, refusals)
	if ok {
		return b, nil
	}
	return zero, errors.Join(append(refusals, ended)...)
}

// sweepRootPeers is one pass of fetchFromRootPeers over peers. It reports the first answer that authenticates (ok); otherwise refusals[i]
// holds peer i's refusal, with its id, for every peer it asked; cut is the peer whose request or answer the end of ctx overtook (its entry
// says so), -1 for none; ended is the context's error when the pass stopped because ctx ended before the next peer was asked.
func sweepRootPeers[B any](ctx context.Context, peers []peer.AddrInfo, request func(context.Context, peer.ID) (B, error), accept func(B) error,
	refusals []error) (b B, ok bool, cut int, ended error) {
	for i, root := range peers {
		if err := ctx.Err(); err != nil {
			return b, false, -1, err
		}
		b, err := request(ctx, root.ID)
		// an answer that arrives as the budget ends is not authenticated, and one whose authentication outlasts it is not chosen: the
		// caller installs under its own, longer context, so a late answer would make the install outlast the budget (astra on #1081)
		if cerr := ctx.Err(); cerr != nil {
			refusals[i] = fmt.Errorf("peer %s: %w", root.ID, errors.Join(cerr, err))
			return b, false, i, nil
		}
		if err == nil && accept != nil {
			if aerr := accept(b); aerr != nil {
				err = fmt.Errorf("%w: %w", errInvalidPeerBundle, aerr)
			}
			if cerr := ctx.Err(); cerr != nil {
				refusals[i] = fmt.Errorf("peer %s: authenticated after the wait ended: %w", root.ID, errors.Join(cerr, err))
				return b, false, i, nil
			}
		}
		if err == nil {
			return b, true, -1, nil
		}
		refusals[i] = fmt.Errorf("peer %s: %w", root.ID, err)
	}
	return b, false, -1, nil
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
	if r.wait <= 0 || len(peers) == 0 {
		return fetchFromRootPeers(ctx, peers, request, accept)
	}
	ctx, cancel := context.WithTimeout(ctx, r.wait)
	defer cancel()
	var zero B
	// last holds every peer's latest refusal over all sweeps: a wait that ends at the start of a sweep, or part way through one, still
	// reports why each peer refused when it was last asked (#1171), not only the expiry. A request the end of the wait overtook is no
	// refusal of its peer: it is reported along with that peer's previous one.
	last := make([]error, len(peers))
	ended := func(attempt int) (B, error) {
		return zero, fmt.Errorf("after %d attempts within %s: %w", attempt, r.wait, errors.Join(append([]error{ctx.Err()}, last...)...))
	}
	delay := r.first
	for attempt := 1; ; attempt++ {
		refusals := make([]error, len(peers))
		b, ok, cut, _ := sweepRootPeers(ctx, peers, request, accept, refusals)
		for i, err := range refusals {
			switch {
			case err == nil:
			case i == cut:
				last[i] = errors.Join(err, last[i])
			default:
				last[i] = err
			}
		}
		if ctx.Err() != nil {
			return ended(attempt)
		}
		if ok {
			return b, nil
		}
		if waiting != nil {
			waiting(attempt, errors.Join(refusals...))
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ended(attempt)
		case <-timer.C:
		}
		delay = min(2*delay, r.max)
	}
}
