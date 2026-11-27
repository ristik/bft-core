package consensus

import (
	"context"
	"errors"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/unicitynetwork/bft-core/q3active"
)

// Q3EpochSwitch is the EpochSwitch of a root wired to a verified Q3 history (#1086): it captures the activation bundle from this root's
// own committed evidence, or adopts one a root peer served, authenticates it with the runtime (the history and the root's install checks,
// nothing written) and installs it with the runtime's Activate, the one path every activation takes: the journal stages the bundle and
// carries the root manager, the safety module and the other participants to completion, exactly as the install at a process start does.
type Q3EpochSwitch struct {
	Runtime *q3active.Runtime
	// Bundle is this root's own evidence of the activation into an epoch (the journal's staged bundle, else the committed checkpoint and
	// the artifacts retained at the Freeze).
	Bundle func(ctx context.Context, epoch uint64) (q3active.Bundle, error)
	// Fetch asks one root peer for the bundle of the activation into an epoch (q3delivery), for a root that does not hold the commit
	// itself: a joiner, a follower, a member that lagged (PR 2 of #1086). Nothing it returns is trusted: Adopt authenticates it against
	// this root's own history on the consensus loop, exactly as the install restart authenticates a peer's bundle. Nil: such a root installs
	// across a restart.
	Fetch func(ctx context.Context, from peer.ID, epoch uint64) (q3active.Bundle, error)
	// After re-derives, once the activation is complete, what the process derives from the installed epoch at its start (the request
	// history selection, the committee it keeps connected). Nil derives nothing.
	After func(ctx context.Context, epoch uint64) error
}

// ErrNoOwnActivation is returned when this root holds no authenticated activation of its own for the epoch.
var ErrNoOwnActivation = errors.New("consensus: no own authenticated activation to switch into")

// ErrNoPeerActivation is returned when a bundle a root peer served does not authenticate, or no peer served one.
var ErrNoPeerActivation = errors.New("consensus: no authenticated activation from a root peer")

func (s *Q3EpochSwitch) Capture(ctx context.Context, epoch uint64) (CapturedActivation, error) {
	if s == nil || s.Runtime == nil || s.Bundle == nil {
		return nil, ErrNoOwnActivation
	}
	b, err := s.Bundle(ctx, epoch)
	if err != nil {
		return nil, errors.Join(ErrNoOwnActivation, err)
	}
	c, err := s.authenticate(b, epoch)
	if err != nil {
		return nil, errors.Join(ErrNoOwnActivation, err)
	}
	return c, nil
}

// Acquires reports whether the switch can fetch an activation from a root peer.
func (s *Q3EpochSwitch) Acquires() bool { return s != nil && s.Runtime != nil && s.Fetch != nil }

// FetchActivation asks root peer from for its bundle of the activation into epoch and returns its canonical encoding. It runs off the
// consensus loop and authenticates nothing: AdoptActivation does, on the loop.
func (s *Q3EpochSwitch) FetchActivation(ctx context.Context, from peer.ID, epoch uint64) ([]byte, error) {
	if !s.Acquires() {
		return nil, ErrNoPeerActivation
	}
	b, err := s.Fetch(ctx, from, epoch)
	if err != nil {
		return nil, err
	}
	raw, err := q3active.EncodeBundle(b)
	if err != nil {
		return nil, err
	}
	// the canonical, bounded decoding and the epoch of the last link, before the loop spends an authentication on it
	if _, env, err := q3active.DecodeBundle(raw); err != nil {
		return nil, err
	} else if len(env.Links) == 0 || env.Links[len(env.Links)-1].Body.Epoch != epoch {
		return nil, fmt.Errorf("%w: the bundle does not activate epoch %d", ErrNoPeerActivation, epoch)
	}
	return raw, nil
}

// AdoptActivation authenticates a bundle a root peer served (FetchActivation) against this root's own history and install checks, as
// Capture does its own evidence; nothing is written.
func (s *Q3EpochSwitch) AdoptActivation(_ context.Context, raw []byte, epoch uint64) (CapturedActivation, error) {
	if s == nil || s.Runtime == nil {
		return nil, ErrNoPeerActivation
	}
	b, _, err := q3active.DecodeBundle(raw)
	if err != nil {
		return nil, errors.Join(ErrNoPeerActivation, err)
	}
	c, err := s.authenticate(b, epoch)
	if err != nil {
		return nil, errors.Join(ErrNoPeerActivation, err)
	}
	return c, nil
}

// authenticate checks a bundle against the runtime (Authenticate: the history and the root's install checks, nothing staged) and captures
// it immutably: the bytes are what Install stages.
func (s *Q3EpochSwitch) authenticate(b q3active.Bundle, epoch uint64) (*capturedQ3, error) {
	if err := s.Runtime.Authenticate(b); err != nil {
		return nil, err
	}
	raw, err := q3active.EncodeBundle(b)
	if err != nil {
		return nil, err
	}
	_, env, err := q3active.DecodeBundle(raw)
	if err != nil {
		return nil, err
	}
	if len(env.Links) == 0 {
		return nil, errors.New("the bundle carries no link")
	}
	link := env.Links[len(env.Links)-1]
	if link.Body.Epoch != epoch {
		return nil, fmt.Errorf("the bundle activates epoch %d, not %d", link.Body.Epoch, epoch)
	}
	members := make([]string, 0, len(link.Body.Members))
	for _, m := range link.Body.Members {
		members = append(members, m.NodeID)
	}
	id := link.Body.Identity()
	return &capturedQ3{s: s, epoch: epoch, raw: raw, members: members, body: id[:]}, nil
}

type capturedQ3 struct {
	s       *Q3EpochSwitch
	epoch   uint64
	raw     []byte
	members []string
	body    []byte
}

func (c *capturedQ3) Members() []string { return append([]string(nil), c.members...) }

// Identity is the activated body's identity: the name of a switch into an activation this root did not commit itself.
func (c *capturedQ3) Identity() []byte { return append([]byte(nil), c.body...) }

func (c *capturedQ3) Install(ctx context.Context) error {
	b, _, err := q3active.DecodeBundle(c.raw)
	if err != nil {
		return err
	}
	if err := c.s.Runtime.Activate(ctx, b); err != nil {
		return fmt.Errorf("activation of epoch %d: %w", c.epoch, err)
	}
	if c.s.After != nil {
		if err := c.s.After(ctx, c.epoch); err != nil {
			return fmt.Errorf("after the activation of epoch %d: %w", c.epoch, err)
		}
	}
	return nil
}
