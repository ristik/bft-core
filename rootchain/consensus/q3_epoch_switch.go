package consensus

import (
	"context"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/q3active"
)

// Q3EpochSwitch is the EpochSwitch of a root wired to a verified Q3 history (#1086): it captures the activation bundle from this root's
// own committed evidence, authenticates it with the runtime (the history and the root's install checks, nothing written) and installs it
// with the runtime's Activate, the one path every activation takes: the journal stages the bundle and carries the root manager, the
// safety module and the other participants to completion, exactly as the install at a process start does.
type Q3EpochSwitch struct {
	Runtime *q3active.Runtime
	// Bundle is this root's own evidence of the activation into an epoch (the journal's staged bundle, else the committed checkpoint and
	// the artifacts retained at the Freeze). A switch never takes a peer's bundle: a root that does not hold its own installs across a
	// restart.
	Bundle func(ctx context.Context, epoch uint64) (q3active.Bundle, error)
	// After re-derives, once the activation is complete, what the process derives from the installed epoch at its start (the request
	// history selection, the committee it keeps connected). Nil derives nothing.
	After func(ctx context.Context, epoch uint64) error
}

// ErrNoOwnActivation is returned when this root holds no authenticated activation of its own for the epoch.
var ErrNoOwnActivation = errors.New("consensus: no own authenticated activation to switch into")

func (s *Q3EpochSwitch) Capture(ctx context.Context, epoch uint64) (CapturedActivation, error) {
	if s == nil || s.Runtime == nil || s.Bundle == nil {
		return nil, ErrNoOwnActivation
	}
	b, err := s.Bundle(ctx, epoch)
	if err != nil {
		return nil, errors.Join(ErrNoOwnActivation, err)
	}
	if err := s.Runtime.Authenticate(b); err != nil {
		return nil, errors.Join(ErrNoOwnActivation, err)
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
		return nil, fmt.Errorf("%w: the bundle carries no link", ErrNoOwnActivation)
	}
	link := env.Links[len(env.Links)-1]
	if link.Body.Epoch != epoch {
		return nil, fmt.Errorf("%w: the bundle activates epoch %d, not %d", ErrNoOwnActivation, link.Body.Epoch, epoch)
	}
	members := make([]string, 0, len(link.Body.Members))
	for _, m := range link.Body.Members {
		members = append(members, m.NodeID)
	}
	// the bytes are what Install stages: the capture is immutable from here on
	return &capturedQ3{s: s, epoch: epoch, raw: raw, members: members}, nil
}

type capturedQ3 struct {
	s       *Q3EpochSwitch
	epoch   uint64
	raw     []byte
	members []string
}

func (c *capturedQ3) Members() []string { return append([]string(nil), c.members...) }

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
