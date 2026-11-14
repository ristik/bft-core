package shardnode

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/unicitynetwork/bft-core/network/protocol/handshake"
)

// Catching up with a root activation (#1074). A root handoff restarts the roots, so the subscriptions they keep in memory are gone, and the
// shard's last request, built on the closed epoch's certificate, is refused by the new epoch's freshness rule (#1036/#1051) by design. The
// new epoch's first ordinary block recertifies the shard, but nobody is subscribed to receive that certificate: before this, the shard sat
// idle until its InactivityTimeout (30 s, checked every heartbeat) re-handshook, which made every handoff cost a constant ~37 s of blocks.
//
// Instead, as soon as this node has installed a root epoch later than the epoch of the certificate it holds, it handshakes with the roots of
// THAT installed epoch (the epoch is passed explicitly: the handshake never falls back to the held certificate's committee), at once, then
// with a jittered, capped backoff until it adopts a certificate of that epoch; a further activation resets it. A handshake answer subscribes
// it, so the recertification reaches it the moment it is certified. Each send is admitted last: under the role token captured before its
// preparation, and only while the installed epoch is still its target. Nothing here admits a certificate: those that arrive are verified and
// admitted exactly as before.

const (
	// activationHandshakeEvery is the first delay between catch-up handshakes: the new committee's roots come up one after another and a
	// handshake to one still restarting is lost. It doubles per handshake up to activationHandshakeMax, each with up to half of it of jitter.
	activationHandshakeEvery = time.Second
	activationHandshakeMax   = 8 * time.Second
)

// errActivationRetarget stops a catch-up handshake whose target is no longer the installed epoch: a further activation landed during its
// preparation. The next tick targets the new epoch at once.
var errActivationRetarget = errors.New("shardnode: a further root activation landed during the catch-up handshake")

// activationCatchUp is Run's memory of the root epoch it is catching up with. Run alone touches it.
type activationCatchUp struct {
	epoch uint64    // the installed root epoch being caught up with, zero when none
	next  time.Time // when the next catch-up handshake is due
	sent  int       // catch-up handshakes sent for epoch
}

// activationBackoff is the delay after the n-th catch-up handshake of an epoch: activationHandshakeEvery doubled per handshake, capped at
// activationHandshakeMax, plus a jitter of up to half of it so that a shard's validators do not ask in step.
func activationBackoff(n int) time.Duration {
	d := activationHandshakeEvery
	for i := 1; i < n && d < activationHandshakeMax; i++ {
		d *= 2
	}
	d = min(d, activationHandshakeMax)
	return d + time.Duration(rand.Int64N(int64(d/2)+1))
}

// heldRootEpoch is the root epoch of the certificate this client holds, and whether it holds one.
func (c *BFTClient) heldRootEpoch() (uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.luc == nil {
		return 0, false
	}
	return c.luc.GetRootEpoch(), true
}

// catchUpActivation handshakes with the installed epoch's roots while this node holds a certificate of an earlier root epoch than the one it
// installed: at once when the installation is first seen, then with the backoff, until a certificate of that epoch is adopted.
func (c *BFTClient) catchUpActivation(ctx context.Context, now time.Time) {
	installed, known := c.installedRootEpoch()
	held, holds := c.heldRootEpoch()
	if !known || !holds || installed <= held || c.isFollower() {
		c.activation = activationCatchUp{} // caught up, nothing installed beyond the held certificate, or not this node's to ask
		return
	}
	if c.activation.epoch != installed {
		c.activation = activationCatchUp{epoch: installed, next: now} // a (further) activation: the first catch-up is immediate
		if c.log != nil {
			c.log.InfoContext(ctx, "root epoch installed beyond the held certificate: asking its roots for the new epoch's certificate",
				slog.Uint64("installedRootEpoch", installed), slog.Uint64("heldRootEpoch", held))
		}
	}
	if now.Before(c.activation.next) {
		return
	}
	c.activation.sent++
	c.activation.next = now.Add(activationBackoff(c.activation.sent))
	switch err := c.sendCatchUpHandshake(ctx, installed); {
	case err == nil:
	case errors.Is(err, errActivationRetarget):
		c.activation = activationCatchUp{} // the next tick targets the newer epoch, immediately
	case errors.Is(err, ErrFollower):
		// the role ended (or was re-published) during the preparation: nothing was sent
	default:
		if c.log != nil {
			c.log.WarnContext(ctx, "catch-up handshake after a root activation failed", slog.Uint64("installedRootEpoch", installed), slog.String("err", err.Error()))
		}
	}
}

// sendCatchUpHandshake sends a handshake to roots of the target root epoch's own trust base. It is admitted last, immediately before the send:
// only while target is still the installed epoch (errActivationRetarget otherwise), while no certificate of it is held yet, and under the
// exact role token that was active when its preparation began (ErrFollower otherwise). The transport's role gater remains a separate guard.
func (c *BFTClient) sendCatchUpHandshake(ctx context.Context, target uint64) error {
	role := c.role.Load()
	token, active := role.current()
	if !active {
		return nil // a non-active follower does not subscribe to the roots
	}
	tb, err := c.trustBaseStore.GetByEpoch(ctx, target)
	if err != nil {
		return &trustBaseLoadError{epoch: target, err: err}
	}
	rootIDs, err := randomNodeSelector(tb, c.opts.HandshakeNodes)
	if err != nil {
		return fmt.Errorf("selecting root nodes of root epoch %d for the catch-up handshake: %w", target, err)
	}
	if installed, ok := c.installedRootEpoch(); !ok || installed != target {
		return errActivationRetarget
	}
	if held, ok := c.heldRootEpoch(); ok && held >= target {
		return nil // caught up during the preparation
	}
	if !c.role.Load().admits(token) {
		return ErrFollower
	}
	msg := handshake.Handshake{PartitionID: c.partitionID, ShardID: c.shardID, NodeID: c.nodeID}
	if err := c.net.Send(ctx, msg, rootIDs...); err != nil {
		return fmt.Errorf("sending the catch-up handshake: %w", err)
	}
	return nil
}
