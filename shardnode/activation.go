package shardnode

import (
	"context"
	"log/slog"
	"time"
)

// Catching up with a root activation (#1074). A root handoff restarts the roots, so the subscriptions they keep in memory are gone, and the
// shard's last request, built on the closed epoch's certificate, is refused by the new epoch's freshness rule (#1036/#1051) by design. The
// new epoch's first ordinary block recertifies the shard, but nobody is subscribed to receive that certificate: before this, the shard sat
// idle until its InactivityTimeout (30 s, checked every heartbeat) re-handshook, which made every handoff cost a constant ~37 s of blocks.
//
// Instead, as soon as this node has installed a root epoch later than the epoch of the certificate it holds, it handshakes with the roots of
// the installed epoch at once, and again every activationHandshakeEvery, until it adopts a certificate of that epoch. A handshake answer
// subscribes it, so the recertification reaches it the moment it is certified. Nothing here admits anything: the certificates that arrive are
// verified and admitted exactly as before.

// activationHandshakeEvery is the cadence of the catch-up handshakes after a root activation: short, because the new committee's roots come
// up one after another and a handshake to one still restarting is lost; each handshake is a few hundred bytes to a few roots.
const activationHandshakeEvery = time.Second

// activationCatchUp is Run's memory of the root epoch it is catching up with. Run alone touches it.
type activationCatchUp struct {
	epoch uint64    // the installed root epoch being caught up with, zero when none
	next  time.Time // when the next catch-up handshake is due
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
// installed: at once when the installation is first seen, then every activationHandshakeEvery, until a certificate of that epoch is adopted.
func (c *BFTClient) catchUpActivation(ctx context.Context, now time.Time) {
	installed, known := c.installedRootEpoch()
	held, holds := c.heldRootEpoch()
	if !known || !holds || installed <= held || c.isFollower() {
		c.activation = activationCatchUp{} // caught up, nothing installed beyond the held certificate, or not this node's to ask
		return
	}
	if c.activation.epoch != installed {
		c.activation = activationCatchUp{epoch: installed, next: now}
		if c.log != nil {
			c.log.InfoContext(ctx, "root epoch installed beyond the held certificate: asking its roots for the new epoch's certificate",
				slog.Uint64("installedRootEpoch", installed), slog.Uint64("heldRootEpoch", held))
		}
	}
	if now.Before(c.activation.next) {
		return
	}
	c.activation.next = now.Add(activationHandshakeEvery)
	if err := c.sendHandshake(ctx); err != nil && c.log != nil {
		c.log.WarnContext(ctx, "catch-up handshake after a root activation failed", slog.Uint64("installedRootEpoch", installed), slog.String("err", err.Error()))
	}
}
