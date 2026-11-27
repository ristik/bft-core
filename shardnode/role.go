package shardnode

import "context"

// In-flight policy. A role lease is checked immediately before EACH irreversible action: the prepared Engine build closure, the seal,
// the candidate's retention, its publication, the signature, and every send of a request (bound to the token it was signed under). An
// action admitted before a revocation is published completes (an Engine, authority or network call already in progress is not
// interrupted); no action starts after it. The independent signing authority remains the guard of the signature itself.

// RoleLease is the node's published role. active is true only once the activation that made this node a validator has completed (every
// installation step, and the runtime's completion), and false at once when an installed assignment no longer names it. token identifies
// the role publication: work started under one lease must re-check it before any irreversible action (build, signature, send) and stop
// if the role is no longer active or the token changed.
type RoleLease interface {
	Lease() (token uint64, active bool)
}

// funcRole adapts a non-active predicate to a lease (token 0: only the active bit is compared).
type funcRole struct{ nonActive func() bool }

func (f funcRole) Lease() (uint64, bool) { return 0, !f.nonActive() }

// roleHolder is the optional lease a component reads; nil means always active (no follower role configured).
type roleHolder struct{ lease RoleLease }

func (h *roleHolder) current() (uint64, bool) {
	if h == nil || h.lease == nil {
		return 0, true
	}
	return h.lease.Lease()
}

type roleTokenKey struct{}

// withRoleToken binds a context's sends to the role token the request was produced under.
func withRoleToken(ctx context.Context, token uint64) context.Context {
	return context.WithValue(ctx, roleTokenKey{}, token)
}

// roleTokenOf is the token a context's sends are bound to.
func roleTokenOf(ctx context.Context) (uint64, bool) {
	t, ok := ctx.Value(roleTokenKey{}).(uint64)
	return t, ok
}

// admits reports whether the role still admits an action begun under token: active, with the same token.
func (h *roleHolder) admits(token uint64) bool {
	current, active := h.current()
	return active && current == token
}
