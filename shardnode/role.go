package shardnode

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
