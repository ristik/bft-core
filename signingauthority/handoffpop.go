package signingauthority

import (
	"bytes"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-go-base/types"
)

// HandoffPoPRequest asks the authority for the possession proof its own key owes a coupled handoff. Every field is checked against
// the authority's immutable enrollment: it carries no bytes to sign.
type HandoffPoPRequest struct {
	// Domain must be evmassign.PoPDomain.
	Domain string
	// Context is the attempt context the proof binds (network, predecessor root body, attempt, frozen parent), as printed by
	// `root handoff evm-context`.
	Context evmassign.PoPContext
	// Successor is the candidate binding: the successor configuration of the enrolled shard (next shard epoch, EpochStart zero)
	// whose validator set names this authority's node with this authority's key.
	Successor *types.PartitionDescriptionRecord
	// NodeID is the validator the proof is for; it must be the enrolled node.
	NodeID string
}

/*
SignHandoffPoP signs the one message a handoff possession proof is: evmassign.PoPMessage for this authority's own key, the given
candidate binding and the given attempt context. It is the single, narrow exception to "no generic signing":

  - the message is built here, by evmassign, from structured fields; the caller supplies no bytes and chooses no domain (a request
    naming another domain is refused with ErrPoPDomain);
  - the proof is for the enrolled node and the key this authority generated, for the enrolled network, partition and shard, and for
    the enrolled shard epoch or the one after it (a joining validator's authority may still be pending its configuration, which
    cannot name it before the handoff): anything else is ErrContextMismatch;
  - the successor must be a well-formed assignment that names this node with this key, and the context must name a nonzero
    predecessor and frozen parent.

It does not touch the signing record: a possession proof is not a certification round, cannot be mistaken for one (the message
begins with its own domain tag and a certification preimage cannot), and so cannot consume or replay a round. It is served on the
operator channel only (see service); a shard node's client channel never reaches it.
*/
func (a *Authority) SignHandoffPoP(req HandoffPoPRequest) (evmassign.PoP, error) {
	if req.Domain != evmassign.PoPDomain {
		return evmassign.PoP{}, fmt.Errorf("%w: %q", ErrPoPDomain, req.Domain)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.signer == nil {
		return evmassign.PoP{}, ErrKeyLost
	}
	if a.state != healthActive {
		return evmassign.PoP{}, ErrStateUntrusted
	}
	enroll := a.enroll
	succ := req.Successor
	switch {
	case succ == nil:
		return evmassign.PoP{}, fmt.Errorf("%w: no successor binding", ErrContextMismatch)
	case req.NodeID != enroll.NodeID:
		return evmassign.PoP{}, fmt.Errorf("%w: this authority signs for node %s, not %s", ErrContextMismatch, enroll.NodeID, req.NodeID)
	case req.Context.Network != uint64(enroll.NetworkID) || succ.NetworkID != enroll.NetworkID:
		return evmassign.PoP{}, fmt.Errorf("%w: another network", ErrContextMismatch)
	case succ.PartitionID != enroll.PartitionID || !succ.ShardID.Equal(enroll.ShardID):
		return evmassign.PoP{}, fmt.Errorf("%w: another partition or shard", ErrContextMismatch)
	case succ.Epoch != enroll.ShardEpoch+1 && succ.Epoch != enroll.ShardEpoch:
		// A retained validator is enrolled at the installed shard epoch and proves for the next one; a joining validator's authority
		// is enrolled (possibly still pending) for the successor epoch itself, which no installed configuration names yet.
		return evmassign.PoP{}, fmt.Errorf("%w: the successor is shard epoch %d, this authority is enrolled for %d", ErrContextMismatch, succ.Epoch, enroll.ShardEpoch)
	case req.Context.Predecessor == [32]byte{}:
		return evmassign.PoP{}, fmt.Errorf("%w: the context names no predecessor", ErrContextMismatch)
	}
	if err := evmassign.ValidateAssignment(succ); err != nil {
		return evmassign.PoP{}, fmt.Errorf("%w: %v", ErrContextMismatch, err)
	}
	pub, err := publicKeyOf(a.signer)
	if err != nil {
		return evmassign.PoP{}, err
	}
	named := false
	for _, v := range succ.Validators {
		if v.NodeID == enroll.NodeID {
			named = bytes.Equal(v.SigKey, pub)
		}
	}
	if !named {
		return evmassign.PoP{}, fmt.Errorf("%w: the successor does not name this node with this authority's key", ErrContextMismatch)
	}
	return evmassign.SignPoP(a.signer, req.Context, succ, enroll.NodeID)
}
