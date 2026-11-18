package vrschedule

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// PoPProvider makes the EVM possession proof a successor member owes its intent (VT-09, astra's design for #1201). Both implementations
// make the same bytes: evmassign's possession message over the canonical context (vrhandoff.PoPContext), signed by the EVM key. They differ
// in where the key is: in this process (LocalPoP) or in the node's signing authority (AuthorityPoP), which checks the request against its
// own enrollment before it signs.
//
// The provider returns the proof only. The member wraps it with the intent digest, verifies it (vrhandoff.VerifyPoP) against the intent and
// persists it before anything is released, so a provider that returns a wrong proof (another key, another message) is caught here.
type PoPProvider interface {
	SignHandoffPoP(ctx context.Context, ctxt evmassign.PoPContext, successor *types.PartitionDescriptionRecord, evmNodeID string) (evmassign.PoP, error)
}

// LocalPoP signs with an EVM key held in this process.
type LocalPoP struct {
	Signer abcrypto.Signer
}

// SignHandoffPoP implements PoPProvider.
func (l LocalPoP) SignHandoffPoP(_ context.Context, ctxt evmassign.PoPContext, successor *types.PartitionDescriptionRecord, evmNodeID string) (evmassign.PoP, error) {
	if l.Signer == nil {
		return evmassign.PoP{}, errors.New("no EVM key")
	}
	return evmassign.SignPoP(l.Signer, ctxt, successor, evmNodeID)
}

// HandoffPoPSigner is the authority's possession-proof operation as the member reaches it (service.PoPClient, or service.OperatorClient).
type HandoffPoPSigner interface {
	SignHandoffPoP(ctx context.Context, req signingauthority.HandoffPoPRequest) (evmassign.PoP, error)
}

// AuthorityPoPTimeout bounds one call to the authority.
const AuthorityPoPTimeout = 20 * time.Second

// AuthorityPoP asks the node's signing authority, which holds the EVM key and signs nothing but the structured handoff proof: the request
// carries the canonical context and the successor assignment, never bytes to sign. The authority keeps its enrollment, health, retirement,
// epoch-range, predecessor and node-id/key checks.
type AuthorityPoP struct {
	Client HandoffPoPSigner
}

// SignHandoffPoP implements PoPProvider.
func (a AuthorityPoP) SignHandoffPoP(ctx context.Context, ctxt evmassign.PoPContext, successor *types.PartitionDescriptionRecord, evmNodeID string) (evmassign.PoP, error) {
	if a.Client == nil {
		return evmassign.PoP{}, errors.New("no authority")
	}
	ctx, cancel := context.WithTimeout(ctx, AuthorityPoPTimeout)
	defer cancel()
	return a.Client.SignHandoffPoP(ctx, signingauthority.HandoffPoPRequest{Domain: evmassign.PoPDomain, Context: ctxt, Successor: successor, NodeID: evmNodeID})
}

// offerPoP is stage 2's proof: the provider signs the canonical context of the intent for this member's EVM node, and the member wraps it
// with the intent digest. It does not verify or persist (stepPoP does, before release).
func (m *Member) offerPoP(st memberState) (vrhandoff.PoPOffer, error) {
	ctxt, succ, err := vrhandoff.PoPContext(st.intent)
	if err != nil {
		return vrhandoff.PoPOffer{}, err
	}
	d, err := st.intent.Digest()
	if err != nil {
		return vrhandoff.PoPOffer{}, errors.Join(vrhandoff.ErrIntent, err)
	}
	p, err := m.cfg.EVMPoP.SignHandoffPoP(context.Background(), ctxt, succ, st.self.EVMNodeID)
	if err != nil {
		return vrhandoff.PoPOffer{}, fmt.Errorf("the provider: %w", err)
	}
	return vrhandoff.PoPOffer{IntentDigest: d[:], EVMNodeID: st.self.EVMNodeID, PoP: p}, nil
}
