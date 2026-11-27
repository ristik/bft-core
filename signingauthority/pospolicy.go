package signingauthority

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strconv"
	"time"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The P85 election's possession proofs under a signing authority (#1216). The proof-of-stake module (the PosElectionAdapter over P85) takes
// two EVM possession signatures from each elected member's key: the delegation possession of ElectionPolicy.admitDelegation and the
// assignment possession of ElectionPolicy.submitAssignmentPoPs (Election.popDigest). The first is SignDelegationPossession; the second is
// SignPosPoP, which unlike SignElectionPoP does not need a candidate: the proof-of-stake relayer reads the frozen result's fields from the
// election itself, so the request is those fields.
//
// The pin is the scope all three P85 signatures are valid in: the election's network word, the chain id and the ElectionPolicy address
// (the digest domain), and the identity ids this authority's key may prove for. A request outside it is refused. The key signs only
// evmassign.PoPDigest and the delegation digest, keccak digests under their own domain tags that a certification preimage cannot equal.
//
// The pin is verified, not taken (#1222). The deployment fields are derived from the authority's own execution client, under the pins its
// activation fence already relies on: the execution genesis hash and VR's runtime hash from the b1 profile. The client's EVM chain id
// must equal the chain id of the enrolled shard configuration, or before the enrollment is complete the trusted b1 profile's
// ExecutionChainID. Every id must be a VR identity whose current or staged binding names this node with this key (PosSource). A field the
// pin supplies must equal the derived one. A startup pin (WithPosPolicy) and a late one (SetPosPolicy, the operator channel) go through
// the same check. The first verified pin is final for the authority's lifetime: the same pin again succeeds and another is
// ErrPosPolicyConflict. Until a pin is verified, the three signing operations are refused; a source that cannot be read leaves the pin
// pending (ErrPosPending) rather than refused. A shard configuration installed later with another chain id latches the authority faulted.
//
// The authority trusts its execution client as the fence does. A client that fabricates its replies can still mislead it; that threat
// needs proofs against a certified state root, which this does not do.

// ErrPosPolicy is a P85 possession request that the authority's pin does not allow, or a pin that the deployment does not confirm: no
// verified pin, another deployment, or an identity the pin does not list or VR does not bind to this node and key.
var ErrPosPolicy = errors.New("signing-pos-policy-refused")

// ErrPosPolicyConflict is an attempt to pin a different election than the one already pinned.
var ErrPosPolicyConflict = errors.New("signing-pos-policy-conflict")

// ErrPosPending is a pin that could not be verified yet: the execution source is not provisioned or did not answer, or an id is not
// registered at the block read. Nothing was found wrong; retry. Signing stays refused meanwhile.
var ErrPosPending = errors.New("signing-pos-policy-pending")

// posVerifyTimeout bounds the verification a signing request triggers for a pending startup pin.
const posVerifyTimeout = 10 * time.Second

// PosPolicy is the scope of the P85 possession signatures. In a pin to install, a zero Network, ChainID or Election is derived from
// the deployment; a verified pin has all four.
type PosPolicy struct {
	Network  [32]byte
	ChainID  [32]byte
	Election [20]byte
	// IDs are the identity ids (custody StakingIDs) this authority's key may prove for.
	IDs []uint64
}

// PosQuery is what the deployment is read for: this authority's EVM node and key, and the ids a pin lists.
type PosQuery struct {
	NodeID string
	EVMKey []byte
	IDs    []uint64
}

// PosDeploymentView is the deployment a PosSource derived: the network word, the EVM chain id the execution client reports, and the
// election.
type PosDeploymentView struct {
	Network  [32]byte
	ChainID  [32]byte
	Election [20]byte
}

// PosSource reads the P85 deployment from the authority's execution client and checks the queried ids' VR bindings. An error wrapping
// ErrPosPending is a read to retry; any other error refuses the pin.
type PosSource interface {
	ReadPosDeployment(ctx context.Context, q PosQuery) (PosDeploymentView, error)
}

func (p PosPolicy) validIDs() error {
	if len(p.IDs) == 0 {
		return fmt.Errorf("%w: the pin lists no identity", ErrPosPolicy)
	}
	for _, id := range p.IDs {
		if id == 0 {
			return fmt.Errorf("%w: identity 0", ErrPosPolicy)
		}
	}
	return nil
}

func sameIDs(a, b []uint64) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

// compatible reports whether two pins can name the same scope: the same ids, and no field both state differently (a zero field is
// one to derive).
func (p PosPolicy) compatible(q PosPolicy) bool {
	return sameIDs(p.IDs, q.IDs) &&
		(p.Network == [32]byte{} || q.Network == [32]byte{} || p.Network == q.Network) &&
		(p.ChainID == [32]byte{} || q.ChainID == [32]byte{} || p.ChainID == q.ChainID) &&
		(p.Election == [20]byte{} || q.Election == [20]byte{} || p.Election == q.Election)
}

func (p PosPolicy) clone() PosPolicy {
	p.IDs = slices.Clone(p.IDs)
	return p
}

func chainWord(id uint64) [32]byte {
	var w [32]byte
	new(big.Int).SetUint64(id).FillBytes(w[:])
	return w
}

// confChainID is a shard configuration's chain_id partition parameter, in its canonical base-10 form.
func confChainID(conf *types.PartitionDescriptionRecord) (uint64, bool) {
	raw, ok := conf.PartitionParams["chain_id"]
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || id == 0 || strconv.FormatUint(id, 10) != raw {
		return 0, false
	}
	return id, true
}

// WithRequirePosPolicy makes every P85 possession signature (SignElectionPoP, SignDelegationPossession, SignPosPoP) refused until a pin is
// verified. A pinned authority, or one with a P85 source, refuses them so anyway; without any of the three, an authority keeps the
// earlier behavior of the first two (the deployment from the request).
func WithRequirePosPolicy() Option {
	return func(a *Authority) error { a.requirePos = true; return nil }
}

// WithPosSource gives the authority the P85 deployment source pins are verified against, and the trusted b1 profile's ExecutionChainID
// (zero: none; then no pin is verified before the enrollment is complete).
func WithPosSource(src PosSource, b1Chain uint64) Option {
	return func(a *Authority) error {
		if src == nil {
			return errors.New("no P85 deployment source")
		}
		a.posSource, a.posB1Chain = src, b1Chain
		return nil
	}
}

// ProvisionPosSource gives a running authority its P85 deployment source, once: for the pre-genesis enrollment mode, whose execution
// source is known only when the fence is provisioned.
func (a *Authority) ProvisionPosSource(src PosSource, b1Chain uint64) error {
	if src == nil {
		return errors.New("signingauthority: no P85 deployment source to provision")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.posSource != nil {
		return errors.New("signingauthority: this authority already has its P85 deployment source")
	}
	a.posSource, a.posB1Chain = src, b1Chain
	return nil
}

// WithPosPolicy states the pin at startup. It is verified like a late pin, on the first P85 signing request or VerifyPosPolicy, and
// nothing is signed before it is. A startup pin is never replaced: a late pin must agree with it.
func WithPosPolicy(p PosPolicy) Option {
	own := p.clone() // a private copy: the option may be reused and the caller's slice may change
	return func(a *Authority) error {
		if err := own.validIDs(); err != nil {
			return err
		}
		if a.posWant != nil && !a.posWant.compatible(own) {
			return fmt.Errorf("%w: two different startup pins", ErrPosPolicyConflict)
		}
		q := own.clone()
		a.posWant, a.posWantStartup = &q, true
		return nil
	}
}

// SetPosPolicy installs a pin on a running authority: the operator's late path, for a joiner that learns its id at registration or a
// member whose election is deployed in the genesis after the authority started. It is verified exactly as a startup pin. If the source
// cannot be read now, the pin is kept pending (ErrPosPending) and verified on the next P85 signing request or VerifyPosPolicy; nothing
// is signed meanwhile. A later late pin replaces a pending one: an unverified pin restricts nothing, so it must not lock the authority.
func (a *Authority) SetPosPolicy(ctx context.Context, p PosPolicy) error {
	return a.installPos(ctx, p.clone())
}

// VerifyPosPolicy verifies the pending pin, if there is one. It reports whether this call installed it.
func (a *Authority) VerifyPosPolicy(ctx context.Context) (bool, error) {
	a.mu.Lock()
	want, done := a.posWant, a.pos != nil
	a.mu.Unlock()
	if done || want == nil {
		return false, nil
	}
	if err := a.installPos(ctx, want.clone()); err != nil {
		return false, err
	}
	return true, nil
}

// posChainLocked is the chain id a pin is verified against: the enrolled shard configuration's, or before the enrollment is complete the
// b1 profile's. An authority enrolled with a bare hash at New (no configuration it could read) has only the b1 profile's.
func (a *Authority) posChainLocked() (uint64, error) {
	switch {
	case a.confSeen && !a.confChainKnown:
		return 0, fmt.Errorf("%w: the enrolled shard configuration names no chain id", ErrPosPolicy)
	case a.confSeen:
		return a.confChain, nil
	case a.posB1Chain != 0:
		return a.posB1Chain, nil
	}
	return 0, fmt.Errorf("%w: no chain id to verify against before the enrollment is complete (give the b1 profile)", ErrPosPending)
}

// installPos is the one check of a pin, startup or late: derive the deployment, compare, and install it if no other pin was.
func (a *Authority) installPos(ctx context.Context, p PosPolicy) error {
	if err := p.validIDs(); err != nil {
		return err
	}
	a.posInstall.Lock()
	defer a.posInstall.Unlock()

	a.mu.Lock()
	if a.pos != nil {
		ok := a.pos.compatible(p)
		a.mu.Unlock()
		if !ok {
			return fmt.Errorf("%w: this authority is pinned to another election or identity set", ErrPosPolicyConflict)
		}
		return nil
	}
	if a.posWantStartup {
		if !a.posWant.compatible(p) {
			a.mu.Unlock()
			return fmt.Errorf("%w: this authority's startup pin names another election or identity set", ErrPosPolicyConflict)
		}
		p = a.posWant.clone() // the startup pin is what is verified
	}
	src, waiting := a.posSource, a.fencePending
	chain, chainErr := a.posChainLocked()
	node := a.enroll.NodeID
	var pub []byte
	var err error
	switch {
	case a.signer == nil:
		err = ErrKeyLost
	case a.state != healthActive:
		err = ErrStateUntrusted
	default:
		pub, err = publicKeyOf(a.signer)
	}
	a.mu.Unlock()
	switch {
	case err != nil:
		return err
	case src == nil && !waiting:
		return fmt.Errorf("%w: this authority has no execution source to verify a P85 pin against (--activation-source-url on a VR generation)", ErrPosPolicy)
	}

	verified, err := a.verifyPos(ctx, src, chain, chainErr, node, pub, p)
	a.mu.Lock()
	defer a.mu.Unlock()
	if err == nil && a.state != healthActive {
		err = ErrStateUntrusted
	}
	if err == nil {
		if now, cerr := a.posChainLocked(); cerr != nil || now != chain {
			err = fmt.Errorf("%w: the shard configuration changed while the pin was verified; retry", ErrPosPending)
		}
	}
	switch {
	case err == nil:
		a.pos, a.posWant, a.posWantStartup = &verified, nil, false
		return nil
	case a.posWantStartup:
		// the startup pin stays as it is: pending, or refused for the authority's lifetime
	case errors.Is(err, ErrPosPending):
		a.posWant = &p // kept pending, verified on the next signing request
	default:
		a.posWant = nil // a refused late pin installs nothing and holds nothing
	}
	return err
}

// verifyPos reads the deployment and checks the pin against it, outside the lock.
func (a *Authority) verifyPos(ctx context.Context, src PosSource, chain uint64, chainErr error, node string, pub []byte, p PosPolicy) (PosPolicy, error) {
	switch {
	case src == nil:
		return PosPolicy{}, fmt.Errorf("%w: the execution source is provisioned with the fence, which is still pending", ErrPosPending)
	case chainErr != nil:
		return PosPolicy{}, chainErr
	}
	view, err := src.ReadPosDeployment(ctx, PosQuery{NodeID: node, EVMKey: pub, IDs: slices.Clone(p.IDs)})
	if err != nil {
		if errors.Is(err, ErrPosPending) {
			return PosPolicy{}, err
		}
		return PosPolicy{}, fmt.Errorf("%w: %w", ErrPosPolicy, err)
	}
	want := chainWord(chain)
	switch {
	case view.Network == [32]byte{} || view.Election == [20]byte{}:
		return PosPolicy{}, fmt.Errorf("%w: the source derived no network word or election", ErrPosPolicy)
	case view.ChainID != want:
		return PosPolicy{}, fmt.Errorf("%w: the execution client is on chain %s, the authority's chain is %d", ErrPosPolicy, new(big.Int).SetBytes(view.ChainID[:]), chain)
	case p.ChainID != [32]byte{} && p.ChainID != want:
		return PosPolicy{}, fmt.Errorf("%w: the pin names chain %s, the authority's chain is %d", ErrPosPolicy, new(big.Int).SetBytes(p.ChainID[:]), chain)
	case p.Network != [32]byte{} && p.Network != view.Network:
		return PosPolicy{}, fmt.Errorf("%w: the pin names network word %x, VR's is %x", ErrPosPolicy, p.Network, view.Network)
	case p.Election != [20]byte{} && p.Election != view.Election:
		return PosPolicy{}, fmt.Errorf("%w: the pin names election %x, VR's PoS adapter names %x", ErrPosPolicy, p.Election, view.Election)
	}
	return PosPolicy{Network: view.Network, ChainID: want, Election: view.Election, IDs: slices.Clone(p.IDs)}, nil
}

// noteConfLocked records the chain id of a shard configuration the authority installs (its enrollment's or an advance's). One that
// disagrees with a verified pin latches the authority faulted: its pin was verified against another chain than it now signs for.
func (a *Authority) noteConfLocked(conf *types.PartitionDescriptionRecord) error {
	a.confChain, a.confChainKnown = confChainID(conf)
	a.confSeen = true
	if a.pos != nil && (!a.confChainKnown || chainWord(a.confChain) != a.pos.ChainID) {
		a.state = healthFaulted
		return fmt.Errorf("%w: the shard configuration's chain id is not the one the P85 pin was verified for", ErrStateUntrusted)
	}
	return nil
}

// posPrepare verifies a pending startup pin before a P85 signing request takes the lock (a source that cannot be read leaves it pending,
// and the request is then refused).
func (a *Authority) posPrepare() {
	ctx, cancel := context.WithTimeout(context.Background(), posVerifyTimeout)
	defer cancel()
	_, _ = a.VerifyPosPolicy(ctx)
}

// checkPosScope is the one check of all three P85 possession signatures against the pin. The caller holds a.mu.
func (a *Authority) checkPosScope(network, chain [32]byte, election [20]byte, id uint64) error {
	if a.pos == nil {
		if a.requirePos || a.posWant != nil || a.posSource != nil {
			return fmt.Errorf("%w: this authority has no verified P85 election pin", ErrPosPolicy)
		}
		return nil
	}
	if network != a.pos.Network || chain != a.pos.ChainID || election != a.pos.Election || !slices.Contains(a.pos.IDs, id) {
		return fmt.Errorf("%w: another election, chain, network word or identity than this authority's pin", ErrPosPolicy)
	}
	return nil
}

// PosPoPRequest asks for the assignment possession proof this authority's key owes one frozen member of a reserved result: the fields of
// Election.popDigest other than the pinned deployment and the key. ID is the member's identity; Generation its generation in the result.
type PosPoPRequest struct {
	ResultID, AssignmentID, Snapshot [32]byte
	Attempt, ID, Generation          uint64
}

// SignPosPoP signs evmassign.PoPDigest for this authority's own key under the pinned election, for a pinned identity, and nothing else.
func (a *Authority) SignPosPoP(req PosPoPRequest) (evmassign.EVMPoP, error) {
	if _, err := a.fenceGate(); err != nil {
		return evmassign.EVMPoP{}, err
	}
	a.posPrepare()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pos == nil {
		return evmassign.EVMPoP{}, fmt.Errorf("%w: this authority has no verified P85 election pin", ErrPosPolicy)
	}
	if err := a.checkPosScope(a.pos.Network, a.pos.ChainID, a.pos.Election, req.ID); err != nil {
		return evmassign.EVMPoP{}, err
	}
	if req.ResultID == [32]byte{} || req.AssignmentID == [32]byte{} || req.Snapshot == [32]byte{} || req.Generation == 0 {
		return evmassign.EVMPoP{}, fmt.Errorf("%w: the request names no result, assignment, snapshot or generation", ErrContextMismatch)
	}
	hs, pub, err := a.ethSigner()
	if err != nil {
		return evmassign.EVMPoP{}, err
	}
	var d evmassign.ElectionDeployment
	d.NetworkWord, d.ChainID, d.Election = a.pos.Network, a.pos.ChainID, a.pos.Election
	digest := evmassign.PoPDigest(d, req.ResultID, req.AssignmentID, req.Snapshot, req.Attempt, req.ID, req.Generation, pub)
	sig, err := ethSign(hs, digest)
	if err != nil {
		return evmassign.EVMPoP{}, err
	}
	return evmassign.EVMPoP{ID: req.ID, EVMKey: pub, Signature: sig}, nil
}
