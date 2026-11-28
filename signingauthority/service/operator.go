package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-go-base/types"
)

/*
OperatorClient is the control plane's end of the boundary.

It exists so that the operations a shard node must never perform have somewhere else to live: it
replaces the session, reads status and reads the enrollment, and it cannot reserve, sign, retain or
release. Its credential is the operator's, not the shard's, and neither endpoint accepts the other's.

Issuing a session is an operator act with a consequence: the previous client is fenced. That is the
intended way to take a shard process out of service and the reason this is not something the shard
can ask for.
*/
type OperatorClient struct {
	ex *exchange
}

// NewOperatorClient provisions the control-plane client.
func NewOperatorClient(cfg ClientConfig) (*OperatorClient, error) {
	if cfg.Dial == nil {
		return nil, errors.New("service: no dialer for the authority")
	}
	if len(cfg.Credential) < CredentialBytes {
		return nil, fmt.Errorf("service: the operator credential must be at least %d bytes", CredentialBytes)
	}
	return &OperatorClient{ex: newExchange(cfg)}, nil
}

func (o *OperatorClient) Close() error {
	return o.ex.close()
}

/*
ReplaceSession fences the current client and returns the credential for the next one.

The credential is returned once. The authority does not store it in a form it can hand out again, so
an operator that loses it replaces the session again, which fences again: losing a credential is not
a way to recover one.

Two operators replacing at the same time are serialised by the authority, and the credential the
server admits afterwards belongs to the session it is holding. One of the two is fenced on arrival,
the same as any other replaced client, and its holder learns that from the first operation it tries.
*/
func (o *OperatorClient) ReplaceSession(ctx context.Context) ([]byte, error) {
	return o.ex.call(ctx, opReplaceSession, nil)
}

// ReplaceSessionFor deliberately fences the configured client in favor of an
// operator-managed credential at a different target. Legacy servers ignore the target.
func (o *OperatorClient) ReplaceSessionFor(ctx context.Context, target string) ([]byte, error) {
	payload, err := types.Cbor.Marshal(target)
	if err != nil {
		return nil, err
	}
	return o.ex.call(ctx, opReplaceSession, payload)
}

// SessionPublication describes the managed publication requested by the operator.
// ActiveAlternate names an admitted alternate destination relative to the operator
// socket when a non-forced managed operation preserves that session.
type SessionPublication struct {
	Managed         bool
	Issued          bool
	ActiveAlternate string
}

// PublishSession asks the authority to publish its configured credential. A different
// target or a legacy server leaves publication to the caller.
func (o *OperatorClient) PublishSession(ctx context.Context, target string, replace bool) (SessionPublication, error) {
	payload, err := types.Cbor.Marshal(publishSessionRequest{Target: target, Replace: replace})
	if err != nil {
		return SessionPublication{}, err
	}
	answer, err := o.ex.call(ctx, opPublishSession, payload)
	if errors.Is(err, ErrWrongEndpoint) {
		return SessionPublication{}, nil
	}
	if err != nil {
		return SessionPublication{}, err
	}
	var result publishSessionResult
	err = types.Cbor.Unmarshal(answer, &result)
	return SessionPublication{Managed: result.Managed, Issued: result.Issued, ActiveAlternate: result.ActiveAlternate}, err
}

/*
CompleteEnrollment states the shard configuration of a pending authority.

The authority checks the configuration itself: it must name the enrolled node with this authority's
own signing key, for the enrolled network, partition, shard and shard epoch. Only then does the
authority compute the configuration hash and fix it. A second completion is refused, including one
with the same configuration, because enrollment is not reopened within an authority lifetime.
*/
func (o *OperatorClient) CompleteEnrollment(ctx context.Context, conf *types.PartitionDescriptionRecord) error {
	if conf == nil {
		return errors.New("service: no shard configuration")
	}
	payload, err := types.Cbor.Marshal(conf)
	if err != nil {
		return fmt.Errorf("encoding the shard configuration: %w", err)
	}
	_, err = o.ex.call(ctx, opCompleteEnrollment, payload)
	return err
}

// AdvanceEpoch provisions the one successor scope through the operator channel.
// Success fences the old client credential; issue a new session before resuming.
func (o *OperatorClient) AdvanceEpoch(ctx context.Context, conf *types.PartitionDescriptionRecord, trust *types.RootTrustBaseV1) error {
	if conf == nil || trust == nil {
		return fmt.Errorf("%w: missing successor context", signingauthority.ErrContextMismatch)
	}
	confBytes, err := types.Cbor.Marshal(conf)
	if err != nil {
		return err
	}
	trustBytes, err := types.Cbor.Marshal(trust)
	if err != nil {
		return err
	}
	payload, err := types.Cbor.Marshal(advanceEpochPayload{Configuration: confBytes, TrustBase: trustBytes})
	if err != nil {
		return err
	}
	_, err = o.ex.call(ctx, opAdvanceEpoch, payload)
	return err
}

// AdvanceWithProof hands the authority one root activation bundle (the root's staged q3active.Bundle encoding), which it verifies
// against its own lineage before it changes anything (#1085). An advance fences the old client credential; issue a new session before
// resuming. Send the bundles of several epochs one call each, in epoch order.
func (o *OperatorClient) AdvanceWithProof(ctx context.Context, bundle []byte) (signingauthority.AdvanceResult, error) {
	if len(bundle) == 0 {
		return signingauthority.AdvanceResult{}, fmt.Errorf("%w: no activation bundle", signingauthority.ErrLineageUnverified)
	}
	answer, err := o.ex.call(ctx, opAdvanceWithProof, bundle)
	if err != nil {
		return signingauthority.AdvanceResult{}, err
	}
	var wire advanceResultPayload
	if err := types.Cbor.Unmarshal(answer, &wire); err != nil {
		return signingauthority.AdvanceResult{}, fmt.Errorf("decoding the advance result: %w", err)
	}
	return signingauthority.AdvanceResult{Epoch: wire.Epoch, Replay: wire.Replay, Advanced: wire.Advanced, Retired: wire.Retired,
		RootEpoch: wire.RootEpoch, ShardEpoch: wire.ShardEpoch, LineageEpoch: wire.LineageEpoch}, nil
}

// SignHandoffPoP asks the authority for the possession proof its own key owes a coupled handoff: the one signing operation
// outside certification, narrow and domain-separated (see signingauthority.SignHandoffPoP). It is an operator operation, also served to the
// automated member on the possession-proof endpoint (PoPClient): the shard node's client channel refuses it.
func (o *OperatorClient) SignHandoffPoP(ctx context.Context, req signingauthority.HandoffPoPRequest) (evmassign.PoP, error) {
	return signHandoffPoP(ctx, o.ex, req)
}

/*
PoPClient is the automated root member's end of its authority: the one operation its handoff duty needs, over the possession-proof
endpoint and under its own credential. It cannot replace a session, advance an epoch, read the enrollment or status, or sign a
registration, and its credential is refused on every other endpoint. The authority keeps its own checks on every proof it signs
(enrollment, health, retirement, the permitted epoch range, the exact node id and key).
*/
type PoPClient struct {
	ex *exchange
}

// NewPoPClient provisions the member's client. It does not connect.
func NewPoPClient(cfg ClientConfig) (*PoPClient, error) {
	if cfg.Dial == nil {
		return nil, errors.New("service: no dialer for the authority")
	}
	if len(cfg.Credential) < CredentialBytes {
		return nil, fmt.Errorf("service: the possession-proof credential must be at least %d bytes", CredentialBytes)
	}
	return &PoPClient{ex: newExchange(cfg)}, nil
}

func (c *PoPClient) Close() error { return c.ex.close() }

// SignHandoffPoP asks for the possession proof of the authority's own key (see signingauthority.SignHandoffPoP).
func (c *PoPClient) SignHandoffPoP(ctx context.Context, req signingauthority.HandoffPoPRequest) (evmassign.PoP, error) {
	return signHandoffPoP(ctx, c.ex, req)
}

func signHandoffPoP(ctx context.Context, ex *exchange, req signingauthority.HandoffPoPRequest) (evmassign.PoP, error) {
	if req.Successor == nil {
		return evmassign.PoP{}, fmt.Errorf("%w: no successor binding", signingauthority.ErrContextMismatch)
	}
	succ, err := types.Cbor.Marshal(req.Successor)
	if err != nil {
		return evmassign.PoP{}, err
	}
	payload, err := types.Cbor.Marshal(handoffPoPPayload{Domain: req.Domain, Network: req.Context.Network, Attempt: req.Context.Attempt,
		Predecessor: req.Context.Predecessor[:], Successor: succ, NodeID: req.NodeID, Identities: req.Context.Identities[:]})
	if err != nil {
		return evmassign.PoP{}, err
	}
	answer, err := ex.call(ctx, opSignHandoffPoP, payload)
	if err != nil {
		return evmassign.PoP{}, err
	}
	var pop evmassign.PoP
	if err := types.Cbor.Unmarshal(answer, &pop); err != nil {
		return evmassign.PoP{}, fmt.Errorf("decoding the possession proof: %w", err)
	}
	return pop, nil
}

// SignElectionPoP asks the authority for the EVM possession proof its own key owes a primary candidate (see signingauthority.SignElectionPoP).
func (o *OperatorClient) SignElectionPoP(ctx context.Context, req signingauthority.ElectionPoPRequest) (evmassign.EVMPoP, error) {
	cand, err := req.Candidate.Encode()
	if err != nil {
		return evmassign.EVMPoP{}, err
	}
	d := req.Deployment
	payload, err := types.Cbor.Marshal(electionPoPPayload{Candidate: cand, NetworkWord: d.NetworkWord[:], ChainID: d.ChainID[:], Custody: d.Custody[:],
		Election: d.Election[:], Attempt: req.Attempt})
	if err != nil {
		return evmassign.EVMPoP{}, err
	}
	answer, err := o.ex.call(ctx, opSignElectionPoP, payload)
	if err != nil {
		return evmassign.EVMPoP{}, err
	}
	var pop evmassign.EVMPoP
	if err := types.Cbor.Unmarshal(answer, &pop); err != nil {
		return evmassign.EVMPoP{}, fmt.Errorf("decoding the election possession proof: %w", err)
	}
	return pop, nil
}

// SignDelegationPossession asks the authority for the signature its own key owes an admitDelegation payload (see
// signingauthority.SignDelegationPossession).
func (o *OperatorClient) SignDelegationPossession(ctx context.Context, req signingauthority.DelegationPossessionRequest) ([]byte, error) {
	r := req.Request
	b := r.Binding
	payload, err := types.Cbor.Marshal(delegationPayload{Network: req.Network[:], Chain: req.Chain[:], Election: req.Election[:], Id: r.Id,
		Generation: r.Generation, RootNodeID: b.RootNodeID[:], RootKey: b.RootKey, EvmNodeID: b.EvmNodeID[:], EvmKey: b.EvmKey,
		OperatorPayee: b.OperatorPayee[:], RoleNonce: r.RoleNonce, DelegationNonce: r.DelegationNonce, Expiry: r.Expiry})
	if err != nil {
		return nil, err
	}
	return o.ex.call(ctx, opSignDelegationPossession, payload)
}

// SignPosPoP asks the authority for the P85 assignment possession proof its own key owes a frozen member (see signingauthority.SignPosPoP).
func (o *OperatorClient) SignPosPoP(ctx context.Context, req signingauthority.PosPoPRequest) (evmassign.EVMPoP, error) {
	payload, err := types.Cbor.Marshal(posPoPPayload{ResultID: req.ResultID[:], AssignmentID: req.AssignmentID[:], Snapshot: req.Snapshot[:],
		Attempt: req.Attempt, ID: req.ID, Generation: req.Generation})
	if err != nil {
		return evmassign.EVMPoP{}, err
	}
	answer, err := o.ex.call(ctx, opSignPosPoP, payload)
	if err != nil {
		return evmassign.EVMPoP{}, err
	}
	var pop evmassign.EVMPoP
	if err := types.Cbor.Unmarshal(answer, &pop); err != nil {
		return evmassign.EVMPoP{}, fmt.Errorf("decoding the P85 possession proof: %w", err)
	}
	return pop, nil
}

// SetPosPolicy pins the P85 election scope of the running authority (see signingauthority.SetPosPolicy); it cannot be changed afterwards.
func (o *OperatorClient) SetPosPolicy(ctx context.Context, p signingauthority.PosPolicy) error {
	payload, err := types.Cbor.Marshal(posPolicyPayload{Network: p.Network[:], ChainID: p.ChainID[:], Election: p.Election[:], IDs: p.IDs})
	if err != nil {
		return err
	}
	_, err = o.ex.call(ctx, opSetPosPolicy, payload)
	return err
}

// SignRegistration asks the authority for the EVM possession signature of a VR registration or binding proposal (see
// signingauthority.SignRegistration). It carries the typed fields, never a digest; the authority computes the digest from its pinned
// deployment.
func (o *OperatorClient) SignRegistration(ctx context.Context, req signingauthority.RegistrationRequest) ([]byte, error) {
	r := req.Registration
	payload, err := types.Cbor.Marshal(registrationPayload{Domain: req.Domain, Owner: req.Owner[:], ID: req.ID, RootNodeID: r.RootNodeID, RootKey: r.RootKey,
		EVMNodeID: r.EVMNodeID, EVMKey: r.EVMKey, Payee: r.Payee[:], Nonce: r.Nonce})
	if err != nil {
		return nil, err
	}
	return o.ex.call(ctx, opSignRegistration, payload)
}

// ReloadRegistrationPolicy replaces the authorized registrations of the running authority (see
// signingauthority.ReloadRegistrationAuthorizations); the deployment pin, the key and the signing record are untouched.
func (o *OperatorClient) ReloadRegistrationPolicy(ctx context.Context, expect signingauthority.RegistrationDeployment, list []signingauthority.RegistrationAuthorization) error {
	w := registrationPolicyPayload{Network: expect.Network[:], ChainID: expect.ChainID[:], Registry: expect.Registry[:], Authorized: []authorizedRegistration{}}
	for _, x := range list {
		w.Authorized = append(w.Authorized, authorizedRegistration{Domain: x.Domain, Owner: x.Owner[:], ID: x.ID, RootNodeID: x.RootNodeID, RootKey: x.RootKey, Payee: x.Payee[:]})
	}
	payload, err := types.Cbor.Marshal(w)
	if err != nil {
		return err
	}
	_, err = o.ex.call(ctx, opReloadRegistrationPolicy, payload)
	return err
}

// Status reports what the authority is holding.
func (o *OperatorClient) Status(ctx context.Context) (signingauthority.Status, error) {
	answer, err := o.ex.call(ctx, opStatus, nil)
	if err != nil {
		return signingauthority.Status{}, err
	}
	wire, err := decodeStatus(answer)
	if err != nil {
		return signingauthority.Status{}, fmt.Errorf("decoding the status: %w", err)
	}
	return signingauthority.Status{
		RootEpoch: wire.RootEpoch, ShardEpoch: wire.ShardEpoch,
		Generation: wire.Generation, ReservedRound: wire.ReservedRound,
		HasReservation: wire.HasReservation, ResponseRetained: wire.ResponseRetained,
		Faulted: wire.Faulted, KeyLost: wire.KeyLost,
		LineagePinned: wire.LineagePinned, LineageEpoch: wire.LineageEpoch, Retired: wire.Retired, SessionIssued: wire.SessionIssued,
	}, nil
}

// PosPolicyStatus reports the pin separately from Status, whose wire layout is also used
// by the shard node. An older authority can still answer Status.
func (o *OperatorClient) PosPolicyStatus(ctx context.Context) (signingauthority.PosPolicyStatus, error) {
	var status signingauthority.PosPolicyStatus
	answer, err := o.ex.call(ctx, opPosPolicyStatus, nil)
	if errors.Is(err, ErrWrongEndpoint) {
		return signingauthority.PosPolicyStatus{State: "unavailable"}, nil
	}
	if err != nil {
		return status, err
	}
	if err := types.Cbor.Unmarshal(answer, &status); err != nil {
		return status, fmt.Errorf("decoding the P85 pin status: %w", err)
	}
	return status, nil
}

// Enrollment reports the immutable scope this authority signs for, and the public half of the key it
// generated. This is how a deployment learns the key to check responses against: from the authority,
// through the operator, at provisioning time.
func (o *OperatorClient) Enrollment(ctx context.Context) (signingauthority.Enrollment, []byte, error) {
	answer, err := o.ex.call(ctx, opEnrollment, nil)
	if err != nil {
		return signingauthority.Enrollment{}, nil, err
	}
	var wire enrollmentPayload
	if err := types.Cbor.Unmarshal(answer, &wire); err != nil {
		return signingauthority.Enrollment{}, nil, fmt.Errorf("decoding the enrollment: %w", err)
	}
	var enrollment signingauthority.Enrollment
	if err := types.Cbor.Unmarshal(wire.Enrollment, &enrollment); err != nil {
		return signingauthority.Enrollment{}, nil, fmt.Errorf("decoding the enrollment: %w", err)
	}
	return enrollment, wire.PublicKey, nil
}
