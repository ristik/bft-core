package service

import (
	"context"
	"errors"
	"fmt"

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

// Status reports what the authority is holding.
func (o *OperatorClient) Status(ctx context.Context) (signingauthority.Status, error) {
	answer, err := o.ex.call(ctx, opStatus, nil)
	if err != nil {
		return signingauthority.Status{}, err
	}
	var wire statusPayload
	if err := types.Cbor.Unmarshal(answer, &wire); err != nil {
		return signingauthority.Status{}, fmt.Errorf("decoding the status: %w", err)
	}
	return signingauthority.Status{
		Generation: wire.Generation, ReservedRound: wire.ReservedRound,
		HasReservation: wire.HasReservation, ResponseRetained: wire.ResponseRetained,
		Faulted: wire.Faulted, KeyLost: wire.KeyLost,
	}, nil
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
