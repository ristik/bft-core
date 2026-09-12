package shardnode

import (
	"context"
	"fmt"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

/*
CertificationSigner is the one way a round turns a proposal into a signed certification request
(F6c #105 step 3, docs/design/f6c-signing-state-contract.md §8.3).

It exists so that signing has a single funnel. A round builds a candidate, and whether the signature
comes from a key in this process or from an independent authority that keeps a record of what this
validator has already signed, it takes the same path and the same refusals.

An implementation may refuse, and a refusal is not a failure of the round: the certificate has still
been observed, committed and reconciled by the time this is called. The round abstains, reports why,
and carries on following the shard. It never falls back to another signer, and it never rebuilds a
candidate to get a different answer.
*/
type CertificationSigner interface {
	// Sign returns the signed form of exactly this proposal, under the authorization that the
	// certificate and its bound technical record express. An implementation that cannot sign this
	// proposal returns an error rather than a different request.
	Sign(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord, proposed *certification.BlockCertificationRequest) (*certification.BlockCertificationRequest, error)
}

// LocalKeySigner signs with a key held in this process.
//
// This is what every deployment does today, and it is deliberately unchanged by step 3: it keeps no
// record, so it cannot refuse a second statement for a round it has already signed, and a restart
// forgets everything. That is the gap #105 exists to close, and closing it is an explicit
// deployment decision (a configured authority), not something a library change switches on.
func LocalKeySigner(signer abcrypto.Signer) CertificationSigner {
	return localKeySigner{signer: signer}
}

type localKeySigner struct{ signer abcrypto.Signer }

func (l localKeySigner) Sign(_ context.Context, _ *types.UnicityCertificate, _ *certification.TechnicalRecord, proposed *certification.BlockCertificationRequest) (*certification.BlockCertificationRequest, error) {
	if proposed == nil {
		return nil, fmt.Errorf("shardnode: no proposal to sign")
	}
	signed := *proposed
	if err := signed.Sign(l.signer); err != nil {
		return nil, fmt.Errorf("signing certification request: %w", err)
	}
	return &signed, nil
}
