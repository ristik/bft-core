package recordwiring

import (
	"context"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// NewChildReadiness adapts the W3a readiness predicate to the round's ChildReadiness interface
// (#14 W3b-1). The adapter adds no check: Prepare and Revalidate forward directly, and the round
// only ever holds the opaque PreparedReadiness this package produced. That indirection is what
// keeps shardnode from importing recordwiring, which would be a cycle.
func NewChildReadiness(r *Readiness) shardnode.ChildReadiness {
	return childReadiness{r: r}
}

type childReadiness struct{ r *Readiness }

func (c childReadiness) Prepare(ctx context.Context, held *types.UnicityCertificate) (shardnode.ReadinessTicket, error) {
	prepared, err := c.r.Prepare(ctx, held)
	if err != nil {
		return nil, err
	}
	return prepared, nil
}

func (c childReadiness) Revalidate(ctx context.Context, ticket shardnode.ReadinessTicket, held *types.UnicityCertificate) error {
	prepared, ok := ticket.(PreparedReadiness)
	if !ok {
		return ErrReadinessUnavailable
	}
	return c.r.Revalidate(ctx, prepared, held)
}

// NewCertificateObserver adapts the observation history to the round's CertificateObserver
// interface. The round calls it at the one site where an authenticated certificate and its bound
// technical record arrive together; the history is what a later Prepare uses to prove continuity
// between the durable record and the certificate in hand. Observing authorizes nothing.
func NewCertificateObserver(o *Observations) shardnode.CertificateObserver {
	return certificateObserver{o: o}
}

type certificateObserver struct{ o *Observations }

func (c certificateObserver) ObserveCertificate(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	return c.o.Observe(uc, tr)
}
