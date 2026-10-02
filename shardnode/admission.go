package shardnode

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	ErrAdmissionMode    = errors.New("shardnode: configured certificate admission mode conflict")
	ErrClientRunning    = errors.New("shardnode: BFT client configuration is frozen while running")
	ErrProposalRejected = errors.New("shardnode: untrusted follower proposal rejected")
)

// AdmissionIdentity is the client-owned deployment context supplied to an optional admission
// factory. Callers cannot replace these pins with certificate-supplied values.
type AdmissionIdentity struct {
	PartitionID       types.PartitionID
	ShardID           types.ShardID
	FullShardConfHash []byte
	// ConfForEpoch is the client's installed shard configuration for a shard epoch (false when none is installed). FullShardConfHash
	// stays the deployment's GENESIS identity pin (the factories refuse any other value); ConfForEpoch is what a certificate's
	// observation is authenticated against, so an installed assignment's certificates are admitted and nothing else is.
	ConfForEpoch func(shardEpoch uint64) ([]byte, bool)
	TrustBases   TrustBaseStore
}

// FinalityBoundary is the narrow gate surface needed by a persistence-before-delivery adapter.
type FinalityBoundary interface {
	Hold(context.Context, string) (func(), error)
}

// AdmissionCallbacks separate authenticated feed progress from durable target delivery.
// AuthenticatedFeed must only update bounded local state and signal Run; it must not perform
// network I/O. DeliverDurable is serialized by the admission implementation.
type AdmissionCallbacks struct {
	AuthenticatedFeed func(*types.UnicityCertificate, *certification.TechnicalRecord)
	DeliverDurable    func(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error
}

// CertificateAdmission owns one optional admission episode for a BFTClient Run lifecycle.
type CertificateAdmission interface {
	Submit(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error
	RootEpoch() uint64
	Close() error
}

// PendingAdmission is an authenticated certificate waiting for peer catch-up
// before durable admission. It is diagnostic state, never signing authority.
type PendingAdmission struct {
	RootRound, Round uint64
	BlockHash        []byte
	Since            time.Time
	Attempts         uint64
	LastError        string
}

func (p PendingAdmission) Detail() string {
	return fmt.Sprintf("authenticated certificate awaits peer catch-up: rootRound=%d round=%d block=%x attempts=%d since=%s lastError=%s",
		p.RootRound, p.Round, p.BlockHash, p.Attempts, p.Since.UTC().Format(time.RFC3339Nano), p.LastError)
}

// CertificateAdmissionFactory constructs an inactive admission boundary before the initial
// handshake. Start failure prevents Run from observing any network certificate.
type CertificateAdmissionFactory interface {
	Start(context.Context, AdmissionIdentity, FinalityBoundary, AdmissionCallbacks) (CertificateAdmission, error)
}

func ownAdmissionIdentity(partition types.PartitionID, shard types.ShardID, conf []byte, trust TrustBaseStore, confForEpoch func(uint64) ([]byte, bool)) (AdmissionIdentity, error) {
	text, err := shard.MarshalText()
	if err != nil {
		return AdmissionIdentity{}, err
	}
	var ownedShard types.ShardID
	if err = ownedShard.UnmarshalText(bytes.Clone(text)); err != nil {
		return AdmissionIdentity{}, err
	}
	if len(conf) == 0 || trust == nil {
		return AdmissionIdentity{}, fmt.Errorf("%w: incomplete client identity", ErrAdmissionMode)
	}
	return AdmissionIdentity{PartitionID: partition, ShardID: ownedShard, FullShardConfHash: bytes.Clone(conf), ConfForEpoch: confForEpoch, TrustBases: trust}, nil
}
