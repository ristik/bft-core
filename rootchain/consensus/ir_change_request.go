package consensus

import (
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	Quorum CertReqReason = iota
	QuorumNotPossible
)

type (
	CertReqReason uint8

	IRChangeRequest struct {
		Partition types.PartitionID
		Shard     types.ShardID
		Reason    CertReqReason
		Requests  []*certification.BlockCertificationRequest
		// RootEpoch, when not zero, is the only root epoch the change may be certified in: the collector counted a request it had held
		// in that epoch (#1032). The manager refuses it under any other installed epoch, serialized with activation.
		RootEpoch uint64
	}
)
