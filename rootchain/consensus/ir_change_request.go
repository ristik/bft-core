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
		// RootEpoch is the only root epoch the change may be certified in: the epoch its collector counted every request of the proof
		// in (#1032). The manager refuses it under any other installed epoch, serialized with activation, and refuses a zero one.
		RootEpoch uint64
	}
)
