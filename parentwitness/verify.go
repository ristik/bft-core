package parentwitness

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-go-base/types"
)

// TargetConfig is independently checked local authority. FullShardConfHash is repeated outside
// Registry so construction must prove the two local configuration sources agree.
type TargetConfig struct {
	NetworkID         types.NetworkID
	PartitionID       types.PartitionID
	ShardID           types.ShardID
	FullShardConfHash common.Hash
	Registry          registryproof.Context
	BlockHash         common.Hash
}

// Target owns the exact local context and subject against which a response is checked.
type Target struct {
	request  Request
	registry registryproof.Context
}

func NewTarget(c TargetConfig) (Target, error) {
	if c.FullShardConfHash != c.Registry.FullShardConfHash {
		return Target{}, fmt.Errorf("%w: registry and full configuration hashes differ", ErrContext)
	}
	shard, err := shardFromBytes(c.ShardID.Bytes())
	if err != nil {
		return Target{}, fmt.Errorf("%w: shard: %v", ErrContext, err)
	}
	r := Request{Context: Context{NetworkID: c.NetworkID, PartitionID: c.PartitionID, ShardID: shard, FullShardConfHash: c.FullShardConfHash, RegistryAddress: c.Registry.RegistryAddress, RegistryCodeHash: c.Registry.RegistryCodeHash, GenesisCommitment: c.Registry.GenesisCommitment, EVMGenesisHash: c.Registry.EVMGenesisHash, ShardEpoch: c.Registry.ShardEpoch, RootEpoch: c.Registry.RootEpoch}, BlockHash: c.BlockHash}
	if err := validateRequest(r); err != nil {
		return Target{}, err
	}
	return Target{request: r, registry: c.Registry}, nil
}

func (t Target) Request() Request {
	r := t.request
	r.Context.ShardID, _ = shardFromBytes(t.request.Context.ShardID.Bytes())
	return r
}

// VerifiedResponse contains owned evidence and a snapshot only for OutcomeFound.
type VerifiedResponse struct {
	Outcome  Outcome
	Detail   string
	Snapshot registryproof.Snapshot
	evidence registryproof.Evidence
}

func (r VerifiedResponse) Evidence() registryproof.Evidence {
	e, _ := ownEvidence(r.evidence)
	return e
}

func VerifyResponse(t Target, raw []byte) (VerifiedResponse, error) {
	if t.request.BlockHash == (common.Hash{}) {
		return VerifiedResponse{}, ErrContext
	}
	r, err := decodeResponse(bytes.Clone(raw))
	if err != nil {
		return VerifiedResponse{}, err
	}
	if !sameRequest(t.request, r.Request) {
		return VerifiedResponse{}, ErrContext
	}
	if r.Outcome != OutcomeFound {
		return VerifiedResponse{Outcome: r.Outcome, Detail: r.Detail}, nil
	}
	// decodeResponse has already bounded and owned every byte before proof verification begins.
	snapshot, err := registryproof.Verify(t.registry, t.request.BlockHash, r.Evidence)
	if err != nil {
		return VerifiedResponse{}, err
	}
	return VerifiedResponse{Outcome: OutcomeFound, Detail: r.Detail, Snapshot: snapshot, evidence: r.Evidence}, nil
}

func sameRequest(a, b Request) bool {
	aw, bw := contextToWire(a.Context), contextToWire(b.Context)
	ab, _ := marshalCanonical(aw)
	bb, _ := marshalCanonical(bw)
	return a.BlockHash == b.BlockHash && bytes.Equal(ab, bb)
}
