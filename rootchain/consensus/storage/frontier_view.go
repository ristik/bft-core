package storage

import (
	"fmt"
	"reflect"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	// These are copy-time bounds for the inactive frontier storage view. They are
	// deliberately local limits, not consensus or wire-format limits.
	frontierMaxAggregateBytes = 1 << 20
	frontierMaxFieldBytes     = 256 << 10
	frontierMaxCollectionSize = 1024
	frontierMaxDepth          = 32
	frontierMaxShardBits      = 4096
	frontierMaxNodes          = 10000
)

// FrontierStorageView is an owned, bounded copy of committed root data for one
// requested shard. It is raw storage data, not a freshness proof or authority.
type FrontierStorageView struct {
	CommittedRootRound uint64
	RootEpoch          uint64
	RootNetworkID      types.NetworkID // copied from the committed QC; not local trust
	CommitQC           *rctypes.QuorumCert
	PartitionID        types.PartitionID
	ShardID            types.ShardID
	LastCR             *certification.CertificationResponse
	ShardConfigHash    []byte
	HighQC             *rctypes.QuorumCert
}

// ReadFrontierStorageView copies the committed root and one requested shard
// while holding the tree lock. It does not enumerate other shards or pending
// blocks. Required data and every copied field are bounded and owned by the
// returned value. The future manager sampler must serialize this read with safety
// writes and store replacement. This lock does not protect aliases obtained through
// the existing pointer-returning getters, which callers must not mutate concurrently.
func (bt *BlockTree) ReadFrontierStorageView(partition types.PartitionID, shard types.ShardID) (*FrontierStorageView, error) {
	if bt == nil {
		return nil, fmt.Errorf("block tree is nil")
	}

	bt.m.RLock()
	defer bt.m.RUnlock()

	if bt.root == nil || bt.root.data == nil {
		return nil, fmt.Errorf("committed root is unavailable")
	}
	root := bt.root.data
	if root.BlockData == nil {
		return nil, fmt.Errorf("committed root block data is unavailable")
	}
	if root.CommitQc == nil {
		return nil, fmt.Errorf("committed root commit QC is unavailable")
	}
	if root.CommitQc.VoteInfo == nil || root.CommitQc.LedgerCommitInfo == nil {
		return nil, fmt.Errorf("committed root commit QC is incomplete")
	}
	if shard.Length() > frontierMaxShardBits {
		return nil, fmt.Errorf("requested shard ID exceeds copy bounds")
	}
	key := types.PartitionShardID{PartitionID: partition, ShardID: shard.Key()}
	si, ok := root.ShardState.States[key]
	if !ok || si == nil {
		return nil, fmt.Errorf("requested shard %s - %s is unavailable", partition, shard)
	}
	if si.LastCR == nil {
		return nil, fmt.Errorf("requested shard %s - %s LastCR is unavailable", partition, shard)
	}
	if si.LastCR.UC.InputRecord == nil || si.LastCR.UC.UnicitySeal == nil || si.LastCR.UC.UnicityTreeCertificate == nil {
		return nil, fmt.Errorf("requested shard LastCR certificate is incomplete")
	}
	if len(si.ShardConfHash) == 0 {
		return nil, fmt.Errorf("requested shard %s - %s configuration identity is unavailable", partition, shard)
	}
	if si.ShardID.Length() > frontierMaxShardBits || si.LastCR.Shard.Length() > frontierMaxShardBits || si.LastCR.UC.ShardTreeCertificate.Shard.Length() > frontierMaxShardBits {
		return nil, fmt.Errorf("stored shard ID exceeds copy bounds")
	}

	var budget frontierCopyBudget
	commitQC, err := cloneFrontierValue(root.CommitQc, &budget)
	if err != nil {
		return nil, fmt.Errorf("copying committed root commit QC: %w", err)
	}
	lastCR, err := cloneFrontierValue(si.LastCR, &budget)
	if err != nil {
		return nil, fmt.Errorf("copying requested shard LastCR: %w", err)
	}
	configHash, err := copyFrontierBytes(si.ShardConfHash, &budget)
	if err != nil {
		return nil, fmt.Errorf("copying requested shard configuration identity: %w", err)
	}
	ownedShardID, err := cloneFrontierShardID(si.ShardID, &budget)
	if err != nil {
		return nil, fmt.Errorf("copying requested shard identity: %w", err)
	}

	var highQC *rctypes.QuorumCert
	if bt.highQc != nil {
		highQC, err = cloneFrontierValue(bt.highQc, &budget)
		if err != nil {
			return nil, fmt.Errorf("copying high QC: %w", err)
		}
	}
	return &FrontierStorageView{
		CommittedRootRound: root.GetRound(),
		RootEpoch:          root.BlockData.Epoch,
		RootNetworkID:      root.CommitQc.LedgerCommitInfo.NetworkID,
		CommitQC:           commitQC,
		PartitionID:        si.PartitionID,
		ShardID:            ownedShardID,
		LastCR:             lastCR,
		ShardConfigHash:    configHash,
		HighQC:             highQC,
	}, nil
}

func cloneFrontierShardID(source types.ShardID, budget *frontierCopyBudget) (types.ShardID, error) {
	if source.Length() > frontierMaxShardBits {
		return types.ShardID{}, fmt.Errorf("shard ID exceeds copy bounds")
	}
	encoded, err := types.Cbor.Marshal(source)
	if err != nil {
		return types.ShardID{}, fmt.Errorf("marshal: %w", err)
	}
	if budget.encodedBytes+len(encoded) > frontierMaxAggregateBytes {
		return types.ShardID{}, fmt.Errorf("aggregate value exceeds copy bounds")
	}
	budget.encodedBytes += len(encoded)
	var owned types.ShardID
	if err := types.Cbor.Unmarshal(encoded, &owned); err != nil {
		return types.ShardID{}, fmt.Errorf("unmarshal: %w", err)
	}
	return owned, nil
}

type frontierCopyBudget struct {
	estimatedBytes int
	encodedBytes   int
	nodes          int
	objectStart    int
}

func cloneFrontierValue[T any](source *T, budget *frontierCopyBudget) (*T, error) {
	if source == nil {
		return nil, fmt.Errorf("value is nil")
	}
	budget.objectStart = budget.estimatedBytes
	if err := inspectFrontierValue(reflect.ValueOf(source), 0, budget); err != nil {
		return nil, err
	}
	owned := deepCopyFrontierValue(reflect.ValueOf(source), 0)
	if !owned.IsValid() {
		return nil, fmt.Errorf("deep copy failed")
	}
	encoded, err := types.Cbor.Marshal(owned.Interface())
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	if len(encoded) > frontierMaxFieldBytes || budget.encodedBytes+len(encoded) > frontierMaxAggregateBytes {
		return nil, fmt.Errorf("encoded value exceeds copy bounds")
	}
	budget.encodedBytes += len(encoded)
	var copy T
	if err := types.Cbor.Unmarshal(encoded, &copy); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &copy, nil
}

func copyFrontierBytes(source []byte, budget *frontierCopyBudget) ([]byte, error) {
	if len(source) > frontierMaxFieldBytes || budget.encodedBytes+len(source) > frontierMaxAggregateBytes {
		return nil, fmt.Errorf("byte field exceeds copy bounds")
	}
	if budget.estimatedBytes+len(source) > frontierMaxAggregateBytes {
		return nil, fmt.Errorf("aggregate value exceeds copy bounds")
	}
	budget.estimatedBytes += len(source)
	budget.encodedBytes += len(source)
	return append([]byte(nil), source...), nil
}

func inspectFrontierValue(value reflect.Value, depth int, budget *frontierCopyBudget) error {
	if !value.IsValid() {
		return nil
	}
	budget.nodes++
	if budget.nodes > frontierMaxNodes {
		return fmt.Errorf("value has too many nested fields")
	}
	if depth > frontierMaxDepth {
		return fmt.Errorf("nested value exceeds copy depth")
	}
	// Nine bytes per visited value conservatively account for CBOR scalar/length/tag
	// overhead as well as bounding graphs whose dynamic fields are empty. The fixed
	// UC/QC types have no custom marshalers that expand beyond this estimate.
	if err := budget.addEstimate(9); err != nil {
		return err
	}
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		if value.IsNil() {
			return nil
		}
		return inspectFrontierValue(value.Elem(), depth+1, budget)
	case reflect.String:
		if value.Len() > frontierMaxFieldBytes {
			return fmt.Errorf("string field exceeds copy bounds")
		}
		if err := budget.addEstimate(value.Len()); err != nil {
			return err
		}
	case reflect.Slice:
		if value.Len() > frontierMaxCollectionSize && value.Type().Elem().Kind() != reflect.Uint8 {
			return fmt.Errorf("collection exceeds copy bounds")
		}
		if value.Type().Elem().Kind() == reflect.Uint8 {
			if value.Len() > frontierMaxFieldBytes {
				return fmt.Errorf("byte field exceeds copy bounds")
			}
			if err := budget.addEstimate(value.Len()); err != nil {
				return err
			}
			if budget.estimatedBytes > frontierMaxAggregateBytes {
				return fmt.Errorf("aggregate value exceeds copy bounds")
			}
			return nil
		}
		for i := 0; i < value.Len(); i++ {
			if err := inspectFrontierValue(value.Index(i), depth+1, budget); err != nil {
				return err
			}
		}
	case reflect.Array:
		for i := 0; i < value.Len(); i++ {
			if err := inspectFrontierValue(value.Index(i), depth+1, budget); err != nil {
				return err
			}
		}
	case reflect.Map:
		if value.Len() > frontierMaxCollectionSize {
			return fmt.Errorf("map exceeds copy bounds")
		}
		iter := value.MapRange()
		for iter.Next() {
			if err := inspectFrontierValue(iter.Key(), depth+1, budget); err != nil {
				return err
			}
			if err := inspectFrontierValue(iter.Value(), depth+1, budget); err != nil {
				return err
			}
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			if err := inspectFrontierValue(value.Field(i), depth+1, budget); err != nil {
				return err
			}
		}
	}
	if budget.estimatedBytes > frontierMaxAggregateBytes {
		return fmt.Errorf("aggregate value exceeds copy bounds")
	}
	return nil
}

func (b *frontierCopyBudget) addEstimate(n int) error {
	if n > frontierMaxAggregateBytes-b.estimatedBytes {
		return fmt.Errorf("aggregate value exceeds copy bounds")
	}
	b.estimatedBytes += n
	if b.estimatedBytes-b.objectStart > frontierMaxFieldBytes {
		return fmt.Errorf("value exceeds per-object copy bounds")
	}
	return nil
}

// deepCopyFrontierValue copies the selected object before CBOR encoding. Some
// existing marshalers normalize zero-valued version fields in their receiver.
func deepCopyFrontierValue(value reflect.Value, depth int) reflect.Value {
	if !value.IsValid() || depth > frontierMaxDepth {
		return reflect.Value{}
	}
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		copy := deepCopyFrontierValue(value.Elem(), depth+1)
		out := reflect.New(value.Type()).Elem()
		if copy.IsValid() {
			out.Set(copy)
		}
		return out
	case reflect.Pointer:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		out := reflect.New(value.Type().Elem())
		out.Elem().Set(deepCopyFrontierValue(value.Elem(), depth+1))
		return out
	case reflect.Slice:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		out := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		if value.Type().Elem().Kind() == reflect.Uint8 {
			reflect.Copy(out, value)
			return out
		}
		for i := 0; i < value.Len(); i++ {
			out.Index(i).Set(deepCopyFrontierValue(value.Index(i), depth+1))
		}
		return out
	case reflect.Map:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		out := reflect.MakeMapWithSize(value.Type(), value.Len())
		iter := value.MapRange()
		for iter.Next() {
			out.SetMapIndex(deepCopyFrontierValue(iter.Key(), depth+1), deepCopyFrontierValue(iter.Value(), depth+1))
		}
		return out
	case reflect.Struct:
		out := reflect.New(value.Type()).Elem()
		out.Set(value)
		for i := 0; i < value.NumField(); i++ {
			if !out.Field(i).CanSet() || !value.Field(i).CanInterface() {
				continue
			}
			copy := deepCopyFrontierValue(value.Field(i), depth+1)
			if copy.IsValid() {
				out.Field(i).Set(copy)
			}
		}
		return out
	default:
		return value
	}
}
