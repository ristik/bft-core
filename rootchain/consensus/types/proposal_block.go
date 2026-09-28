package types

import (
	gocrypto "crypto"
	"errors"
	"fmt"
	"strings"

	abhash "github.com/unicitynetwork/bft-go-base/hash"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	errMissingPayload           = errors.New("proposed block is missing payload")
	errMissingQuorumCertificate = errors.New("proposed block is missing quorum certificate")
	ErrControlPartition         = errors.New("reserved root control partition")
)

const ControlPartition types.PartitionID = 0xFFFFFFFF

type BlockData struct {
	_         struct{} `cbor:",toarray"`
	Version   types.Version
	Author    string   `json:"author"` // NodeID of the proposer
	Round     uint64   `json:"round"`  // Root round number
	Epoch     uint64   `json:"epoch"`  // Root epoch to establish valid configuration
	Timestamp uint64   `json:"timestamp"`
	Payload   *Payload `json:"payload"` // Payload that will trigger changes to the state
	// quorum certificate for ancestor
	// before payload can be applied check that local state matches state in qc
	// qc.vote_info.proposed.state_hash == h(UC[])
	Qc *QuorumCert `json:"qc"`
}

type Payload struct {
	_              struct{}       `cbor:",toarray"`
	Requests       []*IRChangeReq `json:"requests"` // IR change requests with quorum or no quorum possible
	Version        uint64         `json:"version,omitempty"`
	HandoffRecords [][]byte       `json:"handoffRecords,omitempty"`
}

type payloadV1 struct {
	_        struct{} `cbor:",toarray"`
	Requests []*IRChangeReq
}
type payloadV2 struct {
	_              struct{} `cbor:",toarray"`
	Version        uint64
	Requests       []*IRChangeReq
	HandoffRecords [][]byte
}

func (x *Payload) MarshalCBOR() ([]byte, error) {
	if x == nil {
		return types.Cbor.Marshal(nil)
	}
	if x.Version == 2 {
		return types.Cbor.Marshal(payloadV2{Version: 2, Requests: x.Requests, HandoffRecords: x.HandoffRecords})
	}
	if x.Version != 0 && x.Version != 1 || len(x.HandoffRecords) != 0 {
		return nil, errors.New("invalid payload version")
	}
	return types.Cbor.Marshal(payloadV1{Requests: x.Requests})
}

func (x *Payload) UnmarshalCBOR(data []byte) error {
	var v2 payloadV2
	if err := types.Cbor.Unmarshal(data, &v2); err == nil {
		if v2.Version != 2 {
			return errors.New("invalid payload version")
		}
		*x = Payload{Version: 2, Requests: v2.Requests, HandoffRecords: v2.HandoffRecords}
		return nil
	}
	var v1 payloadV1
	if err := types.Cbor.Unmarshal(data, &v1); err != nil {
		return err
	}
	*x = Payload{Requests: v1.Requests}
	return nil
}

func (x *Payload) IsValid() error {
	if x.Version > 2 || (x.Version != 2 && len(x.HandoffRecords) > 0) {
		return errors.New("invalid payload version")
	}
	// there can only be one request per partition shard in a block
	sysIdSet := map[types.PartitionShardID]struct{}{}

	for _, req := range x.Requests {
		if req == nil {
			return errors.New("nil IR change request")
		}
		if err := req.IsValid(); err != nil {
			return fmt.Errorf("invalid IR change request for %s: %w", req.Partition, err)
		}
		// Timeout requests do not contain proof
		if req.CertReason == T2Timeout && len(req.Requests) > 0 {
			return fmt.Errorf("partition %s timeout proof contains requests", req.Partition)
		}
		key := types.PartitionShardID{PartitionID: req.Partition, ShardID: req.Shard.Key()}
		if _, found := sysIdSet[key]; found {
			return fmt.Errorf("duplicate requests for partition %s shard %s", req.Partition, req.Shard)
		}
		sysIdSet[key] = struct{}{}
	}
	return nil
}

func (x *Payload) IsEmpty() bool {
	return x != nil && len(x.Requests) == 0 && len(x.HandoffRecords) == 0
}

func (x *BlockData) IsValid() error {
	if x.GetVersion() != 1 && x.GetVersion() != 2 {
		return types.ErrInvalidVersion(x)
	}
	if x.Round < 1 {
		return errRoundNumberUnassigned
	}
	if x.Payload == nil {
		return errMissingPayload
	}
	// does not verify request signatures, this will need to be done later
	if err := x.Payload.IsValid(); err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}
	if (x.GetVersion() == 2) != (x.Payload.Version == 2) {
		return errors.New("block and payload profile versions differ")
	}
	if x.Qc == nil {
		if x.Round == GenesisRootRound {
			// Genesis block does not have previous Qc,
			// skip following Qc validation
			return nil
		}
		return errMissingQuorumCertificate
	}
	if err := x.Qc.IsValid(); err != nil {
		return fmt.Errorf("invalid quorum certificate: %w", err)
	}
	if x.Round <= x.Qc.VoteInfo.RoundNumber {
		return fmt.Errorf("invalid block round %d, round is less or equal to QC round %d", x.Round, x.Qc.VoteInfo.RoundNumber)
	}
	return nil
}

func (x *BlockData) Verify(tb types.RootTrustBase) error {
	if err := x.IsValid(); err != nil {
		return fmt.Errorf("invalid block data: %w", err)
	}
	if err := x.Qc.Verify(tb); err != nil {
		return fmt.Errorf("invalid block data QC: %w", err)
	}
	return nil
}

func (x *BlockData) Hash(algo gocrypto.Hash) ([]byte, error) {
	hasher := abhash.New(algo.New())
	hasher.Write(x)
	return hasher.Sum()
}

// Bytes serializes entire struct for hash calculation.
func (x *BlockData) Bytes() ([]byte, error) {
	return x.MarshalCBOR()
}

func (x *BlockData) GetRound() uint64 {
	if x != nil {
		return x.Round
	}
	return 0
}

func (x *BlockData) GetParentRound() uint64 {
	if x != nil {
		return x.Qc.GetRound()
	}
	return 0
}

// Summary - stringer returns a payload summary
func (x *BlockData) String() string {
	if x.Payload == nil || x.Payload.IsEmpty() {
		return fmt.Sprintf("round: %v, time: %v, payload: empty", x.Round, x.Timestamp)
	}
	var changed []string
	for _, req := range x.Payload.Requests {
		changed = append(changed, req.String())
	}
	return fmt.Sprintf("round: %v, time: %v, payload: %s", x.Round, x.Timestamp, strings.Join(changed, ", "))
}

func (x *BlockData) GetVersion() types.Version {
	if x == nil || x.Version == 0 {
		return 1
	}
	return x.Version
}

func (x *BlockData) MarshalCBOR() ([]byte, error) {
	type alias BlockData
	if x.Version == 0 {
		x.Version = x.GetVersion()
	}
	return types.Cbor.MarshalTaggedValue(types.RootPartitionBlockDataTag, (*alias)(x))
}

func (x *BlockData) UnmarshalCBOR(data []byte) error {
	type alias BlockData
	if err := types.Cbor.UnmarshalTaggedValue(types.RootPartitionBlockDataTag, data, (*alias)(x)); err != nil {
		return err
	}
	if x.Version != 1 && x.Version != 2 {
		return types.ErrInvalidVersion(x)
	}
	return nil
}
