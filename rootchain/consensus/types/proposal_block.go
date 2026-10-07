package types

import (
	"bytes"
	gocrypto "crypto"
	"errors"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
	abhash "github.com/unicitynetwork/bft-go-base/hash"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
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
	// Anchor is present only for a profile-2 bootstrap parent. Exactly one of
	// Qc and Anchor is present on an ordinary proposal.
	Anchor *EpochAnchor `json:"anchor,omitempty"`
}

type Payload struct {
	_              struct{}       `cbor:",toarray"`
	Requests       []*IRChangeReq `json:"requests"` // IR change requests with quorum or no quorum possible
	Version        uint64         `json:"version,omitempty"`
	HandoffRecords [][]byte       `json:"handoffRecords,omitempty"`
	// PosControls are the P85 root controls (CloseLiability, Retirement, RejectResult), only in a version 2 payload. The version 2 wire
	// form is exactly the four-element tuple [2, Requests, HandoffRecords, PosControls], every collection a definite array.
	PosControls []PosControl `json:"posControls,omitempty"`
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
	PosControls    []PosControl
}

func (x *Payload) MarshalCBOR() ([]byte, error) {
	if x == nil {
		return types.Cbor.Marshal(nil)
	}
	if x.Version == 2 {
		// every collection is a definite array, empty rather than null
		v := payloadV2{Version: 2, Requests: x.Requests, HandoffRecords: x.HandoffRecords, PosControls: x.PosControls}
		if v.Requests == nil {
			v.Requests = []*IRChangeReq{}
		}
		if v.HandoffRecords == nil {
			v.HandoffRecords = [][]byte{}
		}
		if v.PosControls == nil {
			v.PosControls = []PosControl{}
		}
		return types.Cbor.Marshal(v)
	}
	if x.Version != 0 && x.Version != 1 || len(x.HandoffRecords) != 0 || len(x.PosControls) != 0 {
		return nil, errors.New("invalid payload version")
	}
	return types.Cbor.Marshal(payloadV1{Requests: x.Requests})
}

// ErrPayloadEncoding reports a version 2 payload that is not the canonical four-element tuple: another arity, another profile tag, a
// collection that is not a definite array, a null element, trailing bytes or any encoding that is not the one the codec writes.
var ErrPayloadEncoding = errors.New("non-canonical root payload")

func (x *Payload) UnmarshalCBOR(data []byte) error {
	var top []cbor.RawMessage
	if err := types.Cbor.Unmarshal(data, &top); err != nil {
		return fmt.Errorf("%w: %v", ErrPayloadEncoding, err)
	}
	if len(top) == 1 { // the legacy profile's payload is the one-element array [Requests]
		var v1 payloadV1
		if err := types.Cbor.Unmarshal(data, &v1); err != nil {
			return err
		}
		*x = Payload{Requests: v1.Requests}
		return nil
	}
	if len(top) != 4 {
		return fmt.Errorf("%w: %d elements, want 4", ErrPayloadEncoding, len(top))
	}
	var version uint64
	if err := types.Cbor.Unmarshal(top[0], &version); err != nil || version != 2 {
		return fmt.Errorf("%w: profile tag", ErrPayloadEncoding)
	}
	for i, raw := range top[1:] {
		// each collection is a definite-length array whose elements are real values, never null
		if len(raw) == 0 || raw[0]>>5 != 4 || raw[0] == 0x9f {
			return fmt.Errorf("%w: collection %d is not a definite array", ErrPayloadEncoding, i+1)
		}
		var elems []cbor.RawMessage
		if err := types.Cbor.Unmarshal(raw, &elems); err != nil {
			return fmt.Errorf("%w: collection %d: %v", ErrPayloadEncoding, i+1, err)
		}
		for j, e := range elems {
			if len(e) == 1 && e[0] == 0xf6 {
				return fmt.Errorf("%w: collection %d element %d is null", ErrPayloadEncoding, i+1, j)
			}
		}
	}
	var v2 payloadV2
	if err := types.Cbor.Unmarshal(data, &v2); err != nil {
		return fmt.Errorf("%w: %v", ErrPayloadEncoding, err)
	}
	// an empty collection is the nil slice in memory (the wire form is always the definite empty array), so a payload round-trips equal
	nilIfEmpty := func(n int) bool { return n == 0 }
	if nilIfEmpty(len(v2.Requests)) {
		v2.Requests = nil
	}
	if nilIfEmpty(len(v2.HandoffRecords)) {
		v2.HandoffRecords = nil
	}
	if nilIfEmpty(len(v2.PosControls)) {
		v2.PosControls = nil
	}
	*x = Payload{Version: 2, Requests: v2.Requests, HandoffRecords: v2.HandoffRecords, PosControls: v2.PosControls}
	again, err := x.MarshalCBOR()
	if err != nil || !bytes.Equal(again, data) {
		return fmt.Errorf("%w: does not re-encode to the bytes read", ErrPayloadEncoding)
	}
	return nil
}

func (x *Payload) IsValid() error {
	if x.Version > 2 || (x.Version != 2 && (len(x.HandoffRecords) > 0 || len(x.PosControls) > 0)) {
		return errors.New("invalid payload version")
	}
	if err := validatePosControls(x.PosControls); err != nil {
		return err
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
	return x != nil && len(x.Requests) == 0 && len(x.HandoffRecords) == 0 && len(x.PosControls) == 0
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
	if x.Anchor != nil {
		if x.GetVersion() != 2 || x.Qc != nil || x.Anchor.IsValid() != nil || x.Epoch != x.Anchor.Epoch || x.Round <= x.Anchor.Slot {
			return ErrEpochAnchor
		}
		return nil
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
	if x.GetVersion() == 2 && x.Qc.VoteInfo.Epoch != x.Epoch {
		return fmt.Errorf("block and ordinary parent QC epochs differ")
	}
	return nil
}

// VerifyWith is Verify by the rule of the epoch of the block's QC, resolved in the store (trust base, signing configuration, genesis pin).
func (x *BlockData) VerifyWith(tbs *trustbase.TrustBaseStore) error {
	if err := x.IsValid(); err != nil {
		return fmt.Errorf("invalid block data: %w", err)
	}
	if x.Anchor != nil {
		// authenticated against the locally installed handoff checkpoint by the consensus bootstrap admission path
		return nil
	}
	if err := x.Qc.VerifyWith(tbs); err != nil {
		return fmt.Errorf("invalid block data QC: %w", err)
	}
	return nil
}

func (x *BlockData) Verify(tb types.RootTrustBase, pin ...*trustbase.GenesisPin) error {
	if err := x.IsValid(); err != nil {
		return fmt.Errorf("invalid block data: %w", err)
	}
	if x.Anchor != nil {
		// The anchor is authenticated against the locally installed handoff
		// checkpoint by the consensus bootstrap admission path.
		return nil
	}
	if err := x.Qc.Verify(tb, pin...); err != nil {
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
		if x.Anchor != nil {
			return x.Anchor.Slot
		}
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
	if x.Version == 0 {
		x.Version = x.GetVersion()
	}
	if x.Anchor != nil {
		return types.Cbor.MarshalTaggedValue(types.RootPartitionBlockDataTag, blockDataAnchorWire{
			Version: x.Version, Author: x.Author, Round: x.Round, Epoch: x.Epoch,
			Timestamp: x.Timestamp, Payload: x.Payload, Qc: x.Qc, Anchor: x.Anchor})
	}
	return types.Cbor.MarshalTaggedValue(types.RootPartitionBlockDataTag, blockDataLegacyWire{
		Version: x.Version, Author: x.Author, Round: x.Round, Epoch: x.Epoch,
		Timestamp: x.Timestamp, Payload: x.Payload, Qc: x.Qc})
}

func (x *BlockData) UnmarshalCBOR(data []byte) error {
	var anchor blockDataAnchorWire
	if err := types.Cbor.UnmarshalTaggedValue(types.RootPartitionBlockDataTag, data, &anchor); err == nil {
		*x = BlockData{Version: anchor.Version, Author: anchor.Author, Round: anchor.Round, Epoch: anchor.Epoch,
			Timestamp: anchor.Timestamp, Payload: anchor.Payload, Qc: anchor.Qc, Anchor: anchor.Anchor}
	} else {
		var legacy blockDataLegacyWire
		if err := types.Cbor.UnmarshalTaggedValue(types.RootPartitionBlockDataTag, data, &legacy); err != nil {
			return err
		}
		*x = BlockData{Version: legacy.Version, Author: legacy.Author, Round: legacy.Round, Epoch: legacy.Epoch,
			Timestamp: legacy.Timestamp, Payload: legacy.Payload, Qc: legacy.Qc}
	}
	if x.Version != 1 && x.Version != 2 {
		return types.ErrInvalidVersion(x)
	}
	return nil
}

type blockDataLegacyWire struct {
	_         struct{} `cbor:",toarray"`
	Version   types.Version
	Author    string
	Round     uint64
	Epoch     uint64
	Timestamp uint64
	Payload   *Payload
	Qc        *QuorumCert
}

type blockDataAnchorWire struct {
	_         struct{} `cbor:",toarray"`
	Version   types.Version
	Author    string
	Round     uint64
	Epoch     uint64
	Timestamp uint64
	Payload   *Payload
	Qc        *QuorumCert
	Anchor    *EpochAnchor
}
