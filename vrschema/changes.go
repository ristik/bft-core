package vrschema

import (
	"fmt"
	"unicode/utf8"
)

// ChangePayloadTypes are the frozen abi.encode field types of every change kind.
var ChangePayloadTypes = map[uint8][]string{
	KindSetModule:          {"address", "bytes32", "bytes"},
	KindModuleAction:       {"address", "bytes"},
	KindSetGovernor:        {"address", "bytes32"},
	KindCommitteeLimits:    {"uint32", "uint32", "uint32"},
	KindFeeParams:          {"uint64", "uint64", "address"},
	KindReplaceAggregator:  {"uint32", "bytes", "bytes32", "bytes", "bytes"},
	KindAddPartition:       {"bytes", "bytes"},
	KindUpdatePartition:    {"uint32", "bytes", "bytes32", "bytes"},
	KindScheduleActivation: {"bytes32", "bytes32", "uint64", "uint64", "string"},
	KindForceRemove:        {"uint64"},
}

// ChangePayloadFields are the field names, in order.
var ChangePayloadFields = map[uint8][]string{
	KindSetModule:          {"module", "codeHash", "initData"},
	KindModuleAction:       {"module", "action"},
	KindSetGovernor:        {"governor", "codeHash"},
	KindCommitteeLimits:    {"nMin", "nTarget", "nMax"},
	KindFeeParams:          {"baseFeeFloor", "changeDenominator", "feeCollector"},
	KindReplaceAggregator:  {"partition", "shard", "expectedOldPdrHash", "successorPdr", "pops"},
	KindAddPartition:       {"pdr", "pops"},
	KindUpdatePartition:    {"partition", "shard", "expectedOldPdrHash", "successorPdr"},
	KindScheduleActivation: {"ruleId", "releaseDigest", "rootEpoch", "notBeforeUcTime", "label"},
	KindForceRemove:        {"id"},
}

// Structural bounds inside payloads.
const (
	MaxShardIDBytes         = 32 // a shard id bit string, length-prefixed as bft-go-base ShardID.Bytes()
	MaxLabelBytes           = 64
	MaxModuleAction         = MaxChangePayload
	ModuleActionAdmit       = 1
	ModuleActionRemove      = 2
	ModuleActionConfirmExit = 3
)

// EncodeChange is abi.encode of a kind's fields.
func EncodeChange(kind uint8, vals ...any) ([]byte, error) {
	ts, ok := ChangePayloadTypes[kind]
	if !ok {
		return nil, fmt.Errorf("%w: change kind %d", ErrUnknownKind, kind)
	}
	b, err := EncodeABI(ts, vals)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxChangePayload {
		return nil, ErrOversize
	}
	return b, nil
}

// DecodeChangePayload is the strict decoder of one kind's payload (size bound first, then the exact ABI shape).
func DecodeChangePayload(kind uint8, payload []byte) ([]any, error) {
	ts, ok := ChangePayloadTypes[kind]
	if !ok {
		return nil, fmt.Errorf("%w: change kind %d", ErrUnknownKind, kind)
	}
	if len(payload) > MaxChangePayload {
		return nil, ErrOversize
	}
	return DecodeABI(ts, payload)
}

// QueueEnv is the VR state a queue-time check reads.
type QueueEnv struct {
	KnownRootEpoch uint64
	UCTime         uint64
	Pending        int      // changes not Active, Cancelled or Rejected
	PendingForce   int      // ForceRemove changes Queued, Scheduled or Bound
	Committee      []uint64 // ids of the committee in force
	MaxGas         uint64   // the generation's fixed fee-profile fields
	SystemGas      uint64
}

// QueueCheck is the structural, state-light queue-time validation of design section 3.5.3 (code presence and module metadata are
// checked by VR against the chain and are not part of this pure function). It returns nil or the refusal.
func QueueCheck(kind uint8, payload []byte, env QueueEnv) error {
	if kind == 0 || kind > KindForceRemove {
		return fmt.Errorf("%w: change kind %d", ErrUnknownKind, kind)
	}
	if env.Pending >= MaxPendingChanges {
		return fmt.Errorf("TooManyPending")
	}
	v, err := DecodeChangePayload(kind, payload)
	if err != nil {
		return err
	}
	zeroAddr := [20]byte{}
	switch kind {
	case KindSetModule, KindSetGovernor:
		if v[0].([20]byte) == zeroAddr || v[1].(Word) == (Word{}) {
			return fmt.Errorf("%w: zero address or code hash", ErrRange)
		}
	case KindModuleAction:
		if v[0].([20]byte) == zeroAddr || len(v[1].([]byte)) == 0 {
			return fmt.Errorf("%w: empty module action", ErrRange)
		}
	case KindCommitteeLimits:
		l := CommitteeLimits{uint32(v[0].(uint64)), uint32(v[1].(uint64)), uint32(v[2].(uint64))}
		if !l.Valid() {
			return fmt.Errorf("%w: committee limits", ErrRange)
		}
	case KindFeeParams:
		f := FeeParams{BaseFeeFloor: v[0].(uint64), ChangeDenominator: v[1].(uint64), FeeCollector: v[2].([20]byte)}
		if err := ValidateProfile(env.MaxGas, env.SystemGas, f); err != nil {
			return err
		}
	case KindReplaceAggregator, KindUpdatePartition:
		shard := v[1].([]byte)
		if len(shard) > MaxShardIDBytes || v[2].(Word) == (Word{}) || len(v[3].([]byte)) == 0 {
			return fmt.Errorf("%w: shard change shape", ErrRange)
		}
		if kind == KindReplaceAggregator && len(v[4].([]byte)) == 0 {
			return fmt.Errorf("%w: no PoPs", ErrRange)
		}
	case KindAddPartition:
		if len(v[0].([]byte)) == 0 || len(v[1].([]byte)) == 0 {
			return fmt.Errorf("%w: AddPartition shape", ErrRange)
		}
	case KindScheduleActivation:
		label := v[4].(string)
		if v[0].(Word) == (Word{}) || len(label) > MaxLabelBytes || !utf8.ValidString(label) {
			return fmt.Errorf("%w: schedule shape", ErrRange)
		}
		if v[2].(uint64) < env.KnownRootEpoch+3 || env.KnownRootEpoch > ^uint64(0)-3 {
			return fmt.Errorf("ScheduleTooEarly")
		}
		if env.UCTime > ^uint64(0)-DelaySeconds || v[3].(uint64) < env.UCTime+DelaySeconds {
			return fmt.Errorf("ScheduleTooSoon")
		}
	case KindForceRemove:
		id := v[0].(uint64)
		in := false
		for _, c := range env.Committee {
			in = in || c == id
		}
		if !in {
			return fmt.Errorf("NotInCommittee")
		}
		if env.PendingForce >= MaxPendingForce {
			return fmt.Errorf("TooManyForceRemoves")
		}
	}
	return nil
}
