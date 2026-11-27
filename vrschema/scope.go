package vrschema

import (
	"errors"
	"fmt"
)

// ErrScope refuses a payload whose binding scope cannot be read (queue time: UnreadableScope).
var ErrScope = errors.New("UnreadableScope")

// ChangeScope is the binding-selection scope of a change (design section 3.5.1, "singleton per output"): "kind:N" for the singleton
// kinds 1, 3, 4 and 5; "shard:<partition>/<shard hex>" for kinds 6 and 8, which therefore share one scope per shard; "partition:<p>"
// for kind 7; "rule:<ruleId hex>" for kind 9; and "" (no scope) for kinds 2 and 10. VR computes it at queue time and stores nothing
// new: the shard scope is read from the ABI words, the partition from the PDR's leading CBOR words (PDRPartition) and the rule from the
// first word.
func ChangeScope(kind uint8, payload []byte) (string, error) {
	switch kind {
	case KindSetModule, KindSetGovernor, KindCommitteeLimits, KindFeeParams:
		return fmt.Sprintf("kind:%d", kind), nil
	case KindModuleAction, KindForceRemove:
		return "", nil
	}
	v, err := DecodeChangePayload(kind, payload)
	if err != nil {
		return "", errors.Join(ErrScope, err)
	}
	switch kind {
	case KindReplaceAggregator, KindUpdatePartition:
		return fmt.Sprintf("shard:%d/%x", v[0].(uint64), v[1].([]byte)), nil
	case KindAddPartition:
		p, err := PDRPartition(v[0].([]byte))
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("partition:%d", p), nil
	case KindScheduleActivation:
		r := v[0].(Word)
		return fmt.Sprintf("rule:%x", r[:]), nil
	}
	return "", fmt.Errorf("%w: kind %d", ErrUnknownKind, kind)
}

// PDRTag is bft-go-base's PartitionDescriptionRecordTag: a canonical PDR is CBOR tag 39008 around its array.
const PDRTag = 39008

// PDRPartition reads the partition id of a canonical CBOR PDR from its leading bytes, the way VR does without a CBOR decoder: the
// tag head 39008 (major type 6, shortest form: d9 98 60), an array head (major type 4, shortest form) of at least three items, then
// three shortest-form unsigned integers (major type 0): version, network id and partition id, the last at most 2^32 - 1. Anything
// else is ErrScope.
func PDRPartition(pdr []byte) (uint32, error) {
	pos := 0
	head := func(major byte) (uint64, bool) {
		if pos >= len(pdr) || pdr[pos]>>5 != major {
			return 0, false
		}
		ai := pdr[pos] & 0x1f
		pos++
		if ai < 24 {
			return uint64(ai), true
		}
		n := map[byte]int{24: 1, 25: 2, 26: 4, 27: 8}[ai]
		if n == 0 || pos+n > len(pdr) {
			return 0, false
		}
		var v uint64
		for i := 0; i < n; i++ {
			v = v<<8 | uint64(pdr[pos+i])
		}
		pos += n
		min := map[int]uint64{1: 24, 2: 1 << 8, 4: 1 << 16, 8: 1 << 32}[n]
		return v, v >= min
	}
	if t, ok := head(6); !ok || t != PDRTag {
		return 0, ErrScope
	}
	if l, ok := head(4); !ok || l < 3 {
		return 0, ErrScope
	}
	var p uint64
	for i := 0; i < 3; i++ {
		v, ok := head(0)
		if !ok {
			return 0, ErrScope
		}
		p = v
	}
	if p > 0xffffffff {
		return 0, ErrScope
	}
	return uint32(p), nil
}
