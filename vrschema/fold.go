package vrschema

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ShardKey names one installed shard: the partition and the shard id bytes (bft-go-base ShardID.Bytes()).
type ShardKey struct {
	Partition uint32
	Shard     string
}

// FoldInput is everything the verdicts read (design section 3.5.4). It changes only at a committed handoff.
type FoldInput struct {
	Network            uint64 // root network id
	SuccessorRootEpoch uint64
	Installed          map[ShardKey]*types.PartitionDescriptionRecord
	ReservedPartitions []uint32 // 0xFFFFFFFF, 0xFFFFFFFE, the EVM partition, the control partition
	PartitionCeiling   uint32   // 64
	Schedule           []Activation
}

// ErrFoldList refuses a RegistryChanges list VR could never have bound (the candidate is invalid; no verdict applies).
var ErrFoldList = errors.New("vrschema: registry change list is not bindable")

// ChangePoPMessage is the VR-context possession message one validator key signs at queue time: CBOR(["UNICITY_VR_CHANGE_POP", 1,
// network, VR, changeId, partition, shard, keccak256(pdr), nodeId]) with network the root network id, VR the 20-byte address and
// keccak256 over the exact canonical PDR bytes carried in the payload.
func ChangePoPMessage(network uint64, registry [20]byte, changeID uint64, partition uint32, shard []byte, pdr []byte, nodeID string) ([]byte, error) {
	h := ethcrypto.Keccak256(pdr)
	if shard == nil {
		shard = []byte{}
	}
	return types.Cbor.Marshal([]any{ChangePoPDomain, uint64(1), network, registry[:], changeID, uint64(partition), shard, h, nodeID})
}

func decodePDR(b []byte) (*types.PartitionDescriptionRecord, error) {
	var p types.PartitionDescriptionRecord
	if len(b) == 0 || types.Cbor.Unmarshal(b, &p) != nil {
		return nil, ErrCanonical
	}
	again, err := types.Cbor.Marshal(&p)
	if err != nil || !bytes.Equal(again, b) {
		return nil, ErrCanonical
	}
	return &p, nil
}

func decodePoPs(b []byte) ([]evmassign.PoP, error) {
	var ps []evmassign.PoP
	if len(b) == 0 || types.Cbor.Unmarshal(b, &ps) != nil {
		return nil, ErrCanonical
	}
	again, err := types.Cbor.Marshal(ps)
	if err != nil || !bytes.Equal(again, b) {
		return nil, ErrCanonical
	}
	return ps, nil
}

// verifyChangePoPs: exactly one proof per validator, in validator order, by the validator's own key, with a canonical recovery byte.
func verifyChangePoPs(in FoldInput, changeID uint64, pdr *types.PartitionDescriptionRecord, pdrBytes []byte, pops []evmassign.PoP) error {
	if len(pops) != len(pdr.Validators) {
		return errors.New("pop count")
	}
	for i, v := range pdr.Validators {
		p := pops[i]
		if p.NodeID != v.NodeID || !bytes.Equal(p.Key, v.SigKey) || len(p.Signature) != 65 {
			return fmt.Errorf("pop %d names another validator", i)
		}
		msg, err := ChangePoPMessage(in.Network, ValidatorRegistry, changeID, uint32(pdr.PartitionID), pdr.ShardID.Bytes(), pdrBytes, v.NodeID)
		if err != nil {
			return err
		}
		if err := Verify(v.SigKey, p.Signature, msg); err != nil {
			return err
		}
		d := sha256.Sum256(msg)
		pub, err := ethcrypto.SigToPub(d[:], p.Signature)
		if err != nil || !bytes.Equal(ethcrypto.CompressPubkey(pub), v.SigKey) {
			return errors.New("non-canonical recovery byte")
		}
	}
	return nil
}

func sameValidators(a, b []*types.NodeInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].NodeID != b[i].NodeID || !bytes.Equal(a[i].SigKey, b[i].SigKey) || a[i].Stake != b[i].Stake {
			return false
		}
	}
	return true
}

// FoldVerdicts derives the verdicts of the bound changes, in ascending id over a tentative state. Order of judgment for each change:
// Duplicate (same kind and payload hash as an earlier Accepted change), Malformed (payload, PDR or PoP list not canonical), then the
// kind's rules (Conflict, Invalid, Ceiling, BadPoP, PastCutoff, Earlier, Latched). EVM-side and membership kinds are Accepted. The
// shard acknowledgement gate is not a fold input (AckGate). verifyProofConfig is an additional Invalid check VT-05a applies to kinds 6,
// 7 and 8 with the root's proof configuration; it is outside this reference.
func FoldVerdicts(in FoldInput, rc []RegistryChange) ([]uint8, error) {
	if err := CheckRegistryChangesShape(rc); err != nil {
		return nil, err
	}
	tentative := map[ShardKey]*types.PartitionDescriptionRecord{}
	for k, v := range in.Installed {
		tentative[k] = v
	}
	touched := map[ShardKey]bool{}
	added := map[uint32]bool{}
	ruled := map[Word]bool{}
	effective := Effective(in.Schedule)
	accepted := map[string]bool{}
	reserved := map[uint32]bool{}
	for _, p := range in.ReservedPartitions {
		reserved[p] = true
	}
	partitions := func() int {
		s := map[uint32]bool{}
		for k := range tentative {
			s[k.Partition] = true
		}
		return len(s)
	}
	out := make([]uint8, len(rc))
	for i, c := range rc {
		k := uint8(c.Kind)
		dk := fmt.Sprintf("%d/%x", k, PayloadHash(c.Payload))
		v, derr := DecodeChangePayload(k, c.Payload)
		verdict := VerdictAccepted
		switch {
		case accepted[dk]:
			verdict = VerdictDuplicate
		case derr != nil:
			if !RootSide(k) && k != KindScheduleActivation {
				return nil, fmt.Errorf("%w: entry %d of kind %d does not decode", ErrFoldList, i, k)
			}
			verdict = VerdictMalformed
		default:
			switch k {
			case KindReplaceAggregator, KindUpdatePartition:
				verdict = foldShard(in, c.ID, k, v, tentative, touched)
			case KindAddPartition:
				verdict = foldAdd(in, c.ID, v, tentative, added, reserved, partitions())
			case KindScheduleActivation:
				s := Schedule{RuleID: v[0].(Word), ReleaseDigest: v[1].(Word), RootEpoch: v[2].(uint64), NotBeforeUcTime: v[3].(uint64)}
				if ruled[s.RuleID] {
					verdict = VerdictConflict
				} else if verdict = ScheduleVerdict(s, in.SuccessorRootEpoch, effective); verdict == VerdictAccepted {
					ruled[s.RuleID] = true
					effective[s.RuleID] = Activation{RuleID: s.RuleID, RootEpoch: s.RootEpoch, NotBeforeUcTime: s.NotBeforeUcTime, State: ActActive, ChangeID: c.ID}
				}
			}
		}
		if verdict == VerdictAccepted {
			accepted[dk] = true
		}
		out[i] = verdict
	}
	return out, nil
}

// CheckRegistryChangesShape is CheckRegistryChanges without the verdict values (the fold assigns them).
func CheckRegistryChangesShape(rc []RegistryChange) error {
	cp := make([]RegistryChange, len(rc))
	for i, c := range rc {
		cp[i] = c
		cp[i].Verdict = 0
	}
	if err := CheckRegistryChanges(cp); err != nil {
		return errors.Join(ErrFoldList, err)
	}
	return nil
}

func foldShard(in FoldInput, id uint64, k uint8, v []any, tentative map[ShardKey]*types.PartitionDescriptionRecord, touched map[ShardKey]bool) uint8 {
	key := ShardKey{uint32(v[0].(uint64)), string(v[1].([]byte))}
	expected, succBytes := v[2].(Word), v[3].([]byte)
	succ, err := decodePDR(succBytes)
	if err != nil {
		return VerdictMalformed
	}
	var pops []evmassign.PoP
	if k == KindReplaceAggregator {
		if pops, err = decodePoPs(v[4].([]byte)); err != nil {
			return VerdictMalformed
		}
	}
	if touched[key] {
		return VerdictConflict
	}
	cur := tentative[key]
	if cur == nil || cur.PartitionTypeID == evmassign.EVMPartitionTypeID {
		return VerdictInvalid
	}
	h, err := evmassign.PDRHash(cur)
	if err != nil || h != expected {
		return VerdictConflict
	}
	if succ.NetworkID != cur.NetworkID || uint64(succ.NetworkID) != in.Network || succ.PartitionID != cur.PartitionID ||
		!bytes.Equal(succ.ShardID.Bytes(), []byte(key.Shard)) || uint32(succ.PartitionID) != key.Partition {
		return VerdictInvalid
	}
	switch k {
	case KindReplaceAggregator:
		if evmassign.ValidateSuccessor(cur, succ) != nil {
			return VerdictInvalid
		}
		if verifyChangePoPs(in, id, succ, succBytes, pops) != nil {
			return VerdictBadPoP
		}
	case KindUpdatePartition:
		if succ.IsValid() != nil || succ.PartitionTypeID != cur.PartitionTypeID || succ.TypeIDLen != cur.TypeIDLen || succ.UnitIDLen != cur.UnitIDLen ||
			cur.Epoch == ^uint64(0) || succ.Epoch != cur.Epoch+1 || succ.EpochStart != 0 || !sameValidators(cur.Validators, succ.Validators) {
			return VerdictInvalid
		}
	}
	tentative[key], touched[key] = succ, true
	return VerdictAccepted
}

func foldAdd(in FoldInput, id uint64, v []any, tentative map[ShardKey]*types.PartitionDescriptionRecord, added map[uint32]bool, reserved map[uint32]bool, count int) uint8 {
	pdrBytes := v[0].([]byte)
	pdr, err := decodePDR(pdrBytes)
	if err != nil {
		return VerdictMalformed
	}
	pops, err := decodePoPs(v[1].([]byte))
	if err != nil {
		return VerdictMalformed
	}
	p := uint32(pdr.PartitionID)
	if added[p] {
		return VerdictConflict
	}
	for k := range tentative {
		if k.Partition == p {
			return VerdictInvalid
		}
	}
	if reserved[p] || pdr.PartitionTypeID == evmassign.EVMPartitionTypeID || uint64(pdr.NetworkID) != in.Network || pdr.Epoch != 0 ||
		pdr.EpochStart != 0 || evmassign.ValidateAssignment(pdr) != nil {
		return VerdictInvalid
	}
	if uint32(count+1) > in.PartitionCeiling {
		return VerdictCeiling
	}
	if verifyChangePoPs(in, id, pdr, pdrBytes, pops) != nil {
		return VerdictBadPoP
	}
	tentative[ShardKey{p, string(pdr.ShardID.Bytes())}] = pdr
	added[p] = true
	return VerdictAccepted
}

// AckGate is the shard acknowledgement gate at the Freeze block: every Accepted kind 6 or 8 change targets a shard X with
// si.TR.Epoch == si.IR.Epoch for X (acked[X] true), and so does the EVM shard. It returns the first unacknowledged change index.
func AckGate(rc []RegistryChange, verdicts []uint8, acked map[ShardKey]bool, evmAcked bool) (int, bool) {
	if !evmAcked {
		return -1, false
	}
	idx := make([]int, 0)
	for i, c := range rc {
		if verdicts[i] != VerdictAccepted || (uint8(c.Kind) != KindReplaceAggregator && uint8(c.Kind) != KindUpdatePartition) {
			continue
		}
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		v, err := DecodeChangePayload(uint8(rc[i].Kind), rc[i].Payload)
		if err != nil || !acked[ShardKey{uint32(v[0].(uint64)), string(v[1].([]byte))}] {
			return i, false
		}
	}
	return 0, true
}
