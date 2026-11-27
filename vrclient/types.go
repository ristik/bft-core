package vrclient

import (
	"fmt"
	"reflect"

	ethcommon "github.com/ethereum/go-ethereum/common"
)

// The view structs mirror src/vr/VRTypes.sol. Field names are the ABI component names in Go case, so the ABI decoder copies by name.

// Registration is VR's registration struct (design section 3.1).
type Registration struct {
	RootNodeID string            `abi:"rootNodeID"`
	RootKey    []byte            `abi:"rootKey"`
	EvmNodeID  string            `abi:"evmNodeID"`
	EvmKey     []byte            `abi:"evmKey"`
	Payee      ethcommon.Address `abi:"payee"`
	Nonce      uint64            `abi:"nonce"`
}

// Binding is one stored binding with its preimages.
type Binding struct {
	RootNodeWord [32]byte
	RootKeyHash  [32]byte
	EvmNodeWord  [32]byte
	EvmKeyHash   [32]byte
	Payee        ethcommon.Address
	RootNodeID   string
	RootKey      []byte
	EvmNodeID    string
	EvmKey       []byte
}

// IdentityView is VR.identity(id).
type IdentityView struct {
	Owner             ethcommon.Address
	Generation        uint64
	CurrentRef        [32]byte
	StagedRef         [32]byte
	BindingNonce      uint64
	RegistrationNonce uint64
	Current           Binding
	Staged            Binding
	Endpoints         []byte
}

// Known reports whether the identity exists (generation zero is an unknown id).
func (v IdentityView) Known() bool { return v.Generation != 0 }

// Member is a committee member's ten words.
type Member struct {
	Id             uint64
	Generation     uint64
	Weight         uint64
	RawWeight      uint64
	RootNodeWord   [32]byte
	RootKeyHash    [32]byte
	EvmNodeWord    [32]byte
	EvmKeyHash     [32]byte
	Payee          ethcommon.Address
	ExposureDigest [32]byte
}

// FeeSet is VR's fee parameters.
type FeeSet struct {
	BaseFeeFloor      uint64
	ChangeDenominator uint64
	FeeCollector      ethcommon.Address
}

// ConfigView is VR.config().
type ConfigView struct {
	Network            [32]byte
	Governor           ethcommon.Address
	NMin               uint32
	NTarget            uint32
	NMax               uint32
	VMax               uint32
	LMax               uint32
	RMax               uint32
	MaxBatch           uint32
	FeesPrevious       FeeSet
	FeesCurrent        FeeSet
	FeesEffectiveBlock uint64
	DelayRounds        uint64
	DelaySeconds       uint64
	KnownRootEpoch     uint64
	EpochStartProgress uint64
	MaxGas             uint64
	SystemGas          uint64
	ContinuityMaxM     uint64
	ContinuityDistNum  uint64
	ContinuityDistDen  uint64
}

// ModuleMeta is a module's cached metadata.
type ModuleMeta struct {
	ModuleTag               [32]byte
	Capabilities            uint32
	MaxElectionInterval     uint64
	GasBounds               [8]uint64
	LiabilityHolder         ethcommon.Address
	LiabilityHolderCodeHash [32]byte
}

// ModuleView is VR.activeModule().
type ModuleView struct {
	Module        ethcommon.Address
	CodeHash      [32]byte
	Meta          ModuleMeta
	Health        uint8
	WorkPending   bool
	WorkSince     uint64
	StallDeadline uint64
}

// OutputView is VR.output(resultId).
type OutputView struct {
	State             uint8
	Attempt           uint64
	ReservedProgress  uint64
	ExpiresAtProgress uint64
	Predecessor       [32]byte
	SourceModule      ethcommon.Address
	Native            bool
	ModuleTag         [32]byte
	MembersDigest     [32]byte
	KDigest           [32]byte
	ChangesDigest     [32]byte
	SnapshotDigest    [32]byte
	PolicyDigest      [32]byte
	OutputCommit      [32]byte
	InvalidReason     uint8
	InvalidAtProgress uint64
	Members           []Member
	Changes           []uint64
}

// ChangeView is VR.change(changeId).
type ChangeView struct {
	Kind              uint8
	State             uint8
	RejectReason      uint8
	NotBeforeProgress uint64
	NotBeforeTime     uint64
	ActiveRootEpoch   uint64
	ScheduledAt       uint64
	PayloadHash       [32]byte
	BoundTo           [32]byte
	Payload           []byte
}

// Activation is VR.activationAt(i).
type Activation struct {
	RuleId          [32]byte
	ReleaseDigest   [32]byte
	RootEpoch       uint64
	NotBeforeUcTime uint64
	State           uint8
	ChangeId        uint64
}

// ---- names (src/vr/VRConstants.sol, src/vr/poa/PoaElection.sol) ----

// PoA states (design 3.7.1).
const (
	PoaNone uint8 = iota
	PoaApplied
	PoaAdmitted
	PoaJoining
	PoaActive
	PoaExitRequested
	PoaRemoving
	PoaLeaving
	PoaExited
	PoaParked
)

var poaStates = []string{"None", "Applied", "Admitted", "Joining", "Active", "ExitRequested", "Removing", "Leaving", "Exited", "Parked"}

// PoaState names a PoA state.
func PoaState[T ~uint8 | ~int](s T) string {
	if int(s) >= 0 && int(s) < len(poaStates) {
		return poaStates[s]
	}
	return fmt.Sprintf("state %d", s)
}

// PoA ModuleAction payload actions (abi.encode(uint64 action, uint64 id)).
const (
	ActionAdmit       uint64 = 1
	ActionRemove      uint64 = 2
	ActionConfirmExit uint64 = 3
)

// ActionName names a PoA ModuleAction.
func ActionName(a uint64) string {
	switch a {
	case ActionAdmit:
		return "Admit"
	case ActionRemove:
		return "Remove"
	case ActionConfirmExit:
		return "ConfirmExit"
	}
	return fmt.Sprintf("action %d", a)
}

// KindModuleAction is change kind 2.
const KindModuleAction uint8 = 2

var changeKinds = []string{"", "SetModule", "ModuleAction", "SetGovernor", "CommitteeLimits", "FeeParams", "ReplaceAggregatorValidators",
	"AddPartition", "UpdatePartition", "ScheduleActivation", "ForceRemove"}

// ChangeKind names a change kind.
func ChangeKind(k uint8) string {
	if k > 0 && int(k) < len(changeKinds) {
		return changeKinds[k]
	}
	return fmt.Sprintf("kind %d", k)
}

var changeStates = []string{"None", "Queued", "Scheduled", "Bound", "Active", "Rejected", "Cancelled"}

// ChangeState names a change state.
func ChangeState(s uint8) string {
	if int(s) < len(changeStates) {
		return changeStates[s]
	}
	return fmt.Sprintf("state %d", s)
}

var outputStates = []string{"None", "Reserved", "Published", "Invalidated", "Rejected", "Acknowledged", "Recovered", "Closed"}

// OutputState names an output state.
func OutputState(s uint8) string {
	if int(s) < len(outputStates) {
		return outputStates[s]
	}
	return fmt.Sprintf("state %d", s)
}

var healths = []string{"Healthy", "Faulted", "Stalled", "Inconsistent"}

// Health names VR's module health.
func Health(h uint8) string {
	if int(h) < len(healths) {
		return healths[h]
	}
	return fmt.Sprintf("health %d", h)
}

var activationStates = []string{"", "Active", "Superseded", "Latched"}

// ActivationState names an activation entry's state.
func ActivationState(s uint8) string {
	if s > 0 && int(s) < len(activationStates) {
		return activationStates[s]
	}
	return fmt.Sprintf("state %d", s)
}

// MinEpochGap is VRC.MIN_EPOCH_GAP: progress units between a boundary or an epoch's first ordinary round and the next election.
const MinEpochGap = 100

// structFields lists an ABI-decoded tuple's fields.
func structFields(v any) ([]NamedValue, bool) {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil, false
	}
	out := make([]NamedValue, 0, rv.NumField())
	for i := 0; i < rv.NumField(); i++ {
		f := rv.Type().Field(i)
		if !f.IsExported() {
			continue
		}
		out = append(out, NamedValue{Name: f.Name, Value: rv.Field(i).Interface()})
	}
	return out, true
}
