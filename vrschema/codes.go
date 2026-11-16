package vrschema

// Output states (outputs[R].word0.state).
const (
	OutNone         uint8 = 0 // unknown id
	OutReserved     uint8 = 1
	OutPublished    uint8 = 2
	OutInvalidated  uint8 = 3
	OutRejected     uint8 = 4
	OutAcknowledged uint8 = 5
	OutRecovered    uint8 = 6
	OutClosed       uint8 = 7
)

// OutputStateNames are the frozen names of the output states.
var OutputStateNames = map[uint8]string{0: "None", 1: "Reserved", 2: "Published", 3: "Invalidated", 4: "Rejected", 5: "Acknowledged", 6: "Recovered", 7: "Closed"}

// Invalidation reasons (invalidate(R, reason), outputs[R].word10.invalidReason). Zero is not a reason; LOST is an economic event and
// never a module fault; every other nonzero reason is output-level.
const (
	InvalidLost      uint8 = 1
	InvalidWithdrawn uint8 = 2
)

// OutputRejected reasons (record kind 7).
const (
	RejExpired     uint8 = 1
	RejInvalidated uint8 = 2
	RejInvalid     uint8 = 3
)

// Resolutions passed to onResolved.
const (
	ResAcknowledged uint8 = 1
	ResRecovered    uint8 = 2
	ResClosed       uint8 = 3
)

// Module health.
const (
	HealthHealthy      uint8 = 0
	HealthFaulted      uint8 = 1
	HealthStalled      uint8 = 2
	HealthInconsistent uint8 = 3
)

// elect outcomes (packedElect.outcome and VR.elect's return).
const (
	ElectDisabled    uint8 = 0
	ElectNotDue      uint8 = 1
	ElectReserved    uint8 = 2
	ElectNoCandidate uint8 = 3
)

// publish return status.
const (
	PubPublished          uint8 = 0
	PubPending            uint8 = 1
	PubNotMine            uint8 = 2
	PubPreconditionFailed uint8 = 3
)

// packedStatus (outputOf and adoptionReady).
const (
	StatusReady    uint8 = 0
	StatusPending  uint8 = 1
	StatusNotMine  uint8 = 2
	StatusNotReady uint8 = 3 // adoptionReady only
)

// Module capability bits.
const (
	CapLiabilityHolder uint32 = 1 << 0
	CapAdoptionCheck   uint32 = 1 << 1
)

// Change kinds.
const (
	KindSetModule          uint8 = 1
	KindModuleAction       uint8 = 2
	KindSetGovernor        uint8 = 3
	KindCommitteeLimits    uint8 = 4
	KindFeeParams          uint8 = 5
	KindReplaceAggregator  uint8 = 6
	KindAddPartition       uint8 = 7
	KindUpdatePartition    uint8 = 8
	KindScheduleActivation uint8 = 9
	KindForceRemove        uint8 = 10
)

// ChangeKindNames are the frozen kind names.
var ChangeKindNames = map[uint8]string{1: "SetModule", 2: "ModuleAction", 3: "SetGovernor", 4: "CommitteeLimits", 5: "FeeParams",
	6: "ReplaceAggregatorValidators", 7: "AddPartition", 8: "UpdatePartition", 9: "ScheduleActivation", 10: "ForceRemove"}

// RootSide reports the kinds counted against the 8 root-side bound changes.
func RootSide(kind uint8) bool {
	return kind == KindReplaceAggregator || kind == KindAddPartition || kind == KindUpdatePartition || kind == KindForceRemove
}

// Singleton reports the kinds of which an output binds at most one.
func Singleton(kind uint8) bool {
	return kind == KindSetModule || kind == KindSetGovernor || kind == KindCommitteeLimits || kind == KindFeeParams
}

// Change states (changes[id].word0.state).
const (
	ChNone      uint8 = 0
	ChQueued    uint8 = 1
	ChScheduled uint8 = 2
	ChBound     uint8 = 3
	ChActive    uint8 = 4
	ChRejected  uint8 = 5
	ChCancelled uint8 = 6
)

// ChangeStateNames are the frozen names of the change states.
var ChangeStateNames = map[uint8]string{0: "None", 1: "Queued", 2: "Scheduled", 3: "Bound", 4: "Active", 5: "Rejected", 6: "Cancelled"}

// Verdicts carried in candidate v6 RegistryChanges and reasons recorded in changes[id].rejectReason. Codes 1 to 15 are root verdicts
// (from the fold); codes 16 and up are EVM-side activation-time rejections and failures, which never appear in a candidate.
const (
	VerdictAccepted   uint8 = 0
	VerdictConflict   uint8 = 1
	VerdictDuplicate  uint8 = 2
	VerdictMalformed  uint8 = 3 // payload does not decode canonically
	VerdictInvalid    uint8 = 4 // fails a semantic check of design section 6
	VerdictBadPoP     uint8 = 5 // a VR-context possession proof fails
	VerdictPastCutoff uint8 = 6
	VerdictEarlier    uint8 = 7
	VerdictLatched    uint8 = 8 // the rule is already latched
	VerdictCeiling    uint8 = 9 // the partition ceiling would be exceeded

	RejectCodeMismatch     uint8 = 16 // SetModule/SetGovernor code hash differs at activation
	RejectHolderMismatch   uint8 = 17
	RejectAdoptionNotReady uint8 = 18
	RejectActionFailed     uint8 = 19 // ModuleAction onGovernance failed
	RejectNotActive        uint8 = 20 // ModuleAction names a module that is not active
	RejectHolderCeiling    uint8 = 21 // a ninth holder
)

// VerdictNames are the frozen verdict and reason names.
var VerdictNames = map[uint8]string{0: "Accepted", 1: "Conflict", 2: "Duplicate", 3: "Malformed", 4: "Invalid", 5: "BadPoP",
	6: "PastCutoff", 7: "Earlier", 8: "Latched", 9: "Ceiling", 16: "CodeMismatch", 17: "HolderMismatch", 18: "AdoptionNotReady",
	19: "ActionFailed", 20: "NotActive", 21: "HolderCeiling"}

// Activation entry states (activations[i].state).
const (
	ActActive     uint8 = 1
	ActSuperseded uint8 = 2
	ActLatched    uint8 = 3
)

// Root-record kinds.
const (
	RecSessionClosed    uint8 = 1
	RecAck              uint8 = 2
	RecRecoveryAck      uint8 = 3
	RecClosure          uint8 = 4
	RecRetirement       uint8 = 5
	RecBoundary         uint8 = 6
	RecOutputRejected   uint8 = 7
	RecHolderRetirement uint8 = 8
)

// VR-mode root control ops.
const (
	OpCloseLiability   uint64 = 1
	OpHolderRetirement uint64 = 2 // v2
	OpRejectResult     uint64 = 3 // v2
	OpRuleSupport      uint64 = 4
	OpHandoffView      uint64 = 5
)
