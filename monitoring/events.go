package monitoring

import "log/slog"

// EventKey is the structured log key every lifecycle line carries: `event=<dotted.name>`. The names below are a compatibility promise
// (docs/operations/monitoring/events.md): they are never renamed or reused, only added; a line's human message may be reworded, the
// event name may not. TestEventCatalogue fails on a rename, on a name that is not in the catalogue document and on a line that lost its event.
const EventKey = "event"

// Event is the attribute that marks a log line with a stable event name.
func Event(name string) slog.Attr { return slog.String(EventKey, name) }

// The event names. Group by the validator lifecycle: apply and election (vr.identity.* is logged by the VR exporter from the on-chain state,
// the rest by the nodes), the handoff (vr.intent, vr.member, vr.handoff, root.handoff, root.epoch, shard.handoff), exit, and the health
// events (root.round, root.vote, root.recovery, shard.certification, node.disk, node.peers).
const (
	EvVRIntentDerived     = "vr.intent.derived"       // admitted or elected: a handoff intent exists
	EvVRIntentDied        = "vr.intent.died"          // the intent was superseded or expired
	EvVRMemberPossession  = "vr.member.possession"    // this member sent its possession proof
	EvVRMemberReady       = "vr.member.ready"         // ready: this member signed its readiness
	EvVRMemberStaged      = "vr.member.staged"        // staged: the candidate is staged for the switch
	EvVRUpgradeRequired   = "vr.upgrade.required"     // the schedule holds a rule this binary lacks
	EvVRHandoffAssembled  = "vr.handoff.assembled"    // the view's assembly was made
	EvVRHandoffCertified  = "vr.handoff.certified"    // a complete verified certificate is held
	EvVRHandoffOrdering   = "vr.handoff.ordering"     // the leader orders a handoff step
	EvVRHandoffShardStage = "vr.handoff.shard_staged" // the paired shard node holds the staged successor
	EvVRHandoffRefused    = "vr.handoff.refused"      // the leader leaves out a handoff record every root refuses (#1306)
	EvVROutputPublished   = "vr.output.published"     // VR's open output was published and its source recorded
	EvVRRecoveryOrdered   = "vr.recovery.ordered"     // the leader orders the exact recovery
	EvVRRecoveryFollowed  = "vr.recovery.followed"    // the leader follows the exact recovery
	EvVRRecoveryDropped   = "vr.recovery.dropped"     // a recovery request was dropped
	EvRootHandoffOutcome  = "root.handoff.outcome"    // committed, aborted or lapsed
	EvRootEpochSwitch     = "root.epoch.switch"       // the root switched epoch in process (joined the successor committee)
	EvRootEpochSwitchFail = "root.epoch.switch_failed"
	EvShardHandoffActive  = "shard.handoff.activated" // active: the shard node activated the successor
	EvExitRetirementReq   = "exit.retirement.requested"
	EvExitRetirementProof = "exit.retirement.proof_ready"
	EvExitRetirementDone  = "exit.retirement.complete"
	EvRootRoundTimeout    = "root.round.timeout"          // a late round: the local round timer fired
	EvRootVoteMissed      = "root.vote.missed"            // a member ended rounds without a vote
	EvRootRecovery        = "root.recovery.triggered"     // behind: a QC the local state does not match
	EvShardNoProgress     = "shard.certification.stalled" // behind: submitted work is not being certified
	EvNodePeersLow        = "node.peers.low"
	EvNodePeersRecovered  = "node.peers.recovered"
	EvDiskLow             = "node.disk.low"
	EvDiskRecovered       = "node.disk.recovered"
)

// The on-chain identity events: the VR exporter logs one when the validator's own PoA state changes (vrexporter.go), so the applied, admitted,
// joining, active, exit and parked steps are visible without a node log line. The suffix is the state's name, lower-cased with underscores.
const (
	EvVRModuleHealth        = "vr.module.health_changed" // VR's module health changed (logged by the VR exporter)
	EvIdentityApplied       = "vr.identity.applied"
	EvIdentityAdmitted      = "vr.identity.admitted"
	EvIdentityJoining       = "vr.identity.joining"
	EvIdentityActive        = "vr.identity.active"
	EvIdentityExitRequested = "vr.identity.exit_requested"
	EvIdentityRemoving      = "vr.identity.removing"
	EvIdentityLeaving       = "vr.identity.leaving"
	EvIdentityExited        = "vr.identity.exited"
	EvIdentityParked        = "vr.identity.parked"
	EvIdentityNone          = "vr.identity.none"
)

// EventInfo describes one event: its name, the exact log message of the line that carries it ("" for events logged from a computed
// message) and where it is logged.
type EventInfo struct {
	Name string
	Msg  string // a literal that appears next to the event in Source
	File string // repository-relative source file
	// Via, when set, is the function that computes the event name at the call site (the source then carries Via instead of the constant).
	Via string
}

// Events is the catalogue the test checks against the source and the document.
var Events = []EventInfo{
	{EvVRIntentDerived, "VR handoff: intent", "rootchain/vrschedule/service.go", ""},
	{EvVRIntentDied, "VR handoff: the intent died", "rootchain/vrschedule/service.go", ""},
	{EvVRMemberPossession, "VR handoff member: possession proof", "rootchain/vrschedule/member.go", ""},
	{EvVRMemberReady, "VR handoff member: readiness", "rootchain/vrschedule/member.go", ""},
	{EvVRMemberStaged, "VR handoff member: candidate staged", "rootchain/vrschedule/member.go", ""},
	{EvVRUpgradeRequired, "VR handoff member: UpgradeRequired", "rootchain/vrschedule/member.go", ""},
	{EvVRHandoffAssembled, "VR handoff: assembled", "rootchain/vrschedule/service.go", ""},
	{EvVRHandoffCertified, "VR handoff: a complete verified certificate is held (I-RET)", "rootchain/vrschedule/service.go", ""},
	{EvVRHandoffOrdering, "VR handoff: ordering the ", "rootchain/consensus/vr_handoff.go", ""},
	{EvVRHandoffShardStage, "VR handoff: the paired shard node holds the staged successor", "rootchain/consensus/vr_handoff.go", ""},
	{EvVRHandoffRefused, "VR handoff: the leader leaves out a refused ", "rootchain/consensus/handoff_refused.go", ""},
	{EvVROutputPublished, "VR output published: source recorded", "rootchain/vrschedule/observe.go", ""},
	{EvVRRecoveryOrdered, "VR recovery: the leader orders the Prepare of the exact recovery", "rootchain/consensus/vr_recovery.go", ""},
	{EvVRRecoveryFollowed, "VR recovery: the leader follows the exact recovery", "rootchain/consensus/vr_recovery.go", ""},
	{EvVRRecoveryDropped, "VR recovery: the request is dropped", "rootchain/consensus/vr_recovery.go", ""},
	{EvRootHandoffOutcome, "root handoff outcome", "rootchain/consensus/storage/block_store.go", ""},
	{EvRootEpochSwitch, "switching epoch in process at the committed activation", "rootchain/consensus/epoch_switch.go", ""},
	{EvRootEpochSwitchFail, "in-process epoch switch failed", "rootchain/consensus/epoch_switch.go", ""},
	{EvShardHandoffActive, "handoff activated", "cli/ubft/cmd/shard_node_run.go", ""},
	{EvExitRetirementReq, "retirement requested", "rootchain/posretire/posretire.go", ""},
	{EvExitRetirementProof, "retirement proof ready", "rootchain/posretire/posretire.go", ""},
	{EvExitRetirementDone, "retirement request complete", "rootchain/posretire/posretire.go", ""},
	{EvRootRoundTimeout, "local timeout", "rootchain/consensus/consensus_manager.go", ""},
	{EvRootVoteMissed, "this root ended rounds without a vote", "rootchain/consensus/unicity_metrics.go", ""},
	{EvRootRecovery, "failure to process QC triggers recovery", "rootchain/consensus/consensus_manager.go", ""},
	{EvShardNoProgress, "certification work has not progressed", "shardnode/bftclient.go", ""},
	{EvNodePeersLow, "connected peers are below the committee", "monitoring/peers.go", ""},
	{EvNodePeersRecovered, "connected peers are back to the committee", "monitoring/peers.go", ""},
	{EvDiskLow, "disk space is low", "monitoring/disk.go", ""},
	{EvDiskRecovered, "disk space recovered", "monitoring/disk.go", ""},
	{EvVRModuleHealth, "VR module health changed", "cli/ubft/cmd/validator_exporter.go", ""},
	{EvIdentityNone, "validator state changed", "cli/ubft/cmd/validator_exporter.go", "IdentityEvent("},
	{EvIdentityApplied, "validator state changed", "cli/ubft/cmd/validator_exporter.go", "IdentityEvent("},
	{EvIdentityAdmitted, "validator state changed", "cli/ubft/cmd/validator_exporter.go", "IdentityEvent("},
	{EvIdentityJoining, "validator state changed", "cli/ubft/cmd/validator_exporter.go", "IdentityEvent("},
	{EvIdentityActive, "validator state changed", "cli/ubft/cmd/validator_exporter.go", "IdentityEvent("},
	{EvIdentityExitRequested, "validator state changed", "cli/ubft/cmd/validator_exporter.go", "IdentityEvent("},
	{EvIdentityRemoving, "validator state changed", "cli/ubft/cmd/validator_exporter.go", "IdentityEvent("},
	{EvIdentityLeaving, "validator state changed", "cli/ubft/cmd/validator_exporter.go", "IdentityEvent("},
	{EvIdentityExited, "validator state changed", "cli/ubft/cmd/validator_exporter.go", "IdentityEvent("},
	{EvIdentityParked, "validator state changed", "cli/ubft/cmd/validator_exporter.go", "IdentityEvent("},
}

// ExternalEvents are catalogued events another ticket's code logs (VT-07, bft-core#1228); the source check starts when it merges.
var ExternalEvents = []string{"activation.latched", "activation.active", "upgrade.required"}

// IdentityEvent is the event name of a PoA state name ("Applied", "ExitRequested", ...).
func IdentityEvent(state string) string {
	switch state {
	case "Applied":
		return EvIdentityApplied
	case "Admitted":
		return EvIdentityAdmitted
	case "Joining":
		return EvIdentityJoining
	case "Active":
		return EvIdentityActive
	case "ExitRequested":
		return EvIdentityExitRequested
	case "Removing":
		return EvIdentityRemoving
	case "Leaving":
		return EvIdentityLeaving
	case "Exited":
		return EvIdentityExited
	case "Parked":
		return EvIdentityParked
	}
	return EvIdentityNone
}
