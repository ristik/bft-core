package b1state

// OperationalSlots is the one fresh deployment's operational field inventory.
// It preserves field meaning while replacing the old slot domain. The fresh
// proof reader and pinned artifact checks consume this same inventory.
// RecordSlots are the fixed words of the authenticated root-record log (the P85 registry's `records.*`), appended to the operational
// inventory in the pinned artifact. They are not part of OperationalSlots: B1 history logic never reads them.
func RecordSlots() []string {
	return []string{"records.count", "records.tip", "records.progress", "records.ucTime", "records.targetCount", "records.targetTip", "records.importedRound"}
}

func OperationalSlots() []string {
	return []string{
		"genesisCommitment", "config.shardConfHash", "assignment.epoch", "assignment.rootEpoch",
		"assignment.activeConfHash", "assignment.spanCommitment", "clock.rootRound", "origin.rootEpoch",
		"origin.timestamp", "origin.treeRoot", "origin.identity", "origin.trHash", "round.authorized",
		"input.commitment", "certified.round", "certified.stateHash", "certified.hasBlockHash",
		"certified.blockHash", "phase", "outcomes.round", "outcomes.commitment", "transition.cursor",
		"inbox.consumed", "transition.bodyID", "transition.genesisID", "transition.frozenID",
		"transition.commitID", "transition.frozenParent", "transition.successorTR",
	}
}
