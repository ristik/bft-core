package b1state

// OperationalSlots is the one fresh deployment's operational field inventory.
// It preserves field meaning while replacing the old slot domain. The fresh
// proof reader and pinned artifact checks consume this same inventory.
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
