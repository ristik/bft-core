package b1state

// OperationalSlots is the one fresh deployment's operational field inventory.
// It preserves field meaning while replacing the old slot domain. This is a
// specification export, not the live registryproof reader or PR3 artifact.
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
