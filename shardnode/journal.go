package shardnode

import "context"

// ProposalJournal is the persistence barrier for execution candidates. A successful call means
// the complete original proposal and its authorizing UC/TR are durable. Failure withholds both
// publication and a certification signature. Certification itself is admitted before delivery
// through the configured progress store, which owns the same journal transaction domain.
type ProposalJournal interface {
	RetainCandidate(context.Context, Block, RoundParams, bool) error
}

func (r *Round) SetProposalJournal(j ProposalJournal) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.journal = j
}

func (n *Node) SetProposalJournal(j ProposalJournal) {
	n.round.SetProposalJournal(j)
}
