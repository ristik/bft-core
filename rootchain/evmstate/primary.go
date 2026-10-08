package evmstate

import (
	"errors"
	"fmt"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/unicitynetwork/bft-core/evmassign"
)

// VerifyPrimary proves from one certified EVM state root the fixed proof slots of a published primary result and the two custody facts that
// keep it current (briefs/p85-design-v5.md section 5, "Prepare proves ..."). The witness carries exactly two accounts, Election and custody,
// each pinned by address and code hash; Election must name the pinned custody and the deployment's network word. The facts feed
// evmassign.VerifyPrimary, which binds them to the candidate.
func (a Authority) VerifyPrimary(raw []byte, stateRoot [32]byte, resultID [32]byte) (evmassign.PrimaryFacts, error) {
	var f evmassign.PrimaryFacts
	w, err := decodeWitness(raw)
	if err != nil {
		return f, err
	}
	if len(w.Accounts) != 2 {
		return f, fmt.Errorf("%w: %d accounts, want election and custody", ErrWitness, len(w.Accounts))
	}
	all, err := w.verify(stateRoot)
	if err != nil {
		return f, err
	}
	election, custody := all[ethcommon.Address(a.Pins.Election)], all[ethcommon.Address(a.Pins.Custody)]
	if election == nil || custody == nil {
		return f, fmt.Errorf("%w: the witness lacks the election or the custody account", ErrWitness)
	}
	if election.codeHash != a.Pins.ElectionCode || custody.codeHash != a.Pins.CustodyCode {
		return f, fmt.Errorf("%w: election or custody code hash is not the pinned one", ErrProof)
	}
	if err := readPrimary(election, custody, a.Pins, resultID, &f); err != nil {
		return f, err
	}
	return f, errors.Join(election.unused(), custody.unused())
}

func readPrimary(election, custody reader, pins Pins, resultID [32]byte, f *evmassign.PrimaryFacts) error {
	for _, c := range []struct {
		name string
		r    reader
		slot uint64
	}{{"election", election, electionNetwork}, {"custody", custody, custodyNetwork}} {
		nw, err := c.r.word(baseSlot(c.slot))
		if err != nil {
			return err
		}
		if nw != pins.NetworkWord {
			return fmt.Errorf("%w: %s.network is not the deployment's", ErrProof, c.name)
		}
	}
	pointer, err := election.word(baseSlot(electionCustody))
	if err != nil {
		return err
	}
	if ethcommon.BytesToAddress(pointer[:]) != ethcommon.Address(pins.Custody) {
		return fmt.Errorf("%w: election.custody is not the pinned custody", ErrProof)
	}

	pub := mapSlot(baseSlot(electionPublications), resultID[:])
	words := map[uint64]*[32]byte{
		pubPrimaryHash: &f.PrimaryHash, pubKCommit: &f.KCommit, pubIncumbent: &f.Incumbent, pubIncumbentExposure: &f.IncumbentExposureDigest,
		pubIncumbentKey: &f.IncumbentKeyDigest, pubPolicy: &f.PolicyDigest, pubContracts: &f.ContractsDigest, pubSnapshot: &f.SnapshotDigest,
		pubAssignment: &f.AssignmentID, pubPopSet: &f.PopSetDigest,
	}
	for i := uint64(0); i <= pubPopSet; i++ {
		if *words[i], err = election.word(slotWord(pub, i)); err != nil {
			return err
		}
	}
	flags, err := election.word(slotWord(pub, pubFlags))
	if err != nil {
		return err
	}
	f.ResultID = resultID
	f.Published = fieldUint(flags, pubPublishedOffset, 1) == 1
	f.PopCount = uint32(fieldUint(flags, pubPopCountOffset, 4))
	f.Attempt = fieldUint(flags, pubAttemptOffset, 8)

	// custody: the result's session is open over its reserved assignment, and the incumbent is still the last acknowledged assignment
	session := mapSlot(baseSlot(custodySessions), resultID[:])
	state, err := custody.word(slotWord(session, sessionStateSlot))
	if err != nil {
		return err
	}
	assignmentID, err := custody.word(slotWord(session, sessionAssignmentSlot))
	if err != nil {
		return err
	}
	incumbent, err := custody.word(slotWord(session, sessionIncumbentSlot))
	if err != nil {
		return err
	}
	asg, err := custody.word(slotWord(mapSlot(baseSlot(custodyAssignments), assignmentID[:]), assignmentStateSlot))
	if err != nil {
		return err
	}
	acked, err := custody.word(baseSlot(custodyLastAckedAssignment))
	if err != nil {
		return err
	}
	f.Open = fieldUint(state, 0, 1) == sessionOpen && fieldUint(asg, 0, 1) == assignmentReserved && assignmentID == f.AssignmentID
	f.IncumbentIsLastAcked = incumbent == f.Incumbent && acked == f.Incumbent
	return nil
}
