package consensus

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	basetypes "github.com/unicitynetwork/bft-go-base/types"
)

// ErrNoQ3Evidence is returned when this validator holds no committed V3 activation for the epoch: no Q3 history, no committed
// checkpoint of the handoff into it, or a retained body or receipt set that is not the V3 one.
var ErrNoQ3Evidence = errors.New("no committed Q3 activation evidence for the epoch")

// Q3ActivationEvidence assembles, from this validator's own committed old tip and the artifacts it retained when it admitted the
// Freeze, everything the activation of the successor epoch needs beyond the verified history: the link (V3 body, the evidence its
// candidate rests on, the old committee's commit proof and the readiness receipts of every member), the committed checkpoint the
// successor's root anchor is installed from, and the candidate preimage of a coupled change (nil for a root-only one).
//
// Nothing here is trusted by the receiver: the link's claim is left empty, the history derives it, and the checkpoint is
// re-authenticated against the verified entry. The evidence is the leader's and every endorser's identical retained copy, so any root
// peer can serve it.
func (x *ConsensusManager) Q3ActivationEvidence(epoch uint64) (q3format.Link, *abdrc.CommittedBlock, []byte, error) {
	none := q3format.Link{}
	if x.q3 == nil || x.params.NetworkProfileVersion != storage.ProfileHandoff || epoch < 2 {
		return none, nil, nil, fmt.Errorf("%w: epoch %d", ErrNoQ3Evidence, epoch)
	}
	head, path, record, err := x.blockStore.HandoffCheckpoint()
	if err != nil || head == nil || head.Control == nil || head.CommitQc == nil || record.Epoch+1 != epoch {
		return none, nil, nil, fmt.Errorf("%w: no committed checkpoint into epoch %d", ErrNoQ3Evidence, epoch)
	}
	rawBody, err := x.blockStore.HandoffBody(record.NextBodyID)
	if err != nil || len(rawBody) == 0 {
		return none, nil, nil, fmt.Errorf("%w: no retained body", ErrNoQ3Evidence)
	}
	body, err := q3format.DecodeBody(rawBody)
	if err != nil {
		return none, nil, nil, errors.Join(ErrNoQ3Evidence, err)
	}
	if id := body.Identity(); string(id[:]) != string(record.NextBodyID) {
		return none, nil, nil, fmt.Errorf("%w: the retained body is not the committed one", ErrNoQ3Evidence)
	}
	rawReceipts, err := x.blockStore.HandoffReceipts(record.NextBodyID)
	if err != nil || len(rawReceipts) == 0 {
		return none, nil, nil, fmt.Errorf("%w: no retained readiness receipts", ErrNoQ3Evidence)
	}
	receipts, err := q3format.DecodeReceipts(rawReceipts)
	if err != nil {
		return none, nil, nil, errors.Join(ErrNoQ3Evidence, err)
	}
	candidate, err := x.blockStore.HandoffCandidate(record.NextBodyID)
	if err != nil {
		return none, nil, nil, errors.Join(ErrNoQ3Evidence, err)
	}
	var digest []byte
	if len(candidate) != 0 {
		sum := sha256.Sum256(candidate)
		digest = sum[:]
	} else {
		operator, err := evmroot.D4OperatorCandidateDigest(body.Members)
		if err != nil {
			return none, nil, nil, errors.Join(ErrNoQ3Evidence, err)
		}
		digest = operator[:]
	}
	proof, err := basetypes.Cbor.Marshal(handoff.OldCommitProof{Profile: evmroot.D4Profile, Record: record, Control: *head.Control, ControlPath: path, CommitQC: head.CommitQc})
	if err != nil {
		return none, nil, nil, err
	}
	link := q3format.Link{Body: body, Proof: proof, Receipts: receipts,
		Evidence: q3format.Evidence{Summary: body.StateSummary, FrozenParent: append([]byte(nil), head.Control.FrozenParent...), CandidateDigest: digest}}
	return link, head, candidate, nil
}


// SafetyModule is the manager's safety module: the participant a q3active.Runtime requires to be bound to its history.
func (x *ConsensusManager) SafetyModule() *SafetyModule { return x.safety }
