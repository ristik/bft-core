package handoffdelivery

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-go-base/types"
)

const witnessV3Tag = "UNICITY_P85_CLOSURE_WITNESS_V3"

// WitnessV3 is the terminal handoff of a Q3 (V3 body) epoch as a P85 closure witness: the old committee's commit proof, the canonical V3
// body it commits to, the committed checkpoint and the candidate preimage (empty for a root-only change). It is not a Bundle: the V2
// bundle's body is a different type with a different identity, and a V3 activation is never archived as one. It carries no readiness
// receipts: they authorise the activation, which the history has verified, and the closure facts do not depend on them.
type WitnessV3 struct {
	_         struct{} `cbor:",toarray"`
	Tag       string
	Proof     handoff.OldCommitProof
	Body      []byte // q3format.BodyV3.Encode()
	Snapshot  *abdrc.CommittedBlock
	Candidate []byte
}

// EncodeWitnessV3 is the canonical witness bytes.
func EncodeWitnessV3(w WitnessV3) ([]byte, error) {
	w.Tag = witnessV3Tag
	return types.Cbor.Marshal(w)
}

// decodeWitnessV3 reports whether raw is a V3 witness; a V2 bundle is not (its first element is the proof, not the tag).
func decodeWitnessV3(raw []byte) (WitnessV3, bool) {
	var w WitnessV3
	if err := types.Cbor.Unmarshal(raw, &w); err != nil || w.Tag != witnessV3Tag {
		return WitnessV3{}, false
	}
	return w, true
}

// verifyV3 is Verify for a V3 witness: the same judgement against the closed epoch's own committee and the configuration installed when
// H was ordered, with the V3 body's bindings (body identity, frozen identity, candidate context) in place of the V2 successor body's.
func (v ClosureVerifier) verifyV3(w WitnessV3, closedEpoch uint64) (ClosureEvidence, error) {
	fail := func(err error) (ClosureEvidence, error) { return ClosureEvidence{}, errors.Join(ErrClosure, err) }
	body, err := q3format.DecodeBody(w.Body)
	if err != nil {
		return fail(err)
	}
	if err := body.Validate(); err != nil {
		return fail(err)
	}
	if body.Epoch != closedEpoch+1 {
		return fail(fmt.Errorf("the body opens epoch %d, not the epoch after the closed epoch %d", body.Epoch, closedEpoch))
	}
	if w.Snapshot == nil || w.Snapshot.Control == nil || len(w.Snapshot.ShardInfo) == 0 {
		return fail(errors.New("no checkpoint"))
	}
	old, cfg, err := v.History.TrustBase(closedEpoch)
	if err != nil {
		return fail(err)
	}
	r := w.Proof.Record
	confHash, ids, assignmentID, err := v.History.Assignment(r.OrderedRound)
	if err != nil {
		return fail(err)
	}
	verified, err := handoff.VerifyOldCommitProofSigning(w.Proof, old, cfg)
	if err != nil {
		return fail(err)
	}
	if verified.SignerEpoch != closedEpoch {
		return fail(fmt.Errorf("the record was committed by epoch %d, not the closed epoch %d", verified.SignerEpoch, closedEpoch))
	}
	if id := body.Identity(); !bytes.Equal(r.NextBodyID, id[:]) {
		return fail(errors.New("the record names another body"))
	}
	var digest [32]byte
	if len(w.Candidate) != 0 {
		digest = sha256.Sum256(w.Candidate)
	} else if digest, err = evmroot.D4OperatorCandidateDigest(body.Members); err != nil {
		return fail(err)
	}
	ev := q3format.Evidence{Summary: body.StateSummary, FrozenParent: w.Snapshot.Control.FrozenParent, CandidateDigest: digest[:]}
	if err := q3format.BindCandidate(body, r, ev); err != nil {
		return fail(err)
	}
	if _, err := VerifySnapshot(w.Proof, verified, w.Snapshot, v.Partition, v.Shard, confHash); err != nil {
		return fail(err)
	}
	c, err := decodeWitnessV3Copy(w)
	if err != nil {
		return fail(err)
	}
	stripSignatures(&c.Proof, c.Snapshot)
	stripped, err := types.Cbor.Marshal(c)
	if err != nil {
		return fail(err)
	}
	return ClosureEvidence{ClosedEpoch: closedEpoch, BundleID: sha256.Sum256(stripped), HRecordID: verified.RecordID, HRound: verified.OrderRound,
		TerminalRoot: verified.StateRoot, AssignmentID: assignmentID, Closed: ids}, nil
}

// decodeWitnessV3Copy is a deep copy, so the caller's witness keeps its signatures.
func decodeWitnessV3Copy(w WitnessV3) (WitnessV3, error) {
	raw, err := EncodeWitnessV3(w)
	if err != nil {
		return WitnessV3{}, err
	}
	c, ok := decodeWitnessV3(raw)
	if !ok {
		return WitnessV3{}, ErrBundle
	}
	return c, nil
}
