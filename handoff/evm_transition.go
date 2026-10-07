package handoff

import (
	"bytes"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// EVMTransitionVersion is the only transition encoding. It replaces the
// root-epoch-only version 2: one body now names both the root epoch and the
// EVM assignment step, so a consumer cannot read an assignment change as a
// root-only one.
const EVMTransitionVersion uint64 = 3

// MaxSupersessionSpan bounds the committed handoffs one folded acknowledgement
// may summarize, matching the Ureth decoder.
const MaxSupersessionSpan uint64 = 2

// EVMTransition is the single acknowledgement payload sent across the trusted
// local bft-core/ureth link. The Ack encoding binds the EVM round and parent.
//
// A root-only handoff advances the root epoch by one and keeps the shard epoch
// and active configuration hash. An EVM assignment handoff advances both by
// one and changes the hash. A superseding acknowledgement folds more than one
// committed step: root and shard epochs jump by the same span, the hash changes,
// and a nonzero commitment names the verified chain. The Ack fields are those
// of the latest committed handoff; every step froze the same parent.
type EVMTransition struct {
	OldRootEpoch, NewRootEpoch           uint64
	OldShardEpoch, NewShardEpoch         uint64
	OldActiveConfHash, NewActiveConfHash [32]byte
	SupersessionSpan                     uint64
	SupersessionCommitment               [32]byte
	NextBodyID, GenesisID                [32]byte
	Ack                                  AckRecord
}

func (t EVMTransition) epochsValid() bool {
	rootDelta, ok := sub(t.NewRootEpoch, t.OldRootEpoch)
	if !ok || t.OldActiveConfHash == ([32]byte{}) || t.NewActiveConfHash == ([32]byte{}) {
		return false
	}
	shardDelta, shardOK := sub(t.NewShardEpoch, t.OldShardEpoch)
	changed := t.NewShardEpoch != t.OldShardEpoch || t.NewActiveConfHash != t.OldActiveConfHash
	switch {
	case rootDelta == 1 && !changed:
		return shardOK && shardDelta == 0 && t.SupersessionSpan == 0 && t.SupersessionCommitment == [32]byte{}
	case rootDelta == 1:
		return shardOK && shardDelta == 1 && t.NewActiveConfHash != t.OldActiveConfHash &&
			t.SupersessionSpan == 0 && t.SupersessionCommitment == [32]byte{}
	case rootDelta > 1:
		return rootDelta <= MaxSupersessionSpan && shardOK && shardDelta == rootDelta &&
			t.NewActiveConfHash != t.OldActiveConfHash && t.SupersessionSpan == rootDelta &&
			t.SupersessionCommitment != [32]byte{}
	}
	return false
}

func sub(a, b uint64) (uint64, bool) {
	if a < b {
		return 0, false
	}
	return a - b, true
}

func (t EVMTransition) Valid() bool {
	return t.epochsValid() &&
		t.NextBodyID != ([32]byte{}) && t.GenesisID != ([32]byte{}) &&
		t.Ack.FrozenID != ([32]byte{}) && t.Ack.CommitID != ([32]byte{}) &&
		t.Ack.FrozenParent != ([32]byte{}) && t.Ack.FrozenParent == t.Ack.SuccessorParent &&
		t.Ack.SuccessorTR != ([32]byte{}) && t.Ack.EVMRound != 0
}

func (t EVMTransition) Encode() ([]byte, error) {
	if !t.Valid() {
		return nil, ErrCodec
	}
	ack, err := t.Ack.Encode()
	if err != nil {
		return nil, err
	}
	return enc("UNICITY_HANDOFF_EVM_TRANSITION", EVMTransitionVersion, t.OldRootEpoch, t.NewRootEpoch,
		t.OldShardEpoch, t.NewShardEpoch, t.OldActiveConfHash[:], t.NewActiveConfHash[:],
		t.SupersessionSpan, t.SupersessionCommitment[:], t.NextBodyID[:], t.GenesisID[:], ack)
}

func DecodeEVMTransition(data []byte) (EVMTransition, error) {
	var t EVMTransition
	v, err := exact(data, 13, "UNICITY_HANDOFF_EVM_TRANSITION")
	if err != nil {
		return t, err
	}
	if x, e := u(v[1]); e != nil || x != EVMTransitionVersion {
		return t, ErrCodec
	}
	for i, p := range []*uint64{&t.OldRootEpoch, &t.NewRootEpoch, &t.OldShardEpoch, &t.NewShardEpoch} {
		if *p, err = u(v[i+2]); err != nil {
			return t, err
		}
	}
	if t.OldActiveConfHash, err = b32(v[6]); err != nil {
		return t, err
	}
	if t.NewActiveConfHash, err = b32(v[7]); err != nil {
		return t, err
	}
	if t.SupersessionSpan, err = u(v[8]); err != nil {
		return t, err
	}
	if t.SupersessionCommitment, err = b32(v[9]); err != nil {
		return t, err
	}
	if t.NextBodyID, err = b32(v[10]); err != nil {
		return t, err
	}
	if t.GenesisID, err = b32(v[11]); err != nil {
		return t, err
	}
	ack, err := raw(v[12])
	if err != nil {
		return t, err
	}
	if t.Ack, err = DecodeAck(ack); err != nil || !t.Valid() {
		return EVMTransition{}, ErrCodec
	}
	canonical, err := t.Encode()
	if err != nil || !bytes.Equal(canonical, data) {
		return EVMTransition{}, ErrCodec
	}
	return t, nil
}

// FoldTransitions summarizes consecutive committed steps, oldest first, into the
// one acknowledgement of a supersession. Every step must continue the previous
// one exactly (same registry-visible epochs and hashes), freeze the same parent,
// and be itself valid. One step is returned unchanged. The span commitment is the
// chain commitment over the steps' commit record identifiers, which is exactly
// what a consumer recomputes from its own retained history.
func FoldTransitions(steps []EVMTransition) (EVMTransition, error) {
	if len(steps) == 0 || uint64(len(steps)) > MaxSupersessionSpan {
		return EVMTransition{}, ErrBoundary
	}
	if len(steps) == 1 {
		if !steps[0].Valid() {
			return EVMTransition{}, ErrBoundary
		}
		return steps[0], nil
	}
	ids := make([][]byte, 0, len(steps))
	for i, s := range steps {
		if !s.Valid() || s.NewRootEpoch != s.OldRootEpoch+1 || s.SupersessionSpan != 0 {
			return EVMTransition{}, ErrBoundary
		}
		if i > 0 {
			p := steps[i-1]
			if s.OldRootEpoch != p.NewRootEpoch || s.OldShardEpoch != p.NewShardEpoch ||
				s.OldActiveConfHash != p.NewActiveConfHash || s.Ack.FrozenParent != steps[0].Ack.FrozenParent {
				return EVMTransition{}, ErrBoundary
			}
			if s.NewShardEpoch != s.OldShardEpoch+1 {
				return EVMTransition{}, ErrBoundary // only assignment steps can be superseded
			}
		}
		ids = append(ids, bytes.Clone(s.Ack.CommitID[:]))
	}
	first, last := steps[0], steps[len(steps)-1]
	if first.NewShardEpoch != first.OldShardEpoch+1 {
		return EVMTransition{}, ErrBoundary
	}
	commitment, err := evmassign.ChainCommit(first.OldRootEpoch, first.OldShardEpoch, first.OldActiveConfHash[:], ids)
	if err != nil {
		return EVMTransition{}, ErrBoundary
	}
	out := last
	out.OldRootEpoch, out.OldShardEpoch, out.OldActiveConfHash = first.OldRootEpoch, first.OldShardEpoch, first.OldActiveConfHash
	out.SupersessionSpan = uint64(len(steps))
	out.SupersessionCommitment = commitment
	if !out.Valid() {
		return EVMTransition{}, ErrBoundary
	}
	return out, nil
}

// BuildTransition derives the one-step acknowledgement payload of a committed
// handoff. record and frozenParent come from the verified old commit proof,
// genesisID from the derived epoch genesis, and snapshotTR is the shard's technical
// record in the verified old checkpoint. For an assignment step the committed
// successor record is the derived one, so the acknowledgement round is the next
// monotone shard round; the successor certificate re-authenticates the hash.
func BuildTransition(record evmroot.OrderedHandoffRecord, frozenParent []byte, genesisEpoch uint64, genesisID []byte,
	snapshotTR certification.TechnicalRecord, step AssignmentStep) (EVMTransition, error) {
	var t EVMTransition
	if len(frozenParent) != 32 || len(genesisID) != 32 || record.Epoch == ^uint64(0) || genesisEpoch != record.Epoch+1 || snapshotTR.Round == 0 {
		return t, ErrProof
	}
	round := snapshotTR.Round
	if step.Assignment {
		if snapshotTR.Round == ^uint64(0) || snapshotTR.Epoch != step.OldShardEpoch || step.NewShardEpoch != step.OldShardEpoch+1 {
			return t, ErrProof
		}
		round++
	} else {
		digest, err := snapshotTR.Hash()
		if err != nil || !bytes.Equal(digest, record.SuccessorTRHash) || step.NewShardEpoch != step.OldShardEpoch ||
			step.NewActiveConfHash != step.OldActiveConfHash {
			return t, ErrProof
		}
	}
	t.OldRootEpoch, t.NewRootEpoch = record.Epoch, genesisEpoch
	t.OldShardEpoch, t.NewShardEpoch = step.OldShardEpoch, step.NewShardEpoch
	t.OldActiveConfHash, t.NewActiveConfHash = step.OldActiveConfHash, step.NewActiveConfHash
	copy(t.NextBodyID[:], record.NextBodyID)
	copy(t.GenesisID[:], genesisID)
	copy(t.Ack.FrozenID[:], record.FrozenID)
	copy(t.Ack.CommitID[:], record.ID())
	copy(t.Ack.FrozenParent[:], frozenParent)
	t.Ack.SuccessorParent = t.Ack.FrozenParent
	copy(t.Ack.SuccessorTR[:], record.SuccessorTRHash)
	// The root activation round and shard assignment are separate counters.
	t.Ack.EVMRound = round
	if !t.Valid() {
		return EVMTransition{}, ErrProof
	}
	return t, nil
}

// TransitionFromInstalledAnchor verifies H under the old trust base and derives
// the successor identity before using the installed typed anchor. The control
// state must carry the freeze parent committed under the same old QC.
func TransitionFromInstalledAnchor(p OldCommitProof, old *types.RootTrustBaseV1,
	body evmroot.TrustBaseBodyV2, anchor *rctypes.EpochAnchor, snapshotTR certification.TechnicalRecord, step AssignmentStep) (EVMTransition, error) {
	verified, err := VerifyOldCommitProof(p, old)
	if err != nil || anchor == nil || len(p.Control.FrozenParent) != 32 {
		return EVMTransition{}, ErrProof
	}
	v := evmroot.VerifiedHandoff{RecordID: bytes.Clone(verified.RecordID[:]), Root: bytes.Clone(verified.StateRoot[:]),
		ControlDigest: bytes.Clone(verified.ControlDigest[:]), OrderRound: verified.OrderRound,
		CommitSealRound: verified.CommitSealRound, Epoch: verified.SignerEpoch, Record: p.Record}
	g, err := evmroot.DeriveEpochGenesis(v, body)
	if err != nil || anchor.Epoch != g.Epoch || anchor.Slot+1 != g.Start ||
		!bytes.Equal(anchor.GenesisID, g.ID()) || !bytes.Equal(anchor.StateRoot, v.Root) {
		return EVMTransition{}, ErrProof
	}
	return BuildTransition(p.Record, p.Control.FrozenParent, g.Epoch, g.ID(), snapshotTR, step)
}

// AssignmentStep carries the EVM assignment context of one committed handoff. A
// root-only handoff keeps the shard epoch and the installed configuration hash; an
// assignment handoff changes both.
type AssignmentStep struct {
	// Assignment is set when H replaces the EVM assignment.
	Assignment                           bool
	OldShardEpoch, NewShardEpoch         uint64
	OldActiveConfHash, NewActiveConfHash [32]byte
}
