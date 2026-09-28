package handoff

import (
	"bytes"
	"math"

	"github.com/unicitynetwork/bft-core/evmroot"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// EVMTransition is the single acknowledgement payload sent across the trusted
// local bft-core/ureth link. The Ack encoding binds the EVM round and parent.
type EVMTransition struct {
	OldEpoch, NewEpoch    uint64
	NextBodyID, GenesisID [32]byte
	Ack                   AckRecord
}

func (t EVMTransition) Valid() bool {
	return t.OldEpoch != math.MaxUint64 && t.NewEpoch == t.OldEpoch+1 &&
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
	return enc("UNICITY_HANDOFF_EVM_TRANSITION", Version, t.OldEpoch, t.NewEpoch,
		t.NextBodyID[:], t.GenesisID[:], ack)
}

func DecodeEVMTransition(data []byte) (EVMTransition, error) {
	var t EVMTransition
	v, err := exact(data, 7, "UNICITY_HANDOFF_EVM_TRANSITION")
	if err != nil {
		return t, err
	}
	if x, e := u(v[1]); e != nil || x != Version {
		return t, ErrCodec
	}
	if t.OldEpoch, err = u(v[2]); err != nil {
		return t, err
	}
	if t.NewEpoch, err = u(v[3]); err != nil {
		return t, err
	}
	if t.NextBodyID, err = b32(v[4]); err != nil {
		return t, err
	}
	if t.GenesisID, err = b32(v[5]); err != nil {
		return t, err
	}
	ack, err := raw(v[6])
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

// TransitionFromInstalledAnchor verifies H under the old trust base and derives
// the successor identity before using the installed typed anchor. The control
// state must carry the freeze parent committed under the same old QC.
func TransitionFromInstalledAnchor(p OldCommitProof, old *types.RootTrustBaseV1,
	body evmroot.TrustBaseBodyV2, anchor *rctypes.EpochAnchor, evmRound uint64) (EVMTransition, error) {
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
	var t EVMTransition
	t.OldEpoch, t.NewEpoch = p.Record.Epoch, g.Epoch
	copy(t.NextBodyID[:], p.Record.NextBodyID)
	copy(t.GenesisID[:], g.ID())
	copy(t.Ack.FrozenID[:], p.Record.FrozenID)
	copy(t.Ack.CommitID[:], p.Record.ID())
	copy(t.Ack.FrozenParent[:], p.Control.FrozenParent)
	t.Ack.SuccessorParent = t.Ack.FrozenParent
	copy(t.Ack.SuccessorTR[:], p.Record.SuccessorTRHash)
	t.Ack.EVMRound = evmRound
	if !t.Valid() {
		return EVMTransition{}, ErrProof
	}
	return t, nil
}
