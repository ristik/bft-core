package consensus

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

type fakeWitness struct {
	err    error
	parent []byte
	asked  int
}

func (f *fakeWitness) PrimaryWitness(parent []byte, _ [32]byte) ([]byte, error) {
	f.asked++
	f.parent = parent
	return []byte("witness"), f.err
}

type fakeAuthority struct{}

func (fakeAuthority) VerifyPrimary([]byte, [32]byte, [32]byte) (evmassign.PrimaryFacts, error) {
	return evmassign.PrimaryFacts{}, nil
}

func managerFor(judged bool) *ConsensusManager {
	bs := &storage.BlockStore{}
	svc := &storage.PosServices{}
	if judged {
		svc.Primary = fakeAuthority{}
		svc.Deployment.Election = [20]byte{19: 3}
	}
	bs.SetPosServices(svc)
	return &ConsensusManager{blockStore: bs}
}

func pops(t *testing.T) []byte {
	raw, err := evmassign.EncodePoPs([]evmassign.EVMPoP{{ID: 1, EVMKey: bytes.Repeat([]byte{2}, 33), Signature: bytes.Repeat([]byte{3}, 65)}})
	require.NoError(t, err)
	return raw
}

func TestCheckPrimaryPoPsRequiresThemExactlyWhereTheChainJudges(t *testing.T) {
	primary, recovery := evmassign.Candidate{Kind: evmassign.KindPrimary}, evmassign.Candidate{Kind: evmassign.KindRecovery}
	withPoPs := &abdrc.HandoffApprovalMsg{CandidatePreimage: []byte{1}, PrimaryPoPs: pops(t)}
	without := &abdrc.HandoffApprovalMsg{CandidatePreimage: []byte{1}}
	junk := &abdrc.HandoffApprovalMsg{CandidatePreimage: []byte{1}, PrimaryPoPs: []byte{0xf6}}

	judged, plain := managerFor(true), managerFor(false)
	require.NoError(t, judged.checkPrimaryPoPs(withPoPs, primary))
	require.ErrorIs(t, judged.checkPrimaryPoPs(without, primary), storage.ErrPrimaryProofMissing)
	require.ErrorIs(t, judged.checkPrimaryPoPs(junk, primary), storage.ErrPrimaryProofMissing)
	require.ErrorIs(t, judged.checkPrimaryPoPs(withPoPs, recovery), storage.ErrPrimaryProofUnexpected, "a recovery proves nothing")
	require.NoError(t, judged.checkPrimaryPoPs(without, recovery))
	require.ErrorIs(t, plain.checkPrimaryPoPs(withPoPs, primary), storage.ErrPrimaryProofUnexpected, "an unjudged chain takes none")
	require.NoError(t, plain.checkPrimaryPoPs(without, primary))
	require.ErrorIs(t, judged.checkPrimaryPoPs(&abdrc.HandoffApprovalMsg{PrimaryPoPs: pops(t)}, primary), storage.ErrPrimaryProofUnexpected, "a root-only plan carries none")
}

func TestPrimaryFreezeProofIsBuiltAtTheFrozenParent(t *testing.T) {
	parent := bytes.Repeat([]byte{9}, 32)
	primary, recovery := evmassign.Candidate{Kind: evmassign.KindPrimary}, evmassign.Candidate{Kind: evmassign.KindRecovery}
	x := managerFor(true)

	w := &fakeWitness{}
	x.SetPrimaryWitnessSource(w)
	raw, err := x.primaryProofFor(primary, pops(t), parent)
	require.NoError(t, err)
	proof, err := evmassign.DecodePrimaryProof(raw)
	require.NoError(t, err)
	require.Equal(t, []byte("witness"), proof.Witness)
	require.Equal(t, parent, w.parent, "the witness is built at the parent the root bound")

	none, err := x.primaryProofFor(recovery, nil, parent)
	require.NoError(t, err)
	require.Nil(t, none, "a recovery carries no proof")
	none, err = managerFor(false).primaryProofFor(primary, nil, parent)
	require.NoError(t, err)
	require.Nil(t, none, "an unjudged chain builds none")

	_, err = x.primaryProofFor(primary, nil, parent)
	require.ErrorIs(t, err, storage.ErrPrimaryProofMissing)

	w.err = errors.New("node down")
	_, err = x.primaryProofFor(primary, pops(t), parent)
	require.ErrorIs(t, err, storage.ErrWitnessUnavailable, "unavailable, never an empty proof")

	x.SetPrimaryWitnessSource(nil)
	_, err = x.primaryProofFor(primary, pops(t), parent)
	require.ErrorIs(t, err, storage.ErrWitnessUnavailable)
}
