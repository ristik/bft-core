package storage_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate/evmstatetest"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The route that decides real admission, with the real authority and a real Merkle-Patricia state: the frozen shard's IR.Hash is the state
// root, the deployment the election is judged under is the services', the result is the candidate's, and the witness is verified by
// evmstate.Authority before evmassign.VerifyPrimary binds it to the candidate.
type realAdmission struct {
	p        *evmstatetest.Published
	services *storage.PosServices
}

func newRealAdmission(t *testing.T) realAdmission {
	p := evmstatetest.Load(t, "../../evmstate/testdata/publication.json")
	return realAdmission{p: p, services: &storage.PosServices{
		Primary:    evmstate.Authority{Pins: p.Pins},
		Deployment: storage.PosDeployment{Deployment: p.Deployment.Deployment, Election: p.Deployment.Election},
	}}
}

func (r realAdmission) companion(t *testing.T, witness []byte, pops []evmassign.EVMPoP) storage.FreezeCompanion {
	proof, err := evmassign.PrimaryProof{Witness: witness, PoPs: pops}.Encode()
	require.NoError(t, err)
	return storage.FreezeCompanion{Version: storage.FreezeV4VersionForTest, Proof: proof}
}

func (r realAdmission) frozenAt(root [32]byte) *storage.ShardInfo {
	return &storage.ShardInfo{IR: &types.InputRecord{Hash: bytes.Clone(root[:])}}
}

func (r realAdmission) admit(t *testing.T, fc storage.FreezeCompanion, c evmassign.Candidate, root [32]byte) error {
	return storage.VerifyPrimaryProofForTest(fc, c, r.frozenAt(root), r.services)
}

func TestARealPublishedPrimaryIsAdmittedThroughTheRealAuthority(t *testing.T) {
	r := newRealAdmission(t)
	require.NoError(t, r.admit(t, r.companion(t, r.p.Witness, r.p.PoPs), r.p.Candidate, r.p.StateRoot))
}

// Each refusal differs from the positive case in exactly one input.
func TestARealPrimaryProofIsRefusedForEachBreakage(t *testing.T) {
	r := newRealAdmission(t)
	good := r.companion(t, r.p.Witness, r.p.PoPs)
	require.NoError(t, r.admit(t, good, r.p.Candidate, r.p.StateRoot), "the control")

	refused := func(name string, fc storage.FreezeCompanion, c evmassign.Candidate, root [32]byte) {
		t.Helper()
		err := r.admit(t, fc, c, root)
		require.ErrorIs(t, err, storage.ErrPrimaryProofRefused, name)
		require.ErrorIs(t, err, storage.ErrHandoffRecord, name)
	}

	// the root's certified state is not the one the witness proves
	otherRoot := r.p.StateRoot
	otherRoot[0] ^= 1
	refused("another IR.Hash", good, r.p.Candidate, otherRoot)

	// the witness is tampered: one byte inside it
	tampered := bytes.Clone(r.p.Witness)
	tampered[len(tampered)/2] ^= 1
	refused("a tampered witness", r.companion(t, tampered, r.p.PoPs), r.p.Candidate, r.p.StateRoot)

	// the proofs: another member's signature in a member's place
	swapped := append([]evmassign.EVMPoP{}, r.p.PoPs...)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	refused("PoPs of other members", r.companion(t, r.p.Witness, swapped), r.p.Candidate, r.p.StateRoot)
	forged := append([]evmassign.EVMPoP{}, r.p.PoPs...)
	forged[0].Signature = bytes.Clone(r.p.PoPs[1].Signature)
	refused("another member's signature", r.companion(t, r.p.Witness, forged), r.p.Candidate, r.p.StateRoot)

	// the candidate names another result than the witness proves
	other := r.p.Candidate
	a := *r.p.Candidate.Authorization
	a.ResultID = bytes.Clone(a.ResultID)
	a.ResultID[0] ^= 1
	other.Authorization = &a
	refused("another result", good, other, r.p.StateRoot)

	// the candidate's identity records are not the committed ones
	ids := append([]evmassign.Identity{}, r.p.Candidate.Identities...)
	ids[0].OperatorPayee = bytes.Repeat([]byte{9}, len(ids[0].OperatorPayee))
	changed := r.p.Candidate
	changed.Identities = ids
	refused("another payee", good, changed, r.p.StateRoot)

	// the services judge under another deployment (another election address, another chain)
	t.Run("another deployment", func(t *testing.T) {
		moved := *r.services
		moved.Deployment.Election[0] ^= 1
		err := storage.VerifyPrimaryProofForTest(good, r.p.Candidate, r.frozenAt(r.p.StateRoot), &moved)
		require.ErrorIs(t, err, storage.ErrPrimaryProofRefused)
	})

	// and a recovery, or a chain without the election pinned, carries no proof at all
	recovery := r.p.Candidate
	recovery.Kind = evmassign.KindRecovery
	require.ErrorIs(t, r.admit(t, good, recovery, r.p.StateRoot), storage.ErrPrimaryProofUnexpected)
}
