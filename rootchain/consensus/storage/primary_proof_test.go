package storage

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

type fakePrimary struct {
	err   error
	asked int
	root  [32]byte
}

func (f *fakePrimary) VerifyPrimary(_ []byte, root [32]byte, _ [32]byte) (evmassign.PrimaryFacts, error) {
	f.asked++
	f.root = root
	return evmassign.PrimaryFacts{}, f.err
}

func primaryServices(a PrimaryAuthority, election byte) *PosServices {
	return &PosServices{Primary: a, Deployment: PosDeployment{Election: [20]byte{19: election}}}
}

func frozenAt(root byte) *ShardInfo {
	return &ShardInfo{IR: &types.InputRecord{Hash: bytes.Repeat([]byte{root}, 32)}}
}

func proofBytes(t *testing.T) []byte {
	raw, err := evmassign.PrimaryProof{Witness: []byte("w"), PoPs: []evmassign.EVMPoP{{ID: 1, EVMKey: bytes.Repeat([]byte{2}, 33), Signature: bytes.Repeat([]byte{3}, 65)}}}.Encode()
	require.NoError(t, err)
	return raw
}

// Each gate of the primary-proof admission is isolated: only the one input named differs from an otherwise admissible companion.
func TestVerifyPrimaryProofGates(t *testing.T) {
	primary := evmassign.Candidate{Kind: evmassign.KindPrimary}
	recovery := evmassign.Candidate{Kind: evmassign.KindRecovery}
	v4 := FreezeCompanion{Version: freezeV4Version, Proof: proofBytes(t)}
	v3 := FreezeCompanion{Version: freezeV3Version}

	t.Run("a judged primary without the proof is refused", func(t *testing.T) {
		a := &fakePrimary{}
		err := verifyPrimaryProof(v3, primary, frozenAt(7), primaryServices(a, 1))
		require.ErrorIs(t, err, ErrPrimaryProofMissing)
		require.ErrorIs(t, err, ErrHandoffRecord)
		require.Zero(t, a.asked)
	})
	t.Run("a proof nothing would check is refused: recovery", func(t *testing.T) {
		require.ErrorIs(t, verifyPrimaryProof(v4, recovery, frozenAt(7), primaryServices(&fakePrimary{}, 1)), ErrPrimaryProofUnexpected)
	})
	t.Run("a proof nothing would check is refused: no election pinned", func(t *testing.T) {
		require.ErrorIs(t, verifyPrimaryProof(v4, primary, frozenAt(7), primaryServices(&fakePrimary{}, 0)), ErrPrimaryProofUnexpected)
	})
	t.Run("a proof nothing would check is refused: no services", func(t *testing.T) {
		require.ErrorIs(t, verifyPrimaryProof(v4, primary, frozenAt(7), nil), ErrPrimaryProofUnexpected)
	})
	t.Run("an unjudged chain admits the unproven companion", func(t *testing.T) {
		require.NoError(t, verifyPrimaryProof(v3, primary, frozenAt(7), nil))
		require.NoError(t, verifyPrimaryProof(v3, recovery, frozenAt(7), primaryServices(&fakePrimary{}, 1)))
	})
	t.Run("no frozen parent state", func(t *testing.T) {
		require.ErrorIs(t, verifyPrimaryProof(v4, primary, nil, primaryServices(&fakePrimary{}, 1)), ErrPrepareNoEVMParent)
		require.ErrorIs(t, verifyPrimaryProof(v4, primary, &ShardInfo{IR: &types.InputRecord{Hash: []byte{1}}}, primaryServices(&fakePrimary{}, 1)), ErrPrepareNoEVMParent)
	})
	t.Run("a malformed proof", func(t *testing.T) {
		bad := v4
		bad.Proof = []byte{0xf6}
		a := &fakePrimary{}
		require.ErrorIs(t, verifyPrimaryProof(bad, primary, frozenAt(7), primaryServices(a, 1)), evmassign.ErrPrimaryProofEncoding)
		require.Zero(t, a.asked)
	})
	t.Run("the authority judges against the frozen parent's state root and its refusal is the refusal", func(t *testing.T) {
		boom := errors.New("storage proof does not verify")
		a := &fakePrimary{err: boom}
		err := verifyPrimaryProof(v4, primary, frozenAt(7), primaryServices(a, 1))
		require.ErrorIs(t, err, ErrPrimaryProofRefused)
		require.ErrorIs(t, err, boom)
		require.Equal(t, [32]byte(bytes.Repeat([]byte{7}, 32)), a.root)
	})
	t.Run("facts that do not show the candidate published are refused", func(t *testing.T) {
		err := verifyPrimaryProof(v4, primary, frozenAt(7), primaryServices(&fakePrimary{}, 1))
		require.ErrorIs(t, err, ErrPrimaryProofRefused)
	})
}

func TestFreezeV4CompanionIsCanonicalAndComplete(t *testing.T) {
	full := FreezeV4Authorization{Version: freezeV4Version, Body: []byte("b"), Parent: bytes.Repeat([]byte{1}, 32), Candidate: bytes.Repeat([]byte{2}, 32),
		Preimage: []byte("p"), Receipts: []byte("r"), Signatures: map[string]hex.Bytes{"n": {1}}, Proof: []byte("x")}
	raw, err := full.Bytes()
	require.NoError(t, err)
	fc, err := ParseFreezeCompanion(raw)
	require.NoError(t, err)
	require.EqualValues(t, freezeV4Version, fc.Version)
	require.Equal(t, full.Proof, fc.Proof)

	for name, mutate := range map[string]func(*FreezeV4Authorization){
		"no proof":    func(a *FreezeV4Authorization) { a.Proof = nil },
		"no preimage": func(a *FreezeV4Authorization) { a.Preimage = nil },
		"no receipts": func(a *FreezeV4Authorization) { a.Receipts = nil },
		"no sigs":     func(a *FreezeV4Authorization) { a.Signatures = nil },
	} {
		c := full
		mutate(&c)
		bad, err := c.Bytes()
		require.NoError(t, err)
		_, err = ParseFreezeCompanion(bad)
		require.ErrorIs(t, err, ErrHandoffRecord, name)
	}
	_, err = ParseFreezeCompanion(append(bytes.Clone(raw), 0))
	require.ErrorIs(t, err, ErrHandoffRecord)
}
