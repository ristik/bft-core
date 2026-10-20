package xrepo

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/crypto"
)

// goRotationEvidencePath is produced HERE (XREPO_UPDATE=1 go test ./xrepo) and replayed by the contracts (XRepoRotationEvidence.t.sol)
// across a root-key rotation that custody activates with an Ack.
const goRotationEvidencePath = "testdata/go-rotation-evidence.json"

// The contracts' rotation scenario (Evidence.t.sol): identity 2 (rootPk(1) = 0x2001) holds its root key in the genesis assignment G
// (root epoch 1), stages the new key 0x9501, and the primary J (root epoch 2) is reserved with the new key and acknowledged.
const (
	rotatedIdentityIndex = 1
	rotatedNewKeyScalar  = 0x9501
)

type rotationStatementJSON struct {
	Label       string   `json:"label"`
	Key         string   `json:"key"` // compressed secp256k1 root key that signed both votes
	VotingEpoch uint64   `json:"votingEpoch"`
	VotingRound uint64   `json:"votingRound"`
	A           voteJSON `json:"a"`
	B           voteJSON `json:"b"`
}

type goRotationEvidence struct {
	Format      string                  `json:"format"`
	Note        string                  `json:"note"`
	RootNetwork uint64                  `json:"rootNetwork"`
	RootGenesis string                  `json:"rootGenesis"`
	OldKey      string                  `json:"oldKey"`
	NewKey      string                  `json:"newKey"`
	Statements  []rotationStatementJSON `json:"statements"`
}

func buildRotationEvidence(t *testing.T) goRotationEvidence {
	t.Helper()
	_, p := compute(t)
	oldSigner, oldKey := rootSigner(t, rotatedIdentityIndex)
	require.Equal(t, unhex(t, p.Identities[rotatedIdentityIndex].RootKey), oldKey, "the publication's root key of identity 2 is rootPk(1)")
	newSigner, newKey := scalarSigner(t, rotatedNewKeyScalar)
	stmt := func(label string, signer *crypto.InMemorySecp256K1Signer, key []byte, epoch, round uint64) rotationStatementJSON {
		a, b := equivocation(t, signer, epoch, round, t0+round)
		return rotationStatementJSON{Label: label, Key: hx(key), VotingEpoch: epoch, VotingRound: round, A: a, B: b}
	}
	return goRotationEvidence{
		Format: "UNICITY_XREPO_GO_ROTATION_EVIDENCE/v1",
		Note: "Produced by bft-core (XREPO_UPDATE=1 go test ./xrepo). Conflicting non-committing scheme 2 root votes built by the root's statement " +
			"derivation (types.DomainBoundStatement) and signed by the root's signer with the contracts' test scalars, for their rotation scenario: " +
			"the old key in the old epoch, the new key in the new epoch, and the old key in the new epoch. Do not edit by hand.",
		RootNetwork: contractsRootNetwork, RootGenesis: hx(contractsRootGenesis[:]), OldKey: hx(oldKey), NewKey: hx(newKey),
		Statements: []rotationStatementJSON{
			stmt("old-key-old-epoch", oldSigner, oldKey, 1, 10),
			stmt("new-key-new-epoch", newSigner, newKey, 2, 105),
			stmt("old-key-new-epoch", oldSigner, oldKey, 2, 106),
		},
	}
}

// The rotation evidence the root's signer produces for the contracts' scenario is the committed file the contracts replay.
func TestTheRootSignedRotationEvidenceIsTheCommittedVectors(t *testing.T) {
	got := encode(t, buildRotationEvidence(t))
	if os.Getenv("XREPO_UPDATE") == "1" {
		require.NoError(t, os.WriteFile(goRotationEvidencePath, got, 0o644))
	}
	want, err := os.ReadFile(goRotationEvidencePath)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got), "the rotation evidence changed: regenerate with XREPO_UPDATE=1 and replay it in unicity-pos-contracts")
}
