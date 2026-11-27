package evmassign

import (
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

// #1286: an in-place EVM-key rotation keeps the identity's custody id and generation (the bond cycle) and changes only the EVM node and
// key. The frozen binding hash, the possession digest and the binding ref name the new key at the same generation, so a proof by the
// old key cannot serve the rotated member, and nothing in the digests depends on the registry's binding-version counter.
func TestInPlaceEVMRotationDigestsNameTheNewKeyAtTheSameGeneration(t *testing.T) {
	f, d := loadPub(t)
	facts := factsFromFixture(t, f)
	ids := f.identities(t, f.Identities)
	cids, err := ascendingCustodyIDs(ids)
	require.NoError(t, err)
	old := ids[0]
	k, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	rotated := old
	rotated.EVMNodeID = old.EVMNodeID + "-recovered"
	rotated.EVMKey = ethcrypto.CompressPubkey(&k.PublicKey)

	oldHash, err := BindingHash(old)
	require.NoError(t, err)
	newHash, err := BindingHash(rotated)
	require.NoError(t, err)
	require.NotEqual(t, oldHash, newHash, "the frozen binding hash names the new EVM key")
	require.NotEqual(t, old.BindingRef(), rotated.BindingRef(), "a commitment under the old binding ref does not count for the rotated binding")

	oldDigest := PoPDigest(d, facts.ResultID, facts.AssignmentID, facts.SnapshotDigest, facts.Attempt, cids[0], old.Generation, old.EVMKey)
	newDigest := PoPDigest(d, facts.ResultID, facts.AssignmentID, facts.SnapshotDigest, facts.Attempt, cids[0], rotated.Generation, rotated.EVMKey)
	require.NotEqual(t, oldDigest, newDigest)
	// the same custody generation: the digest of the rotated member is the one the election computes for its frozen generation
	require.Equal(t, old.Generation, rotated.Generation)
	require.Equal(t, newDigest, PoPDigest(d, facts.ResultID, facts.AssignmentID, facts.SnapshotDigest, facts.Attempt, cids[0], old.Generation, rotated.EVMKey))

	// a proof by the old key over the new digest does not recover the new key
	oldKey, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	sig, err := ethcrypto.Sign(newDigest[:], oldKey)
	require.NoError(t, err)
	pub, err := ethcrypto.SigToPub(newDigest[:], sig)
	require.NoError(t, err)
	require.NotEqual(t, rotated.EVMKey, ethcrypto.CompressPubkey(pub))
	sig, err = ethcrypto.Sign(newDigest[:], k)
	require.NoError(t, err)
	pub, err = ethcrypto.SigToPub(newDigest[:], sig)
	require.NoError(t, err)
	require.Equal(t, rotated.EVMKey, ethcrypto.CompressPubkey(pub))
}
