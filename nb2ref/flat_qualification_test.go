package nb2ref

import (
	"bytes"
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

// extendQualificationCertificate certifies a deliberately deep path with the
// fixture's full weighted committee. No live authority or deployment is used.
func extendQualificationCertificate(t *testing.T, committee *Committee, uc *types.UnicityCertificate) {
	t.Helper()
	tree := uc.UnicityTreeCertificate
	tree.HashSteps = make([]*types.PathItem, 32)
	for i := range tree.HashSteps {
		hash := HU([]byte(fmt.Sprintf("qualification/unicity/%d", i)))
		tree.HashSteps[i] = &types.PathItem{Key: tree.Partition + types.PartitionID(i+1), Hash: hash[:]}
	}
	shard, err := uc.ShardTreeCertificate.ComputeCertificateHash(uc.InputRecord, uc.TRHash, uc.ShardConfHash, crypto.SHA256)
	require.NoError(t, err)
	root, err := tree.EvalAuthPath(shard, crypto.SHA256)
	require.NoError(t, err)
	uc.UnicitySeal.Hash = root
	uc.UnicitySeal.Signatures = nil
	for _, member := range committee.members {
		require.NoError(t, uc.UnicitySeal.Sign(member.info.NodeID, member.signer))
	}
	require.Len(t, uc.UnicitySeal.Signatures, 16)
}

func TestFlatJointNativeQualification(t *testing.T) {
	w, err := NewWorld(64, 16, 1)
	require.NoError(t, err)
	first, err := NewCommittee("qualification-old", 16, 3, 2)
	require.NoError(t, err)
	second, err := NewCommittee("qualification-tip", 16, 2, 3)
	require.NoError(t, err)
	genesis, err := first.Genesis(DevNetwork, 1, 1)
	require.NoError(t, err)
	successor, err := first.Successor(genesis, second, RotationRound)
	require.NoError(t, err)
	pin, err := genesis.EntryID()
	require.NoError(t, err)
	bundle, err := TrustBundle(genesis, successor)
	require.NoError(t, err)
	w.Trust, err = LoadTrustInput(bundle, pin)
	require.NoError(t, err)
	w.Roots = []*Committee{first, second}
	w.Entries = []*types.RootTrustBaseV2{genesis, successor}
	w.Agg.Committee = first

	_, old, _ := flatFixtureVerifier(t)
	cfg := *old.cfg
	cfg.RootGenesis = pin
	cfg.Ty, cfg.Aid = FlatAssetIDs(&cfg)
	gamma := FlatConfigBytes(&cfg)
	w, v, registry := flatFixtureVerifierWithWorld(t, w, gamma, old.deployment)

	receipt := ReceiptOpts{Type: 2, TxIndex: 127, FillerLogs: 1, MutReceipt: func(r *RawReceipt) {
		r.Logs[0].Data = bytes.Repeat([]byte{0xa5}, 48_000)
	}}
	deposit, predecessor := receipt, receipt
	deposit.TamperUC = func(uc *types.UnicityCertificate) { extendQualificationCertificate(t, first, uc) }
	predecessor.Rotated = true
	predecessor.TamperUC = func(uc *types.UnicityCertificate) { extendQualificationCertificate(t, second, uc) }
	fullPath := func(proof *InclusionProof) {
		sid := StateID(proof.CD.Source, proof.CD.SourceHash)
		uc, err := decodeUC(proof.UC)
		require.NoError(t, err)
		var shard types.ShardID
		require.NoError(t, shard.UnmarshalCBOR(CBytes(append(sid[:], 0x80))))
		require.Equal(t, uint(256), shard.Length())
		uc.ShardTreeCertificate.Shard = shard
		uc.ShardTreeCertificate.SiblingHashes = make([][]byte, 256)
		for i := range uc.ShardTreeCertificate.SiblingHashes {
			hash := HU([]byte(fmt.Sprintf("qualification/shard/%d", i)))
			uc.ShardTreeCertificate.SiblingHashes[i] = hash[:]
		}
		pdr := FixturePDR(DevNetwork, DevAggPartition, shard, 0, "qualification-shard")
		uc.ShardConfHash, err = pdr.Hash(crypto.SHA256)
		require.NoError(t, err)
		extendQualificationCertificate(t, first, uc)
		proof.UC, err = types.Cbor.Marshal(uc)
		require.NoError(t, err)
		t.Logf("child certificate bytes=%d signatures=16 shard siblings=256 unicity steps=32", len(proof.UC))
	}

	const name = "joint-native-qualification"
	flatLargeCombinedWitnesses(t, w, v, registry, deposit, predecessor, fullPath, name)
	if dir := os.Getenv("NB2_FLAT_VECTOR_OUT"); dir != "" {
		generation := FlatHash("GEN", v.deployment.Salt[:], v.domain[:])
		for file, data := range map[string][]byte{
			"gamma.bin": gamma, "domain.bin": v.domain[:], "generation.bin": generation[:],
			"pins.bin": v.deployment.Pins[:],
		} {
			require.NoError(t, os.WriteFile(filepath.Join(dir, name, file), data, 0644))
		}
	}
}
